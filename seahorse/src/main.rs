use std::io;
use std::path::PathBuf;

use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use seahorse::auth;
use seahorse::config;
use seahorse::crypto;
use seahorse::saml;
use seahorse::tui::app::{App, FlowMode, Screen, SigningMode};
use seahorse::tui::input::handle_input;
use seahorse::tui::ui::render;

fn find_config_base_path() -> Option<PathBuf> {
    // Check current working directory
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("config").is_dir() {
            return Some(cwd);
        }
        // Check parent of cwd
        if let Some(parent) = cwd.parent() {
            if parent.join("config").is_dir() {
                return Some(parent.to_path_buf());
            }
        }
    }
    // Check relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            if exe_dir.join("config").is_dir() {
                return Some(exe_dir.to_path_buf());
            }
            if let Some(parent) = exe_dir.parent() {
                if parent.join("config").is_dir() {
                    return Some(parent.to_path_buf());
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let config_base = find_config_base_path();

    let result = run_app(&mut terminal, &mut app, config_base).await;

    // Restore terminal
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Application error: {}", e);
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    config_base: Option<PathBuf>,
) -> anyhow::Result<()> {
    while app.running {
        terminal.draw(|frame| render(frame, app))?;

        // Load config when entering FlowSelect if not yet loaded
        if app.screen == Screen::FlowSelect && app.config.is_none() {
            if let Some(ref base) = config_base {
                let env = app.environment.unwrap_or(config::Environment::Prod);
                let config_dir = config::get_config_dir(base, env);
                match config::load_config(&config_dir) {
                    Ok(cfg) => app.config = Some(cfg),
                    Err(e) => {
                        app.error_message = format!("Failed to load config: {}", e);
                        app.screen = Screen::Error;
                        continue;
                    }
                }
            } else {
                app.error_message =
                    "Could not find config/ directory. Run from the project root.".to_string();
                app.screen = Screen::Error;
                continue;
            }
        }

        // Run auth flow when in Waiting state
        if app.screen == Screen::Waiting {
            let flow = app.flow_mode.unwrap_or(FlowMode::RestApi);
            match flow {
                FlowMode::RestApi => {
                    run_rest_flow(app).await;
                }
                FlowMode::Browser => {
                    run_browser_flow(app).await;
                }
            }
            continue;
        }

        handle_input(app)?;

        // Reset config if environment changed (going back to EnvSelect)
        if app.screen == Screen::EnvSelect {
            app.config = None;
        }
    }

    Ok(())
}

async fn run_rest_flow(app: &mut App) {
    let config = match app.config.clone() {
        Some(c) => c,
        None => {
            app.error_message = "No configuration loaded".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    app.status_message = "Starting authentication with CyberArk...".to_string();

    let client = reqwest::Client::new();
    let tenant = &config.url;
    let username = &app.username;
    let otp = &app.otp_code;

    // Step 1: StartAuthentication
    app.status_message = "Calling StartAuthentication...".to_string();
    let start_result = match auth::rest_flow::start_authentication(&client, tenant, username).await
    {
        Ok(r) => r,
        Err(e) => {
            app.error_message = format!("StartAuthentication failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    // Step 2: AdvanceAuthentication with OTP
    let mechanism_id = match start_result.mechanisms.first() {
        Some(m) => m.mechanism_id.clone(),
        None => {
            app.error_message = "No authentication mechanisms returned".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    app.status_message = "Calling AdvanceAuthentication...".to_string();
    let advance_result = match auth::rest_flow::advance_authentication(
        &client,
        tenant,
        &start_result.session_id,
        &mechanism_id,
        otp,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            app.error_message = format!("AdvanceAuthentication failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    if !advance_result.success {
        app.error_message = format!("Authentication failed: {}", advance_result.summary);
        app.screen = Screen::Error;
        return;
    }

    // Step 3: Build SAML assertion
    app.status_message = "Building SAML assertion...".to_string();
    let audience = "epic://epicenvironment";
    let validity_seconds = (config.timeout * 5) as i64;

    let assertion_params = saml::builder::AssertionParams {
        issuer: config.url.clone(),
        audience: audience.to_string(),
        username: app.username.clone(),
        validity_seconds,
    };

    let assertion_xml = if app.signing_mode == SigningMode::Signed {
        // Load certificate for signing
        let env = app.environment.unwrap_or(config::Environment::Prod);
        let base = match find_config_base_path() {
            Some(b) => b,
            None => {
                app.error_message = "Cannot find config base path".to_string();
                app.screen = Screen::Error;
                return;
            }
        };
        let config_dir = config::get_config_dir(&base, env);
        let pfx_path = config::get_pfx_path(&config_dir, &config.certificate);
        let certkey = match config::decode_certkey(&config.certkey) {
            Ok(k) => k,
            Err(e) => {
                app.error_message = format!("Failed to decode certkey: {}", e);
                app.screen = Screen::Error;
                return;
            }
        };
        let bundle = match crypto::load_pfx(&pfx_path, &certkey) {
            Ok(b) => b,
            Err(e) => {
                app.error_message = format!("Failed to load PFX: {}", e);
                app.screen = Screen::Error;
                return;
            }
        };
        let private_key = match bundle.private_key {
            Some(k) => k,
            None => {
                app.error_message = "PFX does not contain a private key".to_string();
                app.screen = Screen::Error;
                return;
            }
        };
        let cert = match bundle.certificate {
            Some(c) => c,
            None => {
                app.error_message = "PFX does not contain a certificate".to_string();
                app.screen = Screen::Error;
                return;
            }
        };
        match saml::builder::build_signed_assertion(&assertion_params, &private_key, &cert) {
            Ok(xml) => xml,
            Err(e) => {
                app.error_message = format!("Failed to build signed assertion: {}", e);
                app.screen = Screen::Error;
                return;
            }
        }
    } else {
        saml::builder::build_unsigned_assertion(&assertion_params)
    };

    // Step 4: Parse and validate
    finalize_assertion(app, &assertion_xml);
}

async fn run_browser_flow(app: &mut App) {
    let config = match app.config.clone() {
        Some(c) => c,
        None => {
            app.error_message = "No configuration loaded".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    app.status_message = "Starting ACS listener...".to_string();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel::<u16>();
    let acs_handle = tokio::spawn(async move {
        auth::browser_flow::start_acs_listener(0, port_tx).await
    });

    let port = match port_rx.await {
        Ok(p) => p,
        Err(e) => {
            app.error_message = format!("Failed to get ACS listener port: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    let _acs_url = format!("http://127.0.0.1:{}/acs", port);
    let login_url = auth::browser_flow::build_login_url(
        &config.url,
        &app.username,
        &config.appkey,
    );

    app.status_message = format!(
        "Browser opening...\nACS listening on port {}\nWaiting for SAMLResponse...",
        port
    );

    if let Err(e) = auth::browser_flow::open_browser(&login_url) {
        app.error_message = format!("Failed to open browser: {}", e);
        app.screen = Screen::Error;
        return;
    }

    // Wait for the SAMLResponse
    let saml_body = match acs_handle.await {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            app.error_message = format!("ACS listener error: {}", e);
            app.screen = Screen::Error;
            return;
        }
        Err(e) => {
            app.error_message = format!("ACS task error: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    // Parse the SAML POST body
    let parse_result = match saml::parser::parse_saml_post_body(&saml_body) {
        Ok(r) => r,
        Err(e) => {
            app.error_message = format!("Failed to parse SAMLResponse: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    finalize_assertion(app, &parse_result.assertion_xml);
}

fn finalize_assertion(app: &mut App, assertion_xml: &str) {
    // Extract details
    match saml::parser::extract_assertion_details(assertion_xml) {
        Ok(details) => {
            app.assertion_details = Some(details);
        }
        Err(e) => {
            app.error_message = format!("Failed to extract assertion details: {}", e);
            app.screen = Screen::Error;
            return;
        }
    }

    // Validate signature
    match saml::validator::validate_assertion_signature(assertion_xml) {
        Ok(validation) => {
            app.signature_validation = Some(validation);
        }
        Err(e) => {
            app.error_message = format!("Signature validation error: {}", e);
            app.screen = Screen::Error;
            return;
        }
    }

    app.raw_xml = assertion_xml.to_string();
    app.screen = Screen::Result;
}
