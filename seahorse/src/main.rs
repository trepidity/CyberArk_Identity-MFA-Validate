use std::io;
use std::path::PathBuf;

use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tracing::{error, info};

use seahorse::auth;
use seahorse::config;
use seahorse::crypto;
use seahorse::saml;
use seahorse::tui::app::{App, FlowMode, Screen, SigningMode};
use seahorse::tui::input::handle_input;
use seahorse::tui::ui::render;

fn find_config_base_path() -> Option<PathBuf> {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("config").is_dir() {
            return Some(cwd);
        }
        if let Some(parent) = cwd.parent() {
            if parent.join("config").is_dir() {
                return Some(parent.to_path_buf());
            }
        }
    }
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

fn main() -> anyhow::Result<()> {
    // Setup file-based logging (seahorse.log in current directory)
    let log_file = std::fs::File::create("seahorse.log").expect("Failed to create seahorse.log");
    tracing_subscriber::fmt()
        .with_writer(log_file)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    info!("=== Seahorse starting ===");
    info!("Working directory: {:?}", std::env::current_dir().ok());

    // Build a multi-threaded tokio runtime (for async HTTP calls)
    // We don't use #[tokio::main] because the main thread must be free
    // for the native webview GUI event loop (macOS requires main thread for GUI).
    let rt = tokio::runtime::Runtime::new()?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        EnterAlternateScreen,
        crossterm::event::EnableBracketedPaste
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let config_base = find_config_base_path();

    let result = run_app(&mut terminal, &mut app, config_base, &rt);

    // Restore terminal
    disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::event::DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Application error: {}", e);
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    config_base: Option<PathBuf>,
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<()> {
    while app.running {
        terminal.draw(|frame| render(frame, app))?;

        // Load config when entering FlowSelect if not yet loaded
        if app.screen == Screen::FlowSelect && app.config.is_none() {
            if let Some(ref base) = config_base {
                let env = app.environment.unwrap_or(config::Environment::Prod);
                info!("Loading config for environment: {:?}", env);
                let config_dir = config::get_config_dir(base, env);
                info!("Config directory: {:?}", config_dir);
                match config::load_config(&config_dir) {
                    Ok(cfg) => {
                        info!("Config loaded successfully:");
                        info!("  url: {}", cfg.url);
                        info!("  appkey: {}", cfg.appkey);
                        info!("  certificate: {}", cfg.certificate);
                        info!("  timeout: {}", cfg.timeout);
                        if let Some(ref idp_cert_file) = cfg.idp_certificate {
                            let idp_cert_path = config_dir.join(idp_cert_file);
                            match saml::trust::load_idp_certificates(&idp_cert_path) {
                                Ok(store) => {
                                    info!(
                                        "Loaded IDP certificate: CN={}",
                                        saml::trust::cert_cn(&store.leaf_cert)
                                    );
                                    app.idp_trust_store = Some(store);
                                }
                                Err(e) => {
                                    info!(
                                        "Warning: Failed to load IDP certificate '{}': {}",
                                        idp_cert_file, e
                                    );
                                }
                            }
                        }
                        app.config = Some(cfg);
                    }
                    Err(e) => {
                        error!("Failed to load config: {}", e);
                        app.error_message = format!("Failed to load config: {}", e);
                        app.screen = Screen::Error;
                        continue;
                    }
                }
            } else {
                error!("Could not find config/ directory");
                app.error_message =
                    "Could not find config/ directory. Run from the project root.".to_string();
                app.screen = Screen::Error;
                continue;
            }
        }

        // Decode SAML input when in Waiting state from SamlInput (no auth flow selected)
        if app.screen == Screen::Waiting && app.flow_mode.is_none() && app.environment.is_none() {
            process_saml_viewer_input(app);
            continue;
        }

        // Run auth flow when in Waiting state
        if app.screen == Screen::Waiting {
            let flow = app.flow_mode.unwrap_or(FlowMode::RestApi);
            info!("Starting auth flow: {:?}", flow);
            info!("Username: {}", app.username);
            info!("Signing mode: {:?}", app.signing_mode);
            match flow {
                FlowMode::RestApi => {
                    rt.block_on(run_rest_flow(app));
                }
                FlowMode::Browser => {
                    run_browser_flow(terminal, app);
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
            error!("No configuration loaded");
            app.error_message = "No configuration loaded".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    info!("=== REST Flow Start ===");
    info!("Tenant: {}", config.url);
    info!("Username: {}", app.username);
    info!("Password length: {}", app.password.len());
    info!("OTP length: {}", app.otp_code.len());

    app.status_message = "Starting authentication with CyberArk...".to_string();

    let client = reqwest::Client::new();
    let tenant = &config.url;
    let username = &app.username;
    let password = &app.password;
    let otp = &app.otp_code;

    // Step 1: StartAuthentication
    let start_url = auth::rest_flow::build_start_auth_url(tenant);
    let start_body = auth::rest_flow::build_start_auth_body(username);
    info!("Step 1: StartAuthentication");
    info!("  URL: {}", start_url);
    info!("  Request body: {}", start_body);

    app.status_message = "Calling StartAuthentication...".to_string();
    let start_result = match auth::rest_flow::start_authentication(&client, tenant, username).await
    {
        Ok(r) => {
            info!("  Response: OK");
            info!("  Resolved tenant: {}", r.tenant);
            info!("  SessionId: {}", r.session_id);
            info!("  Challenges count: {}", r.challenges.len());
            for (ci, challenge) in r.challenges.iter().enumerate() {
                for (mi, m) in challenge.mechanisms.iter().enumerate() {
                    info!(
                        "  Challenge[{}].Mechanism[{}]: id={}, name={}, prompt={}",
                        ci, mi, m.mechanism_id, m.name, m.prompt
                    );
                }
            }
            r
        }
        Err(e) => {
            error!("StartAuthentication failed: {}", e);
            app.error_message = format!("StartAuthentication failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    // Use the resolved tenant (may differ from config due to PodFqdn redirect)
    let resolved_tenant = &start_result.tenant;

    // Step 2: AdvanceAuthentication — Challenge 1 (Password)
    let password_mech = start_result
        .challenges
        .first()
        .and_then(|c| c.mechanisms.iter().find(|m| m.name == "UP"));
    let password_mech_id = match password_mech {
        Some(m) => m.mechanism_id.clone(),
        None => {
            error!("No password mechanism found in Challenge 1");
            app.error_message = "No password mechanism found in Challenge 1".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    info!("Step 2: AdvanceAuthentication (Password)");
    info!("  MechanismId: {}", password_mech_id);

    app.status_message = "Authenticating with password...".to_string();
    let pw_result = match auth::rest_flow::advance_authentication(
        &client,
        resolved_tenant,
        &start_result.session_id,
        &password_mech_id,
        "Answer",
        password,
    )
    .await
    {
        Ok(r) => {
            info!("  Success: {}", r.success);
            info!("  Summary: {}", r.summary);
            r
        }
        Err(e) => {
            error!("Password authentication failed: {}", e);
            app.error_message = format!("Password authentication failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    if !pw_result.success && pw_result.summary != "StartNextChallenge" {
        error!("Password authentication failed: {}", pw_result.summary);
        app.error_message = format!("Password authentication failed: {}", pw_result.summary);
        app.screen = Screen::Error;
        return;
    }

    info!("Password challenge passed, moving to OTP challenge");

    // Step 3: AdvanceAuthentication — Challenge 2 (OATH OTP)
    // OATH has AnswerType "StartTextOob" which requires two calls:
    //   1. StartOOB to select the mechanism
    //   2. Answer with the OTP code
    let oath_mech = start_result
        .challenges
        .get(1)
        .and_then(|c| c.mechanisms.iter().find(|m| m.name == "OATH"));
    let oath_mech_id = match oath_mech {
        Some(m) => m.mechanism_id.clone(),
        None => {
            error!("No OATH mechanism found in Challenge 2");
            app.error_message = "No OATH mechanism found in Challenge 2".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    info!("Step 3a: AdvanceAuthentication (StartOOB for OATH)");
    info!("  MechanismId: {}", oath_mech_id);

    app.status_message = "Starting OATH challenge...".to_string();
    let start_oob_result = match auth::rest_flow::advance_authentication(
        &client,
        resolved_tenant,
        &start_result.session_id,
        &oath_mech_id,
        "StartOOB",
        "",
    )
    .await
    {
        Ok(r) => {
            info!("  Success: {}", r.success);
            info!("  Summary: {}", r.summary);
            r
        }
        Err(e) => {
            error!("StartOOB failed: {}", e);
            app.error_message = format!("StartOOB failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    if !start_oob_result.success {
        error!("StartOOB failed: {}", start_oob_result.summary);
        app.error_message = format!("StartOOB failed: {}", start_oob_result.summary);
        app.screen = Screen::Error;
        return;
    }

    info!("Step 3b: AdvanceAuthentication (Answer OATH OTP)");

    app.status_message = "Validating OTP code...".to_string();
    let otp_result = match auth::rest_flow::advance_authentication(
        &client,
        resolved_tenant,
        &start_result.session_id,
        &oath_mech_id,
        "Answer",
        otp,
    )
    .await
    {
        Ok(r) => {
            info!("  Success: {}", r.success);
            info!("  Summary: {}", r.summary);
            info!("  Token present: {}", r.token.is_some());
            r
        }
        Err(e) => {
            error!("OTP authentication failed: {}", e);
            app.error_message = format!("OTP authentication failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    if !otp_result.success {
        error!("OTP authentication failed: {}", otp_result.summary);
        app.error_message = format!("OTP authentication failed: {}", otp_result.summary);
        app.screen = Screen::Error;
        return;
    }

    info!("Authentication successful!");

    // Step 3: Build SAML assertion
    info!("Step 3: Building SAML assertion");
    app.status_message = "Building SAML assertion...".to_string();
    let audience = "epic://epicenvironment";
    let validity_seconds = (config.timeout * 5) as i64;
    info!("=== SAML Assertion Request ===");
    info!("  Issuer: {}", config.url);
    info!("  Audience: {}", audience);
    info!("  Username: {}", app.username);
    info!("  Validity seconds: {}", validity_seconds);
    info!("  Signing mode: {:?}", app.signing_mode);

    let assertion_params = saml::builder::AssertionParams {
        issuer: config.url.clone(),
        audience: audience.to_string(),
        username: app.username.clone(),
        validity_seconds,
    };

    let assertion_xml = if app.signing_mode == SigningMode::Signed {
        info!("  Loading PFX certificate for signing...");
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

    // Log the built assertion for troubleshooting
    info!("=== SAML Assertion Response ===");
    info!("  Assertion XML length: {} chars", assertion_xml.len());
    info!("  Assertion XML:\n{}", assertion_xml);

    // Step 4: Parse and validate
    finalize_assertion(app, &assertion_xml);
}

fn run_browser_flow(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) {
    let config = match app.config.clone() {
        Some(c) => c,
        None => {
            error!("No configuration loaded for browser flow");
            app.error_message = "No configuration loaded".to_string();
            app.screen = Screen::Error;
            return;
        }
    };

    info!("=== Browser Flow Start ===");
    info!("Tenant: {}", config.url);
    info!("AppKey: {}", config.appkey);
    info!("Username: {}", app.username);

    let login_url = auth::browser_flow::build_login_url(&config.url, &app.username, &config.appkey);
    info!("Login URL: {}", login_url);

    // Exit TUI so the webview window can take focus
    info!("Exiting TUI for webview...");
    let _ = disable_raw_mode();
    let _ = crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    // Run the native webview on the main thread (required for macOS)
    let saml_b64 = match auth::browser_flow::run_webview_flow(&login_url) {
        Ok(b64) => {
            info!("SAMLResponse received ({} chars)", b64.len());
            b64
        }
        Err(e) => {
            error!("Browser flow failed: {}", e);
            // Re-enter TUI before showing error
            let _ = enable_raw_mode();
            let _ = crossterm::execute!(io::stdout(), EnterAlternateScreen);
            app.error_message = format!("Browser flow failed: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    // Re-enter TUI
    info!("Re-entering TUI...");
    let _ = enable_raw_mode();
    let _ = crossterm::execute!(io::stdout(), EnterAlternateScreen);

    // The IPC gives us the raw base64-encoded SAMLResponse value.
    // Decode it to get the XML, then extract the assertion.
    info!("Decoding SAMLResponse...");
    let xml_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &saml_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to base64-decode SAMLResponse: {}", e);
                app.error_message = format!("Failed to base64-decode SAMLResponse: {}", e);
                app.screen = Screen::Error;
                return;
            }
        };

    let response_xml = match String::from_utf8(xml_bytes) {
        Ok(s) => s,
        Err(e) => {
            error!("SAMLResponse is not valid UTF-8: {}", e);
            app.error_message = format!("SAMLResponse is not valid UTF-8: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    info!("SAMLResponse XML length: {}", response_xml.len());
    info!(
        "SAMLResponse XML:\n{}",
        &response_xml[..response_xml.len().min(1000)]
    );

    // Extract the <Assertion> from the <saml2p:Response>
    let assertion_xml = match saml::parser::extract_assertion_from_response(&response_xml) {
        Ok(xml) => xml,
        Err(e) => {
            error!("Failed to extract assertion from response: {}", e);
            app.error_message = format!("Failed to extract assertion: {}", e);
            app.screen = Screen::Error;
            return;
        }
    };

    finalize_assertion(app, &assertion_xml);
}

fn finalize_assertion(app: &mut App, assertion_xml: &str) {
    info!("=== Finalizing Assertion ===");
    info!("Assertion XML length: {}", assertion_xml.len());
    info!("Assertion XML:\n{}", assertion_xml);

    // Extract details
    info!("Extracting assertion details...");
    match saml::parser::extract_assertion_details(assertion_xml) {
        Ok(details) => {
            info!("Assertion details extracted:");
            info!("  Issuer: {}", details.issuer);
            info!("  Subject: {}", details.subject);
            info!("  Audience: {}", details.audience);
            info!("  NotBefore: {:?}", details.not_before);
            info!("  NotAfter: {:?}", details.not_after);
            info!("  AuthnContext: {}", details.authn_context);
            app.assertion_details = Some(details);
        }
        Err(e) => {
            error!("Failed to extract assertion details: {}", e);
            app.error_message = format!("Failed to extract assertion details: {}", e);
            app.screen = Screen::Error;
            return;
        }
    }

    // Validate signature
    info!("Validating assertion...");
    let report = saml::validator::validate_assertion(assertion_xml, app.idp_trust_store.as_ref());
    info!("Validation result: {:?}", report.summary);
    for check in &report.checks {
        info!(
            "  {}: {} (passed: {})",
            check.name, check.detail, check.passed
        );
    }
    app.signature_validation = Some(report);

    info!("=== Assertion finalized, showing result ===");
    app.raw_xml_original = assertion_xml.to_string();
    app.raw_xml = saml::parser::pretty_print_xml(assertion_xml);
    app.screen = Screen::Result;
}

fn process_saml_viewer_input(app: &mut App) {
    let input = std::mem::take(&mut app.status_message);

    match saml::decoder::decode_saml_input(&input) {
        Ok(result) => {
            app.viewer_pretty_xml = saml::parser::pretty_print_xml(&result.xml);

            match result.document_type {
                saml::decoder::SamlDocumentType::AuthnRequest => {
                    if let Ok(details) = saml::parser::extract_authn_request_details(&result.xml) {
                        app.viewer_authn_request = Some(details);
                    }
                }
                saml::decoder::SamlDocumentType::Response => {
                    if let Ok(details) = saml::parser::extract_response_details(&result.xml) {
                        app.viewer_response = Some(details);
                    }
                    if let Ok(assertion_xml) =
                        saml::parser::extract_assertion_from_response(&result.xml)
                    {
                        if let Ok(details) = saml::parser::extract_assertion_details(&assertion_xml)
                        {
                            app.viewer_assertion = Some(details);
                        }
                        if let Ok(attrs) = saml::parser::extract_attributes(&assertion_xml) {
                            app.viewer_attributes = attrs;
                        }
                        let sig = saml::validator::validate_assertion(
                            &assertion_xml,
                            app.idp_trust_store.as_ref(),
                        );
                        app.viewer_signature = Some(sig);
                    }
                }
                saml::decoder::SamlDocumentType::Assertion => {
                    if let Ok(details) = saml::parser::extract_assertion_details(&result.xml) {
                        app.viewer_assertion = Some(details);
                    }
                    if let Ok(attrs) = saml::parser::extract_attributes(&result.xml) {
                        app.viewer_attributes = attrs;
                    }
                    let sig = saml::validator::validate_assertion(
                        &result.xml,
                        app.idp_trust_store.as_ref(),
                    );
                    app.viewer_signature = Some(sig);
                }
            }

            app.decoded_saml = Some(result);
            app.screen = Screen::SamlView;
        }
        Err(e) => {
            app.error_message = format!("Failed to decode SAML: {}", e);
            app.screen = Screen::Error;
        }
    }
}
