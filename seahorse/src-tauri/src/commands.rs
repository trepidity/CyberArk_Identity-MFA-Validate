use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{Emitter, Listener, State};

#[derive(Default)]
pub struct AppState {
    pub config: Option<seahorse::config::Config>,
    pub config_dir: Option<PathBuf>,
    pub idp_trust_store: Option<seahorse::saml::trust::IdpTrustStore>,
    pub last_raw_xml: Option<String>,
}

// --- DTOs ---

#[derive(Serialize)]
pub struct ConfigInfo {
    pub url: String,
    pub timeout: u64,
    pub check_user: bool,
    pub use_bypass: bool,
    pub browser: String,
    pub has_idp_cert: bool,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum DecodedSaml {
    AuthnRequest {
        details: seahorse::saml::parser::AuthnRequestDetails,
        pretty_xml: String,
    },
    Response {
        response: seahorse::saml::parser::ResponseDetails,
        assertion: Option<seahorse::saml::parser::AssertionDetails>,
        attributes: Vec<seahorse::saml::parser::SamlAttribute>,
        validation: Option<seahorse::saml::validator::ValidationReport>,
        pretty_xml: String,
        raw_xml: String,
    },
    Assertion {
        details: seahorse::saml::parser::AssertionDetails,
        attributes: Vec<seahorse::saml::parser::SamlAttribute>,
        validation: seahorse::saml::validator::ValidationReport,
        pretty_xml: String,
        raw_xml: String,
    },
}

#[derive(Serialize)]
pub struct CertInfoDto {
    pub cn: String,
    pub chain_count: usize,
    pub source_path: String,
}

// --- Config path resolution ---

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

// --- Commands ---

#[tauri::command]
pub fn load_config(
    state: State<'_, Mutex<AppState>>,
    environment: Option<String>,
) -> Result<ConfigInfo, String> {
    let base = find_config_base_path()
        .ok_or_else(|| "Could not find config/ directory. Run from the project root.".to_string())?;

    let env = match environment.as_deref() {
        Some("TST") | Some("tst") => seahorse::config::Environment::Tst,
        _ => seahorse::config::Environment::Prod,
    };

    let config_dir = seahorse::config::get_config_dir(&base, env);
    let cfg = seahorse::config::load_config(&config_dir)
        .map_err(|e| format!("Failed to load config: {}", e))?;

    let has_idp_cert;

    {
        let mut guard = state.lock().unwrap();

        // If config has idp_certificate, load trust store
        if let Some(ref idp_cert_file) = cfg.idp_certificate {
            let idp_cert_path = config_dir.join(idp_cert_file);
            match seahorse::saml::trust::load_idp_certificates(&idp_cert_path) {
                Ok(store) => {
                    guard.idp_trust_store = Some(store);
                }
                Err(_) => {
                    // Non-fatal: we continue without trust store
                }
            }
        }

        has_idp_cert = guard.idp_trust_store.is_some();
        guard.config_dir = Some(config_dir);
        guard.config = Some(cfg.clone());
    }

    Ok(ConfigInfo {
        url: cfg.url,
        timeout: cfg.timeout,
        check_user: cfg.check_user,
        use_bypass: cfg.use_bypass,
        browser: cfg.browser,
        has_idp_cert,
    })
}

#[tauri::command]
pub fn decode_saml(
    state: State<'_, Mutex<AppState>>,
    input: String,
) -> Result<DecodedSaml, String> {
    let result = seahorse::saml::decoder::decode_saml_input(&input)
        .map_err(|e| format!("Failed to decode SAML: {}", e))?;

    let pretty_xml = seahorse::saml::parser::pretty_print_xml(&result.xml);

    let decoded = {
        let guard = state.lock().unwrap();
        let trust_store_ref = guard.idp_trust_store.as_ref();

        match result.document_type {
            seahorse::saml::decoder::SamlDocumentType::AuthnRequest => {
                let details =
                    seahorse::saml::parser::extract_authn_request_details(&result.xml)
                        .map_err(|e| format!("Failed to parse AuthnRequest: {}", e))?;
                DecodedSaml::AuthnRequest {
                    details,
                    pretty_xml,
                }
            }
            seahorse::saml::decoder::SamlDocumentType::Response => {
                let response =
                    seahorse::saml::parser::extract_response_details(&result.xml).ok();

                let (assertion, attributes, validation) =
                    match seahorse::saml::parser::extract_assertion_from_response(&result.xml) {
                        Ok(assertion_xml) => {
                            let assertion_details =
                                seahorse::saml::parser::extract_assertion_details(&assertion_xml)
                                    .ok();
                            let attrs =
                                seahorse::saml::parser::extract_attributes(&assertion_xml)
                                    .unwrap_or_default();
                            let sig = seahorse::saml::validator::validate_assertion(
                                &assertion_xml,
                                trust_store_ref,
                            );
                            (assertion_details, attrs, Some(sig))
                        }
                        Err(_) => (None, Vec::new(), None),
                    };

                let response = response.unwrap_or_default();

                DecodedSaml::Response {
                    response,
                    assertion,
                    attributes,
                    validation,
                    pretty_xml,
                    raw_xml: result.xml.clone(),
                }
            }
            seahorse::saml::decoder::SamlDocumentType::Assertion => {
                let details =
                    seahorse::saml::parser::extract_assertion_details(&result.xml)
                        .map_err(|e| format!("Failed to parse Assertion: {}", e))?;
                let attributes = seahorse::saml::parser::extract_attributes(&result.xml)
                    .unwrap_or_default();
                let validation = seahorse::saml::validator::validate_assertion(
                    &result.xml,
                    trust_store_ref,
                );

                DecodedSaml::Assertion {
                    details,
                    attributes,
                    validation,
                    pretty_xml,
                    raw_xml: result.xml.clone(),
                }
            }
        }
    };

    // Store raw XML for save functionality (guard is dropped, safe to re-lock)
    {
        let mut guard = state.lock().unwrap();
        guard.last_raw_xml = Some(result.xml);
    }

    Ok(decoded)
}

#[tauri::command]
pub fn validate_assertion(
    state: State<'_, Mutex<AppState>>,
    xml: String,
) -> Result<seahorse::saml::validator::ValidationReport, String> {
    let guard = state.lock().unwrap();
    Ok(seahorse::saml::validator::validate_assertion(
        &xml,
        guard.idp_trust_store.as_ref(),
    ))
}

#[tauri::command]
pub fn load_idp_cert(
    state: State<'_, Mutex<AppState>>,
    path: String,
) -> Result<CertInfoDto, String> {
    let cert_path = Path::new(&path);
    let store = seahorse::saml::trust::load_idp_certificates(cert_path)
        .map_err(|e| format!("Failed to load IDP certificate: {}", e))?;

    let cn = seahorse::saml::trust::cert_cn(&store.leaf_cert);
    let chain_count = store.chain_certs.len();
    let source_path = store.source_path.display().to_string();

    let mut guard = state.lock().unwrap();
    guard.idp_trust_store = Some(store);

    Ok(CertInfoDto {
        cn,
        chain_count,
        source_path,
    })
}

#[tauri::command]
pub fn save_raw_xml(state: State<'_, Mutex<AppState>>, path: String) -> Result<(), String> {
    let xml = {
        let s = state.lock().unwrap();
        s.last_raw_xml.clone().ok_or("No SAML data to save")?
    };
    std::fs::write(&path, &xml).map_err(|e| format!("Failed to save: {}", e))
}

// --- Helper: emit progress event ---

fn emit_progress(app: &tauri::AppHandle, step: &str, message: &str) {
    app.emit(
        "auth-progress",
        serde_json::json!({ "step": step, "message": message }),
    )
    .ok();
}

// --- Helper: build SAML assertion XML ---

fn build_assertion_xml(
    config: &seahorse::config::Config,
    config_dir: &Path,
    username: &str,
    signed: bool,
) -> Result<String, String> {
    let audience = "epic://epicenvironment";
    let validity_seconds = (config.timeout * 5) as i64;

    let params = seahorse::saml::builder::AssertionParams {
        issuer: config.url.clone(),
        audience: audience.to_string(),
        username: username.to_string(),
        validity_seconds,
    };

    if signed {
        let pfx_path = seahorse::config::get_pfx_path(config_dir, &config.certificate);
        let certkey = seahorse::config::decode_certkey(&config.certkey)
            .map_err(|e| format!("Failed to decode certkey: {}", e))?;
        let bundle = seahorse::crypto::load_pfx(&pfx_path, &certkey)
            .map_err(|e| format!("Failed to load PFX: {}", e))?;
        let private_key = bundle
            .private_key
            .ok_or("PFX does not contain a private key")?;
        let cert = bundle
            .certificate
            .ok_or("PFX does not contain a certificate")?;
        seahorse::saml::builder::build_signed_assertion(&params, &private_key, &cert)
            .map_err(|e| format!("Failed to build signed assertion: {}", e))
    } else {
        Ok(seahorse::saml::builder::build_unsigned_assertion(&params))
    }
}

// --- Helper: validate assertion XML and produce DecodedSaml ---

fn validate_assertion_xml(
    assertion_xml: &str,
    trust_store: Option<&seahorse::saml::trust::IdpTrustStore>,
) -> Result<DecodedSaml, String> {
    let details = seahorse::saml::parser::extract_assertion_details(assertion_xml)
        .map_err(|e| format!("Failed to parse assertion: {}", e))?;
    let attributes =
        seahorse::saml::parser::extract_attributes(assertion_xml).unwrap_or_default();
    let validation =
        seahorse::saml::validator::validate_assertion(assertion_xml, trust_store);
    let pretty_xml = seahorse::saml::parser::pretty_print_xml(assertion_xml);

    Ok(DecodedSaml::Assertion {
        details,
        attributes,
        validation,
        pretty_xml,
        raw_xml: assertion_xml.to_string(),
    })
}

// --- REST Flow Command ---

#[tauri::command]
pub async fn run_rest_flow(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    username: String,
    password: String,
    otp: String,
    signed: bool,
) -> Result<DecodedSaml, String> {
    // Step 1: Read config from state (short lock, no trust store clone needed)
    let (config, config_dir) = {
        let guard = state.lock().unwrap();
        let config = guard
            .config
            .clone()
            .ok_or("No configuration loaded. Go back and select an environment.")?;
        let config_dir = guard
            .config_dir
            .clone()
            .ok_or("No config directory set")?;
        (config, config_dir)
    };

    emit_progress(&app, "start", "Starting authentication...");

    let client = reqwest::Client::new();
    let tenant = &config.url;

    // Step 2: StartAuthentication
    emit_progress(&app, "start_auth", "Calling StartAuthentication...");
    let start_result =
        seahorse::auth::rest_flow::start_authentication(&client, tenant, &username)
            .await
            .map_err(|e| format!("StartAuthentication failed: {}", e))?;

    let resolved_tenant = &start_result.tenant;

    // Step 3: AdvanceAuthentication with password
    emit_progress(&app, "password", "Authenticating with password...");
    let password_mech = start_result
        .challenges
        .first()
        .and_then(|c| c.mechanisms.iter().find(|m| m.name == "UP"))
        .ok_or("No password mechanism (UP) found in Challenge 1")?;

    let pw_result = seahorse::auth::rest_flow::advance_authentication(
        &client,
        resolved_tenant,
        &start_result.session_id,
        &password_mech.mechanism_id,
        "Answer",
        &password,
    )
    .await
    .map_err(|e| format!("Password authentication failed: {}", e))?;

    if !pw_result.success && pw_result.summary != "StartNextChallenge" {
        return Err(format!(
            "Password authentication failed: {}",
            pw_result.summary
        ));
    }

    // Step 4: AdvanceAuthentication StartOOB for OATH
    emit_progress(&app, "start_oob", "Starting OATH challenge...");
    let oath_mech = start_result
        .challenges
        .get(1)
        .and_then(|c| c.mechanisms.iter().find(|m| m.name == "OATH"))
        .ok_or("No OATH mechanism found in Challenge 2")?;

    let start_oob_result = seahorse::auth::rest_flow::advance_authentication(
        &client,
        resolved_tenant,
        &start_result.session_id,
        &oath_mech.mechanism_id,
        "StartOOB",
        "",
    )
    .await
    .map_err(|e| format!("StartOOB failed: {}", e))?;

    if !start_oob_result.success {
        return Err(format!("StartOOB failed: {}", start_oob_result.summary));
    }

    // Step 5: AdvanceAuthentication Answer with OTP
    emit_progress(&app, "otp", "Validating OTP code...");
    let otp_result = seahorse::auth::rest_flow::advance_authentication(
        &client,
        resolved_tenant,
        &start_result.session_id,
        &oath_mech.mechanism_id,
        "Answer",
        &otp,
    )
    .await
    .map_err(|e| format!("OTP authentication failed: {}", e))?;

    if !otp_result.success {
        return Err(format!(
            "OTP authentication failed: {}",
            otp_result.summary
        ));
    }

    // Step 6: Build SAML assertion (sync, no state lock needed)
    emit_progress(&app, "assertion", "Building SAML assertion...");
    let assertion_xml = build_assertion_xml(&config, &config_dir, &username, signed)?;

    // Validate assertion while holding state lock (for trust store reference)
    let decoded = {
        let mut guard = state.lock().unwrap();
        let result = validate_assertion_xml(&assertion_xml, guard.idp_trust_store.as_ref())?;
        guard.last_raw_xml = Some(assertion_xml);
        result
    };

    emit_progress(&app, "done", "Authentication complete!");
    Ok(decoded)
}

// --- Browser Flow Command ---

/// JavaScript injected into the CyberArk login webview to intercept the SAMLResponse.
/// Adapted from seahorse::auth::browser_flow::INTERCEPT_JS to use Tauri IPC.
const TAURI_INTERCEPT_JS: &str = r#"
(function() {
    var captured = false;

    function sendToTauri(value) {
        if (captured) return;
        captured = true;
        if (window.__TAURI__ && window.__TAURI__.event) {
            window.__TAURI__.event.emit('saml-response-captured', value);
        }
    }

    // Layer 1: Override HTMLFormElement.prototype.submit() globally.
    var originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        var input = this.querySelector('input[name="SAMLResponse"]');
        if (input && input.value) {
            sendToTauri(input.value);
            return;
        }
        originalSubmit.call(this);
    };

    // Layer 2: Global submit event listener (capture phase).
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var input = form.querySelector('input[name="SAMLResponse"]');
        if (input && input.value) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            sendToTauri(input.value);
            return false;
        }
    }, true);

    // Layer 3: Poll for SAMLResponse input appearing in the DOM.
    var checkInterval = setInterval(function() {
        var inputs = document.querySelectorAll('input[name="SAMLResponse"]');
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].value) {
                clearInterval(checkInterval);
                sendToTauri(inputs[i].value);
                return;
            }
        }
    }, 50);

    // Stop polling after 120 seconds
    setTimeout(function() { clearInterval(checkInterval); }, 120000);
})();
"#;

#[tauri::command]
pub async fn run_browser_flow(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    username: String,
    signed: bool,
) -> Result<DecodedSaml, String> {
    // Read config from state (short lock, no trust store clone needed)
    let (config, config_dir) = {
        let guard = state.lock().unwrap();
        let config = guard
            .config
            .clone()
            .ok_or("No configuration loaded. Go back and select an environment.")?;
        let config_dir = guard
            .config_dir
            .clone()
            .ok_or("No config directory set")?;
        (config, config_dir)
    };

    // The `signed` parameter is accepted but not used for browser flow:
    // the browser flow returns CyberArk's own signed SAMLResponse, not a locally-built assertion.
    // We keep it in the signature for API symmetry.
    let _ = (signed, &config_dir);

    emit_progress(&app, "start", "Opening CyberArk login window...");

    let login_url =
        seahorse::auth::browser_flow::build_login_url(&config.url, &username, &config.appkey);

    // Create a one-shot channel to receive the SAMLResponse
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let tx = std::sync::Mutex::new(Some(tx));

    // Listen for the saml-response-captured event from the injected JS
    let listener_id = app.listen("saml-response-captured", move |event: tauri::Event| {
        let payload_str = event.payload();
        // The JS emit sends the value as a JSON string, so strip the outer quotes
        let saml_b64 = payload_str.trim().trim_matches('"').to_string();
        if let Some(sender) = tx.lock().unwrap().take() {
            let _ = sender.send(saml_b64);
        }
    });

    // Open a second Tauri webview window for the CyberArk login
    let auth_window = tauri::WebviewWindowBuilder::new(
        &app,
        "cyberark-login",
        tauri::WebviewUrl::External(
            login_url
                .parse()
                .map_err(|e| format!("Invalid login URL: {}", e))?,
        ),
    )
    .title("Seahorse - CyberArk Login")
    .inner_size(800.0, 700.0)
    .initialization_script(TAURI_INTERCEPT_JS)
    .build()
    .map_err(|e| format!("Failed to open login window: {}", e))?;

    emit_progress(
        &app,
        "waiting",
        "Waiting for authentication in browser window...",
    );

    // Listen for the window being closed (destroyed)
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
    let close_tx = std::sync::Mutex::new(Some(close_tx));
    let close_window_label = auth_window.label().to_string();
    let close_listener_id = app.listen("tauri://destroyed", move |event: tauri::Event| {
        let payload = event.payload();
        if payload.contains(&close_window_label) {
            if let Some(sender) = close_tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
    });

    // Wait for either SAMLResponse or window close
    let saml_b64 = tokio::select! {
        result = rx => {
            match result {
                Ok(b64) => b64,
                Err(_) => return Err("Channel closed unexpectedly".to_string()),
            }
        }
        _ = close_rx => {
            app.unlisten(listener_id);
            app.unlisten(close_listener_id);
            return Err("Login window was closed without completing authentication".to_string());
        }
    };

    // Clean up listeners and close the login window
    app.unlisten(listener_id);
    app.unlisten(close_listener_id);
    let _ = auth_window.close();

    emit_progress(&app, "decoding", "Decoding SAML response...");

    // Decode the base64 SAMLResponse
    let xml_bytes = STANDARD
        .decode(&saml_b64)
        .map_err(|e| format!("Failed to base64-decode SAMLResponse: {}", e))?;
    let response_xml = String::from_utf8(xml_bytes)
        .map_err(|e| format!("SAMLResponse is not valid UTF-8: {}", e))?;

    // Extract the assertion from the SAML Response
    let assertion_xml =
        seahorse::saml::parser::extract_assertion_from_response(&response_xml)
            .map_err(|e| format!("Failed to extract assertion: {}", e))?;

    // Validate while holding state lock (for trust store reference)
    emit_progress(&app, "validating", "Validating assertion...");
    let decoded = {
        let mut guard = state.lock().unwrap();
        let result =
            validate_assertion_xml(&assertion_xml, guard.idp_trust_store.as_ref())?;
        guard.last_raw_xml = Some(assertion_xml);
        result
    };

    emit_progress(&app, "done", "Browser authentication complete!");
    Ok(decoded)
}
