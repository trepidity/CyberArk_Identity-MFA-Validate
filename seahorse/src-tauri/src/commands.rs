use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{Emitter, State};

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
    // Walk up from CWD looking for a config/ directory
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        loop {
            if dir.join("config").is_dir() {
                return Some(dir.to_path_buf());
            }
            match dir.parent() {
                Some(parent) => dir = parent,
                None => break,
            }
        }
    }
    // Walk up from executable location
    if let Ok(exe) = std::env::current_exe() {
        let mut dir_opt = exe.parent();
        while let Some(dir) = dir_opt {
            if dir.join("config").is_dir() {
                return Some(dir.to_path_buf());
            }
            dir_opt = dir.parent();
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
    let base = find_config_base_path().ok_or_else(|| {
        "Could not find config/ directory. Run from the project root.".to_string()
    })?;

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
                let details = seahorse::saml::parser::extract_authn_request_details(&result.xml)
                    .map_err(|e| format!("Failed to parse AuthnRequest: {}", e))?;
                DecodedSaml::AuthnRequest {
                    details,
                    pretty_xml,
                }
            }
            seahorse::saml::decoder::SamlDocumentType::Response => {
                let response = seahorse::saml::parser::extract_response_details(&result.xml).ok();

                let (assertion, attributes, validation) =
                    match seahorse::saml::parser::extract_assertion_from_response(&result.xml) {
                        Ok(assertion_xml) => {
                            let assertion_details =
                                seahorse::saml::parser::extract_assertion_details(&assertion_xml)
                                    .ok();
                            let attrs = seahorse::saml::parser::extract_attributes(&assertion_xml)
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
                let details = seahorse::saml::parser::extract_assertion_details(&result.xml)
                    .map_err(|e| format!("Failed to parse Assertion: {}", e))?;
                let attributes =
                    seahorse::saml::parser::extract_attributes(&result.xml).unwrap_or_default();
                let validation =
                    seahorse::saml::validator::validate_assertion(&result.xml, trust_store_ref);

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
pub fn load_chain_cert(
    state: State<'_, Mutex<AppState>>,
    path: String,
) -> Result<CertInfoDto, String> {
    // Load the chain PEM — this uses the same loader which finds leaf + chain certs
    let chain_store = seahorse::saml::trust::load_idp_certificates(Path::new(&path))
        .map_err(|e| format!("Failed to load chain certificates: {}", e))?;

    let mut guard = state.lock().unwrap();
    let store = guard
        .idp_trust_store
        .as_mut()
        .ok_or("Load an IDP certificate first, then add the chain")?;

    // Add all certs from the chain file (both leaf and chain) as chain certs
    let added = 1 + chain_store.chain_certs.len();
    store.chain_certs.push(chain_store.leaf_cert);
    for cert in chain_store.chain_certs {
        store.chain_certs.push(cert);
    }

    let cn = seahorse::saml::trust::cert_cn(&store.leaf_cert);
    let chain_count = store.chain_certs.len();

    Ok(CertInfoDto {
        cn,
        chain_count,
        source_path: format!("{} (+{} chain certs)", store.source_path.display(), added),
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
    let attributes = seahorse::saml::parser::extract_attributes(assertion_xml).unwrap_or_default();
    let validation = seahorse::saml::validator::validate_assertion(assertion_xml, trust_store);
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
        let config_dir = guard.config_dir.clone().ok_or("No config directory set")?;
        (config, config_dir)
    };

    emit_progress(&app, "start", "Starting authentication...");

    let client = reqwest::Client::new();
    let tenant = &config.url;

    // Step 2: StartAuthentication
    emit_progress(&app, "start_auth", "Calling StartAuthentication...");
    let start_result = seahorse::auth::rest_flow::start_authentication(&client, tenant, &username)
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
        return Err(format!("OTP authentication failed: {}", otp_result.summary));
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
///
/// Communication strategy: Tauri v2 CANNOT communicate with webviews showing external URLs
/// via title(), events, XHR, or form POST (all blocked or broken).
///
/// What DOES work:
/// - eval() can SEND JS to the webview (fire-and-forget, no response needed)
/// - on_navigation() can INTERCEPT navigations before they happen
///
/// So: the initialization script captures the SAMLResponse and stores it in a global.
/// Rust periodically eval()s a script to check if it's been captured and navigate to
/// a special URL. The on_navigation() callback intercepts this navigation and extracts
/// the SAMLResponse from the URL fragment.
const INTERCEPT_JS: &str = r#"
(function() {
    var captured = false;
    window._seahorse_saml = null;

    function captureSaml(value) {
        if (captured) return;
        captured = true;
        window._seahorse_saml = value;
        document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#666"><p>Authentication complete. This window will close.</p></div>';
    }

    // Layer 1: Override HTMLFormElement.prototype.submit()
    var originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        var input = this.querySelector('input[name="SAMLResponse"]');
        if (input && input.value) {
            captureSaml(input.value);
            return;
        }
        originalSubmit.call(this);
    };

    // Layer 2: Global submit event listener (capture phase)
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var input = form.querySelector('input[name="SAMLResponse"]');
        if (input && input.value) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            captureSaml(input.value);
            return false;
        }
    }, true);

    // Layer 3: Poll for SAMLResponse input in the DOM
    var checkInterval = setInterval(function() {
        var inputs = document.querySelectorAll('input[name="SAMLResponse"]');
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].value) {
                clearInterval(checkInterval);
                captureSaml(inputs[i].value);
                return;
            }
        }
    }, 50);

    setTimeout(function() { clearInterval(checkInterval); }, 120000);
})();
"#;

/// JS snippet that Rust periodically eval()s to check if the SAMLResponse was captured
/// and trigger a navigation that on_navigation() can intercept.
const CHECK_AND_NAVIGATE_JS: &str = r#"
if (window._seahorse_saml) {
    var v = window._seahorse_saml;
    window._seahorse_saml = null;
    window.location.href = 'seahorse://saml-captured#' + v;
}
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
        let config_dir = guard.config_dir.clone().ok_or("No config directory set")?;
        (config, config_dir)
    };

    // The `signed` parameter is accepted but not used for browser flow:
    // the browser flow returns CyberArk's own signed SAMLResponse, not a locally-built assertion.
    // We keep it in the signature for API symmetry.
    let _ = (signed, &config_dir);

    use tracing::info;

    info!("[browser_flow] Starting browser flow for user: {}", username);
    emit_progress(&app, "start", "Opening CyberArk login window...");

    let login_url =
        seahorse::auth::browser_flow::build_login_url(&config.url, &username, &config.appkey);
    info!("[browser_flow] Login URL: {}", login_url);

    // Channel: on_navigation callback → async command
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));

    // Open the auth webview window with:
    // 1. initialization_script: captures SAMLResponse, stores in window._seahorse_saml
    // 2. on_navigation: intercepts "seahorse://saml-captured#<base64>" and sends via channel
    let auth_window = {
        let tx_clone = tx.clone();
        tauri::WebviewWindowBuilder::new(
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
        .initialization_script(INTERCEPT_JS)
        .on_navigation(move |url| {
            if url.scheme() == "seahorse" {
                if let Some(fragment) = url.fragment() {
                    info!("[browser_flow] on_navigation: captured SAMLResponse ({} chars)", fragment.len());
                    if let Some(sender) = tx_clone.lock().unwrap().take() {
                        let _ = sender.send(fragment.to_string());
                    }
                }
                return false; // Block navigation to fake scheme
            }
            true // Allow all real navigations
        })
        .build()
        .map_err(|e| format!("Failed to open login window: {}", e))?
    };
    info!("[browser_flow] Auth window opened with on_navigation handler");

    emit_progress(
        &app,
        "waiting",
        "Waiting for authentication in browser window...",
    );

    // Periodically eval() the check script.
    // The init script stores SAMLResponse in window._seahorse_saml.
    // The eval'd script reads it and navigates to seahorse://saml-captured#<base64>.
    // The on_navigation callback intercepts this and sends the value via the channel.
    let eval_window = auth_window.clone();
    let poll_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            if eval_window.eval(CHECK_AND_NAVIGATE_JS).is_err() {
                // Window might be navigating or closed — ignore errors
            }
        }
    });

    // Wait for SAMLResponse or timeout
    let saml_b64 = tokio::select! {
        result = rx => {
            match result {
                Ok(b64) => {
                    info!("[browser_flow] Received SAMLResponse via channel ({} chars)", b64.len());
                    b64
                }
                Err(_) => {
                    return Err("Authentication channel closed unexpectedly".to_string());
                }
            }
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(300)) => {
            info!("[browser_flow] Timeout");
            poll_handle.abort();
            let _ = auth_window.close();
            return Err("Authentication timed out after 5 minutes".to_string());
        }
    };

    poll_handle.abort();
    info!("[browser_flow] Closing auth window...");
    let _ = auth_window.close();

    info!("[browser_flow] Decoding base64 SAMLResponse ({} chars)...", saml_b64.len());
    info!("[browser_flow] First 100 chars: {}", &saml_b64[..saml_b64.len().min(100)]);
    emit_progress(&app, "decoding", "Decoding SAML response...");

    let xml_bytes = STANDARD
        .decode(&saml_b64)
        .map_err(|e| {
            info!("[browser_flow] Base64 decode FAILED: {}", e);
            format!("Failed to base64-decode SAMLResponse: {}", e)
        })?;
    info!("[browser_flow] Base64 decoded to {} bytes", xml_bytes.len());

    let response_xml = String::from_utf8(xml_bytes)
        .map_err(|e| {
            info!("[browser_flow] UTF-8 conversion FAILED: {}", e);
            format!("SAMLResponse is not valid UTF-8: {}", e)
        })?;
    info!("[browser_flow] Response XML length: {} chars", response_xml.len());
    info!("[browser_flow] First 200 chars: {}", &response_xml[..response_xml.len().min(200)]);

    let assertion_xml = seahorse::saml::parser::extract_assertion_from_response(&response_xml)
        .map_err(|e| {
            info!("[browser_flow] Assertion extraction FAILED: {}", e);
            format!("Failed to extract assertion: {}", e)
        })?;
    info!("[browser_flow] Assertion extracted ({} chars)", assertion_xml.len());

    emit_progress(&app, "validating", "Validating assertion...");
    info!("[browser_flow] Validating assertion...");
    let decoded = {
        let mut guard = state.lock().unwrap();
        info!("[browser_flow] State lock acquired, validating...");
        let result = validate_assertion_xml(&assertion_xml, guard.idp_trust_store.as_ref())?;
        guard.last_raw_xml = Some(assertion_xml);
        info!("[browser_flow] Validation complete, storing raw XML");
        result
    };

    emit_progress(&app, "done", "Browser authentication complete!");
    info!("[browser_flow] Browser flow complete, returning result");
    Ok(decoded)
}
