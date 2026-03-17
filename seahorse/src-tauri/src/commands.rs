use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::State;

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
