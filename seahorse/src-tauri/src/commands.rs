use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

#[derive(Default)]
pub struct AppState {
    pub config: Option<seahorse::config::Config>,
    pub config_dir: Option<PathBuf>,
    pub idp_trust_store: Option<seahorse::saml::trust::IdpTrustStore>,
    pub last_raw_xml: Option<String>,
}

#[tauri::command]
pub fn load_config(_state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    Ok("stub".to_string())
}

#[tauri::command]
pub fn decode_saml(_state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    Ok("stub".to_string())
}

#[tauri::command]
pub fn validate_assertion(_state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    Ok("stub".to_string())
}

#[tauri::command]
pub fn load_idp_cert(_state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    Ok("stub".to_string())
}
