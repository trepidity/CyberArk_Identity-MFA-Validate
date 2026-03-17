use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Environment {
    Prod,
    Tst,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Prod => write!(f, "PROD"),
            Environment::Tst => write!(f, "TST"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub url: String,
    pub timeout: u64,
    pub certificate: String,
    pub appkey: String,
    pub certkey: String,
    #[serde(rename = "CheckUser")]
    pub check_user: bool,
    #[serde(rename = "UseBypass")]
    pub use_bypass: bool,
    pub browser: String,
    #[serde(default)]
    pub idp_certificate: Option<String>,
}

pub fn load_config(config_dir: &Path) -> Result<Config> {
    let config_path = config_dir.join("config.json");
    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
    let config: Config = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;
    Ok(config)
}

pub fn decode_certkey(encoded: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(encoded)
        .context("Failed to base64-decode certkey")?;
    String::from_utf8(bytes).context("certkey is not valid UTF-8")
}

pub fn get_config_dir(base_path: &Path, env: Environment) -> PathBuf {
    base_path.join("config").join(env.to_string())
}

pub fn get_pfx_path(config_dir: &Path, certificate_filename: &str) -> PathBuf {
    config_dir.join(certificate_filename)
}
