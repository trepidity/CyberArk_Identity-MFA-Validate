use crate::config::{Config, Environment};
use crate::saml::parser::AssertionDetails;
use crate::saml::validator::SignatureValidation;

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    EnvSelect,
    FlowSelect,
    AuthInput,
    Waiting,
    Result,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowMode {
    Browser,
    RestApi,
}

impl std::fmt::Display for FlowMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowMode::Browser => write!(f, "Browser Flow"),
            FlowMode::RestApi => write!(f, "REST API Flow"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigningMode {
    Signed,
    Unsigned,
}

pub struct App {
    pub running: bool,
    pub screen: Screen,
    pub env_selection: usize,
    pub environment: Option<Environment>,
    pub config: Option<Config>,
    pub flow_selection: usize,
    pub flow_mode: Option<FlowMode>,
    pub signing_selection: usize,
    pub signing_mode: SigningMode,
    pub username: String,
    pub password: String,
    pub otp_code: String,
    pub active_field: usize,
    pub status_message: String,
    pub assertion_details: Option<AssertionDetails>,
    pub signature_validation: Option<SignatureValidation>,
    pub raw_xml: String,
    pub scroll_offset: u16,
    pub error_message: String,
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            screen: Screen::EnvSelect,
            env_selection: 0,
            environment: None,
            config: None,
            flow_selection: 0,
            flow_mode: None,
            signing_selection: 0,
            signing_mode: SigningMode::Signed,
            username: String::new(),
            password: String::new(),
            otp_code: String::new(),
            active_field: 0,
            status_message: String::new(),
            assertion_details: None,
            signature_validation: None,
            raw_xml: String::new(),
            scroll_offset: 0,
            error_message: String::new(),
        }
    }

    pub fn get_selected_env(&self) -> Environment {
        match self.env_selection {
            0 => Environment::Prod,
            _ => Environment::Tst,
        }
    }

    pub fn get_selected_flow(&self) -> FlowMode {
        match self.flow_selection {
            0 => FlowMode::Browser,
            _ => FlowMode::RestApi,
        }
    }

    pub fn get_selected_signing(&self) -> SigningMode {
        match self.signing_selection {
            0 => SigningMode::Signed,
            _ => SigningMode::Unsigned,
        }
    }
}
