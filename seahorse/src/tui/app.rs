use crate::config::{Config, Environment};
use crate::saml::decoder::DecodeResult;
use crate::saml::parser::{AssertionDetails, AuthnRequestDetails, ResponseDetails, SamlAttribute};
use crate::saml::trust::IdpTrustStore;
use crate::saml::validator::ValidationReport;

pub use crate::saml::decoder::SamlDocumentType as SamlDocType;

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    EnvSelect,
    FlowSelect,
    AuthInput,
    Waiting,
    Result,
    Error,
    SamlInput,
    SamlView,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SamlInputMode {
    Paste,
    File,
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
    pub signature_validation: Option<ValidationReport>,
    pub raw_xml: String,
    pub raw_xml_original: String, // pre-pretty-print, for saving and re-validation
    pub scroll_offset: u16,
    pub error_message: String,
    pub copy_status: Option<String>,
    // SAML Viewer state
    pub saml_input_mode: SamlInputMode,
    pub saml_paste_buffer: String,
    pub saml_file_path: String,
    pub decoded_saml: Option<DecodeResult>,
    pub viewer_authn_request: Option<AuthnRequestDetails>,
    pub viewer_response: Option<ResponseDetails>,
    pub viewer_assertion: Option<AssertionDetails>,
    pub viewer_attributes: Vec<SamlAttribute>,
    pub viewer_signature: Option<ValidationReport>,
    pub viewer_pretty_xml: String,
    pub viewer_scroll_offset: u16,
    pub viewer_copy_status: Option<String>,
    // IDP trust state
    pub idp_trust_store: Option<IdpTrustStore>,
    pub idp_cert_input: String,
    pub idp_cert_input_active: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
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
            raw_xml_original: String::new(),
            scroll_offset: 0,
            error_message: String::new(),
            copy_status: None,
            saml_input_mode: SamlInputMode::Paste,
            saml_paste_buffer: String::new(),
            saml_file_path: String::new(),
            decoded_saml: None,
            viewer_authn_request: None,
            viewer_response: None,
            viewer_assertion: None,
            viewer_attributes: Vec::new(),
            viewer_signature: None,
            viewer_pretty_xml: String::new(),
            viewer_scroll_offset: 0,
            viewer_copy_status: None,
            idp_trust_store: None,
            idp_cert_input: String::new(),
            idp_cert_input_active: false,
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
