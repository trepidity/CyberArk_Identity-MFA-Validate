use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use quick_xml::events::Event;
use quick_xml::Reader;

use serde::Serialize;

use super::c14n;
use super::trust::{self, IdpTrustStore};

// --- New validation data model (Task 1) ---

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ValidationSummary {
    Trusted,
    Valid,
    Partial,
    Failed,
    Unsigned,
}

impl ValidationSummary {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Trusted => "Signature verified against configured IDP certificate",
            Self::Valid => "Signature cryptographically valid (no IDP certificate configured)",
            Self::Partial => "Validation incomplete — see details",
            Self::Failed => "Signature verification FAILED",
            Self::Unsigned => "No signature present in assertion",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub summary: ValidationSummary,
    pub checks: Vec<ValidationCheck>,
    pub idp_cert_loaded: bool,
    pub algorithm: String,
    pub cert_subject: String,
    pub cert_not_after: Option<String>,
}

pub fn check_time_conditions(not_before: Option<&str>, not_after: Option<&str>) -> Result<()> {
    let now = Utc::now();

    if let Some(nb) = not_before {
        let nb_time: DateTime<Utc> = nb
            .parse()
            .with_context(|| format!("Invalid NotBefore timestamp: {}", nb))?;
        if now < nb_time {
            bail!("Assertion not yet valid (NotBefore: {})", nb);
        }
    }

    if let Some(na) = not_after {
        let na_time: DateTime<Utc> = na
            .parse()
            .with_context(|| format!("Invalid NotOnOrAfter timestamp: {}", na))?;
        if now > na_time {
            bail!("Assertion has expired (NotOnOrAfter: {})", na);
        }
    }

    Ok(())
}

// --- Full Validation Pipeline (Task 8) ---

/// Data extracted from the XML Signature element during structure check.
struct SignatureData {
    signature_method_uri: String,
    digest_method_uri: String,
    digest_value_b64: String,
    signature_value_b64: String,
    x509_cert_b64: String,
    reference_uri: String,
    /// InclusiveNamespaces PrefixList from the Reference's exc-c14n Transform
    inclusive_ns_digest: Vec<String>,
    /// InclusiveNamespaces PrefixList from CanonicalizationMethod
    inclusive_ns_sig: Vec<String>,
    /// NotBefore from Conditions
    not_before: Option<String>,
    /// NotOnOrAfter from Conditions
    not_on_or_after: Option<String>,
}

/// Resolve a digest algorithm URI to an OpenSSL MessageDigest.
fn resolve_digest_algorithm(uri: &str) -> Option<MessageDigest> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some(MessageDigest::sha256()),
        "http://www.w3.org/2000/09/xmldsig#sha1" => Some(MessageDigest::sha1()),
        _ => None,
    }
}

/// Resolve a signature algorithm URI to an OpenSSL MessageDigest.
fn resolve_signature_algorithm(uri: &str) -> Option<MessageDigest> {
    match uri {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(MessageDigest::sha256()),
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Some(MessageDigest::sha1()),
        _ => None,
    }
}

/// Extract all signature-related data from the assertion XML.
/// Returns None if no Signature element is found.
fn extract_signature_data(assertion_xml: &str) -> Result<Option<SignatureData>> {
    let mut reader = Reader::from_str(assertion_xml);
    let mut buf = Vec::new();
    let mut current_element = String::new();

    let mut has_signature = false;
    let mut signature_method_uri = String::new();
    let mut digest_method_uri = String::new();
    let mut digest_value_b64 = String::new();
    let mut signature_value_b64 = String::new();
    let mut x509_cert_b64 = String::new();
    let mut reference_uri = String::new();
    let mut not_before: Option<String> = None;
    let mut not_on_or_after: Option<String> = None;

    // Track InclusiveNamespaces for digest and signature canonicalization
    let mut inclusive_ns_digest: Vec<String> = Vec::new();
    let mut inclusive_ns_sig: Vec<String> = Vec::new();

    // Track context: are we inside Reference>Transforms>Transform or CanonicalizationMethod?
    let mut in_reference = false;
    let mut in_reference_transform = false;
    let mut in_c14n_method = false;
    // Track whether current Transform is the exc-c14n one (for Reference)
    let mut current_transform_is_exc_c14n = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = local_name.clone();

                match local_name.as_str() {
                    "Signature" => {
                        has_signature = true;
                    }
                    "SignatureMethod" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "Algorithm" {
                                signature_method_uri =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "DigestMethod" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "Algorithm" {
                                digest_method_uri =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "Reference" => {
                        in_reference = true;
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "URI" {
                                reference_uri = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "Transform" => {
                        if in_reference {
                            in_reference_transform = true;
                            current_transform_is_exc_c14n = false;
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.local_name().as_ref())
                                    .to_string();
                                if key == "Algorithm" {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    if val == "http://www.w3.org/2001/10/xml-exc-c14n#" {
                                        current_transform_is_exc_c14n = true;
                                    }
                                }
                            }
                        }
                    }
                    "CanonicalizationMethod" => {
                        in_c14n_method = true;
                        // Check for InclusiveNamespaces as child (handled below)
                    }
                    "InclusiveNamespaces" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "PrefixList" {
                                let prefix_list = String::from_utf8_lossy(&attr.value).to_string();
                                let prefixes: Vec<String> = prefix_list
                                    .split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect();
                                if in_reference_transform && current_transform_is_exc_c14n {
                                    inclusive_ns_digest = prefixes;
                                } else if in_c14n_method {
                                    inclusive_ns_sig = prefixes;
                                }
                            }
                        }
                    }
                    "Conditions" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "NotBefore" => not_before = Some(val),
                                "NotOnOrAfter" => not_on_or_after = Some(val),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local_name.as_str() {
                    "Reference" => in_reference = false,
                    "Transform" => {
                        in_reference_transform = false;
                        current_transform_is_exc_c14n = false;
                    }
                    "CanonicalizationMethod" => in_c14n_method = false,
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    match current_element.as_str() {
                        "DigestValue" => digest_value_b64 = text,
                        "SignatureValue" => signature_value_b64 = text,
                        "X509Certificate" => x509_cert_b64 = text,
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error: {}", e),
            _ => {}
        }
        buf.clear();
    }

    if !has_signature {
        return Ok(None);
    }

    Ok(Some(SignatureData {
        signature_method_uri,
        digest_method_uri,
        digest_value_b64,
        signature_value_b64,
        x509_cert_b64,
        reference_uri,
        inclusive_ns_digest,
        inclusive_ns_sig,
        not_before,
        not_on_or_after,
    }))
}

/// Format a certificate subject as a human-readable string.
fn format_cert_subject(cert: &X509) -> String {
    cert.subject_name()
        .entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                String::from_utf8_lossy(e.data().as_slice())
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Run the full 6-check validation pipeline on a SAML assertion.
pub fn validate_assertion(
    assertion_xml: &str,
    trust_store: Option<&IdpTrustStore>,
) -> ValidationReport {
    let idp_cert_loaded = trust_store.is_some();
    let mut checks: Vec<ValidationCheck> = Vec::new();
    let mut algorithm = String::new();
    let mut cert_subject = String::new();
    let mut cert_not_after: Option<String> = None;

    // --- Check 1: Structure ---
    let sig_data = match extract_signature_data(assertion_xml) {
        Ok(Some(data)) => {
            // Verify all required fields are present
            let mut missing = Vec::new();
            if data.signature_method_uri.is_empty() {
                missing.push("SignatureMethod");
            }
            if data.digest_value_b64.is_empty() {
                missing.push("DigestValue");
            }
            if data.signature_value_b64.is_empty() {
                missing.push("SignatureValue");
            }
            if data.x509_cert_b64.is_empty() {
                missing.push("X509Certificate");
            }

            if missing.is_empty() {
                checks.push(ValidationCheck {
                    name: "Structure".to_string(),
                    passed: true,
                    detail: "Signature, SignedInfo, SignatureValue, DigestValue, X509Certificate present".to_string(),
                    diagnostic: None,
                });
                algorithm = data.signature_method_uri.clone();
                data
            } else {
                checks.push(ValidationCheck {
                    name: "Structure".to_string(),
                    passed: false,
                    detail: format!("Missing signature components: {}", missing.join(", ")),
                    diagnostic: Some("Signature element found but incomplete".to_string()),
                });
                return compute_report(
                    checks,
                    idp_cert_loaded,
                    algorithm,
                    cert_subject,
                    cert_not_after,
                );
            }
        }
        Ok(None) => {
            // No signature at all
            checks.push(ValidationCheck {
                name: "Structure".to_string(),
                passed: false,
                detail: "No Signature element found".to_string(),
                diagnostic: None,
            });
            return ValidationReport {
                summary: ValidationSummary::Unsigned,
                checks,
                idp_cert_loaded,
                algorithm,
                cert_subject,
                cert_not_after,
            };
        }
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Structure".to_string(),
                passed: false,
                detail: format!("XML parse error: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return compute_report(
                checks,
                idp_cert_loaded,
                algorithm,
                cert_subject,
                cert_not_after,
            );
        }
    };

    // --- Check 2: Time Conditions ---
    let time_check = check_time_conditions(
        sig_data.not_before.as_deref(),
        sig_data.not_on_or_after.as_deref(),
    );
    match time_check {
        Ok(()) => {
            let detail = match (&sig_data.not_before, &sig_data.not_on_or_after) {
                (Some(nb), Some(na)) => format!("NotBefore={}, NotOnOrAfter={}", nb, na),
                (Some(nb), None) => format!("NotBefore={}", nb),
                (None, Some(na)) => format!("NotOnOrAfter={}", na),
                (None, None) => "No time conditions present".to_string(),
            };
            checks.push(ValidationCheck {
                name: "Time".to_string(),
                passed: true,
                detail,
                diagnostic: None,
            });
        }
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Time".to_string(),
                passed: false,
                detail: e.to_string(),
                diagnostic: None,
            });
            // Continue -- time failure doesn't block other checks
        }
    }

    // --- Check 3: Digest Verification ---
    let _digest_ok = run_digest_check(assertion_xml, &sig_data, &mut checks);

    // --- Check 4: Signature Verification ---
    let (_sig_ok, embedded_cert) = run_signature_check(
        assertion_xml,
        &sig_data,
        &mut checks,
        &mut cert_subject,
        &mut cert_not_after,
    );

    // --- Check 5: IDP Certificate Match ---
    if let (Some(store), Some(ref cert)) = (trust_store, &embedded_cert) {
        let cert_match = trust::compare_certificates(cert, &store.leaf_cert);
        match cert_match {
            trust::CertMatch::Match => {
                checks.push(ValidationCheck {
                    name: "IDP Certificate".to_string(),
                    passed: true,
                    detail: "Embedded certificate matches configured IDP certificate".to_string(),
                    diagnostic: None,
                });
            }
            trust::CertMatch::Mismatch {
                expected_cn,
                actual_cn,
                expected_fingerprint,
                actual_fingerprint,
            } => {
                checks.push(ValidationCheck {
                    name: "IDP Certificate".to_string(),
                    passed: false,
                    detail: format!(
                        "Certificate mismatch: expected CN={}, got CN={}",
                        expected_cn, actual_cn
                    ),
                    diagnostic: Some(format!(
                        "Expected fingerprint: {}\nActual fingerprint: {}",
                        expected_fingerprint, actual_fingerprint
                    )),
                });
            }
        }
    } else if trust_store.is_some() && embedded_cert.is_none() {
        checks.push(ValidationCheck {
            name: "IDP Certificate".to_string(),
            passed: false,
            detail: "No embedded certificate to compare".to_string(),
            diagnostic: None,
        });
    }

    // --- Check 6: Chain Validation ---
    if let (Some(store), Some(ref cert)) = (trust_store, &embedded_cert) {
        let chain_result = trust::validate_chain(cert, &store.chain_certs);
        match chain_result {
            trust::ChainResult::Valid {
                chain_depth,
                root_cn,
            } => {
                checks.push(ValidationCheck {
                    name: "Chain".to_string(),
                    passed: true,
                    detail: format!("Chain valid (depth={}, root={})", chain_depth, root_cn),
                    diagnostic: None,
                });
            }
            trust::ChainResult::Failed { error } => {
                checks.push(ValidationCheck {
                    name: "Chain".to_string(),
                    passed: false,
                    detail: format!("Chain validation failed: {}", error),
                    diagnostic: None,
                });
            }
            trust::ChainResult::Skipped { reason } => {
                checks.push(ValidationCheck {
                    name: "Chain".to_string(),
                    passed: true,
                    detail: reason,
                    diagnostic: None,
                });
            }
        }
    }

    // --- Compute Summary ---
    compute_report(
        checks,
        idp_cert_loaded,
        algorithm,
        cert_subject,
        cert_not_after,
    )
}

/// Run the digest verification check (Check 3).
/// Returns true if digest verification passed.
fn run_digest_check(
    assertion_xml: &str,
    sig_data: &SignatureData,
    checks: &mut Vec<ValidationCheck>,
) -> bool {
    // Check Reference URI is not empty
    if sig_data.reference_uri.is_empty() {
        checks.push(ValidationCheck {
            name: "Digest".to_string(),
            passed: false,
            detail: "Reference URI is empty".to_string(),
            diagnostic: Some("The Reference element must have a non-empty URI attribute pointing to the signed content".to_string()),
        });
        return false;
    }

    // Resolve digest algorithm
    let digest_md = match resolve_digest_algorithm(&sig_data.digest_method_uri) {
        Some(md) => md,
        None => {
            checks.push(ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: format!(
                    "Unsupported digest algorithm: {}",
                    sig_data.digest_method_uri
                ),
                diagnostic: Some(
                    "Supported algorithms: SHA-256 (xmlenc#sha256), SHA-1 (xmldsig#sha1)"
                        .to_string(),
                ),
            });
            return false;
        }
    };

    // Remove signature element (enveloped signature transform)
    let body_xml = match c14n::remove_signature_element(assertion_xml) {
        Ok(xml) => xml,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: format!("Failed to remove Signature element: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return false;
        }
    };

    // Parse InclusiveNamespaces PrefixList for digest transform
    let inclusive_refs: Vec<&str> = sig_data
        .inclusive_ns_digest
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Canonicalize the body
    let canon_body = match c14n::canonicalize_exclusive(&body_xml, &inclusive_refs) {
        Ok(bytes) => bytes,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: format!("Failed to canonicalize assertion body: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return false;
        }
    };

    // Compute digest
    let computed_digest = match openssl::hash::hash(digest_md, &canon_body) {
        Ok(d) => d,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: format!("Failed to compute digest: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return false;
        }
    };

    let computed_b64 = STANDARD.encode(computed_digest);
    let expected_b64 = sig_data.digest_value_b64.replace(['\n', '\r', ' '], "");

    if computed_b64 == expected_b64 {
        checks.push(ValidationCheck {
            name: "Digest".to_string(),
            passed: true,
            detail: format!("Digest verified ({})", &sig_data.digest_method_uri),
            diagnostic: None,
        });
        true
    } else {
        checks.push(ValidationCheck {
            name: "Digest".to_string(),
            passed: false,
            detail: "Digest mismatch".to_string(),
            diagnostic: Some(format!(
                "Expected: {}\nComputed: {}",
                expected_b64, computed_b64
            )),
        });
        false
    }
}

/// Run the signature verification check (Check 4).
/// Returns (passed, Option<X509 cert>) -- the cert is needed for checks 5 & 6.
fn run_signature_check(
    assertion_xml: &str,
    sig_data: &SignatureData,
    checks: &mut Vec<ValidationCheck>,
    cert_subject: &mut String,
    cert_not_after: &mut Option<String>,
) -> (bool, Option<X509>) {
    // Resolve signature algorithm
    let sig_md = match resolve_signature_algorithm(&sig_data.signature_method_uri) {
        Some(md) => md,
        None => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!(
                    "Unsupported signature algorithm: {}",
                    sig_data.signature_method_uri
                ),
                diagnostic: Some(
                    "Supported: rsa-sha256 (xmldsig-more#rsa-sha256), rsa-sha1 (xmldsig#rsa-sha1)"
                        .to_string(),
                ),
            });
            return (false, None);
        }
    };

    // Parse X509 certificate
    let clean_cert_b64 = sig_data.x509_cert_b64.replace(['\n', '\r', ' '], "");
    let cert_der = match STANDARD.decode(&clean_cert_b64) {
        Ok(d) => d,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Failed to base64-decode X509Certificate: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return (false, None);
        }
    };

    let cert = match X509::from_der(&cert_der) {
        Ok(c) => c,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Failed to parse X509 certificate: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return (false, None);
        }
    };

    // Populate metadata
    *cert_subject = format_cert_subject(&cert);
    *cert_not_after = Some(cert.not_after().to_string());

    // Extract SignedInfo
    let signed_info_xml = match c14n::extract_signed_info(assertion_xml) {
        Ok(xml) => xml,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Failed to extract SignedInfo: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return (false, Some(cert));
        }
    };

    // Parse InclusiveNamespaces PrefixList for CanonicalizationMethod
    let inclusive_refs: Vec<&str> = sig_data
        .inclusive_ns_sig
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Canonicalize SignedInfo
    let canon_signed_info = match c14n::canonicalize_exclusive(&signed_info_xml, &inclusive_refs) {
        Ok(bytes) => bytes,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Failed to canonicalize SignedInfo: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return (false, Some(cert));
        }
    };

    // Decode signature value
    let clean_sig_b64 = sig_data.signature_value_b64.replace(['\n', '\r', ' '], "");
    let sig_bytes = match STANDARD.decode(&clean_sig_b64) {
        Ok(b) => b,
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Failed to base64-decode SignatureValue: {}", e),
                diagnostic: Some(e.to_string()),
            });
            return (false, Some(cert));
        }
    };

    // Verify signature
    match crate::crypto::verify_signature(&cert, &canon_signed_info, &sig_bytes, sig_md) {
        Ok(true) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: true,
                detail: format!("Signature verified ({})", &sig_data.signature_method_uri),
                diagnostic: None,
            });
            (true, Some(cert))
        }
        Ok(false) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: "Signature verification failed".to_string(),
                diagnostic: Some(
                    "The RSA signature does not match the canonicalized SignedInfo".to_string(),
                ),
            });
            (false, Some(cert))
        }
        Err(e) => {
            checks.push(ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Signature verification error: {}", e),
                diagnostic: Some(e.to_string()),
            });
            (false, Some(cert))
        }
    }
}

/// Compute the final ValidationReport from the checks.
fn compute_report(
    checks: Vec<ValidationCheck>,
    idp_cert_loaded: bool,
    algorithm: String,
    cert_subject: String,
    cert_not_after: Option<String>,
) -> ValidationReport {
    // Determine summary from checks
    let structure_passed = checks
        .iter()
        .find(|c| c.name == "Structure")
        .map(|c| c.passed)
        .unwrap_or(false);

    let sig_passed = checks
        .iter()
        .find(|c| c.name == "Signature")
        .map(|c| c.passed)
        .unwrap_or(false);

    let idp_cert_passed = checks
        .iter()
        .find(|c| c.name == "IDP Certificate")
        .map(|c| c.passed)
        .unwrap_or(false);

    let any_passed = checks.iter().any(|c| c.passed);

    let summary = if !structure_passed {
        // No valid structure
        if any_passed {
            ValidationSummary::Partial
        } else {
            ValidationSummary::Failed
        }
    } else if sig_passed && idp_cert_loaded && idp_cert_passed {
        ValidationSummary::Trusted
    } else if sig_passed && !idp_cert_loaded {
        ValidationSummary::Valid
    } else if sig_passed {
        // Sig OK but IDP cert didn't match
        ValidationSummary::Partial
    } else if any_passed {
        ValidationSummary::Partial
    } else {
        ValidationSummary::Failed
    };

    ValidationReport {
        summary,
        checks,
        idp_cert_loaded,
        algorithm,
        cert_subject,
        cert_not_after,
    }
}
