use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use openssl::x509::X509;
use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug)]
pub struct SignatureValidation {
    pub signature_present: bool,
    pub signature_valid: bool,
    pub certificate_found: bool,
    pub certificate_subject: String,
    pub certificate_not_after: Option<String>,
    pub algorithm: String,
    pub message: String,
}

pub fn validate_assertion_signature(assertion_xml: &str) -> Result<SignatureValidation> {
    let mut sig_value: Option<String> = None;
    let mut cert_b64: Option<String> = None;
    let mut has_signature = false;
    let mut algorithm = String::new();

    let mut reader = Reader::from_str(assertion_xml);
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = local_name.clone();
                if local_name == "Signature" {
                    has_signature = true;
                }
                if local_name == "SignatureMethod" {
                    for attr in e.attributes().flatten() {
                        let local = attr.key.local_name();
                        let key = String::from_utf8_lossy(local.as_ref());
                        if key == "Algorithm" {
                            algorithm = String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    match current_element.as_str() {
                        "SignatureValue" => sig_value = Some(text),
                        "X509Certificate" => cert_b64 = Some(text),
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
        return Ok(SignatureValidation {
            signature_present: false,
            signature_valid: false,
            certificate_found: false,
            certificate_subject: String::new(),
            certificate_not_after: None,
            algorithm: String::new(),
            message: "No signature present in assertion".to_string(),
        });
    }

    let cert_found = cert_b64.is_some();
    let mut cert_subject = String::new();
    let mut cert_not_after: Option<String> = None;

    if let Some(ref b64) = cert_b64 {
        let clean = b64.replace(['\n', '\r', ' '], "");
        if let Ok(der) = STANDARD.decode(&clean) {
            if let Ok(cert) = X509::from_der(&der) {
                cert_subject = cert
                    .subject_name()
                    .entries()
                    .map(|e| {
                        format!(
                            "{}={}",
                            e.object().nid().short_name().unwrap_or("?"),
                            String::from_utf8_lossy(e.data().as_slice())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                cert_not_after = Some(cert.not_after().to_string());
            }
        }
    }

    let sig_valid = sig_value.is_some() && cert_found;

    Ok(SignatureValidation {
        signature_present: true,
        signature_valid: sig_valid,
        certificate_found: cert_found,
        certificate_subject: cert_subject,
        certificate_not_after: cert_not_after,
        algorithm,
        message: if sig_valid {
            "Signature and certificate present".to_string()
        } else {
            "Signature present but missing components".to_string()
        },
    })
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
