use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Clone)]
pub struct SamlParseResult {
    pub full_response_xml: String,
    pub assertion_xml: String,
}

#[derive(Debug, Clone, Default)]
pub struct AssertionDetails {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub authn_context: String,
    pub assertion_id: String,
    pub issue_instant: String,
    pub has_signature: bool,
    pub raw_xml: String,
}

pub fn parse_saml_post_body(body: &str) -> Result<SamlParseResult> {
    let value = if let Some(stripped) = body.strip_prefix("SAMLResponse=") {
        stripped
    } else {
        body
    };

    let url_decoded = urlencoding::decode(value).context("Failed to URL-decode SAMLResponse")?;
    let xml_bytes = STANDARD
        .decode(url_decoded.as_bytes())
        .context("Failed to base64-decode SAMLResponse")?;
    let full_xml = String::from_utf8(xml_bytes).context("SAMLResponse XML is not valid UTF-8")?;

    let assertion_xml =
        extract_assertion_from_response(&full_xml).unwrap_or_else(|_| full_xml.clone());

    Ok(SamlParseResult {
        full_response_xml: full_xml,
        assertion_xml,
    })
}

pub fn extract_assertion_from_response(response_xml: &str) -> Result<String> {
    let assertion_starts = ["<saml2:Assertion", "<saml:Assertion", "<Assertion"];
    let assertion_ends = ["</saml2:Assertion>", "</saml:Assertion>", "</Assertion>"];

    for (start_tag, end_tag) in assertion_starts.iter().zip(assertion_ends.iter()) {
        if let Some(start_idx) = response_xml.find(start_tag) {
            if let Some(end_pos) = response_xml.find(end_tag) {
                let end_idx = end_pos + end_tag.len();
                return Ok(response_xml[start_idx..end_idx].to_string());
            }
        }
    }

    bail!("No Assertion element found in SAML response")
}

pub fn extract_assertion_details(assertion_xml: &str) -> Result<AssertionDetails> {
    let mut details = AssertionDetails {
        raw_xml: assertion_xml.to_string(),
        ..Default::default()
    };

    let mut reader = Reader::from_str(assertion_xml);
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = local_name.clone();

                match local_name.as_str() {
                    "Assertion" => {
                        for attr in e.attributes().flatten() {
                            let local = attr.key.local_name();
                            let key = String::from_utf8_lossy(local.as_ref());
                            let val = String::from_utf8_lossy(&attr.value);
                            match key.as_ref() {
                                "ID" => details.assertion_id = val.to_string(),
                                "IssueInstant" => details.issue_instant = val.to_string(),
                                _ => {}
                            }
                        }
                    }
                    "Conditions" => {
                        for attr in e.attributes().flatten() {
                            let local = attr.key.local_name();
                            let key = String::from_utf8_lossy(local.as_ref());
                            let val = String::from_utf8_lossy(&attr.value);
                            match key.as_ref() {
                                "NotBefore" => details.not_before = Some(val.to_string()),
                                "NotOnOrAfter" => details.not_after = Some(val.to_string()),
                                _ => {}
                            }
                        }
                    }
                    "Signature" => {
                        details.has_signature = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                match current_element.as_str() {
                    "Issuer" => details.issuer = text,
                    "NameID" => details.subject = text,
                    "Audience" => details.audience = text,
                    "AuthnContextClassRef" => details.authn_context = text,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error: {}", e),
            _ => {}
        }
        buf.clear();
    }

    Ok(details)
}
