use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;
use quick_xml::Writer;

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

#[derive(Debug, Clone, Default)]
pub struct AuthnRequestDetails {
    pub id: String,
    pub issue_instant: String,
    pub issuer: String,
    pub destination: Option<String>,
    pub acs_url: Option<String>,
    pub protocol_binding: Option<String>,
    pub name_id_policy: Option<String>,
    pub force_authn: Option<bool>,
    pub is_passive: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseDetails {
    pub id: String,
    pub issue_instant: String,
    pub issuer: String,
    pub destination: Option<String>,
    pub in_response_to: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct SamlAttribute {
    pub name: String,
    pub values: Vec<String>,
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

pub fn extract_authn_request_details(xml: &str) -> Result<AuthnRequestDetails> {
    let mut details = AuthnRequestDetails::default();
    let mut reader = Reader::from_str(xml);
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = local_name.clone();

                match local_name.as_str() {
                    "AuthnRequest" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "ID" => details.id = val,
                                "IssueInstant" => details.issue_instant = val,
                                "Destination" => details.destination = Some(val),
                                "AssertionConsumerServiceURL" | "AssertionConsumerServiceUrl" => {
                                    details.acs_url = Some(val)
                                }
                                "ProtocolBinding" => details.protocol_binding = Some(val),
                                "ForceAuthn" => details.force_authn = Some(val == "true"),
                                "IsPassive" => details.is_passive = Some(val == "true"),
                                _ => {}
                            }
                        }
                    }
                    "NameIDPolicy" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "Format" {
                                details.name_id_policy =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                if current_element == "Issuer" {
                    details.issuer = text;
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

pub fn extract_response_details(xml: &str) -> Result<ResponseDetails> {
    let mut details = ResponseDetails::default();
    let mut reader = Reader::from_str(xml);
    let mut current_element = String::new();
    let mut buf = Vec::new();
    let mut depth = 0u32;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = local_name.clone();
                depth += 1;

                match local_name.as_str() {
                    "Response" if depth == 1 => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "ID" => details.id = val,
                                "IssueInstant" => details.issue_instant = val,
                                "Destination" => details.destination = Some(val),
                                "InResponseTo" => details.in_response_to = Some(val),
                                _ => {}
                            }
                        }
                    }
                    "StatusCode" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "Value" {
                                details.status = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local_name == "StatusCode" {
                    for attr in e.attributes().flatten() {
                        let key =
                            String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                        if key == "Value" {
                            details.status = String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                if current_element == "Issuer" && depth <= 2 {
                    details.issuer = text;
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

pub fn extract_attributes(xml: &str) -> Result<Vec<SamlAttribute>> {
    let mut attributes = Vec::new();
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut in_attribute_statement = false;
    let mut current_attr: Option<SamlAttribute> = None;
    let mut in_attribute_value = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local_name.as_str() {
                    "AttributeStatement" => in_attribute_statement = true,
                    "Attribute" if in_attribute_statement => {
                        let mut name = String::new();
                        for attr in e.attributes().flatten() {
                            let local = attr.key.local_name();
                            let key = String::from_utf8_lossy(local.as_ref());
                            if key == "Name" {
                                name = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                        current_attr = Some(SamlAttribute {
                            name,
                            values: Vec::new(),
                        });
                    }
                    "AttributeValue" if current_attr.is_some() => {
                        in_attribute_value = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_attribute_value {
                    if let Some(ref mut attr) = current_attr {
                        let text = e.unescape().unwrap_or_default().to_string();
                        attr.values.push(text);
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local_name.as_str() {
                    "AttributeStatement" => in_attribute_statement = false,
                    "Attribute" => {
                        if let Some(attr) = current_attr.take() {
                            attributes.push(attr);
                        }
                    }
                    "AttributeValue" => in_attribute_value = false,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error: {}", e),
            _ => {}
        }
        buf.clear();
    }

    Ok(attributes)
}

/// Pretty-prints XML with indentation for human readability.
pub fn pretty_print_xml(xml: &str) -> String {
    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(event) => {
                if writer.write_event(event).is_err() {
                    return xml.to_string();
                }
            }
            Err(_) => return xml.to_string(),
        }
        buf.clear();
    }

    String::from_utf8(writer.into_inner()).unwrap_or_else(|_| xml.to_string())
}
