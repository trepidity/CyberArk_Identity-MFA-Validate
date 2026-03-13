use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::read::DeflateDecoder;
use std::io::Read;

#[derive(Debug, Clone, PartialEq)]
pub enum SamlDocumentType {
    AuthnRequest,
    Response,
    Assertion,
}

#[derive(Debug, Clone)]
pub struct DecodeResult {
    pub document_type: SamlDocumentType,
    pub xml: String,
}

/// Decodes SAML input from any format: raw XML, base64, URL-encoded,
/// deflated, or a full URL containing SAMLRequest=/SAMLResponse= params.
pub fn decode_saml_input(input: &str) -> Result<DecodeResult> {
    let input = input.trim();

    // Step 1: Extract SAML parameter value from URL if present
    let value = extract_saml_param(input).unwrap_or_else(|| input.to_string());

    // Step 2: URL-decode
    let url_decoded = urlencoding::decode(&value)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| value.clone());

    // Try as raw XML first (before base64 decoding)
    if let Some(result) = try_parse_xml(&url_decoded) {
        return Ok(result);
    }

    // Step 3: Base64-decode
    let bytes = match STANDARD.decode(url_decoded.as_bytes()) {
        Ok(b) => b,
        Err(_) => {
            // Try the original value without URL decoding
            match STANDARD.decode(value.as_bytes()) {
                Ok(b) => b,
                Err(_) => bail!("Input is not valid XML, base64, or a recognized SAML format"),
            }
        }
    };

    // Step 4: Try inflate (deflate decompression)
    let xml_bytes = match try_inflate(&bytes) {
        Some(inflated) => inflated,
        None => bytes,
    };

    // Step 5: UTF-8 conversion
    let xml =
        String::from_utf8(xml_bytes).map_err(|_| anyhow::anyhow!("Decoded data is not valid UTF-8"))?;

    // Step 6-7: XML validation and type detection
    match try_parse_xml(&xml) {
        Some(result) => Ok(result),
        None => bail!("Decoded data is not valid SAML XML"),
    }
}

/// Extract the value of SAMLRequest= or SAMLResponse= from a URL or parameter string.
fn extract_saml_param(input: &str) -> Option<String> {
    for param_name in &["SAMLRequest=", "SAMLResponse="] {
        if let Some(start) = input.find(param_name) {
            let value_start = start + param_name.len();
            let rest = &input[value_start..];
            let value_end = rest.find('&').unwrap_or(rest.len());
            return Some(rest[..value_end].to_string());
        }
    }
    None
}

/// Try to inflate deflate-compressed data.
fn try_inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Try to parse a string as SAML XML and detect its type.
fn try_parse_xml(input: &str) -> Option<DecodeResult> {
    let trimmed = input.trim();
    if !trimmed.contains('<') {
        return None;
    }

    let doc_type = detect_document_type(trimmed)?;

    Some(DecodeResult {
        document_type: doc_type,
        xml: trimmed.to_string(),
    })
}

/// Detect SAML document type from the root element.
fn detect_document_type(xml: &str) -> Option<SamlDocumentType> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let name = e.local_name();
                let local_name = String::from_utf8_lossy(name.as_ref());
                return match local_name.as_ref() {
                    "AuthnRequest" => Some(SamlDocumentType::AuthnRequest),
                    "Response" => Some(SamlDocumentType::Response),
                    "Assertion" => Some(SamlDocumentType::Assertion),
                    _ => None,
                };
            }
            Ok(quick_xml::events::Event::Decl(_)) | Ok(quick_xml::events::Event::PI(_)) => {
                buf.clear();
                continue;
            }
            Ok(quick_xml::events::Event::Eof) => return None,
            Err(_) => return None,
            _ => {
                buf.clear();
                continue;
            }
        }
    }
}
