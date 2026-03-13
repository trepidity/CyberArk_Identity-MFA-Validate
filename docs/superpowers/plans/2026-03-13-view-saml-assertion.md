# View SAML Assertion Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a standalone SAML viewer to seahorse that decodes, pretty-prints, and displays critical details from pasted or file-loaded SAML AuthnRequests and Responses.

**Architecture:** New `decoder.rs` module handles the auto-detect/decode pipeline. Parser is extended with AuthnRequest, Response, and AttributeStatement extraction. Two new TUI screens (SamlInput, SamlView) follow existing patterns. The main menu gains a third option.

**Tech Stack:** Rust, ratatui/crossterm, quick-xml, flate2, base64, urlencoding

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `seahorse/Cargo.toml` | Modify | Add `flate2` dependency |
| `seahorse/src/saml/mod.rs` | Modify | Add `pub mod decoder;` |
| `seahorse/src/saml/decoder.rs` | Create | Decode pipeline: URL extract, URL-decode, base64, deflate, type detection |
| `seahorse/src/saml/parser.rs` | Modify | Add `AuthnRequestDetails`, `ResponseDetails`, `SamlAttribute`, `extract_authn_request_details()`, `extract_response_details()`, `extract_attributes()` |
| `seahorse/src/tui/app.rs` | Modify | Add `SamlInput`/`SamlView` screens, `SamlInputMode`, viewer state fields, `DecodedSaml` |
| `seahorse/src/tui/input.rs` | Modify | Add handlers for SamlInput/SamlView, bracketed paste support |
| `seahorse/src/tui/ui.rs` | Modify | Add renderers for SamlInput/SamlView, update EnvSelect to show 3 items |
| `seahorse/src/main.rs` | Modify | Wire SamlInput decode+view into run_app loop |
| `seahorse/tests/saml_decoder_test.rs` | Create | Tests for decode pipeline |
| `seahorse/tests/saml_parser_test.rs` | Modify | Add tests for AuthnRequest, Response, and attribute extraction |

---

## Chunk 1: Decode Pipeline and Parser Extensions

### Task 1: Add flate2 dependency

**Files:**
- Modify: `seahorse/Cargo.toml`

- [ ] **Step 1: Add flate2 to Cargo.toml**

In `seahorse/Cargo.toml`, add under dependencies after `base64 = "0.22"`:

```toml
flate2 = "1"
```

- [ ] **Step 2: Verify it compiles**

Run: `cd seahorse && cargo check`
Expected: compiles with no errors

- [ ] **Step 3: Commit**

```bash
git add seahorse/Cargo.toml seahorse/Cargo.lock
git commit -m "chore: add flate2 dependency for SAML deflate decoding"
```

---

### Task 2: Create decoder module with decode pipeline

**Files:**
- Create: `seahorse/src/saml/decoder.rs`
- Modify: `seahorse/src/saml/mod.rs`
- Create: `seahorse/tests/saml_decoder_test.rs`

- [ ] **Step 1: Write the failing tests**

Create `seahorse/tests/saml_decoder_test.rs`:

```rust
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;

#[test]
fn test_decode_raw_xml() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
    let result = seahorse::saml::decoder::decode_saml_input(xml).unwrap();
    assert_eq!(result.document_type, seahorse::saml::decoder::SamlDocumentType::AuthnRequest);
    assert!(result.xml.contains("AuthnRequest"));
}

#[test]
fn test_decode_base64_response() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>test</saml:Issuer></saml:Assertion></samlp:Response>"#;
    let b64 = STANDARD.encode(xml.as_bytes());
    let result = seahorse::saml::decoder::decode_saml_input(&b64).unwrap();
    assert_eq!(result.document_type, seahorse::saml::decoder::SamlDocumentType::Response);
    assert!(result.xml.contains("Response"));
}

#[test]
fn test_decode_url_encoded_base64() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>test</saml:Issuer></saml:Assertion></samlp:Response>"#;
    let b64 = STANDARD.encode(xml.as_bytes());
    let url_encoded = urlencoding::encode(&b64);
    let input = format!("SAMLResponse={}", url_encoded);
    let result = seahorse::saml::decoder::decode_saml_input(&input).unwrap();
    assert_eq!(result.document_type, seahorse::saml::decoder::SamlDocumentType::Response);
}

#[test]
fn test_decode_full_url_with_saml_request() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let b64 = STANDARD.encode(&compressed);
    let url_encoded = urlencoding::encode(&b64);
    let full_url = format!("https://idp.example.com/sso?SAMLRequest={}&RelayState=token", url_encoded);
    let result = seahorse::saml::decoder::decode_saml_input(&full_url).unwrap();
    assert_eq!(result.document_type, seahorse::saml::decoder::SamlDocumentType::AuthnRequest);
}

#[test]
fn test_decode_deflated_base64() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_def"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let b64 = STANDARD.encode(&compressed);
    let result = seahorse::saml::decoder::decode_saml_input(&b64).unwrap();
    assert_eq!(result.document_type, seahorse::saml::decoder::SamlDocumentType::AuthnRequest);
}

#[test]
fn test_decode_standalone_assertion() {
    let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>test</saml:Issuer></saml:Assertion>"#;
    let result = seahorse::saml::decoder::decode_saml_input(xml).unwrap();
    assert_eq!(result.document_type, seahorse::saml::decoder::SamlDocumentType::Assertion);
}

#[test]
fn test_decode_invalid_input() {
    let result = seahorse::saml::decoder::decode_saml_input("not xml at all");
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd seahorse && cargo test --test saml_decoder_test 2>&1 | head -5`
Expected: compilation error — `decoder` module doesn't exist

- [ ] **Step 3: Add decoder module declaration**

In `seahorse/src/saml/mod.rs`, add:

```rust
pub mod builder;
pub mod decoder;
pub mod parser;
pub mod validator;
```

- [ ] **Step 4: Implement decoder.rs**

Create `seahorse/src/saml/decoder.rs`:

```rust
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
    let xml = String::from_utf8(xml_bytes)
        .map_err(|_| anyhow::anyhow!("Decoded data is not valid UTF-8"))?;

    // Step 6-7: XML validation and type detection
    match try_parse_xml(&xml) {
        Some(result) => Ok(result),
        None => bail!("Decoded data is not valid SAML XML"),
    }
}

/// Extract the value of SAMLRequest= or SAMLResponse= from a URL or parameter string.
fn extract_saml_param(input: &str) -> Option<String> {
    // Check for SAMLRequest= or SAMLResponse= anywhere in the input
    for param_name in &["SAMLRequest=", "SAMLResponse="] {
        if let Some(start) = input.find(param_name) {
            let value_start = start + param_name.len();
            let rest = &input[value_start..];
            // Value ends at & or end of string
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

    // Find the first element name (skip XML declaration and whitespace)
    let doc_type = detect_document_type(trimmed)?;

    Some(DecodeResult {
        document_type: doc_type,
        xml: trimmed.to_string(),
    })
}

/// Detect SAML document type from the root element.
fn detect_document_type(xml: &str) -> Option<SamlDocumentType> {
    // Scan for the first opening tag that isn't <?xml?>
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref());
                return match local_name.as_ref() {
                    "AuthnRequest" => Some(SamlDocumentType::AuthnRequest),
                    "Response" => Some(SamlDocumentType::Response),
                    "Assertion" => Some(SamlDocumentType::Assertion),
                    _ => None,
                };
            }
            Ok(quick_xml::events::Event::Decl(_)) | Ok(quick_xml::events::Event::PI(_)) => {
                // Skip XML declarations and processing instructions
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd seahorse && cargo test --test saml_decoder_test -- --nocapture`
Expected: all 7 tests pass

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/saml/decoder.rs seahorse/src/saml/mod.rs seahorse/tests/saml_decoder_test.rs
git commit -m "feat: add SAML decoder module with auto-detect decode pipeline"
```

---

### Task 3: Extend parser with AuthnRequest, Response, and Attribute extraction

**Files:**
- Modify: `seahorse/src/saml/parser.rs`
- Modify: `seahorse/tests/saml_parser_test.rs`

- [ ] **Step 1: Write the failing tests**

Append to `seahorse/tests/saml_parser_test.rs`:

```rust
#[test]
fn test_extract_authn_request_details() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://idp.example.com/sso" AssertionConsumerServiceURL="https://sp.example.com/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true"><saml:Issuer>https://sp.example.com</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/></samlp:AuthnRequest>"#;

    let details = seahorse::saml::parser::extract_authn_request_details(xml).unwrap();
    assert_eq!(details.id, "_abc123");
    assert_eq!(details.issue_instant, "2026-01-01T00:00:00Z");
    assert_eq!(details.issuer, "https://sp.example.com");
    assert_eq!(details.destination.as_deref(), Some("https://idp.example.com/sso"));
    assert_eq!(details.acs_url.as_deref(), Some("https://sp.example.com/acs"));
    assert_eq!(details.protocol_binding.as_deref(), Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
    assert_eq!(details.force_authn, Some(true));
    assert_eq!(details.is_passive, None);
    assert_eq!(details.name_id_policy.as_deref(), Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));
}

#[test]
fn test_extract_response_details() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.com/acs" InResponseTo="_req1"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>"#;

    let details = seahorse::saml::parser::extract_response_details(xml).unwrap();
    assert_eq!(details.id, "_resp1");
    assert_eq!(details.issue_instant, "2026-01-01T00:00:00Z");
    assert_eq!(details.issuer, "https://idp.example.com");
    assert_eq!(details.destination.as_deref(), Some("https://sp.example.com/acs"));
    assert_eq!(details.in_response_to.as_deref(), Some("_req1"));
    assert!(details.status.contains("Success"));
}

#[test]
fn test_extract_attributes() {
    let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_a1" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>test</saml:Issuer><saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue xsi:type="xs:string">testuser</saml:AttributeValue></saml:Attribute><saml:Attribute Name="roles"><saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#;

    let attrs = seahorse::saml::parser::extract_attributes(xml).unwrap();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].name, "uid");
    assert_eq!(attrs[0].values, vec!["testuser"]);
    assert_eq!(attrs[1].name, "roles");
    assert_eq!(attrs[1].values, vec!["admin", "user"]);
}

#[test]
fn test_extract_attributes_none() {
    let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>test</saml:Issuer></saml:Assertion>"#;
    let attrs = seahorse::saml::parser::extract_attributes(xml).unwrap();
    assert!(attrs.is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd seahorse && cargo test --test saml_parser_test 2>&1 | head -5`
Expected: compilation error — functions don't exist yet

- [ ] **Step 3: Add new structs and functions to parser.rs**

Add these structs after `AssertionDetails` in `seahorse/src/saml/parser.rs`:

```rust
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
```

Add these functions at the end of parser.rs (before `pretty_print_xml`):

```rust
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
                            let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
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
                            let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
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
                            let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
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
                            let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                            if key == "Value" {
                                details.status =
                                    String::from_utf8_lossy(&attr.value).to_string();
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
                        let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                        if key == "Value" {
                            details.status =
                                String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                // Only capture Issuer at Response level (depth 2 = direct child of Response)
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
                            let key = String::from_utf8_lossy(attr.key.local_name().as_ref());
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd seahorse && cargo test --test saml_parser_test -- --nocapture`
Expected: all 7 tests pass (3 existing + 4 new)

- [ ] **Step 5: Run full test suite**

Run: `cd seahorse && cargo test`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/saml/parser.rs seahorse/tests/saml_parser_test.rs
git commit -m "feat: add AuthnRequest, Response, and attribute extraction to SAML parser"
```

---

## Chunk 2: TUI Screens and Integration

### Task 4: Add new screen variants and state to App

**Files:**
- Modify: `seahorse/src/tui/app.rs`

- [ ] **Step 1: Add imports, enums, and state fields**

In `seahorse/src/tui/app.rs`, add imports at the top:

```rust
use crate::config::{Config, Environment};
use crate::saml::decoder::{DecodeResult, SamlDocumentType};
use crate::saml::parser::{AssertionDetails, AuthnRequestDetails, ResponseDetails, SamlAttribute};
use crate::saml::validator::SignatureValidation;
```

Add new screen variants to `Screen` enum:

```rust
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
```

Add input mode enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SamlInputMode {
    Paste,
    File,
}
```

Add fields to `App` struct (after `copy_status`):

```rust
    // SAML Viewer state
    pub saml_input_mode: SamlInputMode,
    pub saml_paste_buffer: String,
    pub saml_file_path: String,
    pub decoded_saml: Option<DecodeResult>,
    pub viewer_authn_request: Option<AuthnRequestDetails>,
    pub viewer_response: Option<ResponseDetails>,
    pub viewer_assertion: Option<AssertionDetails>,
    pub viewer_attributes: Vec<SamlAttribute>,
    pub viewer_signature: Option<SignatureValidation>,
    pub viewer_pretty_xml: String,
    pub viewer_scroll_offset: u16,
    pub viewer_copy_status: Option<String>,
```

Add defaults in `App::new()`:

```rust
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cd seahorse && cargo check`
Expected: compiles (warnings about unused fields are OK)

- [ ] **Step 3: Commit**

```bash
git add seahorse/src/tui/app.rs
git commit -m "feat: add SamlInput/SamlView screen variants and viewer state to App"
```

---

### Task 5: Update EnvSelect menu to show 3 options

**Files:**
- Modify: `seahorse/src/tui/ui.rs` (render_env_select)
- Modify: `seahorse/src/tui/input.rs` (handle_env_select)

- [ ] **Step 1: Update render_env_select in ui.rs**

Change the `envs` array and list title:

```rust
fn render_env_select(frame: &mut Frame, app: &App) {
    // ... layout stays the same ...

    let items_list = ["PROD", "TST", "View SAML Assertion"];
    let items: Vec<ListItem> = items_list
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let style = if i == app.env_selection {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if i == app.env_selection { "> " } else { "  " };
            ListItem::new(format!("{}{}", prefix, label)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Seahorse - Main Menu")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, chunks[1]);

    // ... help stays the same ...
}
```

- [ ] **Step 2: Update handle_env_select in input.rs**

Change the bound from `< 1` to `< 2`, and branch Enter:

```rust
fn handle_env_select(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up => {
            if app.env_selection > 0 {
                app.env_selection -= 1;
            }
        }
        KeyCode::Down => {
            if app.env_selection < 2 {
                app.env_selection += 1;
            }
        }
        KeyCode::Enter => {
            if app.env_selection == 2 {
                app.screen = Screen::SamlInput;
            } else {
                app.environment = Some(app.get_selected_env());
                app.screen = Screen::FlowSelect;
            }
        }
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd seahorse && cargo check`
Expected: compiles (may warn about unmatched SamlInput/SamlView in render/input match)

- [ ] **Step 4: Commit**

```bash
git add seahorse/src/tui/ui.rs seahorse/src/tui/input.rs
git commit -m "feat: add 'View SAML Assertion' as third main menu option"
```

---

### Task 6: Implement SamlInput screen (input handler + renderer)

**Files:**
- Modify: `seahorse/src/tui/input.rs`
- Modify: `seahorse/src/tui/ui.rs`

- [ ] **Step 1: Add SamlInput handler in input.rs**

Add to the `handle_input` function's match, and handle bracketed paste events. Update the top-level event handling:

```rust
pub fn handle_input(app: &mut App) -> std::io::Result<bool> {
    if event::poll(std::time::Duration::from_millis(100))? {
        let ev = event::read()?;

        // Handle bracketed paste events (for SamlInput paste mode)
        if let Event::Paste(ref text) = ev {
            if app.screen == Screen::SamlInput
                && app.saml_input_mode == super::app::SamlInputMode::Paste
            {
                app.saml_paste_buffer.push_str(text);
            }
            return Ok(false);
        }

        if let Event::Key(key) = ev {
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if app.screen == Screen::Result || app.screen == Screen::SamlView {
                    copy_to_clipboard(app);
                    return Ok(false);
                }
                app.running = false;
                return Ok(true);
            }
            match app.screen {
                Screen::EnvSelect => handle_env_select(app, key.code),
                Screen::FlowSelect => handle_flow_select(app, key.code),
                Screen::AuthInput => handle_auth_input(app, key.code),
                Screen::Waiting => handle_waiting(app, key.code),
                Screen::Result => handle_result(app, key.code),
                Screen::Error => handle_error(app, key.code),
                Screen::SamlInput => handle_saml_input(app, key.code),
                Screen::SamlView => handle_saml_view(app, key.code),
            }
        }
    }
    Ok(false)
}
```

Update `copy_to_clipboard` to handle SamlView:

```rust
fn copy_to_clipboard(app: &mut App) {
    let xml = if app.screen == Screen::SamlView {
        &app.viewer_pretty_xml
    } else {
        &app.raw_xml
    };
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(xml) {
            Ok(_) => {
                let status = Some("Copied to clipboard!".to_string());
                if app.screen == Screen::SamlView {
                    app.viewer_copy_status = status;
                } else {
                    app.copy_status = status;
                }
            }
            Err(e) => {
                let status = Some(format!("Copy failed: {}", e));
                if app.screen == Screen::SamlView {
                    app.viewer_copy_status = status;
                } else {
                    app.copy_status = status;
                }
            }
        },
        Err(e) => {
            let status = Some(format!("Clipboard unavailable: {}", e));
            if app.screen == Screen::SamlView {
                app.viewer_copy_status = status;
            } else {
                app.copy_status = status;
            }
        }
    }
}
```

Add the SamlInput handler:

```rust
fn handle_saml_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Tab => {
            app.saml_input_mode = match app.saml_input_mode {
                super::app::SamlInputMode::Paste => super::app::SamlInputMode::File,
                super::app::SamlInputMode::File => super::app::SamlInputMode::Paste,
            };
        }
        KeyCode::F(5) => {
            // Submit
            let input = match app.saml_input_mode {
                super::app::SamlInputMode::Paste => app.saml_paste_buffer.clone(),
                super::app::SamlInputMode::File => {
                    let path = expand_tilde(&app.saml_file_path);
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            if content.len() > 1_048_576 {
                                app.error_message = "File exceeds 1MB size limit".to_string();
                                app.screen = Screen::Error;
                                return;
                            }
                            content
                        }
                        Err(e) => {
                            app.error_message = format!("Failed to read file: {}", e);
                            app.screen = Screen::Error;
                            return;
                        }
                    }
                }
            };
            if input.trim().is_empty() {
                return;
            }
            if input.len() > 1_048_576 {
                app.error_message = "Input exceeds 1MB size limit".to_string();
                app.screen = Screen::Error;
                return;
            }
            app.status_message = input;
            app.screen = Screen::Waiting;
        }
        KeyCode::Backspace => match app.saml_input_mode {
            super::app::SamlInputMode::Paste => {
                app.saml_paste_buffer.pop();
            }
            super::app::SamlInputMode::File => {
                app.saml_file_path.pop();
            }
        },
        KeyCode::Enter => match app.saml_input_mode {
            super::app::SamlInputMode::Paste => {
                app.saml_paste_buffer.push('\n');
            }
            super::app::SamlInputMode::File => {
                // Submit file path on Enter
                let path = expand_tilde(&app.saml_file_path);
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        if content.len() > 1_048_576 {
                            app.error_message = "File exceeds 1MB size limit".to_string();
                            app.screen = Screen::Error;
                            return;
                        }
                        app.status_message = content;
                        app.screen = Screen::Waiting;
                    }
                    Err(e) => {
                        app.error_message = format!("Failed to read file: {}", e);
                        app.screen = Screen::Error;
                        return;
                    }
                }
            }
        },
        KeyCode::Char(c) => match app.saml_input_mode {
            super::app::SamlInputMode::Paste => app.saml_paste_buffer.push(c),
            super::app::SamlInputMode::File => app.saml_file_path.push(c),
        },
        KeyCode::Esc => {
            app.screen = Screen::EnvSelect;
            app.saml_paste_buffer.clear();
            app.saml_file_path.clear();
        }
        _ => {}
    }
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with('~') {
        if let Some(home) = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
        {
            return path.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}
```

Add SamlView handler:

```rust
fn handle_saml_view(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('c') => copy_to_clipboard(app),
        KeyCode::Char('r') => {
            // Return to SamlInput for new input
            app.screen = Screen::SamlInput;
            app.saml_paste_buffer.clear();
            app.saml_file_path.clear();
            app.decoded_saml = None;
            app.viewer_authn_request = None;
            app.viewer_response = None;
            app.viewer_assertion = None;
            app.viewer_attributes.clear();
            app.viewer_signature = None;
            app.viewer_pretty_xml.clear();
            app.viewer_scroll_offset = 0;
            app.viewer_copy_status = None;
        }
        KeyCode::Up => {
            if app.viewer_scroll_offset > 0 {
                app.viewer_scroll_offset -= 1;
            }
        }
        KeyCode::Down => {
            app.viewer_scroll_offset += 1;
        }
        KeyCode::Esc => {
            app.screen = Screen::EnvSelect;
            app.viewer_copy_status = None;
        }
        _ => {}
    }
}
```

- [ ] **Step 2: Add SamlInput renderer in ui.rs**

Add to `render()` match:

```rust
pub fn render(frame: &mut Frame, app: &App) {
    match app.screen {
        Screen::EnvSelect => render_env_select(frame, app),
        Screen::FlowSelect => render_flow_select(frame, app),
        Screen::AuthInput => render_auth_input(frame, app),
        Screen::Waiting => render_waiting(frame, app),
        Screen::Result => render_result(frame, app),
        Screen::Error => render_error(frame, app),
        Screen::SamlInput => render_saml_input(frame, app),
        Screen::SamlView => render_saml_view(frame, app),
    }
}
```

Add the import for `SamlInputMode`:

```rust
use super::app::{App, Screen, SamlInputMode, SigningMode};
```

Add render functions:

```rust
fn render_saml_input(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let title = Paragraph::new("Seahorse - View SAML Assertion")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let mode_label = match app.saml_input_mode {
        SamlInputMode::Paste => "[Paste]  File ",
        SamlInputMode::File => " Paste  [File]",
    };
    let mode = Paragraph::new(format!("Input Mode: {}", mode_label))
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("Mode (Tab to switch)"));
    frame.render_widget(mode, chunks[1]);

    match app.saml_input_mode {
        SamlInputMode::Paste => {
            let line_count = app.saml_paste_buffer.lines().count().max(1);
            let preview = if app.saml_paste_buffer.is_empty() {
                "Paste SAML data here (XML, base64, URL-encoded, or full URL)...".to_string()
            } else {
                let chars = app.saml_paste_buffer.len();
                format!("{} ({} chars, {} lines)", &app.saml_paste_buffer, chars, line_count)
            };
            let style = if app.saml_paste_buffer.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let input = Paragraph::new(preview)
                .style(style)
                .block(
                    Block::default()
                        .title("SAML Data")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(input, chunks[2]);
        }
        SamlInputMode::File => {
            let display = if app.saml_file_path.is_empty() {
                "Enter file path...".to_string()
            } else {
                app.saml_file_path.clone()
            };
            let style = if app.saml_file_path.is_empty() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let input = Paragraph::new(display)
                .style(style)
                .block(
                    Block::default()
                        .title("File Path")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                );
            frame.render_widget(input, chunks[2]);
        }
    }

    let help_text = match app.saml_input_mode {
        SamlInputMode::Paste => "Tab: Switch Mode | F5: Decode | Esc: Back | q: Quit",
        SamlInputMode::File => "Tab: Switch Mode | Enter: Load & Decode | Esc: Back | q: Quit",
    };
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[3]);
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd seahorse && cargo check`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add seahorse/src/tui/input.rs seahorse/src/tui/ui.rs
git commit -m "feat: implement SamlInput screen with paste and file input modes"
```

---

### Task 7: Implement SamlView renderer

**Files:**
- Modify: `seahorse/src/tui/ui.rs`

- [ ] **Step 1: Add render_saml_view function**

```rust
fn render_saml_view(frame: &mut Frame, app: &App) {
    // Calculate dynamic constraints based on what sections have content
    let has_attrs = !app.viewer_attributes.is_empty();
    let has_sig = app.viewer_signature.is_some();
    let attr_height = if has_attrs {
        (app.viewer_attributes.len() as u16 + 2).min(8)
    } else {
        0
    };
    let sig_height: u16 = if has_sig { 7 } else { 0 };

    let mut constraints = vec![
        Constraint::Length(3),  // title
        Constraint::Length(11), // details
    ];
    if has_attrs {
        constraints.push(Constraint::Length(attr_height));
    }
    if has_sig {
        constraints.push(Constraint::Length(sig_height));
    }
    constraints.push(Constraint::Min(5)); // XML
    constraints.push(Constraint::Length(3)); // help

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    let mut chunk_idx = 0;

    // Title
    let doc_type_label = match &app.decoded_saml {
        Some(d) => match d.document_type {
            super::app::SamlDocumentType::AuthnRequest => "SAML AuthnRequest",
            super::app::SamlDocumentType::Response => "SAML Response",
            super::app::SamlDocumentType::Assertion => "SAML Assertion",
        },
        None => "SAML Document",
    };
    let title = Paragraph::new(format!("Seahorse - {}", doc_type_label))
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[chunk_idx]);
    chunk_idx += 1;

    // Details panel
    let details_text = build_viewer_details(app);
    let details = Paragraph::new(details_text)
        .block(
            Block::default()
                .title("Details")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(details, chunks[chunk_idx]);
    chunk_idx += 1;

    // Attributes panel (if present)
    if has_attrs {
        let attr_lines: Vec<Line> = app
            .viewer_attributes
            .iter()
            .map(|a| {
                let val = a.values.join(", ");
                Line::from(vec![
                    Span::styled(
                        format!("{}: ", a.name),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(val),
                ])
            })
            .collect();
        let attrs = Paragraph::new(attr_lines)
            .block(
                Block::default()
                    .title("Attributes")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(attrs, chunks[chunk_idx]);
        chunk_idx += 1;
    }

    // Signature panel (if present)
    if has_sig {
        if let Some(ref sig) = app.viewer_signature {
            let valid_color = if sig.signature_valid {
                Color::Green
            } else {
                Color::Red
            };
            let sig_text = vec![
                Line::from(vec![
                    Span::styled("Present:     ", Style::default().fg(Color::Cyan)),
                    Span::raw(if sig.signature_present { "Yes" } else { "No" }),
                ]),
                Line::from(vec![
                    Span::styled("Valid:       ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        if sig.signature_valid { "Yes" } else { "No" },
                        Style::default().fg(valid_color),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Algorithm:   ", Style::default().fg(Color::Cyan)),
                    Span::raw(&sig.algorithm),
                ]),
                Line::from(vec![
                    Span::styled("Certificate: ", Style::default().fg(Color::Cyan)),
                    Span::raw(&sig.certificate_subject),
                ]),
                Line::from(vec![
                    Span::styled("Cert Expiry: ", Style::default().fg(Color::Cyan)),
                    Span::raw(sig.certificate_not_after.as_deref().unwrap_or("N/A")),
                ]),
            ];
            let sig_widget = Paragraph::new(sig_text)
                .block(
                    Block::default()
                        .title("Signature Info")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(sig_widget, chunks[chunk_idx]);
        }
        chunk_idx += 1;
    }

    // Formatted XML (scrollable)
    let xml_paragraph = Paragraph::new(app.viewer_pretty_xml.as_str())
        .block(
            Block::default()
                .title("SAML XML (formatted)")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.viewer_scroll_offset, 0));
    frame.render_widget(xml_paragraph, chunks[chunk_idx]);
    chunk_idx += 1;

    // Help bar
    let copy_indicator = match &app.viewer_copy_status {
        Some(msg) => format!(" | {}", msg),
        None => String::new(),
    };
    let help = Paragraph::new(format!(
        "Up/Down: Scroll | c/Ctrl+C: Copy XML | r: New Input | Esc: Main Menu | q: Quit{}",
        copy_indicator
    ))
    .style(Style::default().fg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[chunk_idx]);
}

fn build_viewer_details<'a>(app: &'a App) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    if let Some(ref req) = app.viewer_authn_request {
        lines.push(detail_line("ID:              ", &req.id));
        lines.push(detail_line("IssueInstant:    ", &req.issue_instant));
        lines.push(detail_line("Issuer:          ", &req.issuer));
        lines.push(detail_line("Destination:     ", req.destination.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("ACS URL:         ", req.acs_url.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("ProtocolBinding: ", req.protocol_binding.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("NameIDPolicy:    ", req.name_id_policy.as_deref().unwrap_or("N/A")));
        if let Some(fa) = req.force_authn {
            lines.push(detail_line("ForceAuthn:      ", if fa { "true" } else { "false" }));
        }
        if let Some(ip) = req.is_passive {
            lines.push(detail_line("IsPassive:       ", if ip { "true" } else { "false" }));
        }
    }

    if let Some(ref resp) = app.viewer_response {
        lines.push(detail_line("Response ID:     ", &resp.id));
        lines.push(detail_line("IssueInstant:    ", &resp.issue_instant));
        lines.push(detail_line("Issuer:          ", &resp.issuer));
        lines.push(detail_line("Destination:     ", resp.destination.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("InResponseTo:    ", resp.in_response_to.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("Status:          ", &resp.status));
    }

    if let Some(ref assertion) = app.viewer_assertion {
        if app.viewer_response.is_some() {
            lines.push(Line::from(Span::styled(
                "--- Assertion ---",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(detail_line("Issuer:          ", &assertion.issuer));
        lines.push(detail_line("Subject:         ", &assertion.subject));
        lines.push(detail_line("Audience:        ", &assertion.audience));
        lines.push(detail_line("ID:              ", &assertion.assertion_id));
        lines.push(detail_line("Issued:          ", &assertion.issue_instant));
        lines.push(detail_line("NotBefore:       ", assertion.not_before.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("NotAfter:        ", assertion.not_after.as_deref().unwrap_or("N/A")));
        lines.push(detail_line("Signed:          ", if assertion.has_signature { "Yes" } else { "No" }));
    }

    if lines.is_empty() {
        lines.push(Line::from("No details available"));
    }

    lines
}

fn detail_line<'a>(label: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(label, Style::default().fg(Color::Cyan)),
        Span::raw(value),
    ])
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd seahorse && cargo check`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add seahorse/src/tui/ui.rs
git commit -m "feat: implement SamlView renderer with details, attributes, signature, and XML panels"
```

---

### Task 8: Wire decode logic into main.rs run_app loop

**Files:**
- Modify: `seahorse/src/main.rs`

- [ ] **Step 1: Add decode processing in run_app**

In `run_app()`, the Waiting screen currently runs auth flows. We need to also handle the SAML viewer decode when coming from SamlInput. Add a check before the auth flow block:

After `if app.screen == Screen::Waiting {` and before the flow match, add a branch that checks if we came from SamlInput (detected by checking if `decoded_saml` fields indicate viewer mode — or simpler: check if `flow_mode` is None, meaning no auth flow was selected):

```rust
        // Decode SAML input when in Waiting state from SamlInput
        if app.screen == Screen::Waiting && app.flow_mode.is_none() && app.environment.is_none() {
            process_saml_viewer_input(app);
            continue;
        }
```

Add the function:

```rust
fn process_saml_viewer_input(app: &mut App) {
    let input = std::mem::take(&mut app.status_message);

    // Decode
    match saml::decoder::decode_saml_input(&input) {
        Ok(result) => {
            // Pretty-print
            app.viewer_pretty_xml = saml::parser::pretty_print_xml(&result.xml);

            // Extract details based on type
            match result.document_type {
                saml::decoder::SamlDocumentType::AuthnRequest => {
                    match saml::parser::extract_authn_request_details(&result.xml) {
                        Ok(details) => app.viewer_authn_request = Some(details),
                        Err(e) => {
                            info!("Could not extract AuthnRequest details: {}", e);
                        }
                    }
                }
                saml::decoder::SamlDocumentType::Response => {
                    // Response-level details
                    match saml::parser::extract_response_details(&result.xml) {
                        Ok(details) => app.viewer_response = Some(details),
                        Err(e) => {
                            info!("Could not extract Response details: {}", e);
                        }
                    }
                    // Assertion within response
                    if let Ok(assertion_xml) = saml::parser::extract_assertion_from_response(&result.xml) {
                        match saml::parser::extract_assertion_details(&assertion_xml) {
                            Ok(details) => app.viewer_assertion = Some(details),
                            Err(e) => {
                                info!("Could not extract Assertion details: {}", e);
                            }
                        }
                        // Attributes
                        match saml::parser::extract_attributes(&assertion_xml) {
                            Ok(attrs) => app.viewer_attributes = attrs,
                            Err(e) => {
                                info!("Could not extract attributes: {}", e);
                            }
                        }
                        // Signature
                        match saml::validator::validate_assertion_signature(&assertion_xml) {
                            Ok(sig) => app.viewer_signature = Some(sig),
                            Err(e) => {
                                info!("Could not validate signature: {}", e);
                            }
                        }
                    }
                }
                saml::decoder::SamlDocumentType::Assertion => {
                    match saml::parser::extract_assertion_details(&result.xml) {
                        Ok(details) => app.viewer_assertion = Some(details),
                        Err(e) => {
                            info!("Could not extract Assertion details: {}", e);
                        }
                    }
                    match saml::parser::extract_attributes(&result.xml) {
                        Ok(attrs) => app.viewer_attributes = attrs,
                        Err(e) => {
                            info!("Could not extract attributes: {}", e);
                        }
                    }
                    match saml::validator::validate_assertion_signature(&result.xml) {
                        Ok(sig) => app.viewer_signature = Some(sig),
                        Err(e) => {
                            info!("Could not validate signature: {}", e);
                        }
                    }
                }
            }

            app.decoded_saml = Some(result);
            app.screen = Screen::SamlView;
        }
        Err(e) => {
            app.error_message = format!("Failed to decode SAML: {}", e);
            app.screen = Screen::Error;
        }
    }
}
```

Also, update the Error screen's Esc/r handlers to go back to SamlInput when the viewer was the source. In `input.rs`, update `handle_error`:

```rust
fn handle_error(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') => app.running = false,
        KeyCode::Char('r') => {
            let go_to_saml = app.flow_mode.is_none() && app.environment.is_none();
            if go_to_saml {
                app.screen = Screen::SamlInput;
            } else {
                app.screen = Screen::AuthInput;
                app.password.clear();
                app.otp_code.clear();
                app.active_field = 0;
            }
            app.error_message.clear();
        }
        KeyCode::Esc => {
            let go_to_saml = app.flow_mode.is_none() && app.environment.is_none();
            if go_to_saml {
                app.screen = Screen::SamlInput;
            } else {
                app.screen = Screen::FlowSelect;
            }
            app.error_message.clear();
        }
        _ => {}
    }
}
```

- [ ] **Step 2: Enable bracketed paste in main.rs**

In `main()`, after `enable_raw_mode()`, add:

```rust
    crossterm::execute!(stdout, EnterAlternateScreen, crossterm::event::EnableBracketedPaste)?;
```

And before `LeaveAlternateScreen`, add:

```rust
    crossterm::execute!(terminal.backend_mut(), crossterm::event::DisableBracketedPaste, LeaveAlternateScreen)?;
```

- [ ] **Step 3: Add `SamlDocumentType` re-export to app.rs**

In `seahorse/src/tui/app.rs`, add:

```rust
pub use crate::saml::decoder::SamlDocumentType;
```

(This makes it available for ui.rs to reference via `super::app::SamlDocumentType`.)

- [ ] **Step 4: Verify it compiles**

Run: `cd seahorse && cargo check`
Expected: compiles with no errors

- [ ] **Step 5: Run full test suite**

Run: `cd seahorse && cargo test`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add seahorse/src/main.rs seahorse/src/tui/input.rs seahorse/src/tui/app.rs
git commit -m "feat: wire SAML viewer decode logic into app loop with bracketed paste support"
```

---

### Task 9: Final integration test and cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run cargo clippy**

Run: `cd seahorse && cargo clippy -- -W warnings 2>&1`
Expected: no errors (warnings about unused variables are OK to fix)

- [ ] **Step 2: Fix any clippy warnings**

Address any clippy warnings in the new code.

- [ ] **Step 3: Run full test suite**

Run: `cd seahorse && cargo test`
Expected: all tests pass

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete View SAML Assertion feature with decode, parse, and display"
```
