use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;

#[test]
fn test_decode_raw_xml() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
    let result = seahorse::saml::decoder::decode_saml_input(xml).unwrap();
    assert_eq!(
        result.document_type,
        seahorse::saml::decoder::SamlDocumentType::AuthnRequest
    );
    assert!(result.xml.contains("AuthnRequest"));
}

#[test]
fn test_decode_base64_response() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>test</saml:Issuer></saml:Assertion></samlp:Response>"#;
    let b64 = STANDARD.encode(xml.as_bytes());
    let result = seahorse::saml::decoder::decode_saml_input(&b64).unwrap();
    assert_eq!(
        result.document_type,
        seahorse::saml::decoder::SamlDocumentType::Response
    );
    assert!(result.xml.contains("Response"));
}

#[test]
fn test_decode_url_encoded_base64() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>test</saml:Issuer></saml:Assertion></samlp:Response>"#;
    let b64 = STANDARD.encode(xml.as_bytes());
    let url_encoded = urlencoding::encode(&b64);
    let input = format!("SAMLResponse={}", url_encoded);
    let result = seahorse::saml::decoder::decode_saml_input(&input).unwrap();
    assert_eq!(
        result.document_type,
        seahorse::saml::decoder::SamlDocumentType::Response
    );
}

#[test]
fn test_decode_full_url_with_saml_request() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let b64 = STANDARD.encode(&compressed);
    let url_encoded = urlencoding::encode(&b64);
    let full_url = format!(
        "https://idp.example.com/sso?SAMLRequest={}&RelayState=token",
        url_encoded
    );
    let result = seahorse::saml::decoder::decode_saml_input(&full_url).unwrap();
    assert_eq!(
        result.document_type,
        seahorse::saml::decoder::SamlDocumentType::AuthnRequest
    );
}

#[test]
fn test_decode_deflated_base64() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_def"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"#;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let b64 = STANDARD.encode(&compressed);
    let result = seahorse::saml::decoder::decode_saml_input(&b64).unwrap();
    assert_eq!(
        result.document_type,
        seahorse::saml::decoder::SamlDocumentType::AuthnRequest
    );
}

#[test]
fn test_decode_standalone_assertion() {
    let xml = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>test</saml:Issuer></saml:Assertion>"#;
    let result = seahorse::saml::decoder::decode_saml_input(xml).unwrap();
    assert_eq!(
        result.document_type,
        seahorse::saml::decoder::SamlDocumentType::Assertion
    );
}

#[test]
fn test_decode_invalid_input() {
    let result = seahorse::saml::decoder::decode_saml_input("not xml at all");
    assert!(result.is_err());
}
