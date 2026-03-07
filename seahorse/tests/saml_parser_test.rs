#[test]
fn test_parse_saml_response_post_body() {
    let assertion_xml = r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" IssueInstant="2026-03-06T12:00:00Z" Version="2.0"><saml2:Issuer>https://issuer.example.com</saml2:Issuer><saml2:Subject><saml2:NameID>jsmith</saml2:NameID></saml2:Subject><saml2:Conditions NotBefore="2026-03-06T12:00:00Z" NotOnOrAfter="2026-03-06T12:05:00Z"><saml2:AudienceRestriction><saml2:Audience>epic://epicenvironment</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2026-03-06T12:00:00Z"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>"#;

    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        assertion_xml.as_bytes(),
    );
    let url_encoded = urlencoding::encode(&b64);
    let post_body = format!("SAMLResponse={}", url_encoded);

    let result = seahorse::saml::parser::parse_saml_post_body(&post_body).unwrap();
    assert!(result.assertion_xml.contains("saml2:Assertion"));
    assert!(result.assertion_xml.contains("jsmith"));
}

#[test]
fn test_extract_assertion_details() {
    let assertion_xml = r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" IssueInstant="2026-03-06T12:00:00Z" Version="2.0"><saml2:Issuer>https://issuer.example.com</saml2:Issuer><saml2:Subject><saml2:NameID>jsmith</saml2:NameID></saml2:Subject><saml2:Conditions NotBefore="2026-03-06T12:00:00Z" NotOnOrAfter="2026-03-06T12:05:00Z"><saml2:AudienceRestriction><saml2:Audience>epic://epicenvironment</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2026-03-06T12:00:00Z"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>"#;

    let details = seahorse::saml::parser::extract_assertion_details(assertion_xml).unwrap();

    assert_eq!(details.issuer, "https://issuer.example.com");
    assert_eq!(details.subject, "jsmith");
    assert_eq!(details.audience, "epic://epicenvironment");
    assert_eq!(details.not_before.as_deref(), Some("2026-03-06T12:00:00Z"));
    assert_eq!(details.not_after.as_deref(), Some("2026-03-06T12:05:00Z"));
    assert!(details.authn_context.contains("Password"));
    assert!(!details.has_signature);
}

#[test]
fn test_extract_assertion_from_response_xml() {
    let response_xml = r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc"><saml2:Issuer>test</saml2:Issuer></saml2:Assertion></saml2p:Response>"#;

    let assertion = seahorse::saml::parser::extract_assertion_from_response(response_xml).unwrap();
    assert!(assertion.contains("saml2:Assertion"));
    assert!(assertion.contains("test"));
}
