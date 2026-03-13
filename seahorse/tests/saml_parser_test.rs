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

#[test]
fn test_extract_authn_request_details() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://idp.example.com/sso" AssertionConsumerServiceURL="https://sp.example.com/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true"><saml:Issuer>https://sp.example.com</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/></samlp:AuthnRequest>"#;

    let details = seahorse::saml::parser::extract_authn_request_details(xml).unwrap();
    assert_eq!(details.id, "_abc123");
    assert_eq!(details.issue_instant, "2026-01-01T00:00:00Z");
    assert_eq!(details.issuer, "https://sp.example.com");
    assert_eq!(
        details.destination.as_deref(),
        Some("https://idp.example.com/sso")
    );
    assert_eq!(
        details.acs_url.as_deref(),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(
        details.protocol_binding.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    );
    assert_eq!(details.force_authn, Some(true));
    assert_eq!(details.is_passive, None);
    assert_eq!(
        details.name_id_policy.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
    );
}

#[test]
fn test_extract_response_details() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.com/acs" InResponseTo="_req1"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>"#;

    let details = seahorse::saml::parser::extract_response_details(xml).unwrap();
    assert_eq!(details.id, "_resp1");
    assert_eq!(details.issue_instant, "2026-01-01T00:00:00Z");
    assert_eq!(details.issuer, "https://idp.example.com");
    assert_eq!(
        details.destination.as_deref(),
        Some("https://sp.example.com/acs")
    );
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
