use std::path::PathBuf;

#[test]
fn test_build_unsigned_assertion() {
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test-issuer.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "jsmith".to_string(),
        validity_seconds: 300,
    };

    let xml = seahorse::saml::builder::build_unsigned_assertion(&params);

    assert!(xml.contains("saml2:Assertion"));
    assert!(xml.contains("saml2:Issuer"));
    assert!(xml.contains("https://test-issuer.example.com"));
    assert!(xml.contains("jsmith"));
    assert!(xml.contains("epic://epicenvironment"));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
    assert!(xml.contains("saml2:AudienceRestriction"));
    assert!(xml.contains("saml2:AuthnStatement"));
    assert!(!xml.contains("ds:Signature"));
}

#[test]
fn test_build_signed_assertion() {
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx");

    let bundle = seahorse::crypto::load_pfx(&pfx_path, "testpassword").unwrap();

    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test-issuer.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "jsmith".to_string(),
        validity_seconds: 300,
    };

    let xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    )
    .unwrap();

    assert!(xml.contains("saml2:Assertion"));
    assert!(xml.contains("ds:Signature"));
    assert!(xml.contains("ds:SignatureValue"));
    assert!(xml.contains("ds:X509Certificate"));
    assert!(xml.contains("rsa-sha256"));
    assert!(xml.contains("jsmith"));
}
