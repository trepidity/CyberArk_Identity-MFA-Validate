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

#[test]
fn test_signed_assertion_validates() {
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx");
    let bundle = seahorse::crypto::load_pfx(&pfx_path, "testpassword").unwrap();
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "roundtrip-user".to_string(),
        validity_seconds: 300,
    };
    let xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    )
    .unwrap();
    let report = seahorse::saml::validator::validate_assertion(&xml, None);
    assert_eq!(
        report.summary,
        seahorse::saml::validator::ValidationSummary::Valid,
        "Round-trip failed. Checks: {:#?}",
        report.checks
    );
    for check in &report.checks {
        match check.name.as_str() {
            "Structure" | "Time" | "Digest" | "Signature" => {
                assert!(
                    check.passed,
                    "Check '{}' failed: {} {:?}",
                    check.name, check.detail, check.diagnostic
                );
            }
            _ => {}
        }
    }
}
