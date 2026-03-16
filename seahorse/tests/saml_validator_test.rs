use std::path::PathBuf;

fn test_pfx_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx")
}

fn test_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-idp.pem")
}

// --- Existing tests (preserved) ---

#[test]
fn test_validate_self_signed_assertion() {
    let pfx_path = test_pfx_path();

    let bundle = seahorse::crypto::load_pfx(&pfx_path, "testpassword").unwrap();

    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };

    let signed_xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    )
    .unwrap();

    let result = seahorse::saml::validator::validate_assertion_signature(&signed_xml);
    assert!(result.is_ok(), "Validation failed: {:?}", result.err());

    let validation = result.unwrap();
    assert!(validation.signature_present);
    assert!(validation.certificate_found);
}

#[test]
fn test_unsigned_assertion_no_signature() {
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };

    let unsigned_xml = seahorse::saml::builder::build_unsigned_assertion(&params);
    let result = seahorse::saml::validator::validate_assertion_signature(&unsigned_xml).unwrap();
    assert!(!result.signature_present);
    assert!(!result.certificate_found);
}

#[test]
fn test_check_conditions_valid() {
    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::minutes(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let not_after = (now + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let result =
        seahorse::saml::validator::check_time_conditions(Some(&not_before), Some(&not_after));
    assert!(result.is_ok());
}

#[test]
fn test_check_conditions_expired() {
    let past = (chrono::Utc::now() - chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let also_past = (chrono::Utc::now() - chrono::Duration::minutes(30))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let result = seahorse::saml::validator::check_time_conditions(Some(&past), Some(&also_past));
    assert!(result.is_err());
}

#[test]
fn test_validation_summary_display() {
    assert_eq!(
        seahorse::saml::validator::ValidationSummary::Trusted.message(),
        "Signature verified against configured IDP certificate"
    );
    assert_eq!(
        seahorse::saml::validator::ValidationSummary::Unsigned.message(),
        "No signature present in assertion"
    );
}

#[test]
fn test_validation_report_builder() {
    let report = seahorse::saml::validator::ValidationReport {
        summary: seahorse::saml::validator::ValidationSummary::Unsigned,
        checks: vec![],
        idp_cert_loaded: false,
        algorithm: String::new(),
        cert_subject: String::new(),
        cert_not_after: None,
    };
    assert!(!report.idp_cert_loaded);
    assert!(report.checks.is_empty());
}

// --- New validation pipeline tests (Task 8) ---

#[test]
fn test_validate_unsigned_assertion() {
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };
    let xml = seahorse::saml::builder::build_unsigned_assertion(&params);
    let report = seahorse::saml::validator::validate_assertion(&xml, None);
    assert_eq!(
        report.summary,
        seahorse::saml::validator::ValidationSummary::Unsigned
    );
}

#[test]
fn test_validate_signed_assertion_no_idp_cert() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), "testpassword").unwrap();
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
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
        "Expected Valid, got {:?}. Checks: {:?}",
        report.summary,
        report.checks
    );
}

#[test]
fn test_validate_signed_assertion_with_idp_cert() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), "testpassword").unwrap();
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };
    let xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    )
    .unwrap();
    let trust_store =
        seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    let report = seahorse::saml::validator::validate_assertion(&xml, Some(&trust_store));
    assert_eq!(
        report.summary,
        seahorse::saml::validator::ValidationSummary::Trusted,
        "Expected Trusted, got {:?}. Checks: {:?}",
        report.summary,
        report.checks
    );
}
