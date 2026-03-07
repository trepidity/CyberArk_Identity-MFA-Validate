use std::path::PathBuf;

#[test]
fn test_validate_self_signed_assertion() {
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("config")
        .join("TST")
        .join("hyperdrive-2fa-np-privatekey_export.pfx");

    let password = seahorse::config::decode_certkey("UGFzc3dvcmQx").unwrap();
    let bundle = seahorse::crypto::load_pfx(&pfx_path, &password).unwrap();

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
