use std::path::PathBuf;

fn test_pfx_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx")
}

const TEST_PFX_PASSWORD: &str = "testpassword";

#[test]
fn test_load_pfx() {
    let cert_bundle = seahorse::crypto::load_pfx(&test_pfx_path(), TEST_PFX_PASSWORD).unwrap();

    assert!(cert_bundle.private_key.is_some());
    assert!(cert_bundle.certificate.is_some());
}

#[test]
fn test_sign_and_verify() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), TEST_PFX_PASSWORD).unwrap();

    let data = b"test data to sign";
    let signature =
        seahorse::crypto::sign_sha256(bundle.private_key.as_ref().unwrap(), data).unwrap();

    assert!(!signature.is_empty());

    let valid =
        seahorse::crypto::verify_sha256(bundle.certificate.as_ref().unwrap(), data, &signature)
            .unwrap();
    assert!(valid);
}

#[test]
fn test_cert_to_base64_der() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), TEST_PFX_PASSWORD).unwrap();

    let b64 = seahorse::crypto::cert_to_base64_der(bundle.certificate.as_ref().unwrap()).unwrap();
    assert!(!b64.is_empty());
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).unwrap();
}
