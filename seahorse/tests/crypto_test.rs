use std::path::PathBuf;

#[test]
fn test_load_pfx() {
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("config")
        .join("TST")
        .join("hyperdrive-2fa-np-privatekey_export.pfx");

    let password = seahorse::config::decode_certkey("UGFzc3dvcmQx").unwrap();
    let cert_bundle = seahorse::crypto::load_pfx(&pfx_path, &password).unwrap();

    assert!(cert_bundle.private_key.is_some());
    assert!(cert_bundle.certificate.is_some());
}

#[test]
fn test_sign_and_verify() {
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("config")
        .join("TST")
        .join("hyperdrive-2fa-np-privatekey_export.pfx");

    let password = seahorse::config::decode_certkey("UGFzc3dvcmQx").unwrap();
    let bundle = seahorse::crypto::load_pfx(&pfx_path, &password).unwrap();

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
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("config")
        .join("TST")
        .join("hyperdrive-2fa-np-privatekey_export.pfx");

    let password = seahorse::config::decode_certkey("UGFzc3dvcmQx").unwrap();
    let bundle = seahorse::crypto::load_pfx(&pfx_path, &password).unwrap();

    let b64 = seahorse::crypto::cert_to_base64_der(bundle.certificate.as_ref().unwrap()).unwrap();
    assert!(!b64.is_empty());
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).unwrap();
}
