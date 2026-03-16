use std::path::PathBuf;

#[test]
fn test_load_config_fixture() {
    let config_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let config = seahorse::config::load_config(&config_dir).unwrap();

    assert_eq!(config.url, "test-tenant.my.idaptive.app");
    assert_eq!(config.timeout, 60);
    assert_eq!(config.certificate, "test-cert.pfx");
    assert_eq!(config.appkey, "00000000-0000-0000-0000-000000000000");
    assert_eq!(config.certkey, "dGVzdHBhc3N3b3Jk");
    assert!(!config.check_user);
    assert!(config.use_bypass);
    assert_eq!(config.browser, "chrome");
}

#[test]
fn test_decode_certkey() {
    let decoded = seahorse::config::decode_certkey("dGVzdHBhc3N3b3Jk").unwrap();
    assert_eq!(decoded, "testpassword");
}

#[test]
fn test_decode_certkey_roundtrip() {
    let decoded = seahorse::config::decode_certkey("UGFzc3dvcmQx").unwrap();
    assert_eq!(decoded, "Password1");
}

#[test]
fn test_get_config_dir() {
    let base = PathBuf::from("/some/path");
    let prod = seahorse::config::get_config_dir(&base, seahorse::config::Environment::Prod);
    let tst = seahorse::config::get_config_dir(&base, seahorse::config::Environment::Tst);
    assert_eq!(prod, PathBuf::from("/some/path/config/PROD"));
    assert_eq!(tst, PathBuf::from("/some/path/config/TST"));
}

#[test]
fn test_get_pfx_path() {
    let config_dir = PathBuf::from("/some/path/config/TST");
    let pfx = seahorse::config::get_pfx_path(&config_dir, "mycert.pfx");
    assert_eq!(pfx, PathBuf::from("/some/path/config/TST/mycert.pfx"));
}

#[test]
fn test_config_without_idp_certificate() {
    let config_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config = seahorse::config::load_config(&config_dir).unwrap();
    assert!(config.idp_certificate.is_none());
}
