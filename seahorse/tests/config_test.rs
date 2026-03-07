use std::path::PathBuf;

#[test]
fn test_load_config_tst() {
    let config_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("config")
        .join("TST");

    let config = seahorse::config::load_config(&config_dir).unwrap();

    assert_eq!(config.url, "aad4047.my.idaptive.app");
    assert_eq!(config.timeout, 60);
    assert_eq!(
        config.certificate,
        "hyperdrive-2fa-np-privatekey_export.pfx"
    );
    assert_eq!(config.appkey, "580e07dc-97b6-45b7-85c0-77fae7b141b0");
    assert_eq!(config.certkey, "UGFzc3dvcmQx");
    assert_eq!(config.check_user, false);
    assert_eq!(config.use_bypass, true);
    assert_eq!(config.browser, "chrome");
}

#[test]
fn test_decode_certkey() {
    let decoded = seahorse::config::decode_certkey("UGFzc3dvcmQx").unwrap();
    assert_eq!(decoded, "Password1");
}

#[test]
fn test_decode_certkey_prod() {
    let decoded = seahorse::config::decode_certkey("Y0FyazJlUGNzMjAyMw==").unwrap();
    assert_eq!(decoded, "cArk2ePcs2023");
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
