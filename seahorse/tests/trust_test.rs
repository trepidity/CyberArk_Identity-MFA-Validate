use std::path::PathBuf;

fn test_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-idp.pem")
}

#[test]
fn test_load_idp_certificates_single_cert() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    assert!(store.chain_certs.is_empty());
    let subject = store.leaf_cert.subject_name();
    assert!(subject.entries().count() > 0);
}

#[test]
fn test_compare_certificates_match() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    let result = seahorse::saml::trust::compare_certificates(&store.leaf_cert, &store.leaf_cert);
    assert!(matches!(result, seahorse::saml::trust::CertMatch::Match));
}

#[test]
fn test_validate_chain_no_chain_certs() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    let result = seahorse::saml::trust::validate_chain(&store.leaf_cert, &store.chain_certs);
    assert!(matches!(
        result,
        seahorse::saml::trust::ChainResult::Skipped { .. }
    ));
}

#[test]
fn test_load_nonexistent_pem() {
    let result =
        seahorse::saml::trust::load_idp_certificates(std::path::Path::new("/nonexistent/path.pem"));
    assert!(result.is_err());
}
