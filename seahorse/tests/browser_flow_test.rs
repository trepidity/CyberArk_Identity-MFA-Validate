#[test]
fn test_build_login_url() {
    let url = seahorse::auth::browser_flow::build_login_url(
        "aad4047.my.idaptive.app",
        "jsmith",
        "965505ee-d25f-4d03-98a4-f30ce930b82c",
    );
    assert_eq!(
        url,
        "https://aad4047.my.idaptive.app/run?username=jsmith&appkey=965505ee-d25f-4d03-98a4-f30ce930b82c&failureRedirectUrl=/failure&nozso=True&submitUsername=True"
    );
}

#[test]
fn test_build_authn_request_unsigned() {
    let xml = seahorse::auth::browser_flow::build_authn_request(
        "http://localhost:9876/acs",
        "epic://epicenvironment",
        "https://aad4047.my.idaptive.app",
    ).unwrap();

    assert!(xml.contains("saml2p:AuthnRequest"));
    assert!(xml.contains("http://localhost:9876/acs"));
    assert!(xml.contains("epic://epicenvironment"));
}

#[test]
fn test_encode_authn_request() {
    let xml = "<saml2p:AuthnRequest>test</saml2p:AuthnRequest>";
    let encoded = seahorse::auth::browser_flow::encode_authn_request(xml);
    assert!(!encoded.is_empty());
    // Should be valid base64
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), xml);
}
