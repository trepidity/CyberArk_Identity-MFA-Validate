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
