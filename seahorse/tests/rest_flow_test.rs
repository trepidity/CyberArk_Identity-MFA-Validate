#[test]
fn test_start_auth_request_body() {
    let body = seahorse::auth::rest_flow::build_start_auth_body("jsmith");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["User"], "jsmith");
    assert_eq!(parsed["Version"], "1.0");
}

#[test]
fn test_advance_auth_request_body() {
    let body = seahorse::auth::rest_flow::build_advance_auth_body(
        "session-123", "mech-456", "123456",
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["SessionId"], "session-123");
    assert_eq!(parsed["MechanismId"], "mech-456");
    assert_eq!(parsed["Action"], "Answer");
    assert_eq!(parsed["Answer"], "123456");
}

#[test]
fn test_parse_start_auth_response() {
    let json = r#"{
        "success": true,
        "Result": {
            "SessionId": "sess-abc",
            "Challenges": [{
                "Mechanisms": [{
                    "MechanismId": "mech-xyz",
                    "Name": "OATH OTP",
                    "PromptSelectMech": "Enter OATH OTP code"
                }]
            }]
        }
    }"#;
    let result = seahorse::auth::rest_flow::parse_start_auth_response(json).unwrap();
    assert_eq!(result.session_id, "sess-abc");
    assert_eq!(result.mechanisms.len(), 1);
    assert_eq!(result.mechanisms[0].mechanism_id, "mech-xyz");
}

#[test]
fn test_parse_advance_auth_success() {
    let json = r#"{
        "success": true,
        "Result": {
            "Summary": "LoginSuccess",
            "Auth": "bearer-token-here"
        }
    }"#;
    let result = seahorse::auth::rest_flow::parse_advance_auth_response(json).unwrap();
    assert!(result.success);
    assert_eq!(result.summary, "LoginSuccess");
    assert_eq!(result.token.as_deref(), Some("bearer-token-here"));
}

#[test]
fn test_parse_advance_auth_otp_challenge() {
    let json = r#"{
        "success": true,
        "Result": {
            "Summary": "OobPending"
        }
    }"#;
    let result = seahorse::auth::rest_flow::parse_advance_auth_response(json).unwrap();
    assert!(result.success);
    assert_eq!(result.summary, "OobPending");
    assert!(result.token.is_none());
}

#[test]
fn test_build_start_auth_url() {
    let url = seahorse::auth::rest_flow::build_start_auth_url("aad4047.my.idaptive.app");
    assert_eq!(url, "https://aad4047.my.idaptive.app/Security/StartAuthentication");
}

#[test]
fn test_build_advance_auth_url() {
    let url = seahorse::auth::rest_flow::build_advance_auth_url("aad4047.my.idaptive.app");
    assert_eq!(url, "https://aad4047.my.idaptive.app/Security/AdvanceAuthentication");
}
