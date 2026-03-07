use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct StartAuthRequest {
    #[serde(rename = "User")]
    user: String,
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Debug, Serialize)]
struct AdvanceAuthRequest {
    #[serde(rename = "SessionId")]
    session_id: String,
    #[serde(rename = "MechanismId")]
    mechanism_id: String,
    #[serde(rename = "Action")]
    action: String,
    #[serde(rename = "Answer")]
    answer: String,
}

#[derive(Debug, Clone)]
pub struct Mechanism {
    pub mechanism_id: String,
    pub name: String,
    pub prompt: String,
}

#[derive(Debug)]
pub struct StartAuthResult {
    pub session_id: String,
    pub mechanisms: Vec<Mechanism>,
}

#[derive(Debug)]
pub struct AdvanceAuthResult {
    pub success: bool,
    pub summary: String,
    pub token: Option<String>,
}

pub fn build_start_auth_url(tenant: &str) -> String {
    format!("https://{}/Security/StartAuthentication", tenant)
}

pub fn build_advance_auth_url(tenant: &str) -> String {
    format!("https://{}/Security/AdvanceAuthentication", tenant)
}

pub fn build_start_auth_body(username: &str) -> String {
    serde_json::to_string(&StartAuthRequest {
        user: username.to_string(),
        version: "1.0".to_string(),
    })
    .unwrap()
}

pub fn build_advance_auth_body(session_id: &str, mechanism_id: &str, otp: &str) -> String {
    serde_json::to_string(&AdvanceAuthRequest {
        session_id: session_id.to_string(),
        mechanism_id: mechanism_id.to_string(),
        action: "Answer".to_string(),
        answer: otp.to_string(),
    })
    .unwrap()
}

pub fn parse_start_auth_response(json: &str) -> Result<StartAuthResult> {
    let v: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse StartAuthentication response")?;
    let result = &v["Result"];
    let session_id = result["SessionId"]
        .as_str()
        .context("Missing SessionId in response")?
        .to_string();

    let mut mechanisms = Vec::new();
    if let Some(challenges) = result["Challenges"].as_array() {
        for challenge in challenges {
            if let Some(mechs) = challenge["Mechanisms"].as_array() {
                for mech in mechs {
                    mechanisms.push(Mechanism {
                        mechanism_id: mech["MechanismId"].as_str().unwrap_or("").to_string(),
                        name: mech["Name"].as_str().unwrap_or("").to_string(),
                        prompt: mech["PromptSelectMech"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }
    }

    Ok(StartAuthResult {
        session_id,
        mechanisms,
    })
}

pub fn parse_advance_auth_response(json: &str) -> Result<AdvanceAuthResult> {
    let v: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse AdvanceAuthentication response")?;
    let success = v["success"].as_bool().unwrap_or(false);
    let result = &v["Result"];
    let summary = result["Summary"]
        .as_str()
        .unwrap_or("Unknown")
        .to_string();
    let token = result["Auth"].as_str().map(|s| s.to_string());

    Ok(AdvanceAuthResult {
        success,
        summary,
        token,
    })
}

pub async fn start_authentication(
    client: &reqwest::Client,
    tenant: &str,
    username: &str,
) -> Result<StartAuthResult> {
    let url = build_start_auth_url(tenant);
    let body = build_start_auth_body(username);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("Failed to send StartAuthentication request")?;
    let text = resp
        .text()
        .await
        .context("Failed to read StartAuthentication response")?;
    parse_start_auth_response(&text)
}

pub async fn advance_authentication(
    client: &reqwest::Client,
    tenant: &str,
    session_id: &str,
    mechanism_id: &str,
    otp: &str,
) -> Result<AdvanceAuthResult> {
    let url = build_advance_auth_url(tenant);
    let body = build_advance_auth_body(session_id, mechanism_id, otp);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("Failed to send AdvanceAuthentication request")?;
    let text = resp
        .text()
        .await
        .context("Failed to read AdvanceAuthentication response")?;
    parse_advance_auth_response(&text)
}
