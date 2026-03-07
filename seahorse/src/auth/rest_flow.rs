use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{debug, info};

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

#[derive(Debug, Clone)]
pub struct Challenge {
    pub mechanisms: Vec<Mechanism>,
}

#[derive(Debug)]
pub struct StartAuthResult {
    pub session_id: String,
    pub tenant: String,
    pub challenges: Vec<Challenge>,
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

pub fn build_advance_auth_body(
    session_id: &str,
    mechanism_id: &str,
    action: &str,
    answer: &str,
) -> String {
    serde_json::to_string(&AdvanceAuthRequest {
        session_id: session_id.to_string(),
        mechanism_id: mechanism_id.to_string(),
        action: action.to_string(),
        answer: answer.to_string(),
    })
    .unwrap()
}

pub fn parse_start_auth_response(json: &str, tenant: &str) -> Result<StartAuthResult> {
    let v: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse StartAuthentication response")?;
    let result = &v["Result"];

    // Check for PodFqdn redirect
    if let Some(pod_fqdn) = result["PodFqdn"].as_str() {
        info!("PodFqdn redirect detected: {} -> {}", tenant, pod_fqdn);
        return Ok(StartAuthResult {
            session_id: String::new(),
            tenant: pod_fqdn.to_string(),
            challenges: Vec::new(),
        });
    }

    let session_id = result["SessionId"]
        .as_str()
        .context("Missing SessionId in response")?
        .to_string();

    let mut challenges = Vec::new();
    if let Some(challenge_arr) = result["Challenges"].as_array() {
        for challenge in challenge_arr {
            let mut mechanisms = Vec::new();
            if let Some(mechs) = challenge["Mechanisms"].as_array() {
                for mech in mechs {
                    mechanisms.push(Mechanism {
                        mechanism_id: mech["MechanismId"].as_str().unwrap_or("").to_string(),
                        name: mech["Name"].as_str().unwrap_or("").to_string(),
                        prompt: mech["PromptSelectMech"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
            challenges.push(Challenge { mechanisms });
        }
    }

    Ok(StartAuthResult {
        session_id,
        tenant: tenant.to_string(),
        challenges,
    })
}

pub fn parse_advance_auth_response(json: &str) -> Result<AdvanceAuthResult> {
    let v: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse AdvanceAuthentication response")?;
    let success = v["success"].as_bool().unwrap_or(false);
    let result = &v["Result"];
    let summary = result["Summary"].as_str().unwrap_or("Unknown").to_string();
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
    let mut current_tenant = tenant.to_string();

    // Loop to handle PodFqdn redirects (max 3 hops)
    for attempt in 0..3 {
        let url = build_start_auth_url(&current_tenant);
        let body = build_start_auth_body(username);
        info!("[HTTP] POST {} (attempt {})", url, attempt + 1);
        info!("[HTTP] Request body: {}", body);
        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("Failed to send StartAuthentication request")?;
        let status = resp.status();
        let headers = format!("{:?}", resp.headers());
        info!("[HTTP] Response status: {}", status);
        debug!("[HTTP] Response headers: {}", headers);
        let text = resp
            .text()
            .await
            .context("Failed to read StartAuthentication response")?;
        info!("[HTTP] Response body: {}", text);

        let result = parse_start_auth_response(&text, &current_tenant)
            .with_context(|| format!("Raw response: {}", &text[..text.len().min(500)]))?;

        // If we got a PodFqdn redirect (empty session_id), retry with new tenant
        if result.session_id.is_empty() && result.tenant != current_tenant {
            info!("Redirecting to pod: {}", result.tenant);
            current_tenant = result.tenant;
            continue;
        }

        return Ok(result);
    }

    anyhow::bail!("Too many PodFqdn redirects")
}

pub async fn advance_authentication(
    client: &reqwest::Client,
    tenant: &str,
    session_id: &str,
    mechanism_id: &str,
    action: &str,
    answer: &str,
) -> Result<AdvanceAuthResult> {
    let url = build_advance_auth_url(tenant);
    let body = build_advance_auth_body(session_id, mechanism_id, action, answer);
    info!("[HTTP] POST {}", url);
    info!("[HTTP] Request body: {}", body);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("Failed to send AdvanceAuthentication request")?;
    let status = resp.status();
    let headers = format!("{:?}", resp.headers());
    info!("[HTTP] Response status: {}", status);
    debug!("[HTTP] Response headers: {}", headers);
    let text = resp
        .text()
        .await
        .context("Failed to read AdvanceAuthentication response")?;
    info!("[HTTP] Response body: {}", text);
    parse_advance_auth_response(&text)
        .with_context(|| format!("Raw response: {}", &text[..text.len().min(500)]))
}
