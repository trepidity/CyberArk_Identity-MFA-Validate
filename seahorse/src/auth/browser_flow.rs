use std::future::IntoFuture;
use anyhow::{Context, Result};
use axum::{extract::State, response::Html, routing::post, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub fn build_login_url(tenant: &str, username: &str, appkey: &str) -> String {
    format!(
        "https://{}/run?username={}&appkey={}&failureRedirectUrl=/failure&nozso=True&submitUsername=True",
        tenant, username, appkey
    )
}

pub fn build_authn_request(
    acs_url: &str,
    audience: &str,
    idp_url: &str,
) -> Result<String> {
    let id = format!("_{}", uuid::Uuid::new_v4());
    let instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let xml = format!(
        r#"<saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{instant}" AssertionConsumerServiceURL="{acs}" Destination="{destination}"><saml2:Issuer>{audience}</saml2:Issuer></saml2p:AuthnRequest>"#,
        id = id,
        instant = instant,
        acs = acs_url,
        destination = idp_url,
        audience = audience,
    );

    Ok(xml)
}

pub fn encode_authn_request(xml: &str) -> String {
    STANDARD.encode(xml.as_bytes())
}

struct AcsState {
    response_tx: Option<oneshot::Sender<String>>,
}

pub async fn start_acs_listener(
    port: u16,
    port_tx: oneshot::Sender<u16>,
) -> Result<String> {
    let (response_tx, response_rx) = oneshot::channel::<String>();

    let state = Arc::new(tokio::sync::Mutex::new(AcsState {
        response_tx: Some(response_tx),
    }));

    let app = Router::new()
        .route("/acs", post(handle_acs_post))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .context("Failed to bind ACS listener")?;

    let actual_port = listener.local_addr()?.port();
    let _ = port_tx.send(actual_port);

    let server = axum::serve(listener, app);

    tokio::select! {
        result = response_rx => {
            let saml_response: String = result.context("ACS listener channel closed unexpectedly")?;
            Ok(saml_response)
        }
        result = server.into_future() => {
            let _: () = result.context("ACS HTTP server error")?;
            anyhow::bail!("ACS server stopped without receiving SAMLResponse")
        }
    }
}

async fn handle_acs_post(
    State(state): State<Arc<tokio::sync::Mutex<AcsState>>>,
    body: String,
) -> Html<String> {
    let mut state = state.lock().await;
    if let Some(tx) = state.response_tx.take() {
        let _ = tx.send(body);
    }
    Html("<html><body><h1>Authentication received. You may close this tab.</h1></body></html>".to_string())
}

pub fn open_browser(url: &str) -> Result<()> {
    open::that(url).context("Failed to open browser")
}
