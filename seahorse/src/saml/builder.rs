use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::X509;
use uuid::Uuid;

pub struct AssertionParams {
    pub issuer: String,
    pub audience: String,
    pub username: String,
    pub validity_seconds: i64,
}

pub fn build_unsigned_assertion(params: &AssertionParams) -> String {
    let id = format!("_{}", Uuid::new_v4());
    let now = Utc::now();
    let not_after = now + chrono::Duration::seconds(params.validity_seconds);
    let instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_before_str = instant.clone();
    let not_after_str = not_after.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    format!(
        r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{instant}" Version="2.0"><saml2:Issuer>{issuer}</saml2:Issuer><saml2:Subject><saml2:NameID>{username}</saml2:NameID></saml2:Subject><saml2:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}"><saml2:AudienceRestriction><saml2:Audience>{audience}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="{instant}"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>"#,
        id = id,
        instant = instant,
        issuer = params.issuer,
        username = params.username,
        not_before = not_before_str,
        not_after = not_after_str,
        audience = params.audience,
    )
}

pub fn build_signed_assertion(
    params: &AssertionParams,
    private_key: &PKey<Private>,
    cert: &X509,
) -> Result<String> {
    let id = format!("_{}", Uuid::new_v4());
    let now = Utc::now();
    let not_after = now + chrono::Duration::seconds(params.validity_seconds);
    let instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_before_str = instant.clone();
    let not_after_str = not_after.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let assertion_body = format!(
        r#"<saml2:Subject><saml2:NameID>{username}</saml2:NameID></saml2:Subject><saml2:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}"><saml2:AudienceRestriction><saml2:Audience>{audience}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="{instant}"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>"#,
        username = params.username,
        not_before = not_before_str,
        not_after = not_after_str,
        audience = params.audience,
        instant = instant,
    );

    let assertion_for_digest = format!(
        r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{instant}" Version="2.0"><saml2:Issuer>{issuer}</saml2:Issuer>{body}</saml2:Assertion>"#,
        id = id,
        instant = instant,
        issuer = params.issuer,
        body = assertion_body,
    );

    let canon_body = super::c14n::canonicalize_exclusive(&assertion_for_digest, &[])
        .context("Failed to canonicalize assertion for digest")?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &canon_body)
        .context("Failed to compute SHA-256 digest")?;
    let digest_b64 = STANDARD.encode(digest);

    let uri_ref = format!("#{}", id);
    let signed_info = format!(
        r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="{uri_ref}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
        uri_ref = uri_ref,
        digest = digest_b64,
    );

    let canon_signed_info = super::c14n::canonicalize_exclusive(&signed_info, &[])
        .context("Failed to canonicalize SignedInfo")?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), private_key).context("Failed to create signer")?;
    signer
        .update(&canon_signed_info)
        .context("Failed to update signer")?;
    let signature_bytes = signer.sign_to_vec().context("Failed to sign")?;
    let signature_b64 = STANDARD.encode(&signature_bytes);

    let cert_der = cert.to_der().context("Failed to encode cert as DER")?;
    let cert_b64 = STANDARD.encode(&cert_der);

    let signature_element = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{sig_value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        signed_info = signed_info,
        sig_value = signature_b64,
        cert = cert_b64,
    );

    let signed_assertion = format!(
        r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{instant}" Version="2.0"><saml2:Issuer>{issuer}</saml2:Issuer>{signature}{body}</saml2:Assertion>"#,
        id = id,
        instant = instant,
        issuer = params.issuer,
        signature = signature_element,
        body = assertion_body,
    );

    Ok(signed_assertion)
}
