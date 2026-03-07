use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fs;
use std::path::Path;

pub struct CertBundle {
    pub private_key: Option<PKey<Private>>,
    pub certificate: Option<X509>,
}

pub fn load_pfx(path: &Path, password: &str) -> Result<CertBundle> {
    let pfx_data =
        fs::read(path).with_context(|| format!("Failed to read PFX file: {}", path.display()))?;

    let pkcs12 = Pkcs12::from_der(&pfx_data).context("Failed to parse PFX/PKCS12 data")?;

    let parsed = pkcs12
        .parse2(password)
        .context("Failed to decrypt PFX (wrong password?)")?;

    Ok(CertBundle {
        private_key: parsed.pkey,
        certificate: parsed.cert,
    })
}

pub fn sign_sha256(private_key: &PKey<Private>, data: &[u8]) -> Result<Vec<u8>> {
    let mut signer =
        Signer::new(MessageDigest::sha256(), private_key).context("Failed to create signer")?;
    signer.update(data).context("Failed to update signer")?;
    signer
        .sign_to_vec()
        .context("Failed to produce RSA-SHA256 signature")
}

pub fn verify_sha256(cert: &X509, data: &[u8], signature: &[u8]) -> Result<bool> {
    let pub_key = cert
        .public_key()
        .context("Failed to extract public key from certificate")?;
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &pub_key).context("Failed to create verifier")?;
    verifier.update(data).context("Failed to update verifier")?;
    verifier
        .verify(signature)
        .context("Failed to verify RSA-SHA256 signature")
}

pub fn cert_to_base64_der(cert: &X509) -> Result<String> {
    let der = cert
        .to_der()
        .context("Failed to encode certificate as DER")?;
    Ok(STANDARD.encode(&der))
}
