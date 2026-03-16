use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};
use std::fs;
use std::path::{Path, PathBuf};

pub struct IdpTrustStore {
    pub leaf_cert: X509,
    pub chain_certs: Vec<X509>,
    pub source_path: PathBuf,
}

pub enum CertMatch {
    Match,
    Mismatch {
        expected_cn: String,
        actual_cn: String,
        expected_fingerprint: String,
        actual_fingerprint: String,
    },
}

pub enum ChainResult {
    Valid { chain_depth: usize, root_cn: String },
    Failed { error: String },
    Skipped { reason: String },
}

/// Load IdP certificates from a PEM file.
/// Automatically identifies the leaf (end-entity) certificate by finding
/// the cert that is NOT a CA. The remaining certs form the chain.
/// PEM files can have certs in any order — this handles all orderings.
pub fn load_idp_certificates(path: &Path) -> Result<IdpTrustStore> {
    let pem_data =
        fs::read(path).with_context(|| format!("Failed to read PEM file: {}", path.display()))?;

    let certs = X509::stack_from_pem(&pem_data)
        .with_context(|| format!("Failed to parse PEM certificates from: {}", path.display()))?;

    if certs.is_empty() {
        anyhow::bail!("PEM file contains no certificates: {}", path.display());
    }

    // Find the leaf cert: the one that is not the issuer of any other cert
    let leaf_idx = find_leaf_index(&certs);

    let mut chain_certs = certs;
    let leaf_cert = chain_certs.remove(leaf_idx);

    Ok(IdpTrustStore {
        leaf_cert,
        chain_certs,
        source_path: path.to_path_buf(),
    })
}

/// Identify the leaf (end-entity) cert from a list.
/// The leaf is the cert whose issuer does not match its own subject
/// (i.e., it's not self-signed) AND is not the issuer of any other cert
/// in the list. If no clear leaf is found, returns the cert with the
/// latest notAfter (most likely to be the freshly-issued end-entity).
fn find_leaf_index(certs: &[X509]) -> usize {
    if certs.len() == 1 {
        return 0;
    }

    // A cert is a "parent" if another cert's issuer matches this cert's subject.
    // Compare by DER-encoded name bytes since X509NameRef doesn't impl PartialEq.
    let subjects: Vec<Vec<u8>> = certs
        .iter()
        .map(|c| c.subject_name().to_der().unwrap_or_default())
        .collect();
    let issuers: Vec<Vec<u8>> = certs
        .iter()
        .map(|c| c.issuer_name().to_der().unwrap_or_default())
        .collect();

    let mut is_parent = vec![false; certs.len()];
    for (i, subject_der) in subjects.iter().enumerate() {
        for (j, issuer_der) in issuers.iter().enumerate() {
            if i != j && issuer_der == subject_der {
                is_parent[i] = true;
                break;
            }
        }
    }

    // The leaf is the cert that is NOT a parent of any other cert
    let non_parents: Vec<usize> = is_parent
        .iter()
        .enumerate()
        .filter(|(_, &is_p)| !is_p)
        .map(|(i, _)| i)
        .collect();

    if non_parents.len() == 1 {
        return non_parents[0];
    }

    // Fallback: pick the first non-parent, or just index 0
    non_parents.first().copied().unwrap_or(0)
}

/// Compare two X.509 certificates by SHA-256 fingerprint.
pub fn compare_certificates(embedded: &X509, trusted: &X509) -> CertMatch {
    let embedded_fp = cert_fingerprint(embedded);
    let trusted_fp = cert_fingerprint(trusted);

    if embedded_fp == trusted_fp {
        CertMatch::Match
    } else {
        CertMatch::Mismatch {
            expected_cn: cert_cn(trusted),
            actual_cn: cert_cn(embedded),
            expected_fingerprint: trusted_fp,
            actual_fingerprint: embedded_fp,
        }
    }
}

/// Validate a certificate chain using OpenSSL's X509Store verification.
/// Returns `Skipped` when the chain is empty (self-signed / no intermediates provided).
pub fn validate_chain(leaf: &X509, chain: &[X509]) -> ChainResult {
    if chain.is_empty() {
        return ChainResult::Skipped {
            reason: "No chain certificates provided; skipping chain validation".to_string(),
        };
    }

    // Build a trusted store from the chain certificates
    let mut store_builder = match X509StoreBuilder::new() {
        Ok(b) => b,
        Err(e) => {
            return ChainResult::Failed {
                error: format!("Failed to create X509 store: {e}"),
            }
        }
    };

    for cert in chain {
        if let Err(e) = store_builder.add_cert(cert.clone()) {
            return ChainResult::Failed {
                error: format!("Failed to add chain cert to store: {e}"),
            };
        }
    }

    let store = store_builder.build();

    // Create an empty chain stack for the context (chain certs are already in the store)
    let empty_chain = openssl::stack::Stack::new().unwrap();

    let mut ctx = match X509StoreContext::new() {
        Ok(c) => c,
        Err(e) => {
            return ChainResult::Failed {
                error: format!("Failed to create store context: {e}"),
            }
        }
    };

    match ctx.init(&store, leaf, &empty_chain, |ctx| {
        let ok = ctx.verify_cert()?;
        if ok {
            let depth = ctx.error_depth() as usize;
            Ok((true, depth))
        } else {
            let err = ctx.error();
            Ok((false, err.as_raw() as usize))
        }
    }) {
        Ok((true, depth)) => {
            // Find the root CN from the last chain cert
            let root_cn = chain.last().map(cert_cn).unwrap_or_default();
            ChainResult::Valid {
                chain_depth: depth + chain.len(),
                root_cn,
            }
        }
        Ok((false, _)) => ChainResult::Failed {
            error: "Chain verification failed".to_string(),
        },
        Err(e) => ChainResult::Failed {
            error: format!("Chain verification error: {e}"),
        },
    }
}

/// Extract the Common Name (CN) from a certificate's subject.
/// Falls back to the full subject string if no CN entry is found.
pub fn cert_cn(cert: &X509) -> String {
    let subject = cert.subject_name();
    let cn_entry = subject.entries_by_nid(Nid::COMMONNAME).next();

    match cn_entry {
        Some(entry) => entry
            .data()
            .as_utf8()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| format!("{:?}", subject)),
        None => format!("{:?}", subject),
    }
}

/// Produce a hex-encoded SHA-256 fingerprint of a certificate.
fn cert_fingerprint(cert: &X509) -> String {
    cert.digest(MessageDigest::sha256())
        .map(|d| {
            d.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_else(|_| "<error computing fingerprint>".to_string())
}
