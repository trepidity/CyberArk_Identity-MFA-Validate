# SAML Validation Design Spec

**Date:** 2026-03-16
**Status:** Draft
**Scope:** Add real cryptographic SAML signature validation to Seahorse, including IDP certificate trust verification via user-provided PEM files.

## Background

Seahorse currently has a SAML assertion viewer that parses and displays SAML responses. The existing "validation" is cosmetic — `signature_valid` is set to `true` if `<SignatureValue>` and `<X509Certificate>` elements are present in the XML, with no cryptographic verification. The `verify_sha256` function in `crypto.rs` and `check_time_conditions` in `validator.rs` both exist but are dead code — never called.

The existing assertion builder (`builder.rs`) signs using raw string bytes without canonicalization. This means self-generated assertions will fail proper c14n-based validation. The builder must be updated as part of this work to produce spec-compliant signed assertions.

The tool's purpose is to validate that CyberArk Identity is correctly configured. Without real signature verification, it cannot fulfill that purpose.

## Goals

1. Replace cosmetic validation with real cryptographic SAML signature verification
2. Allow users to provide an IDP certificate (PEM file) to confirm the signing certificate matches expectations
3. Support full certificate chain validation when chain certs are provided
4. Present clear, diagnostic validation results that help troubleshoot IDP configuration issues
5. Keep validation informational (not blocking) — Seahorse is a diagnostic tool
6. Update the assertion builder to use canonicalization so self-generated assertions pass validation

## Non-Goals

- Full SAML 2.0 spec compliance (XPath transforms, document subsets, etc.)
- Acting as a security gateway / service provider policy enforcer
- Certificate revocation checking (CRL/OCSP)
- SAML response encryption support

---

## Design

### 1. Validation Pipeline

When a SAML assertion is processed (from auth flow or SAML viewer), it passes through these checks in order:

| # | Check | Description |
|---|-------|-------------|
| 1 | Structure | Are Signature, SignedInfo, SignatureValue, DigestValue, X509Certificate elements present? |
| 2 | Time Conditions | Is current time between NotBefore and NotOnOrAfter? |
| 3 | Digest Verification | Canonicalize assertion body (minus Signature element), compute digest, compare to DigestValue |
| 4 | Signature Verification | Canonicalize SignedInfo, verify signature using embedded X509Certificate's public key |
| 5 | IDP Certificate Match | If IDP PEM loaded: compare embedded cert fingerprint against leaf cert in PEM |
| 6 | Chain Validation | If PEM has chain certs: verify the IDP signing cert chains to a trusted CA |

Checks 5-6 are skipped (not failed) when no IDP PEM is configured. The summary caps at `Valid` instead of `Trusted` in that case.

**Algorithm dispatch**: Checks 3 and 4 parse the `<DigestMethod Algorithm="...">` and `<SignatureMethod Algorithm="...">` URIs to determine which algorithms to use. Supported algorithms:

| URI | Algorithm | OpenSSL |
|-----|-----------|---------|
| `http://www.w3.org/2001/04/xmlenc#sha256` | SHA-256 digest | `MessageDigest::sha256()` |
| `http://www.w3.org/2000/09/xmldsig#sha1` | SHA-1 digest | `MessageDigest::sha1()` |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` | RSA-SHA256 signature | `MessageDigest::sha256()` |
| `http://www.w3.org/2000/09/xmldsig#rsa-sha1` | RSA-SHA1 signature | `MessageDigest::sha1()` |

Unrecognized algorithms produce a clear diagnostic: `"Unsupported digest algorithm: http://www.w3.org/2001/04/xmlenc#sha512"` and the corresponding check fails (not skipped).

**Reference URI handling**: The `<Reference URI="...">` attribute is parsed to determine the digest scope:
- `URI="#id123"` — digest covers the element with matching ID attribute (standard SAML case)
- `URI=""` — digest covers the entire document; produce diagnostic `"Empty Reference URI — document-level digest not supported"` and fail the digest check

### 2. Data Model

```rust
pub struct ValidationReport {
    pub summary: ValidationSummary,
    pub checks: Vec<ValidationCheck>,
    pub idp_cert_loaded: bool,
}

pub struct ValidationCheck {
    pub name: String,              // e.g. "Digest Verification"
    pub passed: bool,
    pub detail: String,            // e.g. "SHA-256 digest matches"
    pub diagnostic: Option<String>, // On failure: "Expected abc..., got def..."
}

pub enum ValidationSummary {
    Trusted,   // All checks pass including IDP cert match + chain
    Valid,     // Signature cryptographically valid, no IDP cert to compare
    Partial,   // Some checks pass, some fail
    Failed,    // Signature verification failed
    Unsigned,  // No signature present
}
```

Summary semantics:
- **Trusted**: "Signature verified against configured IDP certificate"
- **Valid**: "Signature cryptographically valid (no IDP certificate configured for trust verification)"
- **Partial**: "Validation incomplete — see details"
- **Failed**: "Signature verification FAILED"
- **Unsigned**: "No signature present in assertion"

### 3. Exclusive XML Canonicalization (exc-c14n)

SAML signatures use two transforms:

1. **Enveloped Signature Transform** — remove the `<Signature>` element from the assertion before hashing
2. **Exclusive Canonicalization** — normalize XML to a canonical byte representation

Implementation in a new module `src/saml/c14n.rs`:

```rust
/// Exclusive XML Canonicalization (without comments) per W3C spec.
/// `inclusive_ns_prefixes` are prefixes from <InclusiveNamespaces PrefixList="...">,
/// which are treated as visibly utilized even if not directly referenced.
pub fn canonicalize_exclusive(xml: &str, inclusive_ns_prefixes: &[&str]) -> Result<Vec<u8>>

/// Enveloped signature transform: removes the <Signature> element (and all
/// its children) from the XML. Handles both prefixed (<ds:Signature>) and
/// unprefixed (<Signature>) variants. Removes only the first occurrence.
/// Preserves exact byte content of everything outside the Signature element.
pub fn remove_signature_element(xml: &str) -> Result<String>

/// Extract the <SignedInfo> element from within <Signature>, re-emitting any
/// namespace declarations that were inherited from ancestor elements (e.g.,
/// xmlns:ds on <Signature>) so the extracted fragment is self-contained
/// for canonicalization.
pub fn extract_signed_info(assertion_xml: &str) -> Result<String>
```

**`remove_signature_element` specifics**: Uses `quick-xml` event-based parsing to find the first element whose local name is `Signature` (matching both `<Signature>` and `<ds:Signature>` or any other prefix). Tracks nesting depth to find the matching close tag. Emits all events outside the Signature element verbatim. This avoids regex pitfalls and correctly handles nested elements.

**`extract_signed_info` specifics**: Parses the full assertion, tracking namespace declarations on ancestor elements (`<Assertion>`, `<Signature>`). When the `<SignedInfo>` element is found, any namespace prefixes that are visibly utilized within `<SignedInfo>` but declared on ancestor elements are added as explicit declarations on the extracted `<SignedInfo>` element. This ensures the fragment is self-contained for canonicalization. For example, if `xmlns:ds` is declared on `<Signature>` but inherited by `<SignedInfo>`, it is explicitly added to the output: `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`.

**`inclusive_ns_prefixes` usage**: For each canonicalization call, the caller parses the relevant `<InclusiveNamespaces PrefixList="...">` child element:
- For digest verification: from `<Reference><Transforms><Transform Algorithm="...exc-c14n#"><InclusiveNamespaces PrefixList="...">`
- For signature verification: from `<CanonicalizationMethod><InclusiveNamespaces PrefixList="...">`
- Default to `&[]` when no `<InclusiveNamespaces>` element is present (the common SAML case)

exc-c14n rules implemented (per W3C Exclusive XML Canonicalization spec):
- Sort attributes by namespace URI, then local name
- Only emit namespaces visibly utilized by the element or its attributes (plus any in the inclusive prefix list)
- Expand empty elements: `<Foo/>` to `<Foo></Foo>`
- Preserve inter-element whitespace, normalize attribute whitespace
- Explicitly declare default namespace (no implicit inheritance)
- No XML declaration header
- UTF-8 encoding with specific entity escaping (`&`, `<`, `>`, `"`, `&#xD;`, `&#xA;`, `&#x9;` in attributes)

NOT implemented (not needed for SAML):
- XPath transforms
- Comments (SAML uses without-comments variant)
- Document subsets beyond single elements

The verification flow:
1. `body_xml = remove_signature_element(assertion_xml)`
2. Parse `<InclusiveNamespaces>` from the Reference's exc-c14n Transform (if present)
3. `canon_body = canonicalize_exclusive(body_xml, &inclusive_prefixes)`
4. `digest = hash(canon_body)` using algorithm from `<DigestMethod>`
5. Compare `digest` to `<DigestValue>` in XML
6. `signed_info_xml = extract_signed_info(assertion_xml)` (with inherited namespaces)
7. Parse `<InclusiveNamespaces>` from `<CanonicalizationMethod>` (if present)
8. `canon_signed_info = canonicalize_exclusive(signed_info_xml, &inclusive_prefixes)`
9. Verify signature over `canon_signed_info` against `SignatureValue` using public key and algorithm from `<SignatureMethod>`

Parsing uses `quick-xml` (existing dependency). Internal `NamespaceContext` struct tracks in-scope namespaces and determines visible utilization.

### 4. PEM Loading & Certificate Trust

New module `src/saml/trust.rs`:

```rust
pub struct IdpTrustStore {
    pub leaf_cert: X509,         // First cert in PEM — IDP signing cert
    pub chain_certs: Vec<X509>,  // Remaining certs — intermediates/root
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
    Skipped { reason: String },  // e.g., no chain certs in PEM
}

pub fn load_idp_certificates(path: &Path) -> Result<IdpTrustStore>
pub fn compare_certificates(embedded: &X509, trusted: &X509) -> CertMatch
pub fn validate_chain(leaf: &X509, chain: &[X509]) -> ChainResult
```

**Certificate matching** (check 5): compute SHA-256 fingerprints of the embedded cert (from SAML assertion) and the PEM leaf cert, compare. On mismatch, diagnostic shows: `"Assertion signed by CN=x (fingerprint: abc...) but expected CN=y (fingerprint: def...)"`.

**Chain validation** (check 6): build an OpenSSL `X509Store` from the PEM chain certs, verify the leaf cert against the store. OpenSSL handles chain-walking, expiry, and basic constraints. On failure, diagnostic shows which link failed and why.

**Single-cert PEM (no chain)**: When the PEM contains only one certificate (the IDP signing cert), `chain_certs` is empty. Chain validation (check 6) returns `ChainResult::Skipped { reason: "PEM contains only the leaf certificate; no chain certs to validate" }`. The summary can still reach `Trusted` if checks 1-5 all pass — the fingerprint match on the leaf cert is sufficient trust when the user explicitly provided that cert. The `Trusted` summary message in this case becomes: "Signature verified against configured IDP certificate (no chain validated)".

**PEM format**: standard concatenated PEM with leaf cert first, then intermediates, then optionally root. Example: `hyperdrive-2fa-np_bswhealth_org.pem` with leaf + intermediate — confirmed working.

### 5. Configuration

New optional field in `config.json`:

```json
{
  "tenant": "...",
  "appkey": "...",
  "certificate": "cert.pfx",
  "certkey": "...",
  "idp_certificate": "idp.pem"
}
```

The `Config` struct in `src/config.rs` uses `#[derive(Deserialize)]`. The new field must be `Option<String>` with `#[serde(default)]` to avoid breaking existing config files that lack this key:

```rust
#[serde(default)]
pub idp_certificate: Option<String>,
```

When `idp_certificate` is set, Seahorse loads the PEM from the config directory at startup. If the file is missing or unparseable, a warning is logged but the app continues — checks 5 and 6 are skipped.

### 6. Builder Update

The existing `build_signed_assertion` in `src/saml/builder.rs` computes digest and signature over raw string bytes without canonicalization. This must be updated to use c14n during building.

**Important distinction**: The builder calls `canonicalize_exclusive` directly on the strings it constructs. It does NOT use `remove_signature_element` or `extract_signed_info` — those are validation-path functions for processing received assertions that already contain a Signature element. During building, no Signature element exists yet at digest time.

Updated builder flow:
1. Build the unsigned assertion string (as before — no Signature element exists yet)
2. `canon_body = canonicalize_exclusive(unsigned_assertion, &[])` — canonicalize directly
3. `digest = SHA-256(canon_body)` — digest the canonical form
4. Build the SignedInfo string containing the digest (as before)
5. `canon_signed_info = canonicalize_exclusive(signed_info, &[])` — canonicalize directly
6. `signature = RSA-SHA256(canon_signed_info, private_key)` — sign the canonical form
7. Assemble final assertion with Signature element (as before)

**Invariant**: The unsigned assertion body that the builder canonicalizes in step 2 must be byte-identical to what the validator produces after removing the Signature element and canonicalizing. This is naturally true because: the builder constructs the assertion without a Signature, canonicalizes it, and digests that; the validator takes the signed assertion, removes the Signature (yielding the same unsigned form), canonicalizes it, and compares the digest. Since both pass the same logical XML through the same `canonicalize_exclusive` function, the outputs match.

This ensures self-generated assertions (from the REST flow) pass the new validator. Without this fix, every REST flow run would show a failed digest check.

### 7. TUI Changes

**App state changes**: Both `signature_validation: Option<SignatureValidation>` (line 63 of `app.rs`) and `viewer_signature: Option<SignatureValidation>` (line 77) are replaced with `Option<ValidationReport>`. A new field `idp_trust_store: Option<IdpTrustStore>` is added to `App` for the loaded IDP certificate.

**Runtime PEM loading — interaction flow**:
- Keyboard shortcut `i` from Result or SamlView screens enters a file path input mode
- The status bar area becomes a text input field showing: `IDP Certificate path: _`
- User types or pastes a file path, presses Enter to load
- On success: status message shows "Loaded IDP cert: CN=hyperdrive-2fa-np.bswhealth.org (+ 1 chain cert)", re-runs validation on current assertion
- On error: status message shows the error, returns to previous screen
- Escape cancels and returns to previous screen
- No new Screen enum variant needed — this reuses the status bar area as an inline prompt

**Validation panel (replaces Signature Info):**

The current signature panel uses `Constraint::Length(7)` in layout. The new panel needs approximately 14 lines. Update the layout constraint accordingly.

Passing example:
```
+- Validation --------------------------------------------+
|  V TRUSTED -- Signature verified against IDP certificate |
|                                                          |
|  V Structure       Signature elements present            |
|  V Time            Valid (expires 2026-03-16T20:19:57Z)  |
|  V Digest          SHA-256 matches                       |
|  V Signature       RSA-SHA256 verified                   |
|  V IDP Certificate Matches CN=hyperdrive-2fa-np...       |
|  V Chain           Chains to BSWH Intermediate CA        |
|                                                          |
|  Algorithm: RSA-SHA256                                   |
|  Signer:    CN=hyperdrive-2fa-np.bswhealth.org           |
|  Expires:   2026-12-19                                   |
|  IDP Cert:  config/TST/idp.pem                           |
+---------------------------------------------------------+
```

Failure example:
```
+- Validation --------------------------------------------+
|  X FAILED -- Signature verification failed               |
|                                                          |
|  V Structure       Signature elements present            |
|  X Time            EXPIRED (NotOnOrAfter: 2026-03-15)    |
|  V Digest          SHA-256 matches                       |
|  X Signature       RSA-SHA256 verification failed        |
|  - IDP Certificate Not configured                        |
|  - Chain           Skipped (no IDP certificate)          |
|                                                          |
|  Algorithm: RSA-SHA256                                   |
|  Signer:    CN=hyperdrive-2fa-np.bswhealth.org           |
|  Expires:   2026-12-19                                   |
+---------------------------------------------------------+
```

(V = checkmark, X = cross mark — rendered as Unicode in actual TUI)

**Color coding:**
- Checkmark and passing text: green
- Cross and failing text: red
- Dash and skipped text: dim/gray
- Summary line: green (Trusted/Valid), yellow (Partial/Unsigned), red (Failed)

Both `render_result` and `render_saml_view` in `ui.rs` use the same redesigned panel, driven by the `ValidationReport` struct. Extract the panel rendering into a shared function to avoid duplication.

---

## File Structure

New files:
- `src/saml/c14n.rs` — Exclusive XML canonicalization, enveloped signature transform, SignedInfo extraction
- `src/saml/trust.rs` — PEM loading, certificate matching, chain validation

Modified files:
- `src/saml/validator.rs` — Replace cosmetic validation with full pipeline, new data model
- `src/saml/builder.rs` — Update signing to use canonicalization
- `src/saml/mod.rs` — Export new modules
- `src/config.rs` — Add `idp_certificate: Option<String>` with `#[serde(default)]`
- `src/crypto.rs` — Generalize `verify_sha256` into `verify_signature(cert, data, signature, digest: MessageDigest)` to support both SHA-256 and SHA-1; keep `sign_sha256` as-is (builder only needs SHA-256)
- `src/main.rs` — Integrate new validation pipeline, add IDP cert loading from config
- `src/tui/app.rs` — Replace both `SignatureValidation` fields with `ValidationReport`, add `IdpTrustStore` state
- `src/tui/ui.rs` — Redesign validation panel (shared rendering function), update layout constraints in both `render_result` (`Constraint::Length(7)` at line 276) and `render_saml_view` (`sig_height = 7` at line 556) to ~14 lines
- `src/tui/input.rs` — Add `i` shortcut + inline file path input mode for IDP cert loading

New test files:
- `tests/c14n_test.rs` — Canonicalization tests with W3C test vectors, plus SAML-specific cases
- `tests/saml_validation_test.rs` — End-to-end: build signed assertion with builder, validate with new validator (round-trip), plus crafted failure cases

## Dependencies

No new crate dependencies. All functionality uses existing dependencies:
- `openssl` (vendored) — RSA-SHA256/RSA-SHA1 verification, X509 parsing, chain validation, fingerprints
- `quick-xml` — XML parsing for canonicalization
- `base64` — Encoding/decoding
- `chrono` — Time condition checks
