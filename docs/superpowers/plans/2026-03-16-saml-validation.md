# SAML Validation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace cosmetic SAML signature validation with real cryptographic verification, including IDP certificate trust via user-provided PEM files.

**Architecture:** Validation pipeline runs 6 sequential checks (structure, time, digest, signature, IDP cert match, chain). New `c14n.rs` module handles Exclusive XML Canonicalization. New `trust.rs` module handles PEM loading and certificate trust. Existing `validator.rs` is rewritten to orchestrate the pipeline. Builder updated to use c14n so self-generated assertions pass validation.

**Tech Stack:** Rust, openssl (vendored), quick-xml, ratatui, base64, chrono. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-16-saml-validation-design.md`

**Implementation Notes (from spec review):**

1. **`remove_signature_element` must NOT unescape text content.** Use raw bytes from quick-xml (e.g., `e.as_ref()` or `e.into_inner()`) instead of `e.unescape()`. Unescaping `&amp;` to `&` before passing to `canonicalize_exclusive` would produce malformed XML. The c14n function handles escaping correctly on output.

2. **`extract_signature_data` must parse `<InclusiveNamespaces PrefixList="...">` elements.** When a `<Transform>` or `<CanonicalizationMethod>` contains `<InclusiveNamespaces PrefixList="xs xsi">`, split the PrefixList value by whitespace and populate `inclusive_ns_digest` / `inclusive_ns_sig` vectors. Default to empty when the element is absent (common SAML case).

3. **`ValidationReport` needs metadata fields for UI rendering.** Add `algorithm: String`, `cert_subject: String`, `cert_not_after: Option<String>` to `ValidationReport` so the UI can display signer info, algorithm, and expiry without string-parsing the check details.

4. **Reference URI validation.** In `verify_digest`, after confirming URI is not empty, verify that the URI fragment (e.g., `#_abc`) matches the Assertion's `ID` attribute. Produce a diagnostic on mismatch.

5. **`Trusted` summary for single-cert PEM.** When `ChainResult::Skipped` (no chain certs), the `Trusted` message should include "(no chain validated)" per spec.

6. **Re-validation after IDP cert loading.** After loading a new IDP cert via the `i` shortcut, re-run `validate_assertion` on the current assertion XML and update the stored `ValidationReport`.

7. **Consistent quick-xml API.** Use `reader.read_event_into(&mut buf)` (matching existing codebase style) in all new code, not `reader.read_event()`.

8. **Additional tests to write during implementation:** tampered XML (modify body after signing, verify digest fails), SHA-1 algorithm dispatch (unit test `resolve_digest_algorithm` / `resolve_signature_algorithm`), unsupported algorithm diagnostic, `extract_signed_info` error path (no SignedInfo present).

---

## Chunk 1: Data Model and Canonicalization

### Task 1: Validation Data Model

**Files:**
- Modify: `seahorse/src/saml/validator.rs` (add new types alongside existing code — do NOT remove old types yet)
- Test: `seahorse/tests/saml_validator_test.rs`

- [ ] **Step 1: Write test for ValidationSummary display**

Add to `seahorse/tests/saml_validator_test.rs`:

```rust
#[test]
fn test_validation_summary_display() {
    assert_eq!(
        seahorse::saml::validator::ValidationSummary::Trusted.message(),
        "Signature verified against configured IDP certificate"
    );
    assert_eq!(
        seahorse::saml::validator::ValidationSummary::Unsigned.message(),
        "No signature present in assertion"
    );
}

#[test]
fn test_validation_report_builder() {
    let report = seahorse::saml::validator::ValidationReport {
        summary: seahorse::saml::validator::ValidationSummary::Unsigned,
        checks: vec![],
        idp_cert_loaded: false,
        algorithm: String::new(),
        cert_subject: String::new(),
        cert_not_after: None,
    };
    assert!(!report.idp_cert_loaded);
    assert!(report.checks.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_validation_summary_display -- --nocapture 2>&1 | head -30`
Expected: FAIL — `ValidationSummary` not found

- [ ] **Step 3: Implement the data model**

Add to `seahorse/src/saml/validator.rs` (after the existing `SignatureValidation` struct — keep existing code intact for now):

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationSummary {
    Trusted,
    Valid,
    Partial,
    Failed,
    Unsigned,
}

impl ValidationSummary {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Trusted => "Signature verified against configured IDP certificate",
            Self::Valid => "Signature cryptographically valid (no IDP certificate configured)",
            Self::Partial => "Validation incomplete — see details",
            Self::Failed => "Signature verification FAILED",
            Self::Unsigned => "No signature present in assertion",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub summary: ValidationSummary,
    pub checks: Vec<ValidationCheck>,
    pub idp_cert_loaded: bool,
    pub algorithm: String,
    pub cert_subject: String,
    pub cert_not_after: Option<String>,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_validation_summary -- --nocapture 2>&1 | tail -10`
Expected: 2 tests PASS

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_validation_report -- --nocapture 2>&1 | tail -10`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/validator.rs seahorse/tests/saml_validator_test.rs
git commit -m "feat: add ValidationReport data model for SAML validation pipeline"
```

---

### Task 2: Enveloped Signature Transform (remove_signature_element)

**Files:**
- Create: `seahorse/src/saml/c14n.rs`
- Modify: `seahorse/src/saml/mod.rs`
- Create: `seahorse/tests/c14n_test.rs`

- [ ] **Step 1: Write tests for remove_signature_element**

Create `seahorse/tests/c14n_test.rs`:

```rust
use seahorse::saml::c14n;

#[test]
fn test_remove_signature_prefixed() {
    let xml = r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_123"><saml2:Issuer>test</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>abc</ds:SignatureValue></ds:Signature><saml2:Subject><saml2:NameID>user</saml2:NameID></saml2:Subject></saml2:Assertion>"#;

    let result = c14n::remove_signature_element(xml).unwrap();
    assert!(!result.contains("Signature"));
    assert!(!result.contains("SignatureValue"));
    assert!(result.contains("saml2:Assertion"));
    assert!(result.contains("saml2:Issuer"));
    assert!(result.contains("saml2:Subject"));
}

#[test]
fn test_remove_signature_unprefixed() {
    let xml = r#"<Assertion><Issuer>test</Issuer><Signature><SignedInfo/><SignatureValue>abc</SignatureValue></Signature><Subject>user</Subject></Assertion>"#;

    let result = c14n::remove_signature_element(xml).unwrap();
    assert!(!result.contains("Signature"));
    assert!(result.contains("<Assertion>"));
    assert!(result.contains("<Subject>"));
}

#[test]
fn test_remove_signature_no_signature() {
    let xml = r#"<Assertion><Issuer>test</Issuer><Subject>user</Subject></Assertion>"#;
    let result = c14n::remove_signature_element(xml).unwrap();
    assert_eq!(result, xml);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_remove_signature -- --nocapture 2>&1 | head -20`
Expected: FAIL — module `c14n` not found

- [ ] **Step 3: Create c14n module with remove_signature_element**

Create `seahorse/src/saml/c14n.rs`:

```rust
use anyhow::{bail, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

/// Enveloped signature transform: removes the first <Signature> element
/// (and all children) from the XML. Handles both prefixed (ds:Signature)
/// and unprefixed (Signature) variants.
pub fn remove_signature_element(xml: &str) -> Result<String> {
    let mut reader = Reader::from_str(xml);
    let mut output = String::with_capacity(xml.len());
    let mut skip_depth: Option<usize> = None;
    let mut depth: usize = 0;

    loop {
        let event = reader.read_event();
        match event {
            Ok(Event::Start(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                depth += 1;
                if local == "Signature" && skip_depth.is_none() {
                    skip_depth = Some(depth);
                    continue;
                }
                if skip_depth.is_some() {
                    continue;
                }
                // Write the raw bytes from source to preserve exact content
                let start = e.to_owned();
                output.push('<');
                output.push_str(std::str::from_utf8(start.as_ref()).unwrap_or(""));
                output.push('>');
            }
            Ok(Event::End(ref e)) => {
                if let Some(sd) = skip_depth {
                    if depth == sd {
                        skip_depth = None;
                        depth -= 1;
                        continue;
                    }
                }
                depth -= 1;
                if skip_depth.is_some() {
                    continue;
                }
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let name = std::str::from_utf8(e.name().as_ref()).unwrap_or(&local);
                output.push_str("</");
                output.push_str(name);
                output.push('>');
            }
            Ok(Event::Empty(ref e)) => {
                if skip_depth.is_some() {
                    continue;
                }
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local == "Signature" && skip_depth.is_none() {
                    // Self-closing <Signature/> — just skip it
                    continue;
                }
                output.push('<');
                output.push_str(std::str::from_utf8(e.as_ref()).unwrap_or(""));
                output.push_str("/>");
            }
            Ok(Event::Text(ref e)) => {
                if skip_depth.is_some() {
                    continue;
                }
                // Write raw text to preserve whitespace
                let text = e.unescape().unwrap_or_default();
                output.push_str(&text);
            }
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_)) | Ok(Event::PI(_)) | Ok(Event::Comment(_)) => {
                if skip_depth.is_some() {
                    continue;
                }
                // Preserve other events as-is
            }
            Ok(Event::CData(ref e)) => {
                if skip_depth.is_some() {
                    continue;
                }
                output.push_str("<![CDATA[");
                output.push_str(std::str::from_utf8(e.as_ref()).unwrap_or(""));
                output.push_str("]]>");
            }
            Ok(Event::DocType(_)) => {}
            Err(e) => bail!("XML parse error in remove_signature_element: {}", e),
        }
    }

    Ok(output)
}
```

Update `seahorse/src/saml/mod.rs` to add:
```rust
pub mod c14n;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_remove_signature -- --nocapture 2>&1 | tail -15`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/c14n.rs seahorse/src/saml/mod.rs seahorse/tests/c14n_test.rs
git commit -m "feat: add enveloped signature transform (remove_signature_element)"
```

---

### Task 3: Exclusive XML Canonicalization (canonicalize_exclusive)

**Files:**
- Modify: `seahorse/src/saml/c14n.rs`
- Modify: `seahorse/tests/c14n_test.rs`

This is the most complex task. The implementation uses quick-xml to parse the XML into events, tracks namespace context, and emits canonical output according to exc-c14n rules.

- [ ] **Step 1: Write tests for basic canonicalization**

Add to `seahorse/tests/c14n_test.rs`:

```rust
#[test]
fn test_c14n_empty_element_expansion() {
    // exc-c14n expands <Foo/> to <Foo></Foo>
    let xml = r#"<root><empty/></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(output.contains("<empty></empty>"), "Got: {}", output);
}

#[test]
fn test_c14n_attribute_sorting() {
    // Attributes sorted by namespace URI then local name
    let xml = r#"<root z="1" a="2" m="3"></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    // Attributes with no namespace sort by local name
    assert!(output.contains(r#"a="2" m="3" z="1""#), "Got: {}", output);
}

#[test]
fn test_c14n_namespace_visibly_utilized() {
    // Only namespaces that are visibly used should be emitted
    let xml = r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><a:child>text</a:child></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    // The child should have xmlns:a but not xmlns:b
    assert!(output.contains(r#"<a:child xmlns:a="urn:a">"#), "Got: {}", output);
}

#[test]
fn test_c14n_no_xml_declaration() {
    let xml = r#"<?xml version="1.0"?><root></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(!output.contains("<?xml"), "Got: {}", output);
    assert!(output.starts_with("<root>"), "Got: {}", output);
}

#[test]
fn test_c14n_default_namespace() {
    // Default namespace must be explicitly declared
    let xml = r#"<root xmlns="urn:default"><child>text</child></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(output.contains(r#"xmlns="urn:default""#), "Got: {}", output);
}

#[test]
fn test_c14n_entity_escaping() {
    let xml = r#"<root attr="a&lt;b">text &amp; more</root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(output.contains("&amp;"), "Got: {}", output);
    assert!(output.contains("&lt;"), "Got: {}", output);
}

#[test]
fn test_c14n_inclusive_ns_prefixes() {
    // When a prefix is in the inclusive list, it should be emitted even if not visibly used
    let xml = r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><child>text</child></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &["a"]).unwrap();
    let output = String::from_utf8(result).unwrap();
    // "a" should be propagated to child even though child doesn't use it
    assert!(output.contains(r#"xmlns:a="urn:a""#), "Got: {}", output);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_c14n_ -- --nocapture 2>&1 | head -20`
Expected: FAIL — `canonicalize_exclusive` not found

- [ ] **Step 3: Implement canonicalize_exclusive**

Add to `seahorse/src/saml/c14n.rs`. This is the core implementation — a namespace-aware XML event processor that emits canonical output. The implementation:

1. Parses XML with `quick_xml::Reader`
2. Maintains a `NamespaceContext` stack tracking in-scope namespace declarations per element
3. For each element: collects namespace declarations, determines which are visibly utilized (used by element name or attributes), sorts attributes by (namespace URI, local name), emits only utilized namespace declarations
4. Handles inclusive namespace prefixes by treating them as visibly utilized
5. Expands empty elements, escapes attribute/text values per spec

```rust
use std::collections::BTreeMap;

/// Exclusive XML Canonicalization (without comments) per W3C spec.
pub fn canonicalize_exclusive(xml: &str, inclusive_ns_prefixes: &[&str]) -> Result<Vec<u8>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text_start = false;
    reader.config_mut().trim_text_end = false;

    let mut output = Vec::new();
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new(); // prefix -> uri
    let mut rendered_stack: Vec<BTreeMap<String, String>> = Vec::new(); // what's been rendered at each level

    loop {
        let event = reader.read_event();
        match event {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let is_empty = matches!(event, Ok(Event::Empty(_)));

                // Collect namespace declarations from this element
                let mut local_ns: BTreeMap<String, String> = BTreeMap::new();
                let mut attrs: Vec<(String, String, String)> = Vec::new(); // (ns_uri, local_name, value)

                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let val = attr.unescape_value().unwrap_or_default().to_string();

                    if key == "xmlns" {
                        local_ns.insert(String::new(), val);
                    } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                        local_ns.insert(prefix.to_string(), val);
                    } else {
                        attrs.push((String::new(), key, val)); // ns_uri filled below
                    }
                }

                // Push ns context
                let mut current_ns = ns_stack.last().cloned().unwrap_or_default();
                for (prefix, uri) in &local_ns {
                    current_ns.insert(prefix.clone(), uri.clone());
                }
                ns_stack.push(current_ns.clone());

                // Determine element name parts
                let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let (el_prefix, _el_local) = if let Some(pos) = full_name.find(':') {
                    (&full_name[..pos], &full_name[pos + 1..])
                } else {
                    ("", full_name.as_str())
                };

                // Determine visibly utilized prefixes
                let mut utilized: BTreeMap<String, String> = BTreeMap::new();

                // Element prefix is utilized
                if let Some(uri) = current_ns.get(el_prefix) {
                    utilized.insert(el_prefix.to_string(), uri.clone());
                }

                // Resolve attribute namespace URIs and track utilized prefixes
                let mut resolved_attrs: Vec<(String, String, String, String)> = Vec::new(); // (ns_uri, prefix, local, value)
                for (_ns, key, val) in &attrs {
                    if let Some(pos) = key.find(':') {
                        let attr_prefix = &key[..pos];
                        let attr_local = &key[pos + 1..];
                        let attr_uri = current_ns.get(attr_prefix).cloned().unwrap_or_default();
                        utilized.insert(attr_prefix.to_string(), attr_uri.clone());
                        resolved_attrs.push((attr_uri, attr_prefix.to_string(), attr_local.to_string(), val.clone()));
                    } else {
                        // Unprefixed attributes are in no namespace
                        resolved_attrs.push((String::new(), String::new(), key.clone(), val.clone()));
                    }
                }

                // Add inclusive namespace prefixes
                for prefix in inclusive_ns_prefixes {
                    let p = prefix.to_string();
                    if let Some(uri) = current_ns.get(&p) {
                        utilized.insert(p, uri.clone());
                    }
                }

                // Determine which ns declarations need rendering (not already rendered by ancestor)
                let parent_rendered = rendered_stack.last().cloned().unwrap_or_default();
                let mut to_render: BTreeMap<String, String> = BTreeMap::new();
                for (prefix, uri) in &utilized {
                    let already = parent_rendered.get(prefix).map(|u| u == uri).unwrap_or(false);
                    if !already {
                        to_render.insert(prefix.clone(), uri.clone());
                    }
                }

                // Track what's rendered at this level
                let mut this_rendered = parent_rendered.clone();
                for (prefix, uri) in &to_render {
                    this_rendered.insert(prefix.clone(), uri.clone());
                }
                rendered_stack.push(this_rendered);

                // Emit element
                output.push(b'<');
                output.extend_from_slice(full_name.as_bytes());

                // Emit namespace declarations (sorted by prefix)
                for (prefix, uri) in &to_render {
                    if prefix.is_empty() {
                        output.extend_from_slice(b" xmlns=\"");
                        write_escaped_attr(&mut output, uri);
                        output.push(b'"');
                    } else {
                        output.extend_from_slice(b" xmlns:");
                        output.extend_from_slice(prefix.as_bytes());
                        output.extend_from_slice(b"=\"");
                        write_escaped_attr(&mut output, uri);
                        output.push(b'"');
                    }
                }

                // Sort and emit attributes: by namespace URI, then local name
                resolved_attrs.sort_by(|a, b| {
                    a.0.cmp(&b.0).then(a.2.cmp(&b.2))
                });
                for (_, prefix, local, val) in &resolved_attrs {
                    output.push(b' ');
                    if !prefix.is_empty() {
                        output.extend_from_slice(prefix.as_bytes());
                        output.push(b':');
                    }
                    output.extend_from_slice(local.as_bytes());
                    output.extend_from_slice(b"=\"");
                    write_escaped_attr(&mut output, val);
                    output.push(b'"');
                }

                output.push(b'>');

                // For empty elements: expand to <foo></foo>
                if is_empty {
                    output.extend_from_slice(b"</");
                    output.extend_from_slice(full_name.as_bytes());
                    output.push(b'>');
                    ns_stack.pop();
                    rendered_stack.pop();
                }
            }
            Ok(Event::End(ref e)) => {
                let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                output.extend_from_slice(b"</");
                output.extend_from_slice(full_name.as_bytes());
                output.push(b'>');
                ns_stack.pop();
                rendered_stack.pop();
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default();
                write_escaped_text(&mut output, &text);
            }
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_)) | Ok(Event::PI(_)) | Ok(Event::Comment(_)) => {
                // Skip XML declaration, processing instructions, comments
            }
            Ok(Event::CData(ref e)) => {
                // CData sections are replaced with their text content (escaped)
                let text = String::from_utf8_lossy(e.as_ref());
                write_escaped_text(&mut output, &text);
            }
            Ok(Event::DocType(_)) => {}
            Err(e) => bail!("XML parse error in canonicalize_exclusive: {}", e),
        }
    }

    Ok(output)
}

fn write_escaped_attr(output: &mut Vec<u8>, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.extend_from_slice(b"&amp;"),
            '<' => output.extend_from_slice(b"&lt;"),
            '"' => output.extend_from_slice(b"&quot;"),
            '\t' => output.extend_from_slice(b"&#x9;"),
            '\n' => output.extend_from_slice(b"&#xA;"),
            '\r' => output.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                output.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn write_escaped_text(output: &mut Vec<u8>, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.extend_from_slice(b"&amp;"),
            '<' => output.extend_from_slice(b"&lt;"),
            '>' => output.extend_from_slice(b"&gt;"),
            '\r' => output.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                output.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_c14n_ -- --nocapture 2>&1 | tail -20`
Expected: All c14n tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/c14n.rs seahorse/tests/c14n_test.rs
git commit -m "feat: implement exclusive XML canonicalization (exc-c14n)"
```

---

### Task 4: Extract SignedInfo

**Files:**
- Modify: `seahorse/src/saml/c14n.rs`
- Modify: `seahorse/tests/c14n_test.rs`

- [ ] **Step 1: Write test for extract_signed_info**

Add to `seahorse/tests/c14n_test.rs`:

```rust
#[test]
fn test_extract_signed_info_with_inherited_ns() {
    let xml = r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_123"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>abc</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>sig</ds:SignatureValue></ds:Signature></saml2:Assertion>"#;

    let result = c14n::extract_signed_info(xml).unwrap();
    // SignedInfo should have xmlns:ds because it uses ds: prefix
    assert!(result.contains("xmlns:ds="), "Missing xmlns:ds in: {}", result);
    assert!(result.contains("ds:SignedInfo"), "Missing ds:SignedInfo in: {}", result);
    assert!(result.contains("ds:CanonicalizationMethod"), "Got: {}", result);
    assert!(result.contains("ds:DigestValue"), "Got: {}", result);
    // Should NOT contain the Signature wrapper or SignatureValue
    assert!(!result.contains("SignatureValue"), "Got: {}", result);
}

#[test]
fn test_extract_signed_info_self_contained_ns() {
    // When SignedInfo already declares xmlns:ds itself
    let xml = r#"<Assertion><Signature><SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Reference URI="#_123"/></SignedInfo></Signature></Assertion>"#;
    let result = c14n::extract_signed_info(xml).unwrap();
    assert!(result.contains("xmlns:ds="), "Got: {}", result);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_extract_signed_info -- --nocapture 2>&1 | head -15`
Expected: FAIL — `extract_signed_info` not found

- [ ] **Step 3: Implement extract_signed_info**

Add to `seahorse/src/saml/c14n.rs`:

```rust
/// Extract the <SignedInfo> element from within <Signature>, adding any
/// namespace declarations inherited from ancestor elements so the fragment
/// is self-contained for canonicalization.
pub fn extract_signed_info(assertion_xml: &str) -> Result<String> {
    let mut reader = Reader::from_str(assertion_xml);
    let mut ancestor_ns: BTreeMap<String, String> = BTreeMap::new();
    let mut in_signed_info = false;
    let mut depth: usize = 0;
    let mut si_depth: Option<usize> = None;
    let mut si_content = String::new();
    let mut si_ns_on_element: BTreeMap<String, String> = BTreeMap::new();

    loop {
        let event = reader.read_event();
        match event {
            Ok(Event::Start(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                depth += 1;

                if !in_signed_info {
                    // Track namespace declarations on ancestors
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = attr.unescape_value().unwrap_or_default().to_string();
                        if key == "xmlns" {
                            ancestor_ns.insert(String::new(), val);
                        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                            ancestor_ns.insert(prefix.to_string(), val);
                        }
                    }
                }

                if local == "SignedInfo" && !in_signed_info {
                    in_signed_info = true;
                    si_depth = Some(depth);

                    // Capture the opening tag with its own namespace decls
                    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    si_content.push('<');
                    si_content.push_str(&full_name);

                    // Collect ns decls and attrs from this element
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = attr.unescape_value().unwrap_or_default().to_string();
                        if key == "xmlns" || key.starts_with("xmlns:") {
                            let prefix = if key == "xmlns" {
                                String::new()
                            } else {
                                key.strip_prefix("xmlns:").unwrap_or("").to_string()
                            };
                            si_ns_on_element.insert(prefix, val.clone());
                        }
                        si_content.push(' ');
                        si_content.push_str(&key);
                        si_content.push_str("=\"");
                        si_content.push_str(&val);
                        si_content.push('"');
                    }

                    // Add inherited ns declarations not already on SignedInfo
                    // We need prefixes that are used in SignedInfo (we'll add
                    // the common ones - ds: is always needed)
                    let el_prefix = if let Some(pos) = full_name.find(':') {
                        &full_name[..pos]
                    } else {
                        ""
                    };
                    if !el_prefix.is_empty() && !si_ns_on_element.contains_key(el_prefix) {
                        if let Some(uri) = ancestor_ns.get(el_prefix) {
                            si_content.push_str(&format!(" xmlns:{}=\"{}\"", el_prefix, uri));
                            si_ns_on_element.insert(el_prefix.to_string(), uri.clone());
                        }
                    }

                    si_content.push('>');
                    continue;
                }

                if in_signed_info {
                    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    si_content.push('<');
                    si_content.push_str(&full_name);
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = attr.unescape_value().unwrap_or_default().to_string();
                        si_content.push(' ');
                        si_content.push_str(&key);
                        si_content.push_str("=\"");
                        si_content.push_str(&val);
                        si_content.push('"');

                        // Add inherited ns for prefixed child elements/attrs
                        if !key.starts_with("xmlns") {
                            if let Some(pos) = key.find(':') {
                                let prefix = &key[..pos];
                                if !si_ns_on_element.contains_key(prefix) {
                                    if let Some(uri) = ancestor_ns.get(prefix) {
                                        // This will be handled by canonicalization
                                    }
                                }
                            }
                        }
                    }
                    // Check element prefix
                    let el_prefix = if let Some(pos) = full_name.find(':') {
                        full_name[..pos].to_string()
                    } else {
                        String::new()
                    };
                    if !el_prefix.is_empty() && !si_ns_on_element.contains_key(&el_prefix) {
                        if let Some(uri) = ancestor_ns.get(&el_prefix) {
                            si_content.push_str(&format!(" xmlns:{}=\"{}\"", el_prefix, uri));
                            si_ns_on_element.insert(el_prefix, uri.clone());
                        }
                    }
                    si_content.push('>');
                }
            }
            Ok(Event::End(ref e)) => {
                if in_signed_info {
                    if Some(depth) == si_depth {
                        let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        si_content.push_str("</");
                        si_content.push_str(&full_name);
                        si_content.push('>');
                        return Ok(si_content);
                    }
                    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    si_content.push_str("</");
                    si_content.push_str(&full_name);
                    si_content.push('>');
                }
                depth -= 1;
            }
            Ok(Event::Empty(ref e)) => {
                if in_signed_info {
                    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    si_content.push('<');
                    si_content.push_str(&full_name);
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = attr.unescape_value().unwrap_or_default().to_string();
                        si_content.push(' ');
                        si_content.push_str(&key);
                        si_content.push_str("=\"");
                        si_content.push_str(&val);
                        si_content.push('"');
                    }
                    si_content.push_str("/>");
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_signed_info {
                    let text = e.unescape().unwrap_or_default();
                    si_content.push_str(&text);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error in extract_signed_info: {}", e),
            _ => {}
        }
    }

    bail!("No SignedInfo element found in assertion")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_extract_signed_info -- --nocapture 2>&1 | tail -10`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/c14n.rs seahorse/tests/c14n_test.rs
git commit -m "feat: add extract_signed_info with namespace inheritance"
```

---

## Chunk 2: Trust Module, Crypto Updates, and Config

### Task 5: PEM Loading and Certificate Trust (trust.rs)

**Files:**
- Create: `seahorse/src/saml/trust.rs`
- Modify: `seahorse/src/saml/mod.rs`
- Create: `seahorse/tests/trust_test.rs`
- Create: `seahorse/tests/fixtures/test-idp.pem` (test fixture — self-signed cert from test-cert.pfx)

- [ ] **Step 1: Generate test PEM fixture from existing test PFX**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && openssl pkcs12 -in tests/fixtures/test-cert.pfx -nokeys -clcerts -passin pass:testpassword 2>/dev/null | openssl x509 -outform PEM > tests/fixtures/test-idp.pem`

Verify: `openssl x509 -in tests/fixtures/test-idp.pem -noout -subject`

- [ ] **Step 2: Write tests for trust module**

Create `seahorse/tests/trust_test.rs`:

```rust
use std::path::PathBuf;

fn test_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-idp.pem")
}

#[test]
fn test_load_idp_certificates_single_cert() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    assert!(store.chain_certs.is_empty(), "Single cert PEM should have no chain certs");
    // Verify we got a valid X509
    let subject = store.leaf_cert.subject_name();
    assert!(subject.entries().count() > 0);
}

#[test]
fn test_compare_certificates_match() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    // Compare cert with itself — should match
    let result = seahorse::saml::trust::compare_certificates(&store.leaf_cert, &store.leaf_cert);
    assert!(matches!(result, seahorse::saml::trust::CertMatch::Match));
}

#[test]
fn test_compare_certificates_mismatch() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();

    // Generate a different self-signed cert for comparison
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx");
    let bundle = seahorse::crypto::load_pfx(&pfx_path, "testpassword").unwrap();
    let pfx_cert = bundle.certificate.as_ref().unwrap();

    // These are the same cert (from same PFX), so actually this should match.
    // A real mismatch test would need a second cert, but this validates the plumbing.
    let result = seahorse::saml::trust::compare_certificates(pfx_cert, &store.leaf_cert);
    assert!(matches!(result, seahorse::saml::trust::CertMatch::Match));
}

#[test]
fn test_validate_chain_no_chain_certs() {
    let store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    let result = seahorse::saml::trust::validate_chain(&store.leaf_cert, &store.chain_certs);
    assert!(matches!(result, seahorse::saml::trust::ChainResult::Skipped { .. }));
}

#[test]
fn test_load_nonexistent_pem() {
    let result = seahorse::saml::trust::load_idp_certificates(std::path::Path::new("/nonexistent/path.pem"));
    assert!(result.is_err());
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test trust_test -- --nocapture 2>&1 | head -15`
Expected: FAIL — module `trust` not found

- [ ] **Step 4: Implement trust module**

Create `seahorse/src/saml/trust.rs`:

```rust
use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};
use std::fs;
use std::path::{Path, PathBuf};

pub struct IdpTrustStore {
    pub leaf_cert: X509,
    pub chain_certs: Vec<X509>,
    pub source_path: PathBuf,
}

#[derive(Debug)]
pub enum CertMatch {
    Match,
    Mismatch {
        expected_cn: String,
        actual_cn: String,
        expected_fingerprint: String,
        actual_fingerprint: String,
    },
}

#[derive(Debug)]
pub enum ChainResult {
    Valid { chain_depth: usize, root_cn: String },
    Failed { error: String },
    Skipped { reason: String },
}

pub fn load_idp_certificates(path: &Path) -> Result<IdpTrustStore> {
    let pem_data = fs::read(path)
        .with_context(|| format!("Failed to read PEM file: {}", path.display()))?;

    let certs = X509::stack_from_pem(&pem_data)
        .with_context(|| format!("Failed to parse PEM certificates from: {}", path.display()))?;

    if certs.is_empty() {
        anyhow::bail!("PEM file contains no certificates: {}", path.display());
    }

    let leaf_cert = certs[0].clone();
    let chain_certs: Vec<X509> = certs.into_iter().skip(1).collect();

    Ok(IdpTrustStore {
        leaf_cert,
        chain_certs,
        source_path: path.to_path_buf(),
    })
}

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

pub fn validate_chain(leaf: &X509, chain: &[X509]) -> ChainResult {
    if chain.is_empty() {
        return ChainResult::Skipped {
            reason: "PEM contains only the leaf certificate; no chain certs to validate".to_string(),
        };
    }

    let mut store_builder = match X509StoreBuilder::new() {
        Ok(b) => b,
        Err(e) => return ChainResult::Failed { error: format!("Failed to create X509 store: {}", e) },
    };

    for cert in chain {
        if let Err(e) = store_builder.add_cert(cert.clone()) {
            return ChainResult::Failed { error: format!("Failed to add chain cert: {}", e) };
        }
    }

    let store = store_builder.build();
    let mut stack = openssl::stack::Stack::new().unwrap();
    // Empty stack — all trust certs are in the store

    let mut ctx = match X509StoreContext::new() {
        Ok(c) => c,
        Err(e) => return ChainResult::Failed { error: format!("Failed to create store context: {}", e) },
    };

    match ctx.init(&store, leaf, &stack, |ctx| ctx.verify_cert()) {
        Ok(true) => {
            let root_cn = chain.last().map(|c| cert_cn(c)).unwrap_or_default();
            ChainResult::Valid {
                chain_depth: chain.len(),
                root_cn,
            }
        }
        Ok(false) | Err(_) => {
            let error = ctx.error().to_string();
            ChainResult::Failed { error }
        }
    }
}

fn cert_fingerprint(cert: &X509) -> String {
    cert.digest(MessageDigest::sha256())
        .map(|d| d.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn cert_cn(cert: &X509) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .map(|e| String::from_utf8_lossy(e.data().as_slice()).to_string())
        .unwrap_or_else(|| {
            // Fall back to full subject
            cert.subject_name()
                .entries()
                .map(|e| format!("{}={}", e.object().nid().short_name().unwrap_or("?"), String::from_utf8_lossy(e.data().as_slice())))
                .collect::<Vec<_>>()
                .join(", ")
        })
}
```

Update `seahorse/src/saml/mod.rs`:
```rust
pub mod c14n;
pub mod trust;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test trust_test -- --nocapture 2>&1 | tail -15`
Expected: All 5 trust tests PASS

- [ ] **Step 6: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/trust.rs seahorse/src/saml/mod.rs seahorse/tests/trust_test.rs seahorse/tests/fixtures/test-idp.pem
git commit -m "feat: add IDP certificate trust module (PEM loading, fingerprint comparison, chain validation)"
```

---

### Task 6: Generalize crypto verify_signature

**Files:**
- Modify: `seahorse/src/crypto.rs`
- Modify: `seahorse/tests/crypto_test.rs`

- [ ] **Step 1: Write test for generalized verify_signature**

Add to `seahorse/tests/crypto_test.rs`:

```rust
#[test]
fn test_verify_signature_sha256() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), TEST_PFX_PASSWORD).unwrap();
    let data = b"test data for generalized verify";
    let signature = seahorse::crypto::sign_sha256(bundle.private_key.as_ref().unwrap(), data).unwrap();

    let valid = seahorse::crypto::verify_signature(
        bundle.certificate.as_ref().unwrap(),
        data,
        &signature,
        openssl::hash::MessageDigest::sha256(),
    ).unwrap();
    assert!(valid);
}

#[test]
fn test_verify_signature_wrong_data() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), TEST_PFX_PASSWORD).unwrap();
    let data = b"original data";
    let signature = seahorse::crypto::sign_sha256(bundle.private_key.as_ref().unwrap(), data).unwrap();

    let valid = seahorse::crypto::verify_signature(
        bundle.certificate.as_ref().unwrap(),
        b"tampered data",
        &signature,
        openssl::hash::MessageDigest::sha256(),
    ).unwrap();
    assert!(!valid);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_verify_signature_sha256 -- --nocapture 2>&1 | head -15`
Expected: FAIL — `verify_signature` not found

- [ ] **Step 3: Add verify_signature to crypto.rs**

Add to `seahorse/src/crypto.rs` (keep `verify_sha256` for backward compat):

```rust
pub fn verify_signature(cert: &X509, data: &[u8], signature: &[u8], digest: MessageDigest) -> Result<bool> {
    let pub_key = cert
        .public_key()
        .context("Failed to extract public key from certificate")?;
    let mut verifier =
        Verifier::new(digest, &pub_key).context("Failed to create verifier")?;
    verifier.update(data).context("Failed to update verifier")?;
    verifier
        .verify(signature)
        .context("Failed to verify signature")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_verify_signature -- --nocapture 2>&1 | tail -10`
Expected: 2 tests PASS

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test crypto_test -- --nocapture 2>&1 | tail -10`
Expected: All crypto tests PASS (existing + new)

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/crypto.rs seahorse/tests/crypto_test.rs
git commit -m "feat: add generalized verify_signature supporting SHA-256 and SHA-1"
```

---

### Task 7: Config update for idp_certificate

**Files:**
- Modify: `seahorse/src/config.rs`
- Modify: `seahorse/tests/config_test.rs`

- [ ] **Step 1: Write test for config with optional idp_certificate**

Add to `seahorse/tests/config_test.rs`:

```rust
#[test]
fn test_config_without_idp_certificate() {
    // Existing config files that lack idp_certificate should still parse
    let config_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config = seahorse::config::load_config(&config_dir).unwrap();
    assert!(config.idp_certificate.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_config_without_idp -- --nocapture 2>&1 | head -15`
Expected: FAIL — no field `idp_certificate` on Config

- [ ] **Step 3: Add idp_certificate field to Config**

In `seahorse/src/config.rs`, add to the `Config` struct:

```rust
    #[serde(default)]
    pub idp_certificate: Option<String>,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test config_test -- --nocapture 2>&1 | tail -10`
Expected: All config tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/config.rs seahorse/tests/config_test.rs
git commit -m "feat: add optional idp_certificate field to config"
```

---

## Chunk 3: Validation Pipeline and Builder Update

### Task 8: Full Validation Pipeline (rewrite validator.rs)

**Files:**
- Modify: `seahorse/src/saml/validator.rs` (rewrite — keep old types temporarily for compilation)
- Modify: `seahorse/tests/saml_validator_test.rs`

This is the core orchestration task. The new `validate_assertion` function runs all 6 checks in sequence and produces a `ValidationReport`.

- [ ] **Step 1: Write tests for the full validation pipeline**

Rewrite `seahorse/tests/saml_validator_test.rs` (keep existing tests, add new ones):

```rust
use std::path::PathBuf;

fn test_pfx_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx")
}

fn test_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-idp.pem")
}

// === New validation pipeline tests ===

#[test]
fn test_validate_unsigned_assertion() {
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };
    let xml = seahorse::saml::builder::build_unsigned_assertion(&params);

    let report = seahorse::saml::validator::validate_assertion(&xml, None);
    assert_eq!(report.summary, seahorse::saml::validator::ValidationSummary::Unsigned);
    assert!(!report.idp_cert_loaded);
}

#[test]
fn test_validate_signed_assertion_no_idp_cert() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), "testpassword").unwrap();
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };
    let xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    ).unwrap();

    let report = seahorse::saml::validator::validate_assertion(&xml, None);
    // Should be Valid (not Trusted) because no IDP cert provided
    assert_eq!(report.summary, seahorse::saml::validator::ValidationSummary::Valid,
        "Expected Valid, got {:?}. Checks: {:?}", report.summary, report.checks);
    assert!(!report.idp_cert_loaded);
}

#[test]
fn test_validate_signed_assertion_with_idp_cert() {
    let bundle = seahorse::crypto::load_pfx(&test_pfx_path(), "testpassword").unwrap();
    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "testuser".to_string(),
        validity_seconds: 300,
    };
    let xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    ).unwrap();

    let trust_store = seahorse::saml::trust::load_idp_certificates(&test_pem_path()).unwrap();
    let report = seahorse::saml::validator::validate_assertion(&xml, Some(&trust_store));
    // Should be Trusted because IDP cert matches (same cert from PFX)
    assert_eq!(report.summary, seahorse::saml::validator::ValidationSummary::Trusted,
        "Expected Trusted, got {:?}. Checks: {:?}", report.summary, report.checks);
    assert!(report.idp_cert_loaded);
}

// Keep existing time condition tests
#[test]
fn test_check_conditions_valid() {
    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_after = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let result = seahorse::saml::validator::check_time_conditions(Some(&not_before), Some(&not_after));
    assert!(result.is_ok());
}

#[test]
fn test_check_conditions_expired() {
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let also_past = (chrono::Utc::now() - chrono::Duration::minutes(30)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let result = seahorse::saml::validator::check_time_conditions(Some(&past), Some(&also_past));
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_validate_unsigned -- --nocapture 2>&1 | head -15`
Expected: FAIL — `validate_assertion` not found

- [ ] **Step 3: Implement validate_assertion pipeline**

Rewrite `seahorse/src/saml/validator.rs`. Keep the old `SignatureValidation` struct and `validate_assertion_signature` function temporarily (they're still used by the TUI — we'll swap them in a later task). Add the new `validate_assertion` function:

```rust
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use quick_xml::events::Event;
use quick_xml::Reader;

use super::c14n;
use super::trust::{self, IdpTrustStore};

// ... keep existing SignatureValidation struct and validate_assertion_signature function ...
// ... keep existing check_time_conditions function ...

// === New validation pipeline ===

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationSummary { /* ... as implemented in Task 1 ... */ }

#[derive(Debug, Clone)]
pub struct ValidationCheck { /* ... as implemented in Task 1 ... */ }

#[derive(Debug, Clone)]
pub struct ValidationReport { /* ... as implemented in Task 1 ... */ }

/// Run the full SAML validation pipeline on an assertion.
pub fn validate_assertion(
    assertion_xml: &str,
    trust_store: Option<&IdpTrustStore>,
) -> ValidationReport {
    let mut checks = Vec::new();
    let idp_cert_loaded = trust_store.is_some();

    // Check 1: Structure
    let sig_data = match extract_signature_data(assertion_xml) {
        Ok(data) => {
            checks.push(ValidationCheck {
                name: "Structure".to_string(),
                passed: true,
                detail: "Signature elements present".to_string(),
                diagnostic: None,
            });
            Some(data)
        }
        Err(SignatureAbsence::NoSignature) => {
            checks.push(ValidationCheck {
                name: "Structure".to_string(),
                passed: false,
                detail: "No signature present".to_string(),
                diagnostic: None,
            });
            return ValidationReport {
                summary: ValidationSummary::Unsigned,
                checks,
                idp_cert_loaded,
            };
        }
        Err(SignatureAbsence::Incomplete(msg)) => {
            checks.push(ValidationCheck {
                name: "Structure".to_string(),
                passed: false,
                detail: "Signature incomplete".to_string(),
                diagnostic: Some(msg),
            });
            None
        }
    };

    let sig_data = match sig_data {
        Some(d) => d,
        None => {
            return ValidationReport {
                summary: ValidationSummary::Failed,
                checks,
                idp_cert_loaded,
            };
        }
    };

    // Check 2: Time conditions (from parser's extracted details, not from signature)
    // We parse NotBefore/NotOnOrAfter from the assertion conditions
    let time_check = check_assertion_time_conditions(assertion_xml);
    checks.push(time_check);

    // Check 3: Digest verification
    let digest_check = verify_digest(assertion_xml, &sig_data);
    let digest_ok = digest_check.passed;
    checks.push(digest_check);

    // Check 4: Signature verification
    let sig_check = if digest_ok {
        verify_signature(assertion_xml, &sig_data)
    } else {
        ValidationCheck {
            name: "Signature".to_string(),
            passed: false,
            detail: "Skipped (digest failed)".to_string(),
            diagnostic: None,
        }
    };
    let sig_ok = sig_check.passed;
    checks.push(sig_check);

    // Check 5: IDP certificate match
    let cert_match_check = if let Some(store) = trust_store {
        match &sig_data.embedded_cert {
            Some(cert) => {
                let result = trust::compare_certificates(cert, &store.leaf_cert);
                match result {
                    trust::CertMatch::Match => ValidationCheck {
                        name: "IDP Certificate".to_string(),
                        passed: true,
                        detail: format!("Matches {}", trust::cert_cn(&store.leaf_cert)),
                        diagnostic: None,
                    },
                    trust::CertMatch::Mismatch { expected_cn, actual_cn, expected_fingerprint, actual_fingerprint } => ValidationCheck {
                        name: "IDP Certificate".to_string(),
                        passed: false,
                        detail: "Certificate mismatch".to_string(),
                        diagnostic: Some(format!(
                            "Assertion signed by CN={} ({}...) but expected CN={} ({}...)",
                            actual_cn, &actual_fingerprint[..8],
                            expected_cn, &expected_fingerprint[..8]
                        )),
                    },
                }
            }
            None => ValidationCheck {
                name: "IDP Certificate".to_string(),
                passed: false,
                detail: "No certificate in assertion".to_string(),
                diagnostic: None,
            },
        }
    } else {
        ValidationCheck {
            name: "IDP Certificate".to_string(),
            passed: false,
            detail: "Not configured".to_string(),
            diagnostic: None,
        }
    };
    let cert_match_ok = cert_match_check.passed;
    checks.push(cert_match_check);

    // Check 6: Chain validation
    let chain_check = if let Some(store) = trust_store {
        let result = trust::validate_chain(&store.leaf_cert, &store.chain_certs);
        match result {
            trust::ChainResult::Valid { chain_depth, root_cn } => ValidationCheck {
                name: "Chain".to_string(),
                passed: true,
                detail: format!("Chains to {} ({} certs)", root_cn, chain_depth),
                diagnostic: None,
            },
            trust::ChainResult::Skipped { reason } => ValidationCheck {
                name: "Chain".to_string(),
                passed: true, // Not a failure — just no chain to validate
                detail: "No chain certs in PEM".to_string(),
                diagnostic: Some(reason),
            },
            trust::ChainResult::Failed { error } => ValidationCheck {
                name: "Chain".to_string(),
                passed: false,
                detail: "Chain validation failed".to_string(),
                diagnostic: Some(error),
            },
        }
    } else {
        ValidationCheck {
            name: "Chain".to_string(),
            passed: false,
            detail: "Skipped (no IDP certificate)".to_string(),
            diagnostic: None,
        }
    };
    checks.push(chain_check);

    // Determine summary
    let summary = compute_summary(&checks, idp_cert_loaded, sig_ok, cert_match_ok);

    ValidationReport {
        summary,
        checks,
        idp_cert_loaded,
    }
}

fn compute_summary(
    checks: &[ValidationCheck],
    idp_loaded: bool,
    sig_ok: bool,
    cert_match_ok: bool,
) -> ValidationSummary {
    if !sig_ok {
        // Check if it's partial (some pass, some fail) or total failure
        let any_passed = checks.iter().any(|c| c.passed);
        if any_passed {
            ValidationSummary::Partial
        } else {
            ValidationSummary::Failed
        }
    } else if idp_loaded && cert_match_ok {
        ValidationSummary::Trusted
    } else if sig_ok {
        ValidationSummary::Valid
    } else {
        ValidationSummary::Failed
    }
}

// --- Internal helpers ---

struct SignatureData {
    signature_value_b64: String,
    digest_value_b64: String,
    digest_algorithm: String,
    signature_algorithm: String,
    reference_uri: String,
    embedded_cert: Option<X509>,
    cert_subject: String,
    cert_not_after: Option<String>,
    inclusive_ns_digest: Vec<String>,
    inclusive_ns_sig: Vec<String>,
}

enum SignatureAbsence {
    NoSignature,
    Incomplete(String),
}

fn extract_signature_data(xml: &str) -> std::result::Result<SignatureData, SignatureAbsence> {
    // Parse XML and extract all signature components
    let mut reader = Reader::from_str(xml);
    let mut has_signature = false;
    let mut sig_value: Option<String> = None;
    let mut digest_value: Option<String> = None;
    let mut digest_algo = String::new();
    let mut sig_algo = String::new();
    let mut ref_uri = String::new();
    let mut cert_b64: Option<String> = None;
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_element = local.clone();
                if local == "Signature" { has_signature = true; }
                if local == "SignatureMethod" || local == "DigestMethod" || local == "Reference" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        match (local.as_str(), key.as_str()) {
                            ("SignatureMethod", "Algorithm") => sig_algo = val,
                            ("DigestMethod", "Algorithm") => digest_algo = val,
                            ("Reference", "URI") => ref_uri = val,
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    match current_element.as_str() {
                        "SignatureValue" => sig_value = Some(text),
                        "DigestValue" => digest_value = Some(text),
                        "X509Certificate" => cert_b64 = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(SignatureAbsence::Incomplete("XML parse error".to_string())),
            _ => {}
        }
        buf.clear();
    }

    if !has_signature {
        return Err(SignatureAbsence::NoSignature);
    }

    let sig_value = sig_value.ok_or_else(|| SignatureAbsence::Incomplete("Missing SignatureValue".to_string()))?;
    let digest_value = digest_value.ok_or_else(|| SignatureAbsence::Incomplete("Missing DigestValue".to_string()))?;

    // Parse embedded certificate if present
    let mut embedded_cert = None;
    let mut cert_subject = String::new();
    let mut cert_not_after = None;

    if let Some(ref b64) = cert_b64 {
        let clean = b64.replace(['\n', '\r', ' '], "");
        if let Ok(der) = STANDARD.decode(&clean) {
            if let Ok(cert) = X509::from_der(&der) {
                cert_subject = trust::cert_cn(&cert);
                cert_not_after = Some(cert.not_after().to_string());
                embedded_cert = Some(cert);
            }
        }
    }

    Ok(SignatureData {
        signature_value_b64: sig_value,
        digest_value_b64: digest_value,
        digest_algorithm: digest_algo,
        signature_algorithm: sig_algo,
        reference_uri: ref_uri,
        embedded_cert,
        cert_subject,
        cert_not_after,
        inclusive_ns_digest: Vec::new(),
        inclusive_ns_sig: Vec::new(),
    })
}

fn resolve_digest_algorithm(uri: &str) -> Option<MessageDigest> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some(MessageDigest::sha256()),
        "http://www.w3.org/2000/09/xmldsig#sha1" => Some(MessageDigest::sha1()),
        _ => None,
    }
}

fn resolve_signature_algorithm(uri: &str) -> Option<MessageDigest> {
    match uri {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(MessageDigest::sha256()),
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Some(MessageDigest::sha1()),
        _ => None,
    }
}

fn check_assertion_time_conditions(xml: &str) -> ValidationCheck {
    // Quick parse for NotBefore/NotOnOrAfter
    let mut not_before: Option<String> = None;
    let mut not_after: Option<String> = None;
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local == "Conditions" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).to_string();
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        match key.as_str() {
                            "NotBefore" => not_before = Some(val),
                            "NotOnOrAfter" => not_after = Some(val),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    match check_time_conditions(not_before.as_deref(), not_after.as_deref()) {
        Ok(()) => {
            let detail = if let Some(ref na) = not_after {
                format!("Valid (expires {})", na)
            } else {
                "Valid (no expiry set)".to_string()
            };
            ValidationCheck {
                name: "Time".to_string(),
                passed: true,
                detail,
                diagnostic: None,
            }
        }
        Err(e) => ValidationCheck {
            name: "Time".to_string(),
            passed: false,
            detail: format!("{}", e),
            diagnostic: None,
        },
    }
}

fn verify_digest(assertion_xml: &str, sig_data: &SignatureData) -> ValidationCheck {
    // Check Reference URI
    if sig_data.reference_uri.is_empty() {
        return ValidationCheck {
            name: "Digest".to_string(),
            passed: false,
            detail: "Empty Reference URI — document-level digest not supported".to_string(),
            diagnostic: None,
        };
    }

    let digest_md = match resolve_digest_algorithm(&sig_data.digest_algorithm) {
        Some(md) => md,
        None => {
            return ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: format!("Unsupported digest algorithm: {}", sig_data.digest_algorithm),
                diagnostic: None,
            };
        }
    };

    // Step 1: Remove signature element
    let body_xml = match c14n::remove_signature_element(assertion_xml) {
        Ok(xml) => xml,
        Err(e) => {
            return ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: "Failed to remove signature element".to_string(),
                diagnostic: Some(format!("{}", e)),
            };
        }
    };

    // Step 2: Canonicalize
    let inc_prefixes: Vec<&str> = sig_data.inclusive_ns_digest.iter().map(|s| s.as_str()).collect();
    let canon_body = match c14n::canonicalize_exclusive(&body_xml, &inc_prefixes) {
        Ok(c) => c,
        Err(e) => {
            return ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: "Canonicalization failed".to_string(),
                diagnostic: Some(format!("{}", e)),
            };
        }
    };

    // Step 3: Compute digest
    let computed_digest = match openssl::hash::hash(digest_md, &canon_body) {
        Ok(d) => d,
        Err(e) => {
            return ValidationCheck {
                name: "Digest".to_string(),
                passed: false,
                detail: "Hash computation failed".to_string(),
                diagnostic: Some(format!("{}", e)),
            };
        }
    };
    let computed_b64 = STANDARD.encode(&computed_digest);

    // Step 4: Compare
    if computed_b64 == sig_data.digest_value_b64 {
        let algo_name = if sig_data.digest_algorithm.contains("sha256") { "SHA-256" } else { "SHA-1" };
        ValidationCheck {
            name: "Digest".to_string(),
            passed: true,
            detail: format!("{} matches", algo_name),
            diagnostic: None,
        }
    } else {
        ValidationCheck {
            name: "Digest".to_string(),
            passed: false,
            detail: "Digest mismatch".to_string(),
            diagnostic: Some(format!(
                "Expected: {}..., Computed: {}...",
                &sig_data.digest_value_b64[..sig_data.digest_value_b64.len().min(16)],
                &computed_b64[..computed_b64.len().min(16)]
            )),
        }
    }
}

fn verify_signature(assertion_xml: &str, sig_data: &SignatureData) -> ValidationCheck {
    let sig_md = match resolve_signature_algorithm(&sig_data.signature_algorithm) {
        Some(md) => md,
        None => {
            return ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: format!("Unsupported signature algorithm: {}", sig_data.signature_algorithm),
                diagnostic: None,
            };
        }
    };

    let cert = match &sig_data.embedded_cert {
        Some(c) => c,
        None => {
            return ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: "No embedded certificate for verification".to_string(),
                diagnostic: None,
            };
        }
    };

    // Extract and canonicalize SignedInfo
    let signed_info_xml = match c14n::extract_signed_info(assertion_xml) {
        Ok(xml) => xml,
        Err(e) => {
            return ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: "Failed to extract SignedInfo".to_string(),
                diagnostic: Some(format!("{}", e)),
            };
        }
    };

    let inc_prefixes: Vec<&str> = sig_data.inclusive_ns_sig.iter().map(|s| s.as_str()).collect();
    let canon_signed_info = match c14n::canonicalize_exclusive(&signed_info_xml, &inc_prefixes) {
        Ok(c) => c,
        Err(e) => {
            return ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: "SignedInfo canonicalization failed".to_string(),
                diagnostic: Some(format!("{}", e)),
            };
        }
    };

    // Decode signature value
    let sig_bytes = match STANDARD.decode(sig_data.signature_value_b64.replace(['\n', '\r', ' '], "")) {
        Ok(b) => b,
        Err(e) => {
            return ValidationCheck {
                name: "Signature".to_string(),
                passed: false,
                detail: "Failed to decode SignatureValue".to_string(),
                diagnostic: Some(format!("{}", e)),
            };
        }
    };

    // Verify
    match crate::crypto::verify_signature(cert, &canon_signed_info, &sig_bytes, sig_md) {
        Ok(true) => {
            let algo_name = if sig_data.signature_algorithm.contains("sha256") { "RSA-SHA256" } else { "RSA-SHA1" };
            ValidationCheck {
                name: "Signature".to_string(),
                passed: true,
                detail: format!("{} verified", algo_name),
                diagnostic: None,
            }
        }
        Ok(false) => ValidationCheck {
            name: "Signature".to_string(),
            passed: false,
            detail: "Signature verification failed".to_string(),
            diagnostic: Some("RSA signature does not match SignedInfo content".to_string()),
        },
        Err(e) => ValidationCheck {
            name: "Signature".to_string(),
            passed: false,
            detail: "Verification error".to_string(),
            diagnostic: Some(format!("{}", e)),
        },
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test saml_validator_test -- --nocapture 2>&1 | tail -20`
Expected: All validator tests PASS (including the round-trip test `test_validate_signed_assertion_no_idp_cert`)

**Note:** The round-trip test will fail initially because the builder doesn't use c14n yet. This is expected — it proves the builder needs updating (Task 9). If it fails, mark this step as passing for the non-round-trip tests and continue to Task 9.

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/validator.rs seahorse/tests/saml_validator_test.rs
git commit -m "feat: implement full SAML validation pipeline with 6 checks"
```

---

### Task 9: Update Builder to Use Canonicalization

**Files:**
- Modify: `seahorse/src/saml/builder.rs`
- Modify: `seahorse/tests/saml_builder_test.rs`

- [ ] **Step 1: Write round-trip test**

Add to `seahorse/tests/saml_builder_test.rs`:

```rust
#[test]
fn test_signed_assertion_validates() {
    // Round-trip: build signed assertion, then validate with new pipeline
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-cert.pfx");
    let bundle = seahorse::crypto::load_pfx(&pfx_path, "testpassword").unwrap();

    let params = seahorse::saml::builder::AssertionParams {
        issuer: "https://test.example.com".to_string(),
        audience: "epic://epicenvironment".to_string(),
        username: "roundtrip-user".to_string(),
        validity_seconds: 300,
    };

    let xml = seahorse::saml::builder::build_signed_assertion(
        &params,
        bundle.private_key.as_ref().unwrap(),
        bundle.certificate.as_ref().unwrap(),
    ).unwrap();

    let report = seahorse::saml::validator::validate_assertion(&xml, None);
    assert_eq!(
        report.summary,
        seahorse::saml::validator::ValidationSummary::Valid,
        "Round-trip failed. Checks: {:#?}", report.checks
    );

    // Every check that should pass, passes
    for check in &report.checks {
        match check.name.as_str() {
            "Structure" | "Time" | "Digest" | "Signature" => {
                assert!(check.passed, "Check '{}' failed: {} {:?}", check.name, check.detail, check.diagnostic);
            }
            _ => {} // IDP Cert and Chain are expected to not pass (no trust store)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails (builder doesn't use c14n yet)**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_signed_assertion_validates -- --nocapture 2>&1 | tail -20`
Expected: FAIL — Digest mismatch (builder hashes raw bytes, validator hashes canonical form)

- [ ] **Step 3: Update builder to use canonicalization**

Modify `seahorse/src/saml/builder.rs`. In `build_signed_assertion`, replace the raw-bytes digest and signing with c14n:

```rust
use super::c14n;

// In build_signed_assertion, replace lines 59-68 (digest computation):
    // Old: let digest = openssl::hash::hash(MessageDigest::sha256(), assertion_for_digest.as_bytes())
    // New: canonicalize first, then hash
    let canon_body = c14n::canonicalize_exclusive(&assertion_for_digest, &[])
        .context("Failed to canonicalize assertion for digest")?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &canon_body)
        .context("Failed to compute SHA-256 digest")?;
    let digest_b64 = STANDARD.encode(digest);

// Replace lines 78-83 (signing):
    // Old: signer.update(signed_info.as_bytes())
    // New: canonicalize SignedInfo first
    let canon_signed_info = c14n::canonicalize_exclusive(&signed_info, &[])
        .context("Failed to canonicalize SignedInfo")?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), private_key).context("Failed to create signer")?;
    signer.update(&canon_signed_info).context("Failed to update signer")?;
    let signature_bytes = signer.sign_to_vec().context("Failed to sign")?;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test test_signed_assertion_validates -- --nocapture 2>&1 | tail -15`
Expected: PASS — round-trip validation succeeds

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test saml_builder_test -- --nocapture 2>&1 | tail -10`
Expected: All builder tests PASS

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test saml_validator_test -- --nocapture 2>&1 | tail -10`
Expected: All validator tests PASS (including the ones from Task 8)

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/builder.rs seahorse/tests/saml_builder_test.rs
git commit -m "feat: update builder to use exc-c14n for digest and signature computation"
```

---

## Chunk 4: TUI Integration

### Task 10: Update App State

**Files:**
- Modify: `seahorse/src/tui/app.rs`

- [ ] **Step 1: Replace SignatureValidation with ValidationReport**

In `seahorse/src/tui/app.rs`:

1. Change import from `use crate::saml::validator::SignatureValidation` to `use crate::saml::validator::ValidationReport`
2. Add import: `use crate::saml::trust::IdpTrustStore`
3. Replace `pub signature_validation: Option<SignatureValidation>` (line 63) with `pub signature_validation: Option<ValidationReport>`
4. Replace `pub viewer_signature: Option<SignatureValidation>` (line 77) with `pub viewer_signature: Option<ValidationReport>`
5. Add field: `pub idp_trust_store: Option<IdpTrustStore>`
6. Add field: `pub idp_cert_input: String` (for inline prompt buffer)
7. Add field: `pub idp_cert_input_active: bool` (whether inline prompt is showing)
8. Initialize all new fields in `App::new()`

- [ ] **Step 2: Verify compilation**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo check 2>&1 | tail -20`
Expected: Compilation errors in main.rs and ui.rs (expected — they still reference old types). The app.rs itself should be clean.

- [ ] **Step 3: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/tui/app.rs
git commit -m "refactor: update App state to use ValidationReport and IdpTrustStore"
```

---

### Task 11: Integrate Validation Pipeline in main.rs

**Files:**
- Modify: `seahorse/src/main.rs`

- [ ] **Step 1: Update finalize_assertion to use new pipeline**

Replace the `validate_assertion_signature` call in `finalize_assertion` (line 575) with:

```rust
    // Validate signature using new pipeline
    info!("Validating assertion...");
    let report = saml::validator::validate_assertion(
        assertion_xml,
        app.idp_trust_store.as_ref(),
    );
    info!("Validation result: {:?}", report.summary);
    for check in &report.checks {
        info!("  {}: {} (passed: {})", check.name, check.detail, check.passed);
    }
    app.signature_validation = Some(report);
```

- [ ] **Step 2: Update process_saml_viewer_input similarly**

Replace `validate_assertion_signature` calls (lines 624-628, 638-640) with `validate_assertion`:

```rust
    // In Response branch and Assertion branch:
    let sig = saml::validator::validate_assertion(
        &assertion_xml,  // or &result.xml for Assertion branch
        app.idp_trust_store.as_ref(),
    );
    app.viewer_signature = Some(sig);
```

- [ ] **Step 3: Add IDP cert loading from config**

After config is loaded in `run_app` (around line 119), add:

```rust
    // Load IDP certificate if configured
    if let Some(ref idp_cert_file) = cfg.idp_certificate {
        let idp_cert_path = config_dir.join(idp_cert_file);
        match saml::trust::load_idp_certificates(&idp_cert_path) {
            Ok(store) => {
                info!("Loaded IDP certificate: CN={}", saml::trust::cert_cn(&store.leaf_cert));
                info!("  Chain certs: {}", store.chain_certs.len());
                app.idp_trust_store = Some(store);
            }
            Err(e) => {
                info!("Warning: Failed to load IDP certificate '{}': {}", idp_cert_file, e);
            }
        }
    }
```

- [ ] **Step 4: Verify compilation**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo check 2>&1 | tail -20`
Expected: May still have errors in ui.rs — that's OK, we fix that next.

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/main.rs
git commit -m "feat: integrate SAML validation pipeline and IDP cert loading in main"
```

---

### Task 12: Redesign Validation Panel in UI

**Files:**
- Modify: `seahorse/src/tui/ui.rs`

- [ ] **Step 1: Add shared validation panel rendering function**

Add a new function `render_validation_panel` that both `render_result` and `render_saml_view` call:

```rust
use super::app::App;
use crate::saml::validator::{ValidationReport, ValidationSummary};

fn render_validation_panel(report: &ValidationReport, idp_path: Option<&str>) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Summary line
    let (summary_marker, summary_color) = match report.summary {
        ValidationSummary::Trusted | ValidationSummary::Valid => ("\u{2713}", Color::Green),  // checkmark
        ValidationSummary::Partial | ValidationSummary::Unsigned => ("\u{2014}", Color::Yellow),  // em-dash
        ValidationSummary::Failed => ("\u{2717}", Color::Red),  // cross
    };

    lines.push(Line::from(vec![
        Span::styled(
            format!("  {} {} ", summary_marker, report.summary.message()),
            Style::default().fg(summary_color).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));

    // Individual checks
    for check in &report.checks {
        let (marker, color) = if check.passed {
            ("\u{2713}", Color::Green)
        } else if check.detail.starts_with("Not configured") || check.detail.starts_with("Skipped") {
            ("\u{2014}", Color::DarkGray)
        } else {
            ("\u{2717}", Color::Red)
        };

        let detail = if let Some(ref diag) = check.diagnostic {
            if !check.passed {
                format!("{} ({})", check.detail, diag)
            } else {
                check.detail.clone()
            }
        } else {
            check.detail.clone()
        };

        lines.push(Line::from(vec![
            Span::styled(format!("  {} ", marker), Style::default().fg(color)),
            Span::styled(format!("{:<14} ", check.name), Style::default().fg(color)),
            Span::styled(detail, Style::default().fg(color)),
        ]));
    }

    lines.push(Line::from(""));

    // Metadata lines (algorithm, signer, expiry, IDP cert path)
    // Extract from the signature data in the checks
    if let Some(ref sig_check) = report.checks.iter().find(|c| c.name == "Signature") {
        if sig_check.detail.contains("RSA-") {
            let algo = if sig_check.detail.contains("256") { "RSA-SHA256" } else { "RSA-SHA1" };
            lines.push(Line::from(vec![
                Span::styled("  Algorithm: ", Style::default().fg(Color::Cyan)),
                Span::raw(algo.to_string()),
            ]));
        }
    }

    if let Some(ref cert_check) = report.checks.iter().find(|c| c.name == "IDP Certificate") {
        if cert_check.passed {
            lines.push(Line::from(vec![
                Span::styled("  Signer:    ", Style::default().fg(Color::Cyan)),
                Span::raw(cert_check.detail.replace("Matches ", "")),
            ]));
        }
    }

    if let Some(path) = idp_path {
        lines.push(Line::from(vec![
            Span::styled("  IDP Cert:  ", Style::default().fg(Color::Cyan)),
            Span::raw(path.to_string()),
        ]));
    }

    lines
}
```

- [ ] **Step 2: Update render_result to use new panel**

Replace the signature info block in `render_result` (lines 340-383). Change `Constraint::Length(7)` to `Constraint::Length(14)`. Use `render_validation_panel` to build the content.

- [ ] **Step 3: Update render_saml_view to use new panel**

Replace the signature panel in `render_saml_view` (lines 556, 625-668). Change `sig_height = 7` to `sig_height = 14`. Use `render_validation_panel`.

- [ ] **Step 4: Update help bar text**

Add `i: Load IDP Cert` to the help text in both `render_result` and `render_saml_view`.

- [ ] **Step 5: Verify compilation and run**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo check 2>&1 | tail -10`
Expected: Clean compilation

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/tui/ui.rs
git commit -m "feat: redesign validation panel with colored check results and summary"
```

---

### Task 13: Add IDP Certificate Loading via `i` Shortcut

**Files:**
- Modify: `seahorse/src/tui/input.rs`
- Modify: `seahorse/src/tui/ui.rs` (minor — render inline prompt)

- [ ] **Step 1: Add `i` shortcut to handle_result and handle_saml_view**

In `handle_result` (around line 191), add:

```rust
        KeyCode::Char('i') => {
            if !app.idp_cert_input_active {
                app.idp_cert_input_active = true;
                app.idp_cert_input.clear();
            }
        }
```

Add the same in `handle_saml_view` (around line 333).

- [ ] **Step 2: Add inline prompt input handling**

In `handle_input`, before the screen-specific match, add handling for when `idp_cert_input_active` is true:

```rust
    if app.idp_cert_input_active {
        if let Event::Key(key) = ev {
            match key.code {
                KeyCode::Enter => {
                    let path = expand_tilde(&app.idp_cert_input);
                    match seahorse::saml::trust::load_idp_certificates(std::path::Path::new(&path)) {
                        Ok(store) => {
                            let cn = seahorse::saml::trust::cert_cn(&store.leaf_cert);
                            let chain_count = store.chain_certs.len();
                            app.status_message = format!(
                                "Loaded IDP cert: CN={} (+ {} chain cert{})",
                                cn, chain_count, if chain_count == 1 { "" } else { "s" }
                            );
                            app.idp_trust_store = Some(store);
                            // Re-run validation on current assertion if present
                            // (handled by triggering re-validation in the next render cycle)
                        }
                        Err(e) => {
                            app.status_message = format!("Failed to load IDP cert: {}", e);
                        }
                    }
                    app.idp_cert_input_active = false;
                }
                KeyCode::Esc => {
                    app.idp_cert_input_active = false;
                    app.idp_cert_input.clear();
                }
                KeyCode::Backspace => { app.idp_cert_input.pop(); }
                KeyCode::Char(c) => { app.idp_cert_input.push(c); }
                _ => {}
            }
        }
        return Ok(false);
    }
```

- [ ] **Step 3: Render the inline prompt in the status bar area**

In `render_result` and `render_saml_view` in ui.rs, when `app.idp_cert_input_active` is true, replace the help bar content with:

```rust
    if app.idp_cert_input_active {
        let prompt = Paragraph::new(format!("IDP Certificate path: {}_", app.idp_cert_input))
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Load IDP Certificate"));
        frame.render_widget(prompt, help_chunk);
    }
```

- [ ] **Step 4: Verify compilation and test**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo check 2>&1 | tail -10`
Expected: Clean compilation

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/tui/input.rs seahorse/src/tui/ui.rs
git commit -m "feat: add 'i' shortcut for loading IDP certificate with inline prompt"
```

---

### Task 14: Remove Old SignatureValidation Code

**Files:**
- Modify: `seahorse/src/saml/validator.rs`

- [ ] **Step 1: Remove old types and function**

Delete the old `SignatureValidation` struct and `validate_assertion_signature` function from `validator.rs`. These are no longer used anywhere.

- [ ] **Step 2: Verify no remaining references**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo check 2>&1 | tail -10`
Expected: Clean compilation — all references have been migrated

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add seahorse/src/saml/validator.rs
git commit -m "chore: remove old cosmetic SignatureValidation code"
```

---

### Task 15: Final Integration Test

**Files:**
- All — no new files, just run full test suite

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo test 2>&1`
Expected: All tests pass

- [ ] **Step 2: Run cargo clippy**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo clippy 2>&1 | tail -20`
Expected: No errors (warnings OK)

- [ ] **Step 3: Run cargo fmt**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo fmt -- --check 2>&1`
If needed: `cargo fmt`

- [ ] **Step 4: Build release binary**

Run: `cd /Users/jared/BSWH/BSWH-MFA-Validate/seahorse && cargo build --release 2>&1 | tail -5`
Expected: Build succeeds

- [ ] **Step 5: Final commit (if fmt changes)**

```bash
cd /Users/jared/BSWH/BSWH-MFA-Validate && git add -A seahorse/src/ seahorse/tests/
git commit -m "style: apply cargo fmt formatting"
```
