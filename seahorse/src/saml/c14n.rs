use anyhow::{bail, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::{BTreeMap, HashSet};

/// Removes the first `<Signature>` element (including all children) from the XML.
/// Matches both prefixed (`<ds:Signature>`) and unprefixed (`<Signature>`) by local name.
/// Preserves exact byte content outside the signature element.
/// This implements the enveloped signature transform per XML-DSIG.
pub fn remove_signature_element(xml: &str) -> Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut output = Vec::new();
    let mut skip_depth: u32 = 0;
    let mut found_signature = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local_name = e.local_name();
                let local = String::from_utf8_lossy(local_name.as_ref());
                if local == "Signature" && !found_signature && skip_depth == 0 {
                    // Start skipping: this is the first Signature element
                    skip_depth = 1;
                    found_signature = true;
                    buf.clear();
                    continue;
                }
                if skip_depth > 0 {
                    skip_depth += 1;
                    buf.clear();
                    continue;
                }
                // Write the raw start tag
                output.push(b'<');
                output.extend_from_slice(e.as_ref());
                output.push(b'>');
            }
            Ok(Event::End(ref e)) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    buf.clear();
                    continue;
                }
                output.push(b'<');
                output.push(b'/');
                output.extend_from_slice(e.as_ref());
                output.push(b'>');
            }
            Ok(Event::Empty(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                let local_name = e.local_name();
                let local = String::from_utf8_lossy(local_name.as_ref());
                if local == "Signature" && !found_signature {
                    found_signature = true;
                    buf.clear();
                    continue;
                }
                output.push(b'<');
                output.extend_from_slice(e.as_ref());
                output.push(b'/');
                output.push(b'>');
            }
            Ok(Event::Text(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                // Use raw bytes -- do NOT unescape
                output.extend_from_slice(e.as_ref());
            }
            Ok(Event::CData(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                output.extend_from_slice(b"<![CDATA[");
                output.extend_from_slice(e.as_ref());
                output.extend_from_slice(b"]]>");
            }
            Ok(Event::Comment(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                output.extend_from_slice(b"<!--");
                output.extend_from_slice(e.as_ref());
                output.extend_from_slice(b"-->");
            }
            Ok(Event::PI(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                output.extend_from_slice(b"<?");
                output.extend_from_slice(e.as_ref());
                output.extend_from_slice(b"?>");
            }
            Ok(Event::Decl(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                output.extend_from_slice(b"<?xml ");
                output.extend_from_slice(e.as_ref());
                output.extend_from_slice(b"?>");
            }
            Ok(Event::DocType(ref e)) => {
                if skip_depth > 0 {
                    buf.clear();
                    continue;
                }
                output.extend_from_slice(b"<!DOCTYPE ");
                output.extend_from_slice(e.as_ref());
                output.push(b'>');
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error in remove_signature_element: {}", e),
        }
        buf.clear();
    }

    Ok(String::from_utf8(output)?)
}

// --- Exclusive XML Canonicalization (exc-c14n) ---

/// Per-element state tracking which ns prefixes have been rendered on the output.
#[derive(Debug, Clone)]
struct ElementScope {
    /// Namespace declarations rendered (output) at this level.
    /// Key = prefix, Value = URI.
    rendered: BTreeMap<String, String>,
}

/// Escape a text node value for canonical XML output.
/// Text uses: &amp; &lt; &gt; &#xD;
fn c14n_escape_text(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            0x0D => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
    out
}

/// Escape an attribute value for canonical XML output.
/// Attributes use: &amp; &lt; &quot; &#x9; &#xA; &#xD;
fn c14n_escape_attr(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            0x09 => out.extend_from_slice(b"&#x9;"),
            0x0A => out.extend_from_slice(b"&#xA;"),
            0x0D => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
    out
}

/// Extract prefix from a qualified name (e.g., "ds:SignedInfo" -> "ds", "Foo" -> "").
fn extract_prefix(qname: &str) -> &str {
    match qname.find(':') {
        Some(pos) => &qname[..pos],
        None => "",
    }
}

/// Collected attribute info for canonical sorting.
struct AttrInfo {
    qname: String,
    prefix: String,
    local: String,
    value: Vec<u8>,
}

/// Process a start/empty element for exc-c14n: collect namespaces, determine
/// which to render, sort attributes, and emit the opening tag.
/// Returns the element's qualified name (needed for empty-element close tags).
fn process_element_open(
    e: &quick_xml::events::BytesStart<'_>,
    output: &mut Vec<u8>,
    scope_stack: &mut Vec<ElementScope>,
    ns_stack: &mut Vec<BTreeMap<String, String>>,
    inclusive_set: &HashSet<&str>,
) -> Result<String> {
    let raw_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
    let elem_prefix = extract_prefix(&raw_name);

    // Inherit parent's in-scope namespaces
    let mut in_scope = ns_stack.last().cloned().unwrap_or_default();

    // Collect namespace declarations and regular attributes
    let mut attrs: Vec<AttrInfo> = Vec::new();

    for attr_result in e.attributes() {
        let attr = attr_result.map_err(|e| anyhow::anyhow!("Attribute error: {}", e))?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let value = attr.value.to_vec();

        if key == "xmlns" {
            // Default namespace declaration
            let uri = String::from_utf8_lossy(&value).to_string();
            in_scope.insert(String::new(), uri);
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            let uri = String::from_utf8_lossy(&value).to_string();
            in_scope.insert(prefix.to_string(), uri);
        } else {
            let prefix = extract_prefix(&key).to_string();
            let local_name = attr.key.local_name();
            let local = String::from_utf8_lossy(local_name.as_ref()).to_string();
            attrs.push(AttrInfo {
                qname: key,
                prefix,
                local,
                value,
            });
        }
    }

    // Determine visibly utilized namespace prefixes:
    // 1. The element's own prefix
    // 2. Each attribute's prefix (non-empty only)
    // 3. Any prefix in the inclusive_ns_prefixes list
    let mut utilized: HashSet<String> = HashSet::new();
    utilized.insert(elem_prefix.to_string());
    for attr in &attrs {
        if !attr.prefix.is_empty() {
            utilized.insert(attr.prefix.clone());
        }
    }
    for &inc_prefix in inclusive_set {
        utilized.insert(inc_prefix.to_string());
    }

    // Build cumulative rendered map from all ancestor scopes
    let mut parent_rendered: BTreeMap<String, String> = BTreeMap::new();
    for scope in scope_stack.iter() {
        for (p, u) in &scope.rendered {
            parent_rendered.insert(p.clone(), u.clone());
        }
    }

    // Determine which ns declarations to render
    let mut to_render: BTreeMap<String, String> = BTreeMap::new();
    for prefix in &utilized {
        if let Some(uri) = in_scope.get(prefix) {
            // For default namespace (prefix="") with empty URI: only render to
            // undeclare if an ancestor rendered a non-empty default ns
            if prefix.is_empty() && uri.is_empty() {
                if let Some(ancestor_uri) = parent_rendered.get("") {
                    if !ancestor_uri.is_empty() {
                        to_render.insert(prefix.clone(), uri.clone());
                    }
                }
                continue;
            }

            // Only render if not already rendered by an ancestor with same prefix->URI
            let already_rendered = parent_rendered.get(prefix) == Some(uri);
            if !already_rendered {
                to_render.insert(prefix.clone(), uri.clone());
            }
        }
    }

    // Build the output element
    output.push(b'<');
    output.extend_from_slice(raw_name.as_bytes());

    // Render namespace declarations sorted by prefix
    // Default namespace (prefix="") comes first as "xmlns", then prefixed sorted by BTreeMap order
    if let Some(uri) = to_render.get("") {
        output.extend_from_slice(b" xmlns=\"");
        output.extend_from_slice(&c14n_escape_attr(uri.as_bytes()));
        output.push(b'"');
    }
    for (prefix, uri) in &to_render {
        if prefix.is_empty() {
            continue; // already rendered above
        }
        output.extend_from_slice(b" xmlns:");
        output.extend_from_slice(prefix.as_bytes());
        output.extend_from_slice(b"=\"");
        output.extend_from_slice(&c14n_escape_attr(uri.as_bytes()));
        output.push(b'"');
    }

    // Sort attributes per exc-c14n:
    // First by namespace URI, then by local name.
    // Unprefixed attributes have no namespace URI (sort first).
    attrs.sort_by(|a, b| {
        let a_ns = if a.prefix.is_empty() {
            ""
        } else {
            in_scope.get(&a.prefix).map(|s| s.as_str()).unwrap_or("")
        };
        let b_ns = if b.prefix.is_empty() {
            ""
        } else {
            in_scope.get(&b.prefix).map(|s| s.as_str()).unwrap_or("")
        };
        a_ns.cmp(b_ns).then(a.local.cmp(&b.local))
    });

    for attr in &attrs {
        output.push(b' ');
        output.extend_from_slice(attr.qname.as_bytes());
        output.extend_from_slice(b"=\"");
        output.extend_from_slice(&c14n_escape_attr(&attr.value));
        output.push(b'"');
    }

    output.push(b'>');

    // Push scope
    scope_stack.push(ElementScope {
        rendered: to_render,
    });
    ns_stack.push(in_scope);

    Ok(raw_name)
}

/// Exclusive XML Canonicalization (exc-c14n) per W3C recommendation.
///
/// - Parses XML with quick-xml, maintains namespace context stack
/// - For each element: collect ns declarations, determine visibly utilized prefixes
///   (element prefix + attribute prefixes + inclusive_ns_prefixes), sort attributes,
///   emit only utilized ns declarations not already rendered by ancestors
/// - Expands empty elements: `<Foo/>` -> `<Foo></Foo>`
/// - Skips XML declarations, comments, PIs
/// - Applies canonical escaping for text and attributes
pub fn canonicalize_exclusive(xml: &str, inclusive_ns_prefixes: &[&str]) -> Result<Vec<u8>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut output = Vec::new();

    let mut scope_stack: Vec<ElementScope> = Vec::new();
    let mut ns_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let inclusive_set: HashSet<&str> = inclusive_ns_prefixes.iter().copied().collect();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                process_element_open(
                    e,
                    &mut output,
                    &mut scope_stack,
                    &mut ns_stack,
                    &inclusive_set,
                )?;
            }
            Ok(Event::Empty(ref e)) => {
                // Expand empty elements: <Foo/> -> <Foo></Foo>
                let raw_name = process_element_open(
                    e,
                    &mut output,
                    &mut scope_stack,
                    &mut ns_stack,
                    &inclusive_set,
                )?;
                // Immediately emit close tag and pop scope
                output.extend_from_slice(b"</");
                output.extend_from_slice(raw_name.as_bytes());
                output.push(b'>');
                scope_stack.pop();
                ns_stack.pop();
            }
            Ok(Event::End(ref e)) => {
                let name_ref = e.name();
                let raw_name = String::from_utf8_lossy(name_ref.as_ref());
                output.extend_from_slice(b"</");
                output.extend_from_slice(raw_name.as_bytes());
                output.push(b'>');
                scope_stack.pop();
                ns_stack.pop();
            }
            Ok(Event::Text(ref e)) => {
                // Unescape source entities, then re-escape per c14n rules
                let unescaped = e
                    .unescape()
                    .map_err(|err| anyhow::anyhow!("Text unescape error: {}", err))?;
                output.extend_from_slice(&c14n_escape_text(unescaped.as_bytes()));
            }
            Ok(Event::Decl(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {
                // Skip XML declarations, comments, and processing instructions per c14n
            }
            Ok(Event::CData(ref e)) => {
                // CDATA sections are replaced by their content (escaped as text)
                output.extend_from_slice(&c14n_escape_text(e.as_ref()));
            }
            Ok(Event::DocType(_)) => {
                // Skip DOCTYPE per c14n
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error in canonicalize_exclusive: {}", e),
        }
        buf.clear();
    }

    Ok(output)
}

/// Extracts the `<SignedInfo>` element from a SAML assertion XML string.
///
/// Parses the full assertion, tracking namespace declarations on ancestors
/// (`<Assertion>`, `<Signature>`, etc.). When `<SignedInfo>` is found, the
/// extracted fragment includes inherited namespace declarations that are
/// visibly utilized, making it self-contained for canonicalization.
///
/// Returns the raw XML string of the `<SignedInfo>` element with inherited
/// namespace declarations injected onto the opening tag.
pub fn extract_signed_info(xml: &str) -> Result<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    // Track namespace declarations from ancestor elements
    // Each entry is a vector of (prefix, uri) pairs declared on that element
    let mut ancestor_ns_stack: Vec<BTreeMap<String, String>> = Vec::new();

    // State machine: looking for SignedInfo, then capturing it
    let mut in_signed_info = false;
    let mut signed_info_depth: u32 = 0;
    let mut signed_info_raw = Vec::<u8>::new();
    let mut signed_info_open_tag: Option<Vec<u8>> = None; // The opening <ds:SignedInfo ...> with injected ns
    let mut found = false;

    // Collect all in-scope ns declarations from ancestors when we hit SignedInfo
    let mut inherited_ns: BTreeMap<String, String> = BTreeMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local_name = e.local_name();
                let local = String::from_utf8_lossy(local_name.as_ref()).to_string();

                if in_signed_info {
                    // Capture raw content inside SignedInfo
                    signed_info_raw.push(b'<');
                    signed_info_raw.extend_from_slice(e.as_ref());
                    signed_info_raw.push(b'>');
                    signed_info_depth += 1;
                } else if local == "SignedInfo" {
                    // Found SignedInfo! Collect inherited namespaces
                    inherited_ns.clear();
                    for scope in &ancestor_ns_stack {
                        for (prefix, uri) in scope {
                            inherited_ns.insert(prefix.clone(), uri.clone());
                        }
                    }

                    // Determine which inherited ns prefixes are needed on SignedInfo itself.
                    // We need to look at the element name prefix and attribute prefixes.
                    let raw_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let elem_prefix = extract_prefix(&raw_name).to_string();

                    // Collect this element's own ns declarations and attributes
                    let mut own_ns: BTreeMap<String, String> = BTreeMap::new();
                    let mut attr_prefixes: HashSet<String> = HashSet::new();

                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        if key == "xmlns" {
                            let uri = String::from_utf8_lossy(&attr.value).to_string();
                            own_ns.insert(String::new(), uri);
                        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                            let uri = String::from_utf8_lossy(&attr.value).to_string();
                            own_ns.insert(prefix.to_string(), uri);
                        } else {
                            let p = extract_prefix(&key).to_string();
                            if !p.is_empty() {
                                attr_prefixes.insert(p);
                            }
                        }
                    }

                    // Build the opening tag with inherited ns declarations injected
                    let mut open_tag = Vec::new();
                    open_tag.push(b'<');
                    open_tag.extend_from_slice(raw_name.as_bytes());

                    // Determine which inherited ns to inject: those whose prefix
                    // is used by this element or its attributes, and not already declared here
                    let mut needed_prefixes: HashSet<String> = HashSet::new();
                    // An unprefixed element uses the default namespace (empty prefix)
                    needed_prefixes.insert(elem_prefix);
                    needed_prefixes.extend(attr_prefixes);

                    // Inject inherited ns declarations for needed prefixes
                    // (sorted by prefix for deterministic output)
                    let mut injected: BTreeMap<String, String> = BTreeMap::new();
                    for prefix in &needed_prefixes {
                        if !own_ns.contains_key(prefix) {
                            if let Some(uri) = inherited_ns.get(prefix) {
                                injected.insert(prefix.clone(), uri.clone());
                            }
                        }
                    }

                    // Write own ns declarations (preserve from original)
                    // Then write injected inherited ns declarations
                    // Then write regular attributes
                    // Note: we reconstruct the attributes in original order plus injected ns
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        open_tag.push(b' ');
                        open_tag.extend_from_slice(key.as_bytes());
                        open_tag.extend_from_slice(b"=\"");
                        open_tag.extend_from_slice(&attr.value);
                        open_tag.push(b'"');
                    }

                    // Now inject inherited ns declarations
                    if let Some(uri) = injected.get("") {
                        open_tag.extend_from_slice(b" xmlns=\"");
                        open_tag.extend_from_slice(uri.as_bytes());
                        open_tag.push(b'"');
                    }
                    for (prefix, uri) in &injected {
                        if prefix.is_empty() {
                            continue;
                        }
                        open_tag.extend_from_slice(b" xmlns:");
                        open_tag.extend_from_slice(prefix.as_bytes());
                        open_tag.extend_from_slice(b"=\"");
                        open_tag.extend_from_slice(uri.as_bytes());
                        open_tag.push(b'"');
                    }

                    open_tag.push(b'>');
                    signed_info_open_tag = Some(open_tag);
                    in_signed_info = true;
                    signed_info_depth = 1;
                    found = true;
                } else {
                    // Track namespace declarations on this ancestor element
                    let mut ns_decls: BTreeMap<String, String> = BTreeMap::new();
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        if key == "xmlns" {
                            let uri = String::from_utf8_lossy(&attr.value).to_string();
                            ns_decls.insert(String::new(), uri);
                        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                            let uri = String::from_utf8_lossy(&attr.value).to_string();
                            ns_decls.insert(prefix.to_string(), uri);
                        }
                    }
                    ancestor_ns_stack.push(ns_decls);
                }
            }
            Ok(Event::Empty(ref e)) => {
                if in_signed_info {
                    signed_info_raw.push(b'<');
                    signed_info_raw.extend_from_slice(e.as_ref());
                    signed_info_raw.push(b'/');
                    signed_info_raw.push(b'>');
                } else {
                    let local_name = e.local_name();
                    let local = String::from_utf8_lossy(local_name.as_ref()).to_string();
                    if local == "SignedInfo" {
                        // Empty SignedInfo -- unusual but handle it
                        // Collect inherited ns
                        inherited_ns.clear();
                        for scope in &ancestor_ns_stack {
                            for (prefix, uri) in scope {
                                inherited_ns.insert(prefix.clone(), uri.clone());
                            }
                        }
                        let raw_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        let elem_prefix = extract_prefix(&raw_name).to_string();

                        let mut result = String::from("<");
                        result.push_str(&raw_name);

                        // Copy existing attributes
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let val = String::from_utf8_lossy(&attr.value);
                            result.push(' ');
                            result.push_str(&key);
                            result.push_str("=\"");
                            result.push_str(&val);
                            result.push('"');
                        }

                        // Inject inherited ns for element prefix if needed
                        if !elem_prefix.is_empty() {
                            let has_own = e.attributes().flatten().any(|a| {
                                let k = String::from_utf8_lossy(a.key.as_ref());
                                k == format!("xmlns:{}", elem_prefix)
                            });
                            if !has_own {
                                if let Some(uri) = inherited_ns.get(&elem_prefix) {
                                    result.push_str(&format!(" xmlns:{}=\"{}\"", elem_prefix, uri));
                                }
                            }
                        }

                        result.push_str("/>");
                        return Ok(result);
                    }
                    // Not SignedInfo, still an ancestor -- push empty ns scope
                    // (Empty elements don't add to ancestor stack since they have no children)
                }
            }
            Ok(Event::End(ref e)) => {
                if in_signed_info {
                    signed_info_depth -= 1;
                    let name_ref = e.name();
                    let raw_name = String::from_utf8_lossy(name_ref.as_ref());
                    if signed_info_depth == 0 {
                        // We've captured all of SignedInfo's content
                        let mut result = Vec::new();
                        if let Some(open) = signed_info_open_tag.take() {
                            result.extend_from_slice(&open);
                        }
                        result.extend_from_slice(&signed_info_raw);
                        result.extend_from_slice(b"</");
                        result.extend_from_slice(raw_name.as_bytes());
                        result.push(b'>');
                        return Ok(String::from_utf8(result)?);
                    } else {
                        signed_info_raw.extend_from_slice(b"</");
                        signed_info_raw.extend_from_slice(raw_name.as_bytes());
                        signed_info_raw.push(b'>');
                    }
                } else {
                    ancestor_ns_stack.pop();
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_signed_info {
                    // Preserve raw text bytes
                    signed_info_raw.extend_from_slice(e.as_ref());
                }
            }
            Ok(Event::CData(ref e)) => {
                if in_signed_info {
                    signed_info_raw.extend_from_slice(b"<![CDATA[");
                    signed_info_raw.extend_from_slice(e.as_ref());
                    signed_info_raw.extend_from_slice(b"]]>");
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {} // Skip Decl, Comment, PI, DocType
            Err(e) => bail!("XML parse error in extract_signed_info: {}", e),
        }
        buf.clear();
    }

    if !found {
        bail!("No SignedInfo element found in the XML");
    }

    // Should not reach here if found was true (we return inside the End handler)
    bail!("SignedInfo element was not properly closed");
}
