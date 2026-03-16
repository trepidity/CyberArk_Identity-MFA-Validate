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
