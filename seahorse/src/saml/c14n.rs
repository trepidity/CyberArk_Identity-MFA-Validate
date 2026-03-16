use anyhow::{bail, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

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
