use seahorse::saml::c14n;

#[test]
fn test_remove_signature_prefixed() {
    let xml = r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_123"><saml2:Issuer>test</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>abc</ds:SignatureValue></ds:Signature><saml2:Subject><saml2:NameID>user</saml2:NameID></saml2:Subject></saml2:Assertion>"#;
    let result = c14n::remove_signature_element(xml).unwrap();
    assert!(!result.contains("Signature"), "Got: {}", result);
    assert!(result.contains("saml2:Assertion"), "Got: {}", result);
    assert!(result.contains("saml2:Subject"), "Got: {}", result);
}

#[test]
fn test_remove_signature_unprefixed() {
    let xml = r#"<Assertion><Issuer>test</Issuer><Signature><SignedInfo/><SignatureValue>abc</SignatureValue></Signature><Subject>user</Subject></Assertion>"#;
    let result = c14n::remove_signature_element(xml).unwrap();
    assert!(!result.contains("Signature"), "Got: {}", result);
    assert!(result.contains("<Assertion>"), "Got: {}", result);
}

#[test]
fn test_remove_signature_no_signature() {
    let xml = r#"<Assertion><Issuer>test</Issuer><Subject>user</Subject></Assertion>"#;
    let result = c14n::remove_signature_element(xml).unwrap();
    assert_eq!(result, xml);
}

// --- Task 3: canonicalize_exclusive tests ---

#[test]
fn test_c14n_empty_element_expansion() {
    let xml = r#"<root><empty/></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(output.contains("<empty></empty>"), "Got: {}", output);
}

#[test]
fn test_c14n_attribute_sorting() {
    let xml = r#"<root z="1" a="2" m="3"></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(output.contains(r#"a="2" m="3" z="1""#), "Got: {}", output);
}

#[test]
fn test_c14n_namespace_visibly_utilized() {
    let xml = r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><a:child>text</a:child></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &[]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(
        output.contains(r#"<a:child xmlns:a="urn:a">"#),
        "Got: {}",
        output
    );
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
}

#[test]
fn test_c14n_inclusive_ns_prefixes() {
    let xml = r#"<root xmlns:a="urn:a" xmlns:b="urn:b"><child>text</child></root>"#;
    let result = c14n::canonicalize_exclusive(xml, &["a"]).unwrap();
    let output = String::from_utf8(result).unwrap();
    assert!(output.contains(r#"xmlns:a="urn:a""#), "Got: {}", output);
}

// --- Task 4: extract_signed_info tests ---

#[test]
fn test_extract_signed_info_with_inherited_ns() {
    let xml = r##"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_123"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>abc</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>sig</ds:SignatureValue></ds:Signature></saml2:Assertion>"##;
    let result = c14n::extract_signed_info(xml).unwrap();
    assert!(
        result.contains("xmlns:ds="),
        "Missing xmlns:ds in: {}",
        result
    );
    assert!(result.contains("ds:SignedInfo"), "Got: {}", result);
    assert!(result.contains("ds:DigestValue"), "Got: {}", result);
    assert!(!result.contains("SignatureValue"), "Got: {}", result);
}

#[test]
fn test_extract_signed_info_no_signed_info() {
    let xml = r#"<Assertion><Subject>user</Subject></Assertion>"#;
    let result = c14n::extract_signed_info(xml);
    assert!(result.is_err());
}
