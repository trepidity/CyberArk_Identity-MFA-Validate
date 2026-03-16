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
