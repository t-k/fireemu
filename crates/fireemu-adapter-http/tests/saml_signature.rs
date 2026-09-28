//! Signed SAML responses the strict profile verifies (AUTH-FEDERATION O5 stage B): the
//! vectors in `tests/data/saml/` were signed by the conformance harness's signer, whose
//! canonical form is checked byte for byte against `xmllint --exc-c14n`, so this verifier's
//! canonicalization is checked against an independent implementation. The same signed
//! documents written differently (reordered namespaces and attributes, redundant and unused
//! declarations, padded and self-closed tags, character references) verify too.
use fireemu_adapter_http::saml::{
    canonicalize, certificate_key, verify_saml_response, SamlError, MAX_RESPONSE_BYTES,
};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/data/saml/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn idp() -> Vec<String> {
    vec![fixture("idp.cert.pem")]
}

#[test]
fn a_response_signed_in_each_position_verifies_in_any_serialization() {
    for position in ["assertion", "response", "both"] {
        for form in ["", "-noisy"] {
            let name = format!("{position}-signed{form}.xml");
            let verified = verify_saml_response(&fixture(&name), &idp())
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(verified.response_signed, position != "assertion", "{name}");
            assert_eq!(verified.assertion_signed, position != "response", "{name}");
            assert_eq!(
                verified.name_id.as_deref(),
                Some("fixture-user@example.com"),
                "{name}"
            );
            assert_eq!(
                verified.name_id_format.as_deref(),
                Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            );
            assert_eq!(
                verified.issuer.as_deref(),
                Some("https://idp.example.test/saml/fixture")
            );
            assert_eq!(verified.audiences, vec!["fireemu-fixture-sp".to_owned()]);
            let callback = "https://demo-project.firebaseapp.com/__/auth/handler";
            assert_eq!(verified.destination.as_deref(), Some(callback));
            assert_eq!(verified.recipient.as_deref(), Some(callback));
            assert_eq!(verified.in_response_to.as_deref(), Some("_request-1"));
            assert_eq!(
                verified.confirmation_in_response_to.as_deref(),
                Some("_request-1")
            );
            assert_eq!(verified.not_before.as_deref(), Some("2027-01-15T07:59:00Z"));
            assert_eq!(
                verified.not_on_or_after.as_deref(),
                Some("2027-01-15T08:05:00Z")
            );
            assert_eq!(
                verified.attributes["role"],
                vec!["reader & <writer>".to_owned()],
                "{name}"
            );
            assert_eq!(
                verified.attributes["display name"],
                vec!["Fixture \"User\"".to_owned()],
                "{name}"
            );
        }
    }
}

#[test]
fn a_signature_that_does_not_verify_is_refused() {
    for name in [
        "tampered-signature.xml",
        "tampered-content.xml",
        "other-key.xml",
        "unsigned.xml",
    ] {
        assert_eq!(
            verify_saml_response(&fixture(name), &idp()),
            Err(SamlError::Signature),
            "{name}"
        );
    }
    // Only the configured certificates count: the other key verifies once it is configured.
    let both = vec![fixture("idp.cert.pem"), fixture("other.cert.pem")];
    assert!(verify_saml_response(&fixture("other-key.xml"), &both).is_ok());
    assert_eq!(
        verify_saml_response(
            &fixture("assertion-signed.xml"),
            &[fixture("other.cert.pem")]
        ),
        Err(SamlError::Signature)
    );
}

#[test]
fn only_an_assertion_a_verified_signature_covers_is_read() {
    // An unsigned assertion placed before the signed one is never read.
    let verified = verify_saml_response(&fixture("wrapped.xml"), &idp()).unwrap();
    assert_eq!(
        verified.name_id.as_deref(),
        Some("fixture-user@example.com")
    );
    assert!(verified.assertion_signed && !verified.response_signed);
    // A signature whose reference names another element's ID does not verify.
    let moved =
        fixture("assertion-signed.xml").replace("URI=\"#_assertion-1\"", "URI=\"#_response-1\"");
    assert_eq!(
        verify_saml_response(&moved, &idp()),
        Err(SamlError::Signature)
    );
}

#[test]
fn a_response_without_a_name_id_verifies_and_says_so() {
    let verified = verify_saml_response(&fixture("no-name-id.xml"), &idp()).unwrap();
    assert!(verified.response_signed);
    assert_eq!(verified.name_id, None);
}

#[test]
fn documents_that_are_not_plain_saml_responses_are_refused() {
    assert!(matches!(
        verify_saml_response(&fixture("doctype.xml"), &idp()),
        Err(SamlError::Malformed(_))
    ));
    assert!(matches!(
        verify_saml_response("not xml", &idp()),
        Err(SamlError::Malformed(_))
    ));
    assert!(matches!(
        verify_saml_response("<a xmlns=\"urn:x\"/>", &idp()),
        Err(SamlError::Malformed("not a samlp:Response"))
    ));
    let large = format!(
        "{}{}",
        fixture("assertion-signed.xml"),
        " ".repeat(MAX_RESPONSE_BYTES)
    );
    assert!(matches!(
        verify_saml_response(&large, &idp()),
        Err(SamlError::Malformed(_))
    ));
    let deep = format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">{}{}</samlp:Response>",
        "<x>".repeat(80),
        "</x>".repeat(80)
    );
    assert!(matches!(
        verify_saml_response(&deep, &idp()),
        Err(SamlError::Malformed(_))
    ));
    let encrypted = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:EncryptedAssertion/></samlp:Response>";
    assert!(matches!(
        verify_saml_response(encrypted, &idp()),
        Err(SamlError::Unsupported(_))
    ));
}

#[test]
fn certificates_give_their_rsa_key_and_nothing_else_does() {
    assert!(certificate_key(&fixture("idp.cert.pem")).is_some());
    for junk in [
        "",
        "not a pem",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
    ] {
        assert!(certificate_key(junk).is_none(), "{junk:?}");
        assert_eq!(
            verify_saml_response(&fixture("assertion-signed.xml"), &[junk.to_owned()]),
            Err(SamlError::Certificates)
        );
    }
}

/// The exclusive canonical form of small documents, as `xmllint --exc-c14n` prints them.
#[test]
fn exclusive_canonicalization_matches_xmllint() {
    let cases = [
        // Attributes sorted by namespace then name, namespaces rendered where used.
        (
            r#"<p:a xmlns:p="urn:p" xmlns:q="urn:q" z="1" q:b="2" a="3"><b/></p:a>"#,
            r#"<p:a xmlns:p="urn:p" xmlns:q="urn:q" a="3" z="1" q:b="2"><b></b></p:a>"#,
        ),
        // An unused declaration is dropped; a default namespace is rendered where it applies.
        (
            r#"<a xmlns="urn:d" xmlns:u="urn:unused"><b xmlns="">t</b></a>"#,
            r#"<a xmlns="urn:d"><b xmlns="">t</b></a>"#,
        ),
        // Text and attribute escaping, whitespace kept, character references resolved.
        (
            "<a x=\"&#9;&#10;&quot;&lt;&amp;\">&#13;&amp;&lt;&gt; &#x41;\n</a>",
            "<a x=\"&#x9;&#xA;&quot;&lt;&amp;\">&#xD;&amp;&lt;&gt; A\n</a>",
        ),
        // Processing instructions are kept, comments are not.
        (
            "<a><?pi data?><!--c--><?empty?></a>",
            "<a><?pi data?><?empty?></a>",
        ),
    ];
    for (input, expected) in cases {
        let doc = roxmltree::Document::parse(input).unwrap();
        assert_eq!(
            canonicalize(input, doc.root_element(), None, &[], false).unwrap(),
            expected,
            "{input}"
        );
    }
    // With comments, and a prefix an InclusiveNamespaces list names is rendered though unused.
    let input = r#"<a xmlns:i="urn:i"><!--c--></a>"#;
    let doc = roxmltree::Document::parse(input).unwrap();
    assert_eq!(
        canonicalize(input, doc.root_element(), None, &["i".to_owned()], true).unwrap(),
        r#"<a xmlns:i="urn:i"><!--c--></a>"#
    );
}

/// Signature wrapping (XSW): how the verifier reads documents that bend the binding between a
/// signature and the data read. Production's handling of these forms is unobserved; the
/// tests fix this verifier's reading, which never follows an ID lookup: a signature covers the
/// element it is enveloped in, and only a direct assertion of the response is read.
#[test]
fn signature_wrapping_forms_are_read_by_the_enveloping_element_only() {
    let signed = fixture("assertion-signed.xml");
    // Another element with the same ID (an unsigned assertion before the signed one): the
    // signature still covers its enveloping assertion, and that one is read.
    let forged = "<saml:Assertion ID=\"_assertion-1\" Version=\"2.0\"><saml:Issuer>https://idp.example.test/saml/fixture</saml:Issuer><saml:Subject><saml:NameID>attacker@example.com</saml:NameID></saml:Subject></saml:Assertion>";
    let duplicated = signed.replacen("<saml:Assertion ", &format!("{forged}<saml:Assertion "), 1);
    let verified = verify_saml_response(&duplicated, &idp()).unwrap();
    assert_eq!(
        verified.name_id.as_deref(),
        Some("fixture-user@example.com")
    );

    // A signed response embedded in another document is not a SAML response.
    let embedded = signed.replacen(
        "<samlp:Response ",
        "<wrapper xmlns=\"urn:x\"><samlp:Response ",
        1,
    ) + "</wrapper>";
    let embedded = embedded.replacen("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "", 1);
    assert!(matches!(
        verify_saml_response(&embedded, &idp()),
        Err(SamlError::Malformed("not a samlp:Response"))
    ));

    // Only a direct assertion of the response is read: one below samlp:Extensions is not, with
    // or without a direct one beside it (the response signature covers both).
    assert!(matches!(
        verify_saml_response(&fixture("nested-assertion.xml"), &idp()),
        Err(SamlError::Malformed("no assertion"))
    ));
    let beside = verify_saml_response(&fixture("nested-beside-direct.xml"), &idp()).unwrap();
    assert_eq!(beside.name_id.as_deref(), Some("fixture-user@example.com"));

    // The signed element's ID is its unqualified `ID` attribute, exactly: another case or a
    // namespaced `ID` does not name it.
    let lowercase = signed.replacen("ID=\"_assertion-1\"", "Id=\"_assertion-1\"", 1);
    assert!(matches!(
        verify_saml_response(&lowercase, &idp()),
        Err(SamlError::Malformed("the signed element has no ID"))
    ));
    let namespaced = signed.replacen(
        "ID=\"_assertion-1\"",
        "xmlns:x=\"urn:x\" x:ID=\"_assertion-1\" ID=\"_other\"",
        1,
    );
    assert_eq!(
        verify_saml_response(&namespaced, &idp()),
        Err(SamlError::Signature)
    );
}
