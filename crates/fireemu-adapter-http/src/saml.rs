//! Verification of signed SAML 2.0 responses for the strict profile (AUTH-FEDERATION, owner
//! decision O5 stage B, R2): XML signatures (enveloped, exclusive canonicalization) checked
//! with the RSA keys of the provider's configured X.509 certificates. `KeyInfo` is never
//! trusted, and no key is fetched.
//!
//! Only the signature and the data a sign-in needs are established here; which SAML
//! conditions (audience, destination, time window, `InResponseTo`) a caller enforces rests on
//! production evidence and is decided by the caller.
//!
//! The document is parsed with `roxmltree` without a DTD and with a node limit; a signature
//! covers the element its `Reference` names by `ID`, and only an assertion a verified signature
//! covers is read (a signed response covers its assertions; an unsigned assertion beside a
//! signed one is never read).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use roxmltree::{Document, Node, NodeId, ParsingOptions};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// The largest SAML response read (decoded), and the node and depth limits of its tree.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_NODES: u32 = 20_000;
const MAX_DEPTH: usize = 64;
/// Bounds on the canonicalization input no identity provider comes near, so that its cost
/// stays linear in the document: namespaces in scope of an element, distinct prefixes of an
/// `InclusiveNamespaces` list, and nodes of a `SignedInfo` (canonicalized before its signature
/// is known to verify). Beyond them a response is [`SamlError::Unsupported`].
const MAX_NAMESPACES: usize = 64;
const MAX_INCLUSIVE_PREFIXES: usize = 64;
const MAX_SIGNED_INFO_NODES: usize = 128;

/// Why a response is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlError {
    /// Not a SAML response this verifier reads (not XML, a DTD, too large or deep, no
    /// `samlp:Response`, a signature without its parts).
    Malformed(&'static str),
    /// A signature that does not verify with any configured certificate, or no signature
    /// covering an assertion (production: "Failed to verify the signature in `SAMLResponse`").
    Signature,
    /// An algorithm or form this verifier does not implement (a known limitation, not a
    /// production refusal).
    Unsupported(String),
    /// No configured certificate holds an RSA public key.
    Certificates,
}

/// What a verified response says, for the caller's checks and the sign-in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedSaml {
    /// Whether the response element carries a verified signature.
    pub response_signed: bool,
    /// Whether the assertion read carries a verified signature of its own.
    pub assertion_signed: bool,
    /// `Response/@Destination`.
    pub destination: Option<String>,
    /// `Response/@InResponseTo`.
    pub in_response_to: Option<String>,
    /// The assertion's `Issuer`.
    pub issuer: Option<String>,
    /// `Subject/NameID` and its `Format`.
    pub name_id: Option<String>,
    /// `NameID/@Format`.
    pub name_id_format: Option<String>,
    /// The bearer `SubjectConfirmationData` (`Recipient`, `InResponseTo`, `NotOnOrAfter`).
    pub recipient: Option<String>,
    /// `SubjectConfirmationData/@InResponseTo`.
    pub confirmation_in_response_to: Option<String>,
    /// `SubjectConfirmationData/@NotOnOrAfter`.
    pub confirmation_not_on_or_after: Option<String>,
    /// `Conditions/@NotBefore` and `@NotOnOrAfter`.
    pub not_before: Option<String>,
    /// `Conditions/@NotOnOrAfter`.
    pub not_on_or_after: Option<String>,
    /// Every `AudienceRestriction/Audience`.
    pub audiences: Vec<String>,
    /// `AttributeStatement` values by attribute `Name`, in document order.
    pub attributes: BTreeMap<String, Vec<String>>,
}

/// Verifies `xml` (a decoded `SAMLResponse`) with the RSA keys of `certificates` (PEM, as the
/// provider configuration holds them).
///
/// # Errors
/// [`SamlError`]: the response is malformed, a signature present does not verify, no verified
/// signature covers an assertion, or an algorithm is not implemented.
pub fn verify_saml_response(xml: &str, certificates: &[String]) -> Result<VerifiedSaml, SamlError> {
    if xml.len() > MAX_RESPONSE_BYTES {
        return Err(SamlError::Malformed("the response is too large"));
    }
    let keys: Vec<RsaPublicKey> = certificates
        .iter()
        .filter_map(|pem| certificate_key(pem))
        .collect();
    if keys.is_empty() {
        return Err(SamlError::Certificates);
    }
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_NODES,
        ..ParsingOptions::default()
    };
    let doc =
        Document::parse_with_options(xml, options).map_err(|_| SamlError::Malformed("not XML"))?;
    if doc
        .descendants()
        .any(|node| node.ancestors().count() > MAX_DEPTH)
    {
        return Err(SamlError::Malformed("the response nests too deeply"));
    }
    if doc
        .descendants()
        .any(|node| node.namespaces().len() > MAX_NAMESPACES)
    {
        return Err(SamlError::Unsupported(format!(
            "more than {MAX_NAMESPACES} namespaces in scope"
        )));
    }
    let response = doc.root_element();
    if !response.has_tag_name((PROTOCOL, "Response")) {
        return Err(SamlError::Malformed("not a samlp:Response"));
    }
    let assertions: Vec<Node> = response
        .children()
        .filter(|node| node.has_tag_name((ASSERTION, "Assertion")))
        .collect();
    if assertions.is_empty()
        && response
            .children()
            .any(|node| node.has_tag_name((ASSERTION, "EncryptedAssertion")))
    {
        return Err(SamlError::Unsupported("encrypted assertions".to_owned()));
    }

    let response_signed = match signature_of(response) {
        Some(signature) => {
            verify_enveloped(xml, response, signature, &keys)?;
            true
        }
        None => false,
    };
    let mut signed_assertion = None;
    for assertion in &assertions {
        if let Some(signature) = signature_of(*assertion) {
            verify_enveloped(xml, *assertion, signature, &keys)?;
            signed_assertion.get_or_insert(*assertion);
        }
    }
    // The assertion read is one a verified signature covers: the signed assertion, or the
    // first assertion of a signed response.
    let assertion = match (signed_assertion, response_signed) {
        (Some(assertion), _) => assertion,
        (None, true) => *assertions
            .first()
            .ok_or(SamlError::Malformed("no assertion"))?,
        (None, false) => return Err(SamlError::Signature),
    };
    Ok(read_assertion(
        response,
        assertion,
        response_signed,
        signed_assertion.is_some(),
    ))
}

/// The `ds:Signature` child of `element`, if it has one.
fn signature_of<'a, 'input>(element: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    element
        .children()
        .find(|node| node.has_tag_name((DSIG, "Signature")))
}

fn child<'a, 'input>(node: Node<'a, 'input>, ns: &str, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| child.has_tag_name((ns, name)))
}

fn algorithm<'a>(node: Option<Node<'a, '_>>) -> Option<&'a str> {
    node?.attribute("Algorithm")
}

/// The exclusive canonicalization of an `Algorithm`: with comments or not, and the distinct
/// prefixes of the `InclusiveNamespaces` list a transform names.
fn exclusive_c14n(method: Node) -> Result<(bool, Vec<String>), SamlError> {
    let comments = match method.attribute("Algorithm") {
        Some(EXC_C14N) => false,
        Some(EXC_C14N_COMMENTS) => true,
        other => {
            return Err(SamlError::Unsupported(format!(
                "canonicalization {other:?}"
            )))
        }
    };
    let mut prefixes: Vec<String> = method
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "InclusiveNamespaces")
        .and_then(|node| node.attribute("PrefixList"))
        .map(|list| list.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    prefixes.sort_unstable();
    prefixes.dedup();
    if prefixes.len() > MAX_INCLUSIVE_PREFIXES {
        return Err(SamlError::Unsupported(format!(
            "more than {MAX_INCLUSIVE_PREFIXES} inclusive namespace prefixes"
        )));
    }
    Ok((comments, prefixes))
}

/// Verifies the enveloped `signature` of `element`: one reference to the element's `ID`, the
/// enveloped-signature and exclusive canonicalization transforms, the signature value over the
/// canonical `SignedInfo`, then the digest of the element without the signature (the element,
/// of any size, is canonicalized only once a configured key has signed how to digest it).
fn verify_enveloped(
    input: &str,
    element: Node,
    signature: Node,
    keys: &[RsaPublicKey],
) -> Result<(), SamlError> {
    let malformed = |what| SamlError::Malformed(what);
    let signed_info = child(signature, DSIG, "SignedInfo").ok_or(malformed("no SignedInfo"))?;
    if signed_info.descendants().count() > MAX_SIGNED_INFO_NODES {
        return Err(SamlError::Unsupported(format!(
            "a SignedInfo of more than {MAX_SIGNED_INFO_NODES} nodes"
        )));
    }
    let (info_comments, info_prefixes) = exclusive_c14n(
        child(signed_info, DSIG, "CanonicalizationMethod")
            .ok_or(malformed("no CanonicalizationMethod"))?,
    )?;
    let signature_hash =
        HashAlgorithm::of_signature(algorithm(child(signed_info, DSIG, "SignatureMethod")))?;
    let references: Vec<Node> = signed_info
        .children()
        .filter(|node| node.has_tag_name((DSIG, "Reference")))
        .collect();
    let [reference] = references.as_slice() else {
        return Err(malformed("not exactly one Reference"));
    };
    // The reference names the very element the signature is enveloped in.
    let id = element
        .attribute("ID")
        .ok_or(malformed("the signed element has no ID"))?;
    if reference.attribute("URI") != Some(&format!("#{id}")) {
        return Err(SamlError::Signature);
    }
    let transforms: Vec<Node> = child(*reference, DSIG, "Transforms")
        .map(|node| {
            node.children()
                .filter(|t| t.has_tag_name((DSIG, "Transform")))
                .collect()
        })
        .unwrap_or_default();
    let mut enveloped = false;
    let mut canonical = None;
    for transform in transforms {
        match transform.attribute("Algorithm") {
            Some(ENVELOPED) => enveloped = true,
            Some(EXC_C14N | EXC_C14N_COMMENTS) => canonical = Some(exclusive_c14n(transform)?),
            other => return Err(SamlError::Unsupported(format!("transform {other:?}"))),
        }
    }
    let (Some((comments, prefixes)), true) = (canonical, enveloped) else {
        return Err(SamlError::Unsupported(
            "a reference without enveloped-signature and exclusive canonicalization".to_owned(),
        ));
    };
    let digest_hash = HashAlgorithm::of_digest(algorithm(child(*reference, DSIG, "DigestMethod")))?;
    let expected = base64_content(child(*reference, DSIG, "DigestValue"))
        .ok_or(malformed("no DigestValue"))?;
    let value = base64_content(child(signature, DSIG, "SignatureValue"))
        .ok_or(malformed("no SignatureValue"))?;
    let signed = canonicalize(input, signed_info, None, &info_prefixes, info_comments)?;
    if !keys
        .iter()
        .any(|key| signature_hash.verify(key, signed.as_bytes(), &value))
    {
        return Err(SamlError::Signature);
    }
    let digested = canonicalize(input, element, Some(signature.id()), &prefixes, comments)?;
    if digest_hash.digest(digested.as_bytes()) == expected {
        Ok(())
    } else {
        Err(SamlError::Signature)
    }
}

/// The base64 text of an element (whitespace ignored).
fn base64_content(node: Option<Node>) -> Option<Vec<u8>> {
    decode_base64(&signed_text(node?))
}

/// The text of an element as its canonical form signs it: every child text node, concatenated
/// (a comment splits the text in the tree but not in the signed form, so reading the first text
/// node alone would read less than was signed).
fn signed_text(node: Node) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|text| text.text())
        .collect()
}

/// Standard base64 (padding optional, whitespace ignored), through the base64url decoder.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let unpadded = compact.trim_end_matches('=');
    if unpadded.contains(['-', '_', '=']) {
        return None;
    }
    fireemu_core_auth::jwt::base64url_decode(&unpadded.replace('+', "-").replace('/', "_")).ok()
}

/// The digest and signature algorithms read (the SHA-1 forms are accepted as production's
/// handling of them is unobserved; refusing them could make strict stricter than production).
#[derive(Clone, Copy)]
enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn of_signature(uri: Option<&str>) -> Result<Self, SamlError> {
        match uri {
            Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1") => Ok(Self::Sha1),
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") => Ok(Self::Sha256),
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") => Ok(Self::Sha384),
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") => Ok(Self::Sha512),
            other => Err(SamlError::Unsupported(format!(
                "signature method {other:?}"
            ))),
        }
    }

    fn of_digest(uri: Option<&str>) -> Result<Self, SamlError> {
        match uri {
            Some("http://www.w3.org/2000/09/xmldsig#sha1") => Ok(Self::Sha1),
            Some("http://www.w3.org/2001/04/xmlenc#sha256") => Ok(Self::Sha256),
            Some("http://www.w3.org/2001/04/xmldsig-more#sha384") => Ok(Self::Sha384),
            Some("http://www.w3.org/2001/04/xmlenc#sha512") => Ok(Self::Sha512),
            other => Err(SamlError::Unsupported(format!("digest method {other:?}"))),
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn verify(self, key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = Signature::try_from(signature) else {
            return false;
        };
        let key = key.clone();
        match self {
            Self::Sha1 => VerifyingKey::<sha1::Sha1>::new(key)
                .verify(data, &signature)
                .is_ok(),
            Self::Sha256 => VerifyingKey::<Sha256>::new(key)
                .verify(data, &signature)
                .is_ok(),
            Self::Sha384 => VerifyingKey::<Sha384>::new(key)
                .verify(data, &signature)
                .is_ok(),
            Self::Sha512 => VerifyingKey::<Sha512>::new(key)
                .verify(data, &signature)
                .is_ok(),
        }
    }
}

/// The RSA public key of a PEM X.509 certificate (its `subjectPublicKeyInfo`), or `None`.
#[must_use]
pub fn certificate_key(pem: &str) -> Option<RsaPublicKey> {
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)?
        .split("-----END CERTIFICATE-----")
        .next()?;
    let der = decode_base64(body)?;
    let spki = subject_public_key_info(&der)?;
    RsaPublicKey::from_public_key_der(spki).ok()
}

/// One DER element: its tag, its whole encoding and its content; `None` when truncated or not
/// in the definite form.
/// A DER element read from the front of a buffer: `(tag, whole encoding, content, rest)`.
type DerElement<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

pub(crate) fn der_element(input: &[u8]) -> Option<DerElement<'_>> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, &byte| (acc << 8) | usize::from(byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    let header = input.len() - rest.len();
    Some((
        tag,
        &input[..header + length],
        &rest[..length],
        &rest[length..],
    ))
}

/// The encoded `subjectPublicKeyInfo` of a DER certificate: `Certificate` → `tbsCertificate` →
/// (an optional `[0]` version,) serial, signature, issuer, validity, subject, then the SPKI.
pub(crate) fn subject_public_key_info(der: &[u8]) -> Option<&[u8]> {
    let (0x30, _, certificate, _) = der_element(der)? else {
        return None;
    };
    let (0x30, _, mut fields, _) = der_element(certificate)? else {
        return None;
    };
    let (tag, _, _, rest) = der_element(fields)?;
    if tag == 0xa0 {
        fields = rest;
    }
    for _ in 0..5 {
        fields = der_element(fields)?.3;
    }
    let (0x30, spki, _, _) = der_element(fields)? else {
        return None;
    };
    Some(spki)
}

/// The data of `assertion` (read only once a signature covering it has verified).
fn read_assertion(
    response: Node,
    assertion: Node,
    response_signed: bool,
    assertion_signed: bool,
) -> VerifiedSaml {
    let text = |node: Option<Node>| node.map(|n| signed_text(n).trim().to_owned());
    let subject = child(assertion, ASSERTION, "Subject");
    let name_id = subject.and_then(|s| child(s, ASSERTION, "NameID"));
    let data = subject
        .into_iter()
        .flat_map(|s| {
            s.children()
                .filter(|n| n.has_tag_name((ASSERTION, "SubjectConfirmation")))
        })
        .filter(|c| c.attribute("Method") == Some("urn:oasis:names:tc:SAML:2.0:cm:bearer"))
        .find_map(|c| child(c, ASSERTION, "SubjectConfirmationData"));
    let conditions = child(assertion, ASSERTION, "Conditions");
    let audiences = conditions
        .into_iter()
        .flat_map(|c| {
            c.children()
                .filter(|n| n.has_tag_name((ASSERTION, "AudienceRestriction")))
        })
        .flat_map(|r| {
            r.children()
                .filter(|n| n.has_tag_name((ASSERTION, "Audience")))
        })
        .filter_map(|a| text(Some(a)))
        .collect();
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for statement in assertion
        .children()
        .filter(|n| n.has_tag_name((ASSERTION, "AttributeStatement")))
    {
        for attribute in statement
            .children()
            .filter(|n| n.has_tag_name((ASSERTION, "Attribute")))
        {
            let Some(name) = attribute.attribute("Name") else {
                continue;
            };
            let values = attribute
                .children()
                .filter(|n| n.has_tag_name((ASSERTION, "AttributeValue")))
                .map(signed_text);
            attributes
                .entry(name.to_owned())
                .or_default()
                .extend(values);
        }
    }
    let owned = |value: Option<&str>| value.map(str::to_owned);
    VerifiedSaml {
        response_signed,
        assertion_signed,
        destination: owned(response.attribute("Destination")),
        in_response_to: owned(response.attribute("InResponseTo")),
        issuer: text(child(assertion, ASSERTION, "Issuer")),
        name_id: text(name_id).filter(|id| !id.is_empty()),
        name_id_format: owned(name_id.and_then(|n| n.attribute("Format"))),
        recipient: owned(data.and_then(|d| d.attribute("Recipient"))),
        confirmation_in_response_to: owned(data.and_then(|d| d.attribute("InResponseTo"))),
        confirmation_not_on_or_after: owned(data.and_then(|d| d.attribute("NotOnOrAfter"))),
        not_before: owned(conditions.and_then(|c| c.attribute("NotBefore"))),
        not_on_or_after: owned(conditions.and_then(|c| c.attribute("NotOnOrAfter"))),
        audiences,
        attributes,
    }
}

/// The exclusive XML canonicalization (without or with comments) of `node` as the apex of the
/// canonicalized subtree, leaving out the element `exclude` (the enveloped signature).
/// `inclusive` names the prefixes of an `InclusiveNamespaces` list (`#default` for the default
/// namespace). Element and attribute names are taken as written in `input`.
///
/// # Errors
/// [`SamlError::Malformed`] for a name that cannot be read back from `input`.
pub fn canonicalize(
    input: &str,
    node: Node,
    exclude: Option<NodeId>,
    inclusive: &[String],
    comments: bool,
) -> Result<String, SamlError> {
    let mut out = String::new();
    let inclusive: Vec<&str> = inclusive
        .iter()
        .map(|p| if p == "#default" { "" } else { p.as_str() })
        .collect();
    write_node(
        input,
        node,
        exclude,
        &inclusive,
        comments,
        &BTreeMap::new(),
        &mut out,
    )?;
    Ok(out)
}

/// The qualified name at the start of `range` in `input` (`<` skipped for an element).
fn qname_at(input: &str, start: usize) -> Result<&str, SamlError> {
    let rest = input
        .get(start..)
        .ok_or(SamlError::Malformed("a name outside the input"))?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/' || c == '=')
        .unwrap_or(rest.len());
    Ok(&rest[..end])
}

fn prefix_of(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(prefix, _)| prefix)
}

fn write_node(
    input: &str,
    node: Node,
    exclude: Option<NodeId>,
    inclusive: &[&str],
    comments: bool,
    rendered: &BTreeMap<String, String>,
    out: &mut String,
) -> Result<(), SamlError> {
    if node.is_text() {
        escape_text(node.text().unwrap_or_default(), out);
        return Ok(());
    }
    if node.is_comment() {
        if comments {
            let _ = write!(out, "<!--{}-->", node.text().unwrap_or_default());
        }
        return Ok(());
    }
    if let Some(pi) = node.pi() {
        match pi.value {
            Some(value) if !value.is_empty() => {
                let _ = write!(out, "<?{} {value}?>", pi.target);
            }
            _ => {
                let _ = write!(out, "<?{}?>", pi.target);
            }
        }
        return Ok(());
    }
    if !node.is_element() || Some(node.id()) == exclude {
        return Ok(());
    }
    let qname = qname_at(input, node.range().start + 1)?;
    let scope: BTreeMap<&str, &str> = node
        .namespaces()
        .map(|ns| (ns.name().unwrap_or(""), ns.uri()))
        .collect();
    let mut attributes = Vec::new();
    let mut used = vec![prefix_of(qname)];
    for attribute in node.attributes() {
        let name = qname_at(input, attribute.range_qname().start)?;
        let prefix = prefix_of(name);
        if !prefix.is_empty() && prefix != "xml" {
            used.push(prefix);
        }
        attributes.push((
            attribute.namespace().unwrap_or(""),
            attribute.name(),
            name,
            attribute.value(),
        ));
    }
    used.extend(
        inclusive
            .iter()
            .filter(|p| scope.contains_key(*p) || p.is_empty()),
    );
    used.sort_unstable();
    used.dedup();
    let mut next = rendered.clone();
    let mut declarations = String::new();
    for prefix in used {
        let uri = scope.get(prefix).copied().unwrap_or("");
        if !prefix.is_empty() && uri.is_empty() {
            return Err(SamlError::Malformed("a prefix without a namespace"));
        }
        if rendered.get(prefix).map_or("", String::as_str) == uri {
            continue;
        }
        if prefix.is_empty() {
            declarations.push_str(" xmlns=\"");
        } else {
            let _ = write!(declarations, " xmlns:{prefix}=\"");
        }
        escape_attribute(uri, &mut declarations);
        declarations.push('"');
        next.insert(prefix.to_owned(), uri.to_owned());
    }
    attributes.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let _ = write!(out, "<{qname}{declarations}");
    for (_, _, name, value) in attributes {
        let _ = write!(out, " {name}=\"");
        escape_attribute(value, out);
        out.push('"');
    }
    out.push('>');
    for child in node.children() {
        write_node(input, child, exclude, inclusive, comments, &next, out)?;
    }
    let _ = write!(out, "</{qname}>");
    Ok(())
}

fn escape_text(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

fn escape_attribute(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::der_element;

    #[test]
    fn der_lengths_are_read_in_the_definite_forms_only() {
        // Short form, and long forms of one to four length octets.
        assert_eq!(
            der_element(&[0x04, 0x01, 0xaa, 0xbb]),
            Some((0x04, &[0x04, 0x01, 0xaa][..], &[0xaa][..], &[0xbb][..]))
        );
        assert_eq!(
            der_element(&[0x04, 0x81, 0x00]),
            Some((0x04, &[0x04, 0x81, 0x00][..], &[][..], &[][..]))
        );
        assert_eq!(
            der_element(&[0x04, 0x84, 0, 0, 0, 1, 0xaa]),
            Some((
                0x04,
                &[0x04, 0x84, 0, 0, 0, 1, 0xaa][..],
                &[0xaa][..],
                &[][..]
            ))
        );
        // Indefinite, more than four length octets, truncated length or content.
        let mut indefinite = vec![0x30, 0x80];
        indefinite.extend([0; 130]);
        for input in [
            &indefinite[..],
            &[0x04, 0x85, 0, 0, 0, 0, 1, 0xaa][..],
            &[0x04, 0x82, 0x00][..],
            &[0x04, 0x02, 0xaa][..],
            &[0x04][..],
        ] {
            assert_eq!(der_element(input), None, "{input:02x?}");
        }
    }
}
