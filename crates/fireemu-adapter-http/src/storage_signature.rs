//! V4 signed-URL signature verification (`storage.signedUrlKeys`), off unless keys are registered.
//!
//! Cloud Storage verifies a V4 signed URL against the signing service account's public key; a
//! local run has no such account, so by default the signature is not checked. A test that signs
//! with a key it generated can register the matching public key (or the service-account JSON or
//! private key it signed with), and a request whose signature does not verify against the
//! canonical request is then answered as production answers it: 403 `SignatureDoesNotMatch`, with
//! the `StringToSign` and the `CanonicalRequest` the server calculated (RECORDED, storage-signed-put,
//! two recordings, four causes: a changed `Content-Type`, a changed signed range header, another
//! object name and an altered signature).
//!
//! The canonical request is the one Cloud Storage documents for V4 ("Canonical requests"):
//!
//! ```text
//! HTTP_VERB \n
//! PATH \n                       each segment percent-encoded, `/` kept
//! CANONICAL_QUERY_STRING \n     every parameter but X-Goog-Signature, sorted by name, encoded
//! CANONICAL_HEADERS \n          `name:value\n` for each signed header, then one more `\n`
//! SIGNED_HEADERS \n             the X-Goog-SignedHeaders value
//! UNSIGNED-PAYLOAD
//! ```
//!
//! and the string to sign is `GOOG4-RSA-SHA256`, the date, the credential scope and the hex
//! SHA-256 of the canonical request, signed with RSASSA-PKCS1-v1_5 over SHA-256 and written in
//! hex. V2 signed URLs (`GoogleAccessId`, `Signature`) are not verified.
//!
//! Security notes. Only public keys are kept (a private key or a service-account file is read once
//! to derive its public half and is then dropped). Nothing here logs, formats or returns key
//! material. Every malformed input (a bad percent escape, a non-hex signature, a header list the
//! request does not carry) is a mismatch, never a pass. The verdict carries only the canonical
//! request and string to sign, both of which the client already holds.

use std::collections::BTreeMap;

use rsa::pkcs1::DecodeRsaPrivateKey as _;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rsa::signature::Verifier as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// The only algorithm verified.
pub const ALGORITHM: &str = "GOOG4-RSA-SHA256";

/// Registered keys never exceed this many (a configuration list is bounded).
pub const MAX_KEYS: usize = 32;
/// The largest key file read, in bytes.
pub const MAX_KEY_FILE_BYTES: usize = 64 * 1024;

/// A key file that cannot be used. The message never includes file contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub String);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone)]
struct SignerKey {
    public: RsaPublicKey,
    /// The service account the key belongs to, when the file named one: a credential of another
    /// account then never selects it.
    email: Option<String>,
}

/// The public keys signed URLs are verified against.
#[derive(Clone, Default)]
pub struct SignerKeys {
    keys: Vec<SignerKey>,
}

impl std::fmt::Debug for SignerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts only: key material is never formatted.
        write!(f, "SignerKeys({} keys)", self.keys.len())
    }
}

impl SignerKeys {
    /// Whether no key is registered (verification is then off).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many keys are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Registers the key a file holds: a PEM public key (`PUBLIC KEY` or `RSA PUBLIC KEY`), a PEM
    /// private key (`PRIVATE KEY` or `RSA PRIVATE KEY`, from which only the public half is
    /// kept), a service-account JSON (`private_key`, `client_email`) or an RSA JWK (`n`, `e`).
    ///
    /// # Errors
    /// A [`KeyError`] when the contents are none of these, are too large, or the list is full.
    pub fn add_file_contents(&mut self, contents: &[u8]) -> Result<(), KeyError> {
        if self.keys.len() >= MAX_KEYS {
            return Err(KeyError(format!("more than {MAX_KEYS} signing keys")));
        }
        if contents.len() > MAX_KEY_FILE_BYTES {
            return Err(KeyError("a signing key file is too large".to_owned()));
        }
        let text = std::str::from_utf8(contents)
            .map_err(|_| KeyError("a signing key file is not UTF-8 text".to_owned()))?;
        let key = if text.trim_start().starts_with('{') {
            parse_json_key(text)?
        } else {
            SignerKey {
                public: parse_pem(text)?,
                email: None,
            }
        };
        if key.public.n().bits() < 2048 {
            return Err(KeyError(
                "a signing key is shorter than 2048 bits".to_owned(),
            ));
        }
        self.keys.push(key);
        Ok(())
    }

    fn candidates<'a>(&'a self, email: &'a str) -> impl Iterator<Item = &'a RsaPublicKey> + 'a {
        self.keys
            .iter()
            .filter(move |k| k.email.as_deref().is_none_or(|e| e == email))
            .map(|k| &k.public)
    }
}

fn parse_pem(text: &str) -> Result<RsaPublicKey, KeyError> {
    let text = text.trim();
    if let Ok(public) = RsaPublicKey::from_public_key_pem(text) {
        return Ok(public);
    }
    if let Ok(public) = RsaPublicKey::from_pkcs1_pem(text) {
        return Ok(public);
    }
    if let Ok(private) = RsaPrivateKey::from_pkcs8_pem(text) {
        return Ok(private.to_public_key());
    }
    if let Ok(private) = RsaPrivateKey::from_pkcs1_pem(text) {
        return Ok(private.to_public_key());
    }
    Err(KeyError(
        "a signing key file is not an RSA public or private key in PEM form, a service-account JSON or an RSA JWK"
            .to_owned(),
    ))
}

fn parse_json_key(text: &str) -> Result<SignerKey, KeyError> {
    let bad =
        || KeyError("a signing key JSON is neither a service account nor an RSA JWK".to_owned());
    let value: Value = serde_json::from_str(text).map_err(|_| bad())?;
    let object = value.as_object().ok_or_else(bad)?;
    if let Some(pem) = object.get("private_key").and_then(Value::as_str) {
        let email = object
            .get("client_email")
            .and_then(Value::as_str)
            .filter(|e| !e.is_empty() && e.len() <= 256 && !e.contains(['/', '\r', '\n']))
            .map(str::to_owned);
        return Ok(SignerKey {
            public: parse_pem(pem)?,
            email,
        });
    }
    if object.get("kty").and_then(Value::as_str) == Some("RSA") {
        let component = |name: &str| -> Result<BigUint, KeyError> {
            let encoded = object.get(name).and_then(Value::as_str).ok_or_else(bad)?;
            Ok(BigUint::from_bytes_be(
                &base64url_decode(encoded).ok_or_else(bad)?,
            ))
        };
        let public = RsaPublicKey::new(component("n")?, component("e")?).map_err(|_| bad())?;
        return Ok(SignerKey {
            public,
            email: None,
        });
    }
    Err(bad())
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    for byte in text.trim_end_matches('=').bytes() {
        let v = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// What verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The request carries no V4 signature (nothing to verify).
    NotV4,
    /// The signature verifies against a registered key.
    Valid,
    /// It does not; the calculated string to sign and canonical request, as production's 403 body
    /// carries them.
    Mismatch {
        /// The calculated string to sign.
        string_to_sign: String,
        /// The calculated canonical request.
        canonical_request: String,
    },
}

/// The request as the signature sees it.
#[derive(Clone, Copy)]
pub struct SignedRequest<'a> {
    /// The HTTP method.
    pub method: &'a str,
    /// The request path as received (percent-encoded), without the query.
    pub path: &'a str,
    /// The raw query string, without the `?`.
    pub query: &'a str,
    /// The request headers by lower-case name, each value as received. A header that is absent
    /// from the map is not on the request.
    pub headers: &'a BTreeMap<String, Vec<String>>,
}

/// Verifies the V4 signature of `request` against `keys`. With no key registered, or without an
/// `X-Goog-Signature`, the verdict is [`Verdict::NotV4`]: the caller keeps its other checks.
#[must_use]
pub fn verify_v4(keys: &SignerKeys, request: &SignedRequest<'_>) -> Verdict {
    if keys.is_empty() {
        return Verdict::NotV4;
    }
    let Some(pairs) = parse_query(request.query) else {
        return mismatch_without_signature(request);
    };
    let first = |name: &str| {
        pairs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let Some(signature) = first("x-goog-signature") else {
        return Verdict::NotV4;
    };
    let canonical = canonical_request(request, &pairs);
    let (algorithm, credential, date) = (
        first("x-goog-algorithm"),
        first("x-goog-credential"),
        first("x-goog-date"),
    );
    let scope = credential.and_then(|c| c.split_once('/')).map(|(_, s)| s);
    let sign_text = |canonical: &str| {
        format!(
            "{ALGORITHM}\n{}\n{}\n{}",
            date.unwrap_or_default(),
            scope.unwrap_or_default(),
            hex(&Sha256::digest(canonical.as_bytes()))
        )
    };
    let string_to_sign = sign_text(&canonical);
    let mismatch = || Verdict::Mismatch {
        string_to_sign: string_to_sign.clone(),
        canonical_request: canonical.clone(),
    };
    if algorithm != Some(ALGORITHM) || date.is_none() {
        return mismatch();
    }
    let (Some(credential), Some(signature)) = (credential, unhex(signature)) else {
        return mismatch();
    };
    let Some((email, _)) = credential.split_once('/') else {
        return mismatch();
    };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else {
        return mismatch();
    };
    let verifies = |to_sign: &str| {
        keys.candidates(email).any(|public| {
            VerifyingKey::<Sha256>::new(public.clone())
                .verify(to_sign.as_bytes(), &signature)
                .is_ok()
        })
    };
    if verifies(&string_to_sign) {
        return Verdict::Valid;
    }
    // `@google-cloud/storage` signs `host` as the host name alone, without the port (a production
    // host has none), so a URL it built for a local endpoint names `127.0.0.1` while the request
    // arrives with `Host: 127.0.0.1:9199`. The request is also read with the port removed.
    if let Some(host) = request
        .headers
        .get("host")
        .and_then(|values| values.first())
    {
        let stripped = host_without_port(host);
        if stripped != host {
            let mut headers = request.headers.clone();
            headers.insert("host".to_owned(), vec![stripped.to_owned()]);
            let retry = SignedRequest {
                headers: &headers,
                ..*request
            };
            if verifies(&sign_text(&canonical_request(&retry, &pairs))) {
                return Verdict::Valid;
            }
        }
    }
    mismatch()
}

/// `host` without its `:port` (an IPv6 literal keeps its brackets).
fn host_without_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port))
            if !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && (!name.contains(':') || name.ends_with(']')) =>
        {
            name
        }
        _ => host,
    }
}

/// A request whose query cannot be read (a bad percent escape) fails closed with the raw query.
fn mismatch_without_signature(request: &SignedRequest<'_>) -> Verdict {
    if !request
        .query
        .to_ascii_lowercase()
        .contains("x-goog-signature")
    {
        return Verdict::NotV4;
    }
    Verdict::Mismatch {
        string_to_sign: String::new(),
        canonical_request: String::new(),
    }
}

/// The canonical request of `request` for the decoded query `pairs`.
#[must_use]
pub fn canonical_request(request: &SignedRequest<'_>, pairs: &[(String, String)]) -> String {
    use std::fmt::Write as _;
    let path = match percent_decode(request.path) {
        Some(decoded) => encode_path(&decoded),
        None => request.path.to_owned(),
    };
    let mut query: Vec<(String, String)> = pairs
        .iter()
        .filter(|(n, _)| {
            !n.eq_ignore_ascii_case("x-goog-signature")
                && !n.eq_ignore_ascii_case("x-amz-signature")
        })
        .map(|(n, v)| (encode_component(n), encode_component(v)))
        .collect();
    query.sort();
    let query = query
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let signed = pairs
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("x-goog-signedheaders"))
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    let mut canonical_headers = String::new();
    for name in signed.split(';').filter(|n| !n.is_empty()) {
        let lower = name.to_ascii_lowercase();
        let value = request
            .headers
            .get(&lower)
            .map(|values| {
                values
                    .iter()
                    .map(|v| collapse_whitespace(v))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let _ = writeln!(canonical_headers, "{lower}:{value}");
    }
    format!(
        "{}\n{path}\n{query}\n{canonical_headers}\n{signed}\nUNSIGNED-PAYLOAD",
        request.method
    )
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Splits and percent-decodes a raw query string, or `None` for a bad escape. A `+` is a plus.
#[must_use]
pub fn parse_query(query: &str) -> Option<Vec<(String, String)>> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            Some((percent_decode(name)?, percent_decode(value)?))
        })
        .collect()
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3)?;
            let digits = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// URI-encodes `text`: every byte but the unreserved ones becomes `%XX` (upper-case hex).
fn encode_component(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// URI-encodes a path, keeping its `/` separators.
fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    fn headers(list: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in list {
            map.entry((*k).to_owned())
                .or_default()
                .push((*v).to_owned());
        }
        map
    }

    /// A key generated by the test (never a real credential), made once: generating a 2048-bit
    /// key in a debug build takes seconds.
    fn test_key() -> RsaPrivateKey {
        shared_key().clone()
    }

    /// Builds the URL query a signer produces for `method`/`path`, signs it with `key` and
    /// returns the full query (parameters in a scrambled order, as clients do not sort).
    fn sign(
        key: &RsaPrivateKey,
        email: &str,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        signed_headers: &[(&str, &str)],
    ) -> String {
        let names: Vec<&str> = signed_headers.iter().map(|(n, _)| *n).collect();
        let mut params: Vec<(String, String)> = vec![
            ("X-Goog-Algorithm".into(), ALGORITHM.into()),
            (
                "X-Goog-Credential".into(),
                format!("{email}/20261103/auto/storage/goog4_request"),
            ),
            ("X-Goog-Date".into(), "20261103T120000Z".into()),
            ("X-Goog-Expires".into(), "300".into()),
            ("X-Goog-SignedHeaders".into(), names.join(";")),
        ];
        params.extend(
            extra
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned())),
        );
        let query = params
            .iter()
            .map(|(n, v)| format!("{}={}", encode_component(n), encode_component(v)))
            .collect::<Vec<_>>()
            .join("&");
        let map = headers(signed_headers);
        let request = SignedRequest {
            method,
            path,
            query: &query,
            headers: &map,
        };
        let pairs = parse_query(&query).unwrap();
        let canonical = canonical_request(&request, &pairs);
        let to_sign = format!(
            "{ALGORITHM}\n20261103T120000Z\n20261103/auto/storage/goog4_request\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let signature = SigningKey::<Sha256>::new(key.clone()).sign(to_sign.as_bytes());
        format!("{query}&X-Goog-Signature={}", hex(&signature.to_bytes()))
    }

    fn keys_for(key: &RsaPrivateKey) -> SignerKeys {
        let mut keys = SignerKeys::default();
        let pem = key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        keys.add_file_contents(pem.as_bytes()).unwrap();
        keys
    }

    #[test]
    fn the_documented_canonical_request_layout() {
        // The layout of the documentation's "Canonical requests" page, with the query of a
        // signed URL: headers each end in a newline and a blank line follows them.
        let map = headers(&[("host", "storage.googleapis.com")]);
        let query = "X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=example%40example-project.iam.gserviceaccount.com%2F20181026%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20181026T181309Z&X-Goog-Expires=3600&X-Goog-SignedHeaders=host&X-Goog-Signature=00";
        let request = SignedRequest {
            method: "GET",
            path: "/example-bucket/cat-pics/tabby.jpeg",
            query,
            headers: &map,
        };
        let canonical = canonical_request(&request, &parse_query(query).unwrap());
        assert_eq!(
            canonical,
            "GET\n/example-bucket/cat-pics/tabby.jpeg\nX-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=example%40example-project.iam.gserviceaccount.com%2F20181026%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20181026T181309Z&X-Goog-Expires=3600&X-Goog-SignedHeaders=host\nhost:storage.googleapis.com\n\nhost\nUNSIGNED-PAYLOAD"
        );
    }

    #[test]
    fn the_canonical_request_matches_the_recorded_production_one() {
        // storage-signed-put, production, case `tampered-signature` (the date, run and bucket
        // masked in the recording; the layout is byte-for-byte the recorded one).
        let map = headers(&[
            ("content-type", "image/png"),
            ("host", "storage.googleapis.com"),
            ("x-goog-content-length-range", "0,10485760"),
        ]);
        let query = "X-Goog-Signature=ab&X-Goog-SignedHeaders=content-type%3Bhost%3Bx-goog-content-length-range&X-Goog-Expires=300&X-Goog-Date=20261103T120000Z&X-Goog-Credential=sa%40p.iam.gserviceaccount.com%2F20261103%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Algorithm=GOOG4-RSA-SHA256";
        let request = SignedRequest {
            method: "PUT",
            path: "/bucket/storage-signed-put/run/rec/tampered-signature.png",
            query,
            headers: &map,
        };
        assert_eq!(
            canonical_request(&request, &parse_query(query).unwrap()),
            "PUT\n/bucket/storage-signed-put/run/rec/tampered-signature.png\nX-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=sa%40p.iam.gserviceaccount.com%2F20261103%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261103T120000Z&X-Goog-Expires=300&X-Goog-SignedHeaders=content-type%3Bhost%3Bx-goog-content-length-range\ncontent-type:image/png\nhost:storage.googleapis.com\nx-goog-content-length-range:0,10485760\n\ncontent-type;host;x-goog-content-length-range\nUNSIGNED-PAYLOAD"
        );
    }

    #[test]
    fn a_signed_request_verifies_and_every_alteration_is_a_mismatch() {
        let key = test_key();
        let keys = keys_for(&key);
        let signed = [
            ("content-type", "image/png"),
            ("host", "127.0.0.1:9199"),
            ("x-goog-content-length-range", "0,10"),
        ];
        let path = "/demo-app.appspot.com/signed%20put/a%20%23%20image.png";
        let query = sign(
            &key,
            "sa@p.iam.gserviceaccount.com",
            "PUT",
            path,
            &[],
            &signed,
        );
        let ok = headers(&signed);
        let request = |method, path, query: &str, headers| -> Verdict {
            verify_v4(
                &keys,
                &SignedRequest {
                    method,
                    path,
                    query,
                    headers,
                },
            )
        };
        assert_eq!(request("PUT", path, &query, &ok), Verdict::Valid);
        // Alterations: method, object, header value, a changed query value, a tampered signature.
        assert!(matches!(
            request("GET", path, &query, &ok),
            Verdict::Mismatch { .. }
        ));
        assert!(matches!(
            request("PUT", "/demo-app.appspot.com/other.png", &query, &ok),
            Verdict::Mismatch { .. }
        ));
        let wrong_type = headers(&[
            ("content-type", "text/plain"),
            ("host", "127.0.0.1:9199"),
            ("x-goog-content-length-range", "0,10"),
        ]);
        assert!(matches!(
            request("PUT", path, &query, &wrong_type),
            Verdict::Mismatch { .. }
        ));
        let wrong_range = headers(&[
            ("content-type", "image/png"),
            ("host", "127.0.0.1:9199"),
            ("x-goog-content-length-range", "0,11"),
        ]);
        assert!(matches!(
            request("PUT", path, &query, &wrong_range),
            Verdict::Mismatch { .. }
        ));
        let wrong_host = headers(&[
            ("content-type", "image/png"),
            ("host", "localhost:9199"),
            ("x-goog-content-length-range", "0,10"),
        ]);
        assert!(matches!(
            request("PUT", path, &query, &wrong_host),
            Verdict::Mismatch { .. }
        ));
        let missing = headers(&[("content-type", "image/png"), ("host", "127.0.0.1:9199")]);
        assert!(matches!(
            request("PUT", path, &query, &missing),
            Verdict::Mismatch { .. }
        ));
        let expires = query.replace("X-Goog-Expires=300", "X-Goog-Expires=301");
        assert!(matches!(
            request("PUT", path, &expires, &ok),
            Verdict::Mismatch { .. }
        ));
        let mut flipped = query.clone().into_bytes();
        let last = flipped.len() - 1;
        flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
        assert!(matches!(
            request("PUT", path, &String::from_utf8(flipped).unwrap(), &ok),
            Verdict::Mismatch { .. }
        ));
        // An extra unsigned query parameter is part of the canonical query: it changes it.
        assert!(matches!(
            request("PUT", path, &format!("{query}&extra=1"), &ok),
            Verdict::Mismatch { .. }
        ));
    }

    #[test]
    fn equivalent_encodings_of_one_path_and_query_verify() {
        let key = test_key();
        let keys = keys_for(&key);
        let signed = [("host", "127.0.0.1:9199")];
        let query = sign(
            &key,
            "sa@p",
            "GET",
            "/b/a~b c.txt",
            &[("response-content-type", "text/plain")],
            &signed,
        );
        let ok = headers(&signed);
        let verdict = |path: &str| {
            verify_v4(
                &keys,
                &SignedRequest {
                    method: "GET",
                    path,
                    query: &query,
                    headers: &ok,
                },
            )
        };
        // The signer encoded the space; the server decodes and re-encodes, so `%7E` and `~` and
        // `%20` all name the same object.
        assert_eq!(verdict("/b/a~b%20c.txt"), Verdict::Valid);
        assert_eq!(verdict("/b/a%7Eb%20c.txt"), Verdict::Valid);
        assert!(matches!(verdict("/b/a~b+c.txt"), Verdict::Mismatch { .. }));
    }

    #[test]
    fn a_host_signed_without_its_port_verifies_for_a_request_that_carries_one() {
        // `@google-cloud/storage` signs the host name alone, `127.0.0.1`, for a local endpoint.
        let key = test_key();
        let keys = keys_for(&key);
        let query = sign(&key, "sa@p", "GET", "/b/o", &[], &[("host", "127.0.0.1")]);
        let verdict = |host: &str| {
            let sent = headers(&[("host", host)]);
            verify_v4(
                &keys,
                &SignedRequest {
                    method: "GET",
                    path: "/b/o",
                    query: &query,
                    headers: &sent,
                },
            )
        };
        assert_eq!(verdict("127.0.0.1"), Verdict::Valid);
        assert_eq!(verdict("127.0.0.1:9199"), Verdict::Valid);
        assert!(matches!(
            verdict("localhost:9199"),
            Verdict::Mismatch { .. }
        ));
        assert!(matches!(
            verdict("127.0.0.2:9199"),
            Verdict::Mismatch { .. }
        ));
        // The same URL signed with the port verifies against the port, not another one.
        let with_port = sign(
            &key,
            "sa@p",
            "GET",
            "/b/o",
            &[],
            &[("host", "127.0.0.1:9199")],
        );
        let sent = headers(&[("host", "127.0.0.1:9199")]);
        let request = SignedRequest {
            method: "GET",
            path: "/b/o",
            query: &with_port,
            headers: &sent,
        };
        assert_eq!(verify_v4(&keys, &request), Verdict::Valid);
        let other = headers(&[("host", "127.0.0.1:9200")]);
        let request = SignedRequest {
            method: "GET",
            path: "/b/o",
            query: &with_port,
            headers: &other,
        };
        assert!(matches!(
            verify_v4(&keys, &request),
            Verdict::Mismatch { .. }
        ));
    }

    #[test]
    fn host_without_port_strips_only_a_numeric_port() {
        for (host, expected) in [
            ("127.0.0.1:9199", "127.0.0.1"),
            ("127.0.0.1", "127.0.0.1"),
            ("localhost:80", "localhost"),
            ("[::1]:9199", "[::1]"),
            ("[::1]", "[::1]"),
            ("::1", "::1"),
            ("host:", "host:"),
            ("host:port", "host:port"),
            ("", ""),
        ] {
            assert_eq!(host_without_port(host), expected, "{host:?}");
        }
    }

    #[test]
    fn a_credential_of_another_account_selects_no_key_and_fails() {
        let key = test_key();
        let mut keys = SignerKeys::default();
        let account = format!(
            "{{\"client_email\":\"right@p.iam.gserviceaccount.com\",\"private_key\":{}}}",
            serde_json::to_string(&*key.to_pkcs8_pem(LineEnding::LF).unwrap()).unwrap()
        );
        keys.add_file_contents(account.as_bytes()).unwrap();
        let signed = [("host", "h")];
        let ok = headers(&signed);
        for (email, valid) in [
            ("right@p.iam.gserviceaccount.com", true),
            ("wrong@p.iam.gserviceaccount.com", false),
        ] {
            let query = sign(&key, email, "GET", "/b/o", &[], &signed);
            let verdict = verify_v4(
                &keys,
                &SignedRequest {
                    method: "GET",
                    path: "/b/o",
                    query: &query,
                    headers: &ok,
                },
            );
            assert_eq!(verdict == Verdict::Valid, valid, "{email}");
        }
    }

    #[test]
    fn no_keys_or_no_signature_means_nothing_to_verify() {
        let key = test_key();
        let signed = [("host", "h")];
        let query = sign(&key, "sa@p", "GET", "/b/o", &[], &signed);
        let ok = headers(&signed);
        let request = SignedRequest {
            method: "GET",
            path: "/b/o",
            query: &query,
            headers: &ok,
        };
        assert_eq!(verify_v4(&SignerKeys::default(), &request), Verdict::NotV4);
        let keys = keys_for(&key);
        let unsigned = SignedRequest {
            method: "GET",
            path: "/b/o",
            query: "alt=media",
            headers: &ok,
        };
        assert_eq!(verify_v4(&keys, &unsigned), Verdict::NotV4);
    }

    #[test]
    fn malformed_signature_material_fails_closed() {
        let key = test_key();
        let keys = keys_for(&key);
        let signed = [("host", "h")];
        let ok = headers(&signed);
        let query = sign(&key, "sa@p", "GET", "/b/o", &[], &signed);
        let (base, _) = query.rsplit_once("&X-Goog-Signature=").unwrap();
        for bad in [
            format!("{base}&X-Goog-Signature="),
            format!("{base}&X-Goog-Signature=zz"),
            format!("{base}&X-Goog-Signature=abc"),
            format!("{base}&X-Goog-Signature=00"),
            format!("{base}&X-Goog-Signature=%ZZ"),
            format!(
                "{}&X-Goog-Signature=00",
                base.replace("GOOG4-RSA-SHA256", "AWS4-HMAC-SHA256")
            ),
            format!(
                "{}&X-Goog-Signature=00",
                base.replace("X-Goog-Credential", "X-Goog-Credentia")
            ),
            format!(
                "{}&X-Goog-Signature=00",
                base.replace("X-Goog-Date", "X-Goog-Dat")
            ),
        ] {
            let verdict = verify_v4(
                &keys,
                &SignedRequest {
                    method: "GET",
                    path: "/b/o",
                    query: &bad,
                    headers: &ok,
                },
            );
            assert!(matches!(verdict, Verdict::Mismatch { .. }), "{bad}");
        }
    }

    #[test]
    fn key_files_in_every_supported_form_register_and_junk_does_not() {
        let key = test_key();
        let mut keys = SignerKeys::default();
        let public = key.to_public_key();
        keys.add_file_contents(public.to_public_key_pem(LineEnding::LF).unwrap().as_bytes())
            .unwrap();
        keys.add_file_contents(key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
            .unwrap();
        let n = rsa::traits::PublicKeyParts::n(&public).to_bytes_be();
        let encode = |bytes: &[u8]| {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let v = chunk
                    .iter()
                    .enumerate()
                    .fold(0_u32, |a, (i, b)| a | (u32::from(*b) << (16 - 8 * i)));
                for i in 0..=chunk.len() {
                    out.push(char::from(ALPHABET[((v >> (18 - 6 * i)) & 63) as usize]));
                }
            }
            out
        };
        let jwk = format!(
            "{{\"kty\":\"RSA\",\"n\":\"{}\",\"e\":\"AQAB\"}}",
            encode(&n)
        );
        keys.add_file_contents(jwk.as_bytes()).unwrap();
        assert_eq!(keys.len(), 3);
        // All three name one key: a signature made with it verifies against each.
        let signed = [("host", "h")];
        let query = sign(&key, "sa@p", "GET", "/b/o", &[], &signed);
        let ok = headers(&signed);
        let request = SignedRequest {
            method: "GET",
            path: "/b/o",
            query: &query,
            headers: &ok,
        };
        assert_eq!(verify_v4(&keys, &request), Verdict::Valid);
        for junk in [
            &b""[..],
            b"not a key",
            b"{}",
            b"{\"kty\":\"EC\"}",
            b"{\"kty\":\"RSA\",\"n\":\"AQ\",\"e\":\"AQAB\"}",
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            &[0xff, 0xfe, 0x00],
        ] {
            let mut keys = SignerKeys::default();
            assert!(keys.add_file_contents(junk).is_err(), "{junk:?}");
            assert!(keys.is_empty());
        }
        let mut full = SignerKeys::default();
        let pem = public.to_public_key_pem(LineEnding::LF).unwrap();
        for _ in 0..MAX_KEYS {
            full.add_file_contents(pem.as_bytes()).unwrap();
        }
        assert!(full.add_file_contents(pem.as_bytes()).is_err());
        let huge = vec![b' '; MAX_KEY_FILE_BYTES + 1];
        assert!(SignerKeys::default().add_file_contents(&huge).is_err());
    }

    #[test]
    fn the_debug_form_shows_no_key_material() {
        let key = test_key();
        let keys = keys_for(&key);
        let shown = format!("{keys:?}");
        assert_eq!(shown, "SignerKeys(1 keys)");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Whatever the object name, method, signed header values and extra query parameters,
        /// a signature made over the canonical request verifies, and changing any one signed
        /// header value, the method or the path makes it a mismatch.
        #[test]
        fn sign_then_verify_round_trips_and_any_change_breaks_it(
            name in "[a-zA-Z0-9 _.~#?&=+%/-]{1,24}",
            method in prop::sample::select(vec!["GET", "PUT", "POST", "DELETE", "HEAD"]),
            content_type in "[a-z]{1,8}/[a-z]{1,8}",
            extra in proptest::collection::vec(("[a-z-]{1,6}", "[ -~]{0,8}"), 0..3),
            which in 0usize..3,
        ) {
            let key = shared_key();
            let keys = keys_for(key);
            let path = format!("/bucket/{}", encode_path(&name));
            let signed = [("content-type", content_type.as_str()), ("host", "127.0.0.1:9199"), ("x-goog-meta-k", "v")];
            let extra: Vec<(&str, &str)> = extra.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
            let query = sign(key, "sa@p", method, &path, &extra, &signed);
            let ok = headers(&signed);
            let verify = |method: &str, path: &str, headers: &BTreeMap<String, Vec<String>>| {
                verify_v4(&keys, &SignedRequest { method, path, query: &query, headers })
            };
            prop_assert_eq!(verify(method, &path, &ok), Verdict::Valid);
            match which {
                0 => {
                    let other = if method == "GET" { "PUT" } else { "GET" };
                    prop_assert!(is_mismatch(&verify(other, &path, &ok)));
                }
                1 => {
                    let other = format!("{path}x");
                    prop_assert!(is_mismatch(&verify(method, &other, &ok)));
                }
                _ => {
                    let changed = headers(&[("content-type", &format!("{content_type}x")), ("host", "127.0.0.1:9199"), ("x-goog-meta-k", "v")]);
                    prop_assert!(is_mismatch(&verify(method, &path, &changed)));
                }
            }
        }

        /// Percent-encoding then decoding is the identity, and the encoder only emits the
        /// unreserved set and `%XX`.
        #[test]
        fn encode_component_round_trips(text in ".{0,40}") {
            let encoded = encode_component(&text);
            prop_assert!(encoded.bytes().all(|b| is_unreserved(b) || b == b'%' || b.is_ascii_hexdigit()));
            prop_assert_eq!(percent_decode(&encoded), Some(text));
        }

        /// Arbitrary query strings never panic the verifier and never pass without a key match.
        #[test]
        fn arbitrary_queries_never_pass(query in "[ -~]{0,120}") {
            let key = shared_key();
            let keys = keys_for(key);
            let ok = headers(&[("host", "h")]);
            let verdict = verify_v4(&keys, &SignedRequest { method: "GET", path: "/b/o", query: &query, headers: &ok });
            prop_assert!(verdict != Verdict::Valid);
        }
    }

    fn is_mismatch(verdict: &Verdict) -> bool {
        matches!(verdict, Verdict::Mismatch { .. })
    }

    fn shared_key() -> &'static RsaPrivateKey {
        static KEY: std::sync::OnceLock<RsaPrivateKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            use rand_core::SeedableRng as _;
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0x51_67);
            RsaPrivateKey::new(&mut rng, 2048).unwrap()
        })
    }
}
