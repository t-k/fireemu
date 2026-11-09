//! ID token encoding and verification (`AUTH-TOKEN-1`, spec 12A.4).
//!
//! The official Auth Emulator issues unsigned tokens (`alg: none`); SDKs accept them in
//! emulator mode. This module implements that format exactly. RS256 signing with a
//! session-fixed key is a declared, not yet implemented, capability: choosing it fails closed.

use core::fmt;

use fireemu_core_types::ids::ProjectId;
use fireemu_core_types::json::{parse, JsonValue};
use fireemu_core_types::time::LogicalInstant;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::claims::{ClaimValue, IdTokenClaims};
use crate::store::AuthStore;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 7515 section 2).
#[must_use]
pub fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let index = ((bits >> (18 - i * 6)) & 0x3F) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    out
}

/// Decodes base64url without padding; padding and the standard alphabet are rejected.
pub fn base64url_decode(text: &str) -> Result<Vec<u8>, JwtError> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(JwtError::Malformed),
        };
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if text.len() % 4 == 1 {
        return Err(JwtError::Malformed);
    }
    Ok(out)
}

/// How a Security Rules surface (Firestore, Storage) verifies the ID token a caller
/// presents, which is what the compatibility profile switches.
///
/// The pinned official emulators do not verify the token at all: the Storage emulator calls
/// `jwt.decode` and builds `request.auth` from whatever comes back
/// (`firebase-tools/lib/emulator/storage/rules/runtime.js`), and the Firestore emulator was
/// measured to admit a token whose `sub` names no user, whose `exp` lies in 1970, that
/// carries no `iss`, that names another project in `aud`, and even one whose `RS256`
/// signature is garbage. `@firebase/rules-unit-testing` depends on that: its
/// `authenticatedContext` mints an unsigned token with `iat: 0` and therefore `exp: 3600`
/// for a user that need not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenAcceptance {
    /// The `strict` profile: every token is an ID token of this session's Auth store, with
    /// its issuer, audience, expiry, issued-at and authentication times on the virtual clock
    /// checked. Identity Toolkit also checks the account (subject, disabled, revocation);
    /// Firestore does not (see [`verify_firestore_token`]).
    #[default]
    Verified,
    /// The `emulator` profile: by default ([`RulesTokenPolicy::from`]; `auth.allowUnsignedIdTokens`
    /// decides it on its own) a token this store cannot verify is still accepted when it is
    /// *unsigned* and minted for this project, and `request.auth` is then built from its
    /// claims as given. Two checks the official emulators skip are kept deliberately: a
    /// signed token must still verify against the session key, so a forged `RS256` token is
    /// never a mock token, and the audience must still name the project, so a token of
    /// another session or another project cannot cross the boundary.
    EmulatorMock,
}

impl TokenAcceptance {
    /// The future-claim policy of the profile this acceptance belongs to.
    #[must_use]
    pub const fn future_claims(self) -> FutureClaims {
        match self {
            Self::Verified => FutureClaims::Refuse,
            Self::EmulatorMock => FutureClaims::Accept,
        }
    }
}

/// What a Security Rules surface (Firestore, Storage) admits as the caller's ID token: the
/// profile's [`TokenAcceptance`] and whether unsigned emulator ID tokens (see
/// [`is_unsigned_token`]) that do not verify are still admitted as mock tokens
/// (`auth.allowUnsignedIdTokens`, owner ledger 1393).
///
/// With the setting, a token this store cannot verify is admitted when it is unsigned, minted
/// for the routed project and names a subject; `request.auth` is then built from its claims as
/// given, as the official emulators do for `@firebase/rules-unit-testing`. Every other token
/// keeps the profile's verification: a token that claims a signature is never a mock token, and
/// a session that signs its own tokens (`auth.idTokenSigning: session-rsa`) admits no unsigned
/// token at all. Under [`TokenAcceptance::Verified`] a refused token keeps the verified path's
/// error, so the response is the one the strict profile gives without the setting.
///
/// [`From<TokenAcceptance>`] gives each profile's behaviour before the setting existed: the
/// emulator profile admits mock tokens and the strict profile does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RulesTokenPolicy {
    acceptance: TokenAcceptance,
    allow_unsigned: bool,
}

impl RulesTokenPolicy {
    /// The policy of `acceptance` with unsigned emulator ID tokens admitted or not.
    #[must_use]
    pub const fn new(acceptance: TokenAcceptance, allow_unsigned: bool) -> Self {
        Self {
            acceptance,
            allow_unsigned,
        }
    }

    /// The profile's verification.
    #[must_use]
    pub const fn acceptance(self) -> TokenAcceptance {
        self.acceptance
    }

    /// Whether an unsigned emulator ID token that does not verify is admitted as a mock token.
    #[must_use]
    pub const fn allows_unsigned(self) -> bool {
        self.allow_unsigned
    }
}

impl From<TokenAcceptance> for RulesTokenPolicy {
    fn from(acceptance: TokenAcceptance) -> Self {
        Self::new(
            acceptance,
            matches!(acceptance, TokenAcceptance::EmulatorMock),
        )
    }
}

/// How strictly an ID token's time claims (`iat`, `auth_time`, `exp`) are read: whether a
/// future `iat` or `auth_time` is refused (owner decision ledger 781) and whether a claim must
/// be a present integer (ledger 787).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FutureClaims {
    /// The `strict` profile. Inferred, not recorded: production refused a custom token with a
    /// future `iat` (`INVALID_CUSTOM_TOKEN`), and an ID token with one cannot be produced
    /// there; the Firebase ID-token contract requires all three claims to be present integers
    /// and `iat` and `auth_time` to be in the past.
    #[default]
    Refuse,
    /// The `emulator` profile: firebase-tools 15.28.2 decodes an ID token without verifying it
    /// and reads one time claim, `iat`, against the user's `validSince` and only when the user
    /// has one (`parseIdToken`, `lib/emulator/auth/operations.js:1727`:
    /// `!user.validSince || decoded.payload.iat >= Number(user.validSince)`). So the profile
    /// follows that line exactly: a future time claim is accepted, `auth_time` is never read,
    /// and `iat` is compared as JavaScript compares it (`Number(iat)`, see [`js_number`]; a
    /// value that is not a number fails the comparison) for an account that has a `validSince`
    /// (see `official_valid_since_is_set`) and is not compared at all for any other. A usable
    /// `auth_time` never stands in for an `iat` that does not compare. An `exp` that is present
    /// still ends the token's life, with the surface's allowance (ledger 22), and is read the
    /// same way: only an `exp` that is not a number counts as none.
    Accept,
}

/// JavaScript's `Number(value)` of a decoded JSON value; `None` is `NaN`. `null` and `false` are
/// 0, `true` is 1, an array is its elements joined with `,` and read as a string (`[]` is 0,
/// `[1]` is 1, `[1,2]` is `NaN`), an object is `NaN`, and a string is read by
/// [`string_to_number`].
fn js_number(value: &JsonValue) -> Option<f64> {
    match value {
        JsonValue::Null => Some(0.0),
        JsonValue::Bool(flag) => Some(f64::from(u8::from(*flag))),
        #[allow(clippy::cast_precision_loss)]
        JsonValue::Int(number) => Some(*number as f64),
        JsonValue::Float(number) => Some(*number),
        JsonValue::String(text) => string_to_number(text),
        JsonValue::Array(_) => string_to_number(&js_join(value)),
        JsonValue::Object(_) => None,
    }
}

/// `Array.prototype.toString` of a JSON value: `null` is empty, an array is its elements
/// joined with `,`, and an object is `[object Object]`.
fn js_join(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => String::new(),
        JsonValue::Bool(flag) => flag.to_string(),
        JsonValue::Int(number) => number.to_string(),
        JsonValue::Float(number) => number.to_string(),
        JsonValue::String(text) => text.clone(),
        JsonValue::Array(items) => items.iter().map(js_join).collect::<Vec<_>>().join(","),
        JsonValue::Object(_) => "[object Object]".to_owned(),
    }
}

/// ECMAScript `StringToNumber`: surrounding white space is dropped (the code points JavaScript
/// calls white space or line terminators, which includes U+FEFF and not U+0085), an empty string
/// is 0, `Infinity` with an optional sign is infinite, `0x`, `0o` and `0b` read an unsigned
/// integer in that base, and anything else must be a signed decimal literal (digits with an
/// optional fraction and an optional exponent, which may overflow to infinity). A string that is
/// none of these is `NaN`.
fn string_to_number(text: &str) -> Option<f64> {
    let text = text.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}');
    if text.is_empty() {
        return Some(0.0);
    }
    match text {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    let radix_digits = |prefixes: [&str; 2], radix: u32| {
        let digits = prefixes
            .iter()
            .find_map(|prefix| text.strip_prefix(prefix))?;
        (!digits.is_empty()).then_some(())?;
        digits.chars().try_fold(0.0_f64, |acc, c| {
            c.to_digit(radix)
                .map(|d| acc * f64::from(radix) + f64::from(d))
        })
    };
    for (prefixes, radix) in [(["0x", "0X"], 16), (["0o", "0O"], 8), (["0b", "0B"], 2)] {
        if text.get(..2).is_some_and(|head| prefixes.contains(&head)) {
            return radix_digits(prefixes, radix);
        }
    }
    // The decimal literal grammar, checked before Rust parses it so that `inf`, `nan` and `_`
    // (which Rust would read) stay `NaN`.
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], Some(&unsigned[at + 1..])),
        None => (unsigned, None),
    };
    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, None), |(w, f)| (w, Some(f)));
    let digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    let mantissa_ok = digits(whole)
        && fraction.is_none_or(digits)
        && !(whole.is_empty() && fraction.is_none_or(str::is_empty));
    let exponent_ok = exponent.is_none_or(|part| {
        let part = part.strip_prefix(['+', '-']).unwrap_or(part);
        !part.is_empty() && digits(part)
    });
    (mantissa_ok && exponent_ok)
        .then(|| text.parse::<f64>().ok())
        .flatten()
}

/// A `validSince` instant as the whole-second number firebase-tools compares with.
#[allow(clippy::cast_precision_loss)]
fn valid_since_seconds(instant: LogicalInstant) -> f64 {
    instant.as_nanos().div_euclid(1_000_000_000) as f64
}

/// Whether firebase-tools holds a `validSince` for this account, which is the only case in which
/// `parseIdToken` compares `iat` at all (`operations.js:1727`). It sets one when a password is
/// set or reset (`:169`, `:861`, `:634`, so also at a password sign-up and for a removed
/// password, which leaves it), when tokens are revoked (`:861`, and the email change and the
/// disable that revoke), when an email is changed through `accounts:update` (`:861`; this store
/// revokes the tokens there) and on an import (`:341`). An account made through the Admin API
/// without a password, or by an anonymous, custom-token or federated sign-in, has none. This
/// store holds a `tokens_valid_after` for every account, so the cases are rebuilt from what it
/// remembers.
fn official_valid_since_is_set(store: &AuthStore, user: &crate::store::UserRecord) -> bool {
    store.has_password(&user.local_id)
        || user.removed_password_updated_at.is_some()
        || user.tokens_revoked
        || user.imported
}

/// Token signing mode (`auth.idTokenSigning`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// `alg: none`, identical to the official Auth Emulator.
    UnsignedEmulator,
    /// RS256 with a session-fixed key. Declared; not implemented yet (fails closed).
    SessionRsa,
}

impl SigningMode {
    /// Whether this binary can issue tokens in the mode (RS256 needs a signer installed in
    /// the store by the runtime shell; the core never carries key material).
    #[must_use]
    pub const fn supported(self) -> bool {
        true
    }

    /// Parses the canonical config value.
    #[must_use]
    pub fn parse_config(s: &str) -> Option<Self> {
        match s {
            "unsigned-emulator" => Some(Self::UnsignedEmulator),
            "session-rsa" => Some(Self::SessionRsa),
            _ => None,
        }
    }
}

/// Token errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// Not a three-part base64url JWT with JSON header and payload.
    Malformed,
    /// Header algorithm other than `none`.
    UnsupportedAlgorithm(String),
    /// `exp` is not after `now`.
    Expired,
    /// Issuer mismatch.
    WrongIssuer {
        /// Expected.
        expected: String,
        /// Found.
        actual: String,
    },
    /// Audience mismatch.
    WrongAudience {
        /// Expected.
        expected: String,
        /// Found.
        actual: String,
    },
    /// `firebase.tenant` does not match the selected Auth namespace.
    WrongTenant {
        /// Expected tenant (`None` is the parent project namespace).
        expected: Option<String>,
        /// Tenant carried by the token.
        actual: Option<String>,
    },
    /// A locally issued token belongs to a different fireemu control-session incarnation.
    WrongSessionEpoch {
        /// Epoch required by the selected Auth store.
        expected: String,
        /// Epoch carried by the token, or `None` when absent.
        actual: Option<String>,
    },
    /// `sub` is not a known user.
    UnknownUser,
    /// The authenticated token belongs to a disabled user.
    UserDisabled,
    /// Tokens for this user were revoked after `auth_time`.
    Revoked,
    /// The signing mode cannot be used by this binary.
    SigningUnsupported(SigningMode),
    /// The signature does not verify against the session key.
    BadSignature,
    /// The `kid` header does not name the session key.
    UnknownKeyId,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed token"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported token algorithm {a}"),
            Self::Expired => f.write_str("token expired"),
            Self::WrongIssuer { expected, actual } => write!(f, "issuer {actual} != {expected}"),
            Self::WrongAudience { expected, actual } => {
                write!(f, "audience {actual} != {expected}")
            }
            Self::WrongTenant { expected, actual } => {
                write!(f, "tenant {actual:?} != {expected:?}")
            }
            Self::WrongSessionEpoch { expected, actual } => {
                write!(f, "fireemu session epoch {actual:?} != {expected:?}")
            }
            Self::UnknownUser => f.write_str("token subject is not a known user"),
            Self::Revoked => f.write_str("token revoked"),
            Self::UserDisabled => f.write_str("user is disabled"),
            Self::SigningUnsupported(m) => write!(f, "signing mode {m:?} is not implemented"),
            Self::BadSignature => f.write_str("token signature does not verify"),
            Self::UnknownKeyId => f.write_str("token kid does not name the session key"),
        }
    }
}

impl std::error::Error for JwtError {}

/// Public RSA key fields served by a JWKS endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicJwk {
    /// Key type (`RSA`).
    pub kty: &'static str,
    /// JOSE algorithm (`RS256`).
    pub alg: &'static str,
    /// Intended use (`sig`).
    pub usage: &'static str,
    /// Key ID.
    pub kid: String,
    /// Base64url modulus.
    pub modulus: String,
    /// Base64url public exponent.
    pub exponent: String,
}

/// Signs and verifies ID tokens (`RS256`); implemented by the runtime shell, which owns the
/// session key. The core only sees the signing input and the signature bytes.
pub trait IdTokenSigner: Send + Sync {
    /// JOSE algorithm name (`RS256`).
    fn alg(&self) -> &'static str;
    /// Key id carried in the token header.
    fn kid(&self) -> &str;
    /// Signature over `header.payload`.
    fn sign(&self, signing_input: &[u8]) -> Vec<u8>;
    /// Whether `signature` is valid for `signing_input`.
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool;

    /// Opts into signature reuse only when this instance's algorithm, key ID and verification result for fixed signing-input and signature bytes remain unchanged for its entire lifetime. Mutable and existing custom signers retain full verification by default.
    fn signature_verification_is_immutable(&self) -> bool {
        false
    }

    /// The public key as a JWK (JSON text), for the JWKS endpoint.
    fn public_jwk_json(&self) -> String;
    /// Cached public-key fields, when the signer exposes a structured representation.
    #[must_use]
    fn public_jwk(&self) -> Option<&PublicJwk> {
        None
    }
}

impl fmt::Debug for dyn IdTokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdTokenSigner({} kid {})", self.alg(), self.kid())
    }
}

/// Encodes claims with `signer`, or unsigned (`alg: none`) without one.
#[must_use]
pub fn encode_with(claims: &IdTokenClaims, signer: Option<&dyn IdTokenSigner>) -> String {
    encode_payload_with(&claims.canonical_json(), signer)
}

/// Whether an issued token's header names its type. Production ID tokens carry `typ: JWT`;
/// session cookies and the legacy Identity Toolkit token carry only `alg` and `kid` (sandbox
/// recording 2026-09-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderShape {
    /// `{"alg", "kid", "typ": "JWT"}`.
    Typed,
    /// `{"alg", "kid"}`.
    Untyped,
}

/// The unsigned header of each shape: the internal form a response carries until it is signed.
#[must_use]
pub const fn unsigned_header(shape: HeaderShape) -> &'static [u8] {
    match shape {
        HeaderShape::Typed => br#"{"alg":"none","typ":"JWT"}"#,
        HeaderShape::Untyped => br#"{"alg":"none"}"#,
    }
}

/// Encodes an already serialized JSON payload with `signer`, or unsigned without one.
#[must_use]
pub fn encode_payload_with(payload_json: &str, signer: Option<&dyn IdTokenSigner>) -> String {
    encode_payload_shaped(payload_json, signer, HeaderShape::Typed)
}

/// Encodes an already serialized JSON payload in `shape` with `signer`, or unsigned without
/// one (a session cookie is an ID token's claims under another issuer, lifetime and shape).
#[must_use]
pub fn encode_payload_shaped(
    payload_json: &str,
    signer: Option<&dyn IdTokenSigner>,
    shape: HeaderShape,
) -> String {
    let Some(signer) = signer else {
        let header = base64url_encode(unsigned_header(shape));
        return format!("{header}.{}.", base64url_encode(payload_json.as_bytes()));
    };
    let header = match shape {
        HeaderShape::Typed => format!(
            r#"{{"alg":"{}","kid":"{}","typ":"JWT"}}"#,
            signer.alg(),
            signer.kid()
        ),
        HeaderShape::Untyped => format!(r#"{{"alg":"{}","kid":"{}"}}"#, signer.alg(), signer.kid()),
    };
    let signing_input = format!(
        "{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(payload_json.as_bytes())
    );
    let signature = signer.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(&signature))
}

/// Encodes claims as an unsigned emulator-style token.
#[must_use]
pub fn encode_unsigned(claims: &IdTokenClaims) -> String {
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = base64url_encode(claims.canonical_json().as_bytes());
    format!("{header}.{payload}.")
}

/// Encodes claims in `mode`, failing closed for unimplemented modes.
pub fn encode(claims: &IdTokenClaims, mode: SigningMode) -> Result<String, JwtError> {
    match mode {
        SigningMode::UnsignedEmulator => Ok(encode_unsigned(claims)),
        SigningMode::SessionRsa => Err(JwtError::SigningUnsupported(mode)),
    }
}

/// A decoded (but not yet verified) token.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedToken {
    /// `alg` header.
    pub header_alg: String,
    /// `typ` header.
    pub header_typ: String,
    /// Payload JSON text.
    pub payload_json: String,
    /// Parsed payload.
    pub payload: JsonValue,
}

impl DecodedToken {
    /// `sub` claim.
    #[must_use]
    pub fn sub(&self) -> Option<&str> {
        self.payload.get("sub").and_then(JsonValue::as_str)
    }

    /// `exp` claim.
    #[must_use]
    pub fn exp(&self) -> Option<i64> {
        self.payload.get("exp").and_then(JsonValue::as_i64)
    }

    fn string(&self, key: &str) -> Option<&str> {
        self.payload.get(key).and_then(JsonValue::as_str)
    }
}

/// Decodes an unsigned token without verifying claims.
pub fn decode_unsigned(token: &str) -> Result<DecodedToken, JwtError> {
    decode_token(token, None)
}

/// The `firebase.tenant` claim of a token read as it stands, WITHOUT checking its algorithm or
/// signature: the way the official emulator reads an ID token's tenant before it looks the tenant
/// up (`jsonwebtoken.decode`). The value is unverified: never use it for authentication,
/// identity, store or tenant selection or authorization. It is only for a check that can make a
/// request refuse (the agreement with the tenant a request names), and nothing else of the token
/// is returned. `None` when the token does not parse, has no string tenant claim, or the claim is
/// empty (falsy in the official emulator's check).
#[must_use]
pub fn unverified_tenant_claim(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload, signature] = parts.as_slice() else {
        return None;
    };
    // The official decoder reads nothing unless the whole token matches its JWS pattern, whose
    // signature segment is empty or base64url.
    if !signature
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let header = String::from_utf8(base64url_decode(header_b64).ok()?).ok()?;
    if !matches!(parse(&header), Ok(JsonValue::Object(_))) {
        return None;
    }
    let payload_json = String::from_utf8(base64url_decode(payload).ok()?).ok()?;
    let claims = parse(&payload_json).ok()?;
    let tenant = claims
        .get("firebase")
        .and_then(|firebase| firebase.get("tenant"))
        .and_then(JsonValue::as_str)?;
    (!tenant.is_empty()).then(|| tenant.to_owned())
}

/// The header `createMockUserToken` (`@firebase/util`) writes for a `mockUserToken`, byte for
/// byte: `JSON.stringify({alg: 'none', type: 'JWT'})`.
pub const SDK_MOCK_TOKEN_HEADER: &[u8] = br#"{"alg":"none","type":"JWT"}"#;

/// Whether `token` has the shape of the Firebase JS SDK's `mockUserToken`, which
/// `@firebase/rules-unit-testing`'s `authenticatedContext()` sends: exactly three
/// `.`-separated segments, a header segment that is base64url without padding of exactly the
/// bytes [`SDK_MOCK_TOKEN_HEADER`] (another member order, spacing, an extra member, or the
/// `typ` that fireemu's own unsigned ID tokens carry is not that shape), and an empty
/// signature segment. The payload is not read here. Every SDK mock token is an unsigned token
/// ([`is_unsigned_token`]).
#[must_use]
pub fn is_sdk_mock_token(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(_payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    signature.is_empty()
        && base64url_decode(header_b64).is_ok_and(|header| header == SDK_MOCK_TOKEN_HEADER)
}

/// Whether `token` is an unsigned emulator ID token: exactly three `.`-separated segments, a
/// header segment that is base64url without padding of a JSON object whose `alg` member is
/// the string `none` (case-sensitive; other members such as `typ`, or the `type` the Firebase JS
/// SDK's `mockUserToken` writes, are not read), and an empty signature segment. The payload is
/// not read here. Every other value counts as signed: a non-empty signature, any other `alg`
/// (`None`, `RS256`, a missing or non-string `alg`), a header that is not a JSON object, or a
/// different number of segments.
///
/// This is the shape `@firebase/rules-unit-testing`'s `authenticatedContext()` and the client
/// SDKs' `mockUserToken` send, and the shape fireemu itself issues under
/// `auth.idTokenSigning: unsigned-emulator`.
#[must_use]
pub fn is_unsigned_token(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(_payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !signature.is_empty() {
        return false;
    }
    let Some(header) = base64url_decode(header_b64)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return false;
    };
    // `get` answers `None` for anything but an object, so a header that is no JSON object
    // never counts as unsigned.
    parse(&header).is_ok_and(|value| value.get("alg").and_then(JsonValue::as_str) == Some("none"))
}

/// Decodes a token and checks its signature: with a `signer` the token must carry the
/// signer's algorithm and a valid signature (an unsigned token is refused, so a session
/// issuing RS256 tokens never accepts forged `alg: none` ones); without one only `alg: none`
/// with an empty signature is accepted.
pub fn decode_token(
    token: &str,
    signer: Option<&dyn IdTokenSigner>,
) -> Result<DecodedToken, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload, signature] = parts.as_slice() else {
        return Err(JwtError::Malformed);
    };
    let header =
        String::from_utf8(base64url_decode(header_b64)?).map_err(|_| JwtError::Malformed)?;
    let header = parse(&header).map_err(|_| JwtError::Malformed)?;
    let alg = header
        .get("alg")
        .and_then(JsonValue::as_str)
        .ok_or(JwtError::Malformed)?;
    if let Some(signer) = signer {
        if alg != signer.alg() {
            return Err(JwtError::UnsupportedAlgorithm(alg.to_owned()));
        }
        if header.get("kid").and_then(JsonValue::as_str) != Some(signer.kid()) {
            return Err(JwtError::UnknownKeyId);
        }
        let signing_input = format!("{header_b64}.{payload}");
        let signature = base64url_decode(signature)?;
        if signature.is_empty() || !signer.verify(signing_input.as_bytes(), &signature) {
            return Err(JwtError::BadSignature);
        }
    } else {
        if alg != "none" {
            return Err(JwtError::UnsupportedAlgorithm(alg.to_owned()));
        }
        if !signature.is_empty() {
            return Err(JwtError::Malformed);
        }
    }
    let typ = header
        .get("typ")
        .and_then(JsonValue::as_str)
        .unwrap_or("JWT")
        .to_owned();
    let payload_json =
        String::from_utf8(base64url_decode(payload)?).map_err(|_| JwtError::Malformed)?;
    let parsed = parse(&payload_json).map_err(|_| JwtError::Malformed)?;
    if !matches!(parsed, JsonValue::Object(_)) {
        return Err(JwtError::Malformed);
    }
    Ok(DecodedToken {
        header_alg: alg.to_owned(),
        header_typ: typ,
        payload_json,
        payload: parsed,
    })
}

/// An immutable token whose signature was checked against one installed signer.
///
/// This is not an authenticated principal: account, tenant, epoch and temporal checks must still run against the selected store. Keeping the original signer alive makes identity comparison safe across routing and signer replacement.
pub struct SignatureCheckedToken {
    token: String,
    decoded: DecodedToken,
    signer: Option<Arc<dyn IdTokenSigner>>,
    reusable: bool,
}

impl fmt::Debug for SignatureCheckedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureCheckedToken")
            .finish_non_exhaustive()
    }
}

impl SignatureCheckedToken {
    /// Checks the signature and decodes claims without authenticating the account.
    pub fn decode(token: &str, store: &AuthStore) -> Result<Self, JwtError> {
        let signer = store.signer_arc();
        let reusable = signer
            .as_ref()
            .is_none_or(|signer| signer.signature_verification_is_immutable());
        let decoded = decode_token(token, signer.as_deref())?;
        Ok(Self {
            token: token.to_owned(),
            decoded,
            signer,
            reusable,
        })
    }

    /// Claims for routing only; they have not passed the selected store's checks.
    #[must_use]
    pub fn decoded(&self) -> &DecodedToken {
        &self.decoded
    }

    /// Whether the exact token can reuse this immutable signature result with the currently installed signer. This does not authenticate claims: callers must repeat the live store checks with `verify_for_project`.
    #[must_use]
    pub fn can_reuse_signature_for(&self, token: &str, store: &AuthStore) -> bool {
        if !self.reusable || self.token != token {
            return false;
        }
        let selected_signer = store.signer_arc();
        match (&self.signer, &selected_signer) {
            (None, None) => true,
            (Some(captured), Some(selected)) => Arc::ptr_eq(captured, selected),
            _ => false,
        }
    }

    /// Validates Rules claims against the current store, reusing the signature check only when the installed signer is still the same object and explicitly guarantees immutable verification. Mutable, unclassified and replaced signers are verified normally, including when they advertise the same algorithm and key ID.
    pub fn verify_for_project(
        &self,
        store: &AuthStore,
        now: LogicalInstant,
        policy: impl Into<RulesTokenPolicy>,
        expected_project: &str,
    ) -> Result<DecodedToken, JwtError> {
        let expected_project =
            ProjectId::try_new(expected_project.to_owned()).map_err(|_| JwtError::Malformed)?;
        let policy = policy.into();
        if !self.can_reuse_signature_for(&self.token, store) {
            return verify_rules_token_with_expected_project(
                &self.token,
                store,
                now,
                policy,
                expected_project.as_str(),
            );
        }
        let verified = validate_token_claims(
            self.decoded.clone(),
            store,
            now,
            0,
            TenantRule::Store,
            store.lifecycle_epoch_claim(),
            policy.acceptance().future_claims(),
        )
        .and_then(|decoded| {
            verify_id_token_account(decoded, store, now, policy.acceptance().future_claims())
        })
        .map(|(_, decoded)| decoded);
        mock_fallback(
            &self.token,
            store,
            policy,
            expected_project.as_str(),
            verified,
        )
    }
}

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenVerification {
    /// Subject.
    pub uid: String,
    /// `firebase.sign_in_second_factor`, if present.
    pub second_factor: Option<String>,
}

/// Issuer of the legacy Identity Toolkit token production returns from password and
/// custom-token sign-in when the request does not ask for secure tokens (sandbox recording
/// 2026-09-24, auth-credential/id-token/without-return-secure-token).
pub const LEGACY_TOKEN_ISSUER: &str = "https://identitytoolkit.google.com/";
/// The legacy token's lifetime: two weeks.
pub const LEGACY_TOKEN_TTL_SECONDS: i64 = 14 * 24 * 60 * 60;

/// What a legacy Identity Toolkit token says about its session.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyToken<'a> {
    /// The account.
    pub uid: &'a str,
    /// `sign_in_provider` (`password`, `custom`).
    pub sign_in_provider: &'a str,
    /// The account's address and whether it is verified, when it has one.
    pub email: Option<(&'a str, bool)>,
    /// A custom token's developer claims (`extra_claims`), when it carried any.
    pub extra_claims: Option<&'a BTreeMap<String, ClaimValue>>,
    /// The issuing store's session epoch, only while fireemu session isolation is active (the
    /// same local-only marker ID tokens carry under `firebase`).
    pub session_epoch: Option<&'a str>,
    /// The tenant of a tenant's account: a top-level `tenant` claim (AUTH-TENANT-BLOCKING
    /// sandbox recording 2026-09-27, settings#password-off-update-password).
    pub tenant: Option<&'a str>,
}

/// The claims of a legacy token issued at `iat` for `project`: no `sub`, `auth_time` or
/// `firebase` block, the provider at the top level, a two-week lifetime.
#[must_use]
pub fn legacy_token_payload(project: &str, iat: i64, token: &LegacyToken<'_>) -> String {
    let mut claims = BTreeMap::new();
    claims.insert(
        "iss".to_owned(),
        ClaimValue::String(LEGACY_TOKEN_ISSUER.to_owned()),
    );
    claims.insert("aud".to_owned(), ClaimValue::String(project.to_owned()));
    claims.insert("iat".to_owned(), ClaimValue::Int(iat));
    claims.insert(
        "exp".to_owned(),
        ClaimValue::Int(iat.saturating_add(LEGACY_TOKEN_TTL_SECONDS)),
    );
    claims.insert(
        "user_id".to_owned(),
        ClaimValue::String(token.uid.to_owned()),
    );
    claims.insert(
        "sign_in_provider".to_owned(),
        ClaimValue::String(token.sign_in_provider.to_owned()),
    );
    if let Some((email, verified)) = token.email {
        claims.insert("email".to_owned(), ClaimValue::String(email.to_owned()));
        claims.insert("verified".to_owned(), ClaimValue::Bool(verified));
    }
    if let Some(extra) = token.extra_claims.filter(|extra| !extra.is_empty()) {
        claims.insert("extra_claims".to_owned(), ClaimValue::Map(extra.clone()));
    }
    if let Some(tenant) = token.tenant {
        claims.insert("tenant".to_owned(), ClaimValue::String(tenant.to_owned()));
    }
    if let Some(epoch) = token.session_epoch {
        claims.insert(
            "fireemu_session_epoch".to_owned(),
            ClaimValue::String(epoch.to_owned()),
        );
    }
    crate::claims::canonical_map_json(&claims)
}

/// Verifies a legacy Identity Toolkit token: signature mode, issuer, audience, expiry,
/// issued-at, subject existence, revocation (its `iat` stands for `auth_time`) and disabled
/// users. Production honours it on account lookup and refuses it for a session cookie.
pub fn verify_legacy_token(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    leeway_seconds: i64,
) -> Result<(TokenVerification, DecodedToken), JwtError> {
    let decoded = decode_token(token, store.signer())?;
    let iss = decoded.string("iss").ok_or(JwtError::Malformed)?;
    // A store that never issued a legacy token (the emulator profile, a tenant) honours none.
    if iss != LEGACY_TOKEN_ISSUER || !store.legacy_tokens_issued() {
        return Err(JwtError::WrongIssuer {
            expected: format!("https://securetoken.google.com/{}", store.project_id()),
            actual: iss.to_owned(),
        });
    }
    if store.tenant_id().is_some() {
        return Err(JwtError::WrongTenant {
            expected: store.tenant_id().map(str::to_owned),
            actual: None,
        });
    }
    if let Some(expected) = store.lifecycle_epoch_claim() {
        let actual = decoded.string("fireemu_session_epoch").map(str::to_owned);
        if actual.as_deref() != Some(expected.as_str()) {
            return Err(JwtError::WrongSessionEpoch { expected, actual });
        }
    }
    let aud = decoded.string("aud").ok_or(JwtError::Malformed)?;
    if aud != store.project_id() {
        return Err(JwtError::WrongAudience {
            expected: store.project_id().to_owned(),
            actual: aud.to_owned(),
        });
    }
    let now_secs = i64::try_from(now.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    let exp = decoded.exp().ok_or(JwtError::Malformed)?;
    if now_secs >= exp.saturating_add(leeway_seconds) {
        return Err(JwtError::Expired);
    }
    let issued_at = decoded
        .payload
        .get("iat")
        .and_then(JsonValue::as_i64)
        .filter(|iat| *iat <= now_secs)
        .ok_or(JwtError::Malformed)?;
    let uid = decoded
        .string("user_id")
        .ok_or(JwtError::Malformed)?
        .to_owned();
    let user = store.user_by_id(&uid).ok_or(JwtError::UnknownUser)?;
    if user.disabled {
        return Err(JwtError::UserDisabled);
    }
    if !store.token_is_valid(
        &user.local_id,
        LogicalInstant::from_unix_seconds(issued_at),
        LogicalInstant::from_unix_seconds(exp.saturating_add(leeway_seconds)),
        now,
    ) {
        return Err(JwtError::Revoked);
    }
    Ok((
        TokenVerification {
            uid,
            second_factor: None,
        },
        decoded,
    ))
}

/// Verifies an ID token against the store: signature mode, issuer, audience, expiry,
/// issued-at and authentication times, subject existence, revocation and disabled users.
pub fn verify_id_token(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
) -> Result<TokenVerification, JwtError> {
    verify_id_token_decoded(token, store, now).map(|(v, _)| v)
}

/// Verifies the token a Security Rules surface received under `policy`, returning the
/// claims `request.auth` is built from.
///
/// The verified path is exactly [`verify_id_token_decoded`], with the future-claim policy of
/// the profile's [`TokenAcceptance`]. A policy that allows unsigned tokens
/// ([`RulesTokenPolicy::allows_unsigned`]; the emulator profile's default, and
/// `auth.allowUnsignedIdTokens`) additionally admits the mock tokens the official Firestore and
/// Storage emulators admit: an unsigned token, minted for this project, whose `sub` names nobody
/// and whose `exp` and `iat` are never read. A token this store *can* verify always takes the
/// verified path, so a real session token keeps its full meaning.
pub fn verify_rules_token(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    policy: impl Into<RulesTokenPolicy>,
) -> Result<DecodedToken, JwtError> {
    verify_rules_token_with_expected_project(token, store, now, policy.into(), store.project_id())
}

/// Verifies a token for a Security Rules request whose routed project may be an
/// unregistered Firestore namespace owned by the default session.
///
/// Verified tokens still use the selected [`AuthStore`] exactly as
/// [`verify_rules_token`] does. Only the unsigned mock-token fallback binds its audience to
/// `expected_project` instead of the store's configured project. Callers must still enforce
/// the same routed-project binding on the resulting principal before evaluating rules.
pub fn verify_rules_token_for_project(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    policy: impl Into<RulesTokenPolicy>,
    expected_project: &str,
) -> Result<DecodedToken, JwtError> {
    let expected_project =
        ProjectId::try_new(expected_project.to_owned()).map_err(|_| JwtError::Malformed)?;
    verify_rules_token_with_expected_project(
        token,
        store,
        now,
        policy.into(),
        expected_project.as_str(),
    )
}

/// [`verify_rules_token_for_project`] for Firestore, which checks the token but not the account
/// (see [`verify_firestore_token`]); `expected_project` binds a mock token's audience and
/// defaults to the store's project.
pub fn verify_firestore_rules_token(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    policy: impl Into<RulesTokenPolicy>,
    expected_project: Option<&str>,
) -> Result<DecodedToken, JwtError> {
    let policy = policy.into();
    let expected_project = match expected_project {
        Some(project) => ProjectId::try_new(project.to_owned())
            .map_err(|_| JwtError::Malformed)?
            .as_str()
            .to_owned(),
        None => store.project_id().to_owned(),
    };
    let verified =
        verify_firestore_token_with(token, store, now, policy.acceptance().future_claims());
    mock_fallback(token, store, policy, &expected_project, verified)
}

fn verify_rules_token_with_expected_project(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    policy: RulesTokenPolicy,
    expected_project: &str,
) -> Result<DecodedToken, JwtError> {
    let verified = verify_id_token_with(token, store, now, 0, policy.acceptance().future_claims())
        .map(|(_, decoded)| decoded);
    mock_fallback(token, store, policy, expected_project, verified)
}

/// The mock-token admission after a failed verification, when `policy` allows unsigned
/// tokens (the emulator profile's default, and `auth.allowUnsignedIdTokens`).
fn mock_fallback(
    token: &str,
    store: &AuthStore,
    policy: RulesTokenPolicy,
    expected_project: &str,
    verified: Result<DecodedToken, JwtError>,
) -> Result<DecodedToken, JwtError> {
    let verified_error = match verified {
        Ok(decoded) => return Ok(decoded),
        Err(verified_error) => verified_error,
    };
    // A session that installed a signer issues RS256 tokens and refuses unsigned ones on
    // every surface (`auth.idTokenSigning: session-rsa`); the mock path would undo exactly
    // that, so it is not offered there whatever the policy says. Only an unsigned token can
    // be a mock token, so a forged `RS256` token keeps its refusal rather than becoming an
    // identity. Under strict only the exact shape `createMockUserToken` writes is one
    // (owner ledger 1405): fireemu's own unsigned ID tokens keep every claim check, expiry
    // included; the emulator profile admits any unsigned token, as the official emulator does.
    let mock_shape = match policy.acceptance() {
        TokenAcceptance::Verified => is_sdk_mock_token(token),
        TokenAcceptance::EmulatorMock => is_unsigned_token(token),
    };
    if !policy.allows_unsigned() || store.signer().is_some() || !mock_shape {
        return Err(verified_error);
    }
    match unsigned_mock(token, expected_project) {
        Ok(decoded) => Ok(decoded),
        // The strict profile answers a token it does not admit exactly as it did before the
        // setting existed; the emulator profile keeps the mock path's own error.
        Err(_) if policy.acceptance() == TokenAcceptance::Verified => Err(verified_error),
        Err(mock_error) => Err(mock_error),
    }
}

/// An unsigned token as a mock token: minted for `expected_project` and naming a subject.
fn unsigned_mock(token: &str, expected_project: &str) -> Result<DecodedToken, JwtError> {
    // Without a signer `decode_token` accepts `alg: none` with an empty signature and
    // nothing else.
    let decoded = decode_token(token, None)?;
    let aud = decoded.string("aud").ok_or(JwtError::Malformed)?;
    if aud != expected_project {
        return Err(JwtError::WrongAudience {
            expected: expected_project.to_owned(),
            actual: aud.to_owned(),
        });
    }
    // `request.auth.uid` is the subject; a token without one names no caller.
    decoded.sub().ok_or(JwtError::Malformed)?;
    Ok(decoded)
}

/// [`verify_id_token`] returning the decoded token as well (claims for `request.auth`).
pub fn verify_id_token_decoded(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
) -> Result<(TokenVerification, DecodedToken), JwtError> {
    verify_id_token_decoded_with_leeway(token, store, now, 0)
}

/// Identity Toolkit's allowance past a token's `exp`: production accepted an ID token and a
/// custom token ten seconds after `exp` and refused them 330 seconds after (sandbox recording
/// 2026-09-24); the conventional five-minute clock-skew allowance lies between.
pub const IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS: i64 = 300;

/// [`verify_id_token_decoded`] that still honours a token up to `leeway_seconds` past `exp`.
/// Future time claims follow the store's profile ([`AuthStore::future_id_token_claims`]), which
/// Identity Toolkit sets on every request. A caller outside Identity Toolkit should take the
/// profile from a [`TokenAcceptance`] (as the Rules entry points do) instead of relying on it.
pub fn verify_id_token_decoded_with_leeway(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    leeway_seconds: i64,
) -> Result<(TokenVerification, DecodedToken), JwtError> {
    verify_id_token_with(
        token,
        store,
        now,
        leeway_seconds,
        store.future_id_token_claims(),
    )
}

fn verify_id_token_with(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    leeway_seconds: i64,
    future: FutureClaims,
) -> Result<(TokenVerification, DecodedToken), JwtError> {
    let decoded = verify_token_claims(
        token,
        store,
        now,
        leeway_seconds,
        TenantRule::Store,
        store.lifecycle_epoch_claim(),
        future,
    )?;
    verify_id_token_account(decoded, store, now, future)
}

fn verify_id_token_account(
    decoded: DecodedToken,
    store: &AuthStore,
    now: LogicalInstant,
    future: FutureClaims,
) -> Result<(TokenVerification, DecodedToken), JwtError> {
    let sub = decoded.sub().ok_or(JwtError::Malformed)?;
    let user = store.user_by_id(sub).ok_or(JwtError::UnknownUser)?;
    let auth_time = check_auth_time(&decoded, now, future)?;
    if user.disabled {
        return Err(JwtError::UserDisabled);
    }
    let revoked = match (future, auth_time) {
        (FutureClaims::Refuse, Some(auth_time)) => {
            LogicalInstant::from_unix_seconds(auth_time) < user.tokens_valid_after
        }
        // `check_auth_time` answers a strict token's missing `auth_time` with `Malformed`.
        (FutureClaims::Refuse, None) => return Err(JwtError::Malformed),
        // `operations.js:1727`: the token is compared by its `iat` alone, and only for an
        // account that has a `validSince`; `auth_time` is not read. `NaN` fails the comparison.
        (FutureClaims::Accept, _) => {
            official_valid_since_is_set(store, user)
                && !decoded
                    .payload
                    .get("iat")
                    .and_then(js_number)
                    .is_some_and(|iat| iat >= valid_since_seconds(user.tokens_valid_after))
        }
    };
    if revoked {
        return Err(JwtError::Revoked);
    }
    let second_factor = decoded
        .payload
        .get("firebase")
        .and_then(|f| f.get("sign_in_second_factor"))
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    Ok((
        TokenVerification {
            uid: sub.to_owned(),
            second_factor,
        },
        decoded,
    ))
}

/// What Firestore checks of an ID token before Security Rules see it: the signature, the
/// issuer, audience, tenant and session, `exp` with Firestore's allowance, and that `iat` and
/// `auth_time` are not in the future. Unlike Identity Toolkit it does not consult the
/// account: a token of an account whose refresh tokens were revoked, that was disabled, or
/// that was deleted is honoured until it expires (FS-RULES production recording,
/// 2026-09-24). Future time claims follow the store's profile, as in
/// [`verify_id_token_decoded_with_leeway`]; Rules callers use [`verify_firestore_rules_token`].
pub fn verify_firestore_token(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
) -> Result<DecodedToken, JwtError> {
    verify_firestore_token_with(token, store, now, store.future_id_token_claims())
}

fn verify_firestore_token_with(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    future: FutureClaims,
) -> Result<DecodedToken, JwtError> {
    let decoded = verify_token_claims(
        token,
        store,
        now,
        FIRESTORE_EXPIRY_LEEWAY_SECONDS,
        TenantRule::Store,
        store.lifecycle_epoch_claim(),
        future,
    )?;
    check_auth_time(&decoded, now, future)?;
    Ok(decoded)
}

/// [`verify_firestore_rules_token`] for a token whose tenant no longer exists, checked against
/// its project's `store`. Firestore does not look the tenant up either: an unexpired token of a
/// deleted tenant was honoured about 3 s and 66 s after the deletion (AUTH-FS-CROSS stage 1,
/// 2026-09-27). The token must still carry a tenant claim, so it never passes for the project's
/// user of the same uid.
///
/// `removed` is what the registry remembered of the tenant's deletion. While the project's
/// session epoch is still the one it had then (no reset since), the token must carry the epoch
/// its tenant had; otherwise, or for a tenant never deleted, the project's own epoch.
pub fn verify_firestore_rules_token_of_removed_tenant(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    policy: impl Into<RulesTokenPolicy>,
    expected_project: Option<&str>,
    removed: Option<&crate::store::RemovedTenantEpochs>,
) -> Result<DecodedToken, JwtError> {
    let policy = policy.into();
    let future = policy.acceptance().future_claims();
    let project_epoch = store.lifecycle_epoch_claim();
    let expected_epoch = match removed {
        Some(epochs) if epochs.project == project_epoch => epochs.tenant.clone(),
        _ => project_epoch,
    };
    let expected_project = match expected_project {
        Some(project) => ProjectId::try_new(project.to_owned())
            .map_err(|_| JwtError::Malformed)?
            .as_str()
            .to_owned(),
        None => store.project_id().to_owned(),
    };
    let verified = verify_token_claims(
        token,
        store,
        now,
        FIRESTORE_EXPIRY_LEEWAY_SECONDS,
        TenantRule::Removed,
        expected_epoch,
        future,
    )
    .and_then(|decoded| check_auth_time(&decoded, now, future).map(|_| decoded));
    mock_fallback(token, store, policy, &expected_project, verified)
}

/// Which tenant claim a store accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TenantRule {
    /// Exactly the store's own tenant (none for a project store).
    Store,
    /// Any tenant, from a project store whose tenant was removed: the claim must be present.
    Removed,
}

/// How long past `exp` Firestore still honours an ID token. In two recordings each (FS-RULES,
/// 2026-09-25) production accepted a token sent at a nominal 29.8 s past it (29.3 s on gRPC) and
/// refused one at a nominal 30.3 s (31.3 s on gRPC); dispatch times were not recorded, so this is
/// a nominal bracket, not an exact (29.8, 30.3] s. A token is refused from `exp + 30`.
pub const FIRESTORE_EXPIRY_LEEWAY_SECONDS: i64 = 30;

/// The token checks that do not read the account: see [`verify_firestore_token`].
fn verify_token_claims(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
    leeway_seconds: i64,
    tenant_rule: TenantRule,
    expected_epoch: Option<String>,
    future: FutureClaims,
) -> Result<DecodedToken, JwtError> {
    validate_token_claims(
        decode_token(token, store.signer())?,
        store,
        now,
        leeway_seconds,
        tenant_rule,
        expected_epoch,
        future,
    )
}

fn validate_token_claims(
    decoded: DecodedToken,
    store: &AuthStore,
    now: LogicalInstant,
    leeway_seconds: i64,
    tenant_rule: TenantRule,
    expected_epoch: Option<String>,
    future: FutureClaims,
) -> Result<DecodedToken, JwtError> {
    let expected_iss = format!("https://securetoken.google.com/{}", store.project_id());
    let iss = decoded.string("iss").ok_or(JwtError::Malformed)?;
    if iss != expected_iss {
        return Err(JwtError::WrongIssuer {
            expected: expected_iss,
            actual: iss.to_owned(),
        });
    }
    let aud = decoded.string("aud").ok_or(JwtError::Malformed)?;
    if aud != store.project_id() {
        return Err(JwtError::WrongAudience {
            expected: store.project_id().to_owned(),
            actual: aud.to_owned(),
        });
    }
    let actual_tenant = decoded
        .payload
        .get("firebase")
        .and_then(|firebase| firebase.get("tenant"))
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let expected_tenant = store.tenant_id().map(str::to_owned);
    let tenant_ok = match tenant_rule {
        TenantRule::Store => actual_tenant == expected_tenant,
        TenantRule::Removed => expected_tenant.is_none() && actual_tenant.is_some(),
    };
    if !tenant_ok {
        return Err(JwtError::WrongTenant {
            expected: expected_tenant,
            actual: actual_tenant,
        });
    }
    if let Some(expected) = expected_epoch {
        let actual = decoded
            .payload
            .get("firebase")
            .and_then(|firebase| firebase.get("fireemu_session_epoch"))
            .and_then(JsonValue::as_str)
            .map(str::to_owned);
        if actual.as_deref() != Some(expected.as_str()) {
            return Err(JwtError::WrongSessionEpoch { expected, actual });
        }
    }
    let now_secs = i64::try_from(now.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    match future {
        FutureClaims::Refuse => {
            let exp = decoded.exp().ok_or(JwtError::Malformed)?;
            if now_secs >= exp.saturating_add(leeway_seconds) {
                return Err(JwtError::Expired);
            }
        }
        // Whatever `Number(exp)` is; only `NaN` (an object, an unparsable string, a missing
        // claim) is no `exp`.
        FutureClaims::Accept => {
            #[allow(clippy::cast_precision_loss)]
            let expired = decoded
                .payload
                .get("exp")
                .and_then(js_number)
                .is_some_and(|exp| now_secs as f64 >= exp + leeway_seconds as f64);
            if expired {
                return Err(JwtError::Expired);
            }
        }
    }
    // Firebase's ID-token contract requires `iat` and `auth_time` to be present integers not
    // in the future (strict; the emulator profile accepts any shape and any time, ledgers 781
    // and 787). Claims use whole seconds on this store's logical clock: a token issued in the
    // current second must remain immediately usable.
    if future == FutureClaims::Refuse {
        let issued_at = decoded
            .payload
            .get("iat")
            .and_then(JsonValue::as_i64)
            .ok_or(JwtError::Malformed)?;
        if issued_at > now_secs {
            return Err(JwtError::Malformed);
        }
    }
    decoded.sub().ok_or(JwtError::Malformed)?;
    Ok(decoded)
}

/// `auth_time`, which a strict token must carry as an integer not in the future (`Some`
/// then). The emulator profile never reads it (`None`).
fn check_auth_time(
    decoded: &DecodedToken,
    now: LogicalInstant,
    future: FutureClaims,
) -> Result<Option<i64>, JwtError> {
    if future == FutureClaims::Accept {
        return Ok(None);
    }
    let now_secs = i64::try_from(now.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    let auth_time = decoded
        .payload
        .get("auth_time")
        .and_then(JsonValue::as_i64)
        .ok_or(JwtError::Malformed)?;
    if auth_time > now_secs {
        return Err(JwtError::Malformed);
    }
    Ok(Some(auth_time))
}
