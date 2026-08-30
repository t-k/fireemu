//! ID token encoding and verification (`AUTH-TOKEN-1`, spec 12A.4).
//!
//! The official Auth Emulator issues unsigned tokens (`alg: none`); SDKs accept them in
//! emulator mode. This module implements that format exactly. RS256 signing with a
//! session-fixed key is a declared, not yet implemented, capability: choosing it fails closed.

use core::fmt;

use ftd_core_types::json::{parse, JsonValue};
use ftd_core_types::time::LogicalInstant;

use crate::claims::IdTokenClaims;
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
    /// `sub` is not a known user.
    UnknownUser,
    /// Tokens for this user were revoked after `auth_time`, or the user is disabled.
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
            Self::UnknownUser => f.write_str("token subject is not a known user"),
            Self::Revoked => f.write_str("token revoked"),
            Self::SigningUnsupported(m) => write!(f, "signing mode {m:?} is not implemented"),
            Self::BadSignature => f.write_str("token signature does not verify"),
            Self::UnknownKeyId => f.write_str("token kid does not name the session key"),
        }
    }
}

impl std::error::Error for JwtError {}

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
    /// The public key as a JWK (JSON text), for the JWKS endpoint.
    fn public_jwk_json(&self) -> String;
}

impl fmt::Debug for dyn IdTokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdTokenSigner({} kid {})", self.alg(), self.kid())
    }
}

/// Encodes claims with `signer`, or unsigned (`alg: none`) without one.
#[must_use]
pub fn encode_with(claims: &IdTokenClaims, signer: Option<&dyn IdTokenSigner>) -> String {
    let Some(signer) = signer else {
        return encode_unsigned(claims);
    };
    let header = format!(
        r#"{{"alg":"{}","kid":"{}","typ":"JWT"}}"#,
        signer.alg(),
        signer.kid()
    );
    let signing_input = format!(
        "{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(claims.canonical_json().as_bytes())
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

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenVerification {
    /// Subject.
    pub uid: String,
    /// `firebase.sign_in_second_factor`, if present.
    pub second_factor: Option<String>,
}

/// Verifies an unsigned token against the store: issuer, audience, expiry, subject existence,
/// revocation (`tokens_valid_after`) and disabled users.
pub fn verify_id_token(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
) -> Result<TokenVerification, JwtError> {
    verify_id_token_decoded(token, store, now).map(|(v, _)| v)
}

/// [`verify_id_token`] returning the decoded token as well (claims for `request.auth`).
pub fn verify_id_token_decoded(
    token: &str,
    store: &AuthStore,
    now: LogicalInstant,
) -> Result<(TokenVerification, DecodedToken), JwtError> {
    let decoded = decode_token(token, store.signer())?;
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
    let exp = decoded.exp().ok_or(JwtError::Malformed)?;
    let now_secs = i64::try_from(now.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    if now_secs >= exp {
        return Err(JwtError::Expired);
    }
    let sub = decoded.sub().ok_or(JwtError::Malformed)?;
    let user = store.user_by_id(sub).ok_or(JwtError::UnknownUser)?;
    let auth_time = decoded
        .payload
        .get("auth_time")
        .and_then(JsonValue::as_i64)
        .ok_or(JwtError::Malformed)?;
    if user.disabled || LogicalInstant::from_unix_seconds(auth_time) < user.tokens_valid_after {
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
