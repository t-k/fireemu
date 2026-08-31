//! ID token claims and custom claims (spec 12A.3, 12A.4).

use core::fmt;
use core::fmt::Write as _;
use std::collections::BTreeMap;

use fireemu_core_limits::catalogs::FIREBASE_AUTH_2026_08_30;
use fireemu_core_limits::evaluate::{
    evaluate, LimitDisposition, LimitViolation, DEFAULT_THRESHOLDS,
};
use fireemu_core_limits::plan::FirestorePlanProfile;

/// JSON-like claim value with canonical key ordering.
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimValue {
    /// `null`
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// String.
    String(String),
    /// List.
    List(Vec<ClaimValue>),
    /// Map (canonical key order).
    Map(BTreeMap<String, ClaimValue>),
}

impl ClaimValue {
    /// The same value read from a parsed JSON document.
    #[must_use]
    pub fn from_json(value: &fireemu_core_types::json::JsonValue) -> Self {
        use fireemu_core_types::json::JsonValue;
        match value {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(b) => Self::Bool(*b),
            JsonValue::Int(i) => Self::Int(*i),
            JsonValue::Float(f) => Self::Float(*f),
            JsonValue::String(s) => Self::String(s.clone()),
            JsonValue::Array(items) => Self::List(items.iter().map(Self::from_json).collect()),
            JsonValue::Object(members) => Self::Map(
                members
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::from_json(v)))
                    .collect(),
            ),
        }
    }
}

/// Writes `s` as a JSON string literal.
pub fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl ClaimValue {
    /// Appends the canonical JSON encoding (sorted keys, no whitespace).
    pub fn write_canonical_json(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Int(i) => out.push_str(&i.to_string()),
            Self::Float(f) => {
                if f.is_finite() {
                    let _ = write!(out, "{f:?}");
                } else {
                    out.push_str("null");
                }
            }
            Self::String(s) => write_json_string(out, s),
            Self::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical_json(out);
                }
                out.push(']');
            }
            Self::Map(entries) => write_map(out, entries),
        }
    }
}

fn write_map(out: &mut String, entries: &BTreeMap<String, ClaimValue>) {
    out.push('{');
    for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_json_string(out, k);
        out.push(':');
        v.write_canonical_json(out);
    }
    out.push('}');
}

/// Claim names reserved by OIDC / Firebase that custom claims may not use.
pub const RESERVED_CLAIM_NAMES: &[&str] = &[
    "acr",
    "amr",
    "at_hash",
    "aud",
    "auth_time",
    "azp",
    "c_hash",
    "cnf",
    "email",
    "email_verified",
    "exp",
    "firebase",
    "iat",
    "identities",
    "iss",
    "jti",
    "nbf",
    "nonce",
    "phone_number",
    "sign_in_provider",
    "sub",
    "user_id",
];

/// Custom claims errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomClaimsError {
    /// A reserved claim name was used.
    ReservedName(String),
    /// Empty claim name.
    EmptyName,
    /// The `customAttributes` text is not a JSON object.
    NotAnObject,
}

impl fmt::Display for CustomClaimsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedName(n) => write!(f, "claim name {n:?} is reserved"),
            Self::EmptyName => f.write_str("claim name is empty"),
            Self::NotAnObject => f.write_str("customAttributes is not a JSON object"),
        }
    }
}

impl std::error::Error for CustomClaimsError {}

/// Custom claims set through the Admin SDK.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CustomClaims {
    entries: BTreeMap<String, ClaimValue>,
}

impl CustomClaims {
    /// Inserts a claim, rejecting reserved names.
    pub fn insert(&mut self, name: &str, value: ClaimValue) -> Result<(), CustomClaimsError> {
        if name.is_empty() {
            return Err(CustomClaimsError::EmptyName);
        }
        if RESERVED_CLAIM_NAMES.contains(&name) {
            return Err(CustomClaimsError::ReservedName(name.to_owned()));
        }
        self.entries.insert(name.to_owned(), value);
        Ok(())
    }

    /// Looks up a claim.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ClaimValue> {
        self.entries.get(name)
    }

    /// Entries in canonical order.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<String, ClaimValue> {
        &self.entries
    }

    /// Parses the `customAttributes` text an export or the Identity Toolkit carries.
    ///
    /// The API transports custom claims as a JSON *string* holding an object, so an import
    /// has to parse it back. A reserved claim name is refused rather than dropped: an
    /// artifact that smuggled `sub` or `iss` into the claims would otherwise silently change
    /// what every ID token of that account says.
    pub fn parse_attributes(text: &str) -> Result<Self, CustomClaimsError> {
        let parsed =
            fireemu_core_types::json::parse(text).map_err(|_| CustomClaimsError::NotAnObject)?;
        let fireemu_core_types::json::JsonValue::Object(members) = parsed else {
            return Err(CustomClaimsError::NotAnObject);
        };
        let mut claims = Self::default();
        for (name, value) in &members {
            claims.insert(name, ClaimValue::from_json(value))?;
        }
        Ok(claims)
    }

    /// Canonical JSON encoding.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        write_map(&mut out, &self.entries);
        out
    }

    /// Checks `AUTH-LIMIT-CUSTOM-CLAIMS-BYTES` on the canonical JSON size.
    pub fn check_size(&self) -> Result<(), LimitViolation> {
        let def = FIREBASE_AUTH_2026_08_30
            .find("AUTH-LIMIT-CUSTOM-CLAIMS-BYTES")
            .unwrap_or_else(|| unreachable!("catalog entry is checked by catalog tests"));
        let bytes = self.canonical_json().len() as u64;
        match evaluate(
            def,
            bytes,
            &FirestorePlanProfile::default(),
            DEFAULT_THRESHOLDS,
        ) {
            LimitDisposition::Reject(v) | LimitDisposition::ObservedOverLimit(v) => Err(v),
            LimitDisposition::Allow | LimitDisposition::AllowWithWarnings(_) => Ok(()),
        }
    }
}

/// The `firebase` claim block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirebaseClaims {
    /// Provider identities, e.g. `{"email": ["a@example.com"]}`.
    pub identities: BTreeMap<String, Vec<String>>,
    /// Sign-in provider (`password`, `anonymous`, `custom`, ...).
    pub sign_in_provider: String,
    /// Second factor used (`totp`), if any.
    pub sign_in_second_factor: Option<String>,
    /// Enrollment ID of the second factor, if any.
    pub second_factor_identifier: Option<String>,
    /// Identity Platform tenant ID, absent for the parent project namespace.
    pub tenant: Option<String>,
}

/// ID token claims (unsigned; signing is an adapter concern).
#[derive(Debug, Clone, PartialEq)]
pub struct IdTokenClaims {
    /// Issuer `https://securetoken.google.com/{project}`.
    pub iss: String,
    /// Audience (project ID).
    pub aud: String,
    /// Authentication time (Unix seconds).
    pub auth_time: i64,
    /// User ID (duplicate of `sub`, as Firebase emits it).
    pub user_id: String,
    /// Subject.
    pub sub: String,
    /// Issued at.
    pub iat: i64,
    /// Expiry.
    pub exp: i64,
    /// Email, if any.
    pub email: Option<String>,
    /// Email verified flag.
    pub email_verified: bool,
    /// Phone number, if any.
    pub phone_number: Option<String>,
    /// Display name (`name` in the JWT).
    pub display_name: Option<String>,
    /// Profile photo URL (`picture` in the JWT).
    pub photo_url: Option<String>,
    /// Firebase block.
    pub firebase: FirebaseClaims,
    /// Custom claims (merged at the top level when serialized).
    pub custom: CustomClaims,
}

impl IdTokenClaims {
    /// Canonical JSON (sorted keys, no whitespace).
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let mut entries: BTreeMap<String, ClaimValue> = self.custom.entries.clone();
        entries.insert("iss".into(), ClaimValue::String(self.iss.clone()));
        entries.insert("aud".into(), ClaimValue::String(self.aud.clone()));
        entries.insert("auth_time".into(), ClaimValue::Int(self.auth_time));
        entries.insert("user_id".into(), ClaimValue::String(self.user_id.clone()));
        entries.insert("sub".into(), ClaimValue::String(self.sub.clone()));
        entries.insert("iat".into(), ClaimValue::Int(self.iat));
        entries.insert("exp".into(), ClaimValue::Int(self.exp));
        if let Some(email) = &self.email {
            entries.insert("email".into(), ClaimValue::String(email.clone()));
            entries.insert(
                "email_verified".into(),
                ClaimValue::Bool(self.email_verified),
            );
        }
        if let Some(phone) = &self.phone_number {
            entries.insert("phone_number".into(), ClaimValue::String(phone.clone()));
        }
        if let Some(name) = &self.display_name {
            entries.insert("name".into(), ClaimValue::String(name.clone()));
        }
        if let Some(photo) = &self.photo_url {
            entries.insert("picture".into(), ClaimValue::String(photo.clone()));
        }
        let mut firebase = BTreeMap::new();
        let identities: BTreeMap<String, ClaimValue> = self
            .firebase
            .identities
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    ClaimValue::List(v.iter().cloned().map(ClaimValue::String).collect()),
                )
            })
            .collect();
        firebase.insert("identities".to_owned(), ClaimValue::Map(identities));
        firebase.insert(
            "sign_in_provider".to_owned(),
            ClaimValue::String(self.firebase.sign_in_provider.clone()),
        );
        if let Some(sf) = &self.firebase.sign_in_second_factor {
            firebase.insert(
                "sign_in_second_factor".to_owned(),
                ClaimValue::String(sf.clone()),
            );
        }
        if let Some(id) = &self.firebase.second_factor_identifier {
            firebase.insert(
                "second_factor_identifier".to_owned(),
                ClaimValue::String(id.clone()),
            );
        }
        if let Some(tenant) = &self.firebase.tenant {
            firebase.insert("tenant".to_owned(), ClaimValue::String(tenant.clone()));
        }
        entries.insert("firebase".into(), ClaimValue::Map(firebase));
        let mut out = String::new();
        write_map(&mut out, &entries);
        out
    }
}
