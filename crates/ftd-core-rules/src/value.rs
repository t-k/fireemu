//! Runtime values for Rules evaluation and the `request.auth` context (`AUTH-RULES-1`).

use core::fmt;
use std::collections::BTreeMap;

use ftd_core_types::json::{parse, JsonError, JsonValue};

/// A Rules runtime value.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesValue {
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
    List(Vec<RulesValue>),
    /// Map.
    Map(BTreeMap<String, RulesValue>),
    /// Path (segments without the leading slash).
    Path(Vec<String>),
    /// Timestamp as Unix nanoseconds (full Firestore precision, no saturation).
    Timestamp(i128),
    /// Bytes.
    Bytes(Vec<u8>),
    /// Geo point.
    LatLng {
        /// Latitude.
        latitude: f64,
        /// Longitude.
        longitude: f64,
    },
}

impl RulesValue {
    /// Type name used by `is`.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::List(_) => "list",
            Self::Map(_) => "map",
            Self::Path(_) => "path",
            Self::Timestamp(_) => "timestamp",
            Self::Bytes(_) => "bytes",
            Self::LatLng { .. } => "latlng",
        }
    }

    /// Converts a JSON value.
    #[must_use]
    pub fn from_json(v: &JsonValue) -> Self {
        match v {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(b) => Self::Bool(*b),
            JsonValue::Int(i) => Self::Int(*i),
            JsonValue::Float(f) => Self::Float(*f),
            JsonValue::String(s) => Self::String(s.clone()),
            JsonValue::Array(items) => Self::List(items.iter().map(Self::from_json).collect()),
            JsonValue::Object(m) => Self::Map(
                m.iter()
                    .map(|(k, v)| (k.clone(), Self::from_json(v)))
                    .collect(),
            ),
        }
    }
}

impl fmt::Display for RulesValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(x) => write!(f, "{x}"),
            Self::String(s) => write!(f, "{s:?}"),
            Self::List(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Self::Map(m) => {
                f.write_str("{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                f.write_str("}")
            }
            Self::Path(segments) => write!(f, "/{}", segments.join("/")),
            Self::Timestamp(t) => write!(f, "timestamp({t}ns)"),
            Self::Bytes(b) => write!(f, "bytes({} bytes)", b.len()),
            Self::LatLng {
                latitude,
                longitude,
            } => write!(f, "latlng({latitude}, {longitude})"),
        }
    }
}

/// `request.auth`: the verified identity of the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthContext {
    /// `request.auth.uid`
    pub uid: String,
    /// `request.auth.token` claims.
    pub token: BTreeMap<String, RulesValue>,
}

impl AuthContext {
    /// Builds the context from ID token claims JSON (the payload of a verified token).
    pub fn from_id_token_json(json: &str) -> Result<Self, JsonError> {
        let parsed = parse(json)?;
        let uid = parsed
            .get("sub")
            .and_then(JsonValue::as_str)
            .ok_or(JsonError {
                offset: 0,
                expected: "a sub claim",
            })?
            .to_owned();
        let token = match RulesValue::from_json(&parsed) {
            RulesValue::Map(m) => m,
            _ => BTreeMap::new(),
        };
        Ok(Self { uid, token })
    }

    /// The `request.auth` value.
    #[must_use]
    pub fn to_value(&self) -> RulesValue {
        let mut m = BTreeMap::new();
        m.insert("uid".to_owned(), RulesValue::String(self.uid.clone()));
        m.insert("token".to_owned(), RulesValue::Map(self.token.clone()));
        RulesValue::Map(m)
    }
}
