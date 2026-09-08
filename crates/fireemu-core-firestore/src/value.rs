//! Firestore field values and their total ordering.
//!
//! Official value type order: Null, Boolean, NaN, Integer and floating-point (numerically),
//! Date, Text (UTF-8 byte order), Bytes, Reference, Geographical point, Array, Vector, Map.

use core::cmp::Ordering;
use core::fmt;
use std::collections::BTreeMap;

/// Maximum number of nested map and array containers accepted by Firestore.
pub const MAX_NESTING_DEPTH: u32 = 20;

/// Firestore timestamp: seconds since the Unix epoch plus nanoseconds, restricted to the
/// official range `0001-01-01T00:00:00Z ..= 9999-12-31T23:59:59.999999999Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    seconds: i64,
    nanos: u32,
}

/// Invalid timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampError {
    /// Nanoseconds outside `0..1_000_000_000`.
    NanosOutOfRange,
    /// Seconds outside the supported year range.
    SecondsOutOfRange,
}

impl Timestamp {
    /// `0001-01-01T00:00:00Z`.
    pub const MIN_SECONDS: i64 = -62_135_596_800;
    /// `9999-12-31T23:59:59Z`.
    pub const MAX_SECONDS: i64 = 253_402_300_799;

    /// Validates and builds a timestamp.
    pub const fn new(seconds: i64, nanos: u32) -> Result<Self, TimestampError> {
        if nanos >= 1_000_000_000 {
            return Err(TimestampError::NanosOutOfRange);
        }
        if seconds < Self::MIN_SECONDS || seconds > Self::MAX_SECONDS {
            return Err(TimestampError::SecondsOutOfRange);
        }
        Ok(Self { seconds, nanos })
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Nanosecond part.
    #[must_use]
    pub const fn nanos(self) -> u32 {
        self.nanos
    }

    /// The timestamp Firestore stores for this value: precision below one microsecond is
    /// truncated (the documented storage precision for timestamp fields).
    #[must_use]
    pub const fn truncated_to_micros(self) -> Self {
        Self {
            seconds: self.seconds,
            nanos: self.nanos / 1_000 * 1_000,
        }
    }
}

/// Geographical point. Ordered by latitude, then longitude.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoPoint {
    latitude: f64,
    longitude: f64,
}

/// Invalid geo point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoPointError;

impl GeoPoint {
    /// Validates `[-90, 90]` / `[-180, 180]` and rejects NaN.
    pub fn new(latitude: f64, longitude: f64) -> Result<Self, GeoPointError> {
        if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
            return Err(GeoPointError);
        }
        Ok(Self {
            latitude,
            longitude,
        })
    }

    /// Latitude.
    #[must_use]
    pub const fn latitude(self) -> f64 {
        self.latitude
    }

    /// Longitude.
    #[must_use]
    pub const fn longitude(self) -> f64 {
        self.longitude
    }
}

impl Eq for GeoPoint {}

impl PartialOrd for GeoPoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GeoPoint {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_doubles(self.latitude, other.latitude)
            .then_with(|| cmp_doubles(self.longitude, other.longitude))
    }
}

/// A Firestore field value.
///
/// `==` is structural (`1 != 1.0`, `NaN != NaN`). Use [`IndexValue`] for canonical
/// ordering and [`Value::stored_eq`] for stored document content identity.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Null.
    Null,
    /// Boolean.
    Boolean(bool),
    /// 64-bit integer.
    Integer(i64),
    /// 64-bit float (NaN sorts as its own type).
    Double(f64),
    /// Timestamp.
    Timestamp(Timestamp),
    /// UTF-8 string.
    String(String),
    /// Bytes.
    Bytes(Vec<u8>),
    /// Document reference, as a full resource name.
    Reference(String),
    /// Geo point.
    GeoPoint(GeoPoint),
    /// Array.
    Array(Vec<Value>),
    /// Vector embedding.
    Vector(Vec<f64>),
    /// Map with canonical key order.
    Map(BTreeMap<String, Value>),
}

/// Value kinds in official sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueKind {
    /// Null.
    Null,
    /// Boolean.
    Boolean,
    /// NaN (sorts before all numbers).
    Nan,
    /// Integer or non-NaN double.
    Number,
    /// Timestamp.
    Timestamp,
    /// String.
    String,
    /// Bytes.
    Bytes,
    /// Reference.
    Reference,
    /// Geo point.
    GeoPoint,
    /// Array.
    Array,
    /// Vector.
    Vector,
    /// Map.
    Map,
}

impl Value {
    /// Kind used for type ordering.
    #[must_use]
    pub fn kind(&self) -> ValueKind {
        match self {
            Self::Null => ValueKind::Null,
            Self::Boolean(_) => ValueKind::Boolean,
            Self::Double(d) if d.is_nan() => ValueKind::Nan,
            Self::Integer(_) | Self::Double(_) => ValueKind::Number,
            Self::Timestamp(_) => ValueKind::Timestamp,
            Self::String(_) => ValueKind::String,
            Self::Bytes(_) => ValueKind::Bytes,
            Self::Reference(_) => ValueKind::Reference,
            Self::GeoPoint(_) => ValueKind::GeoPoint,
            Self::Array(_) => ValueKind::Array,
            Self::Vector(_) => ValueKind::Vector,
            Self::Map(_) => ValueKind::Map,
        }
    }

    /// Total order over all values following the official rules. `Equal` means the values are
    /// indistinguishable for ordering purposes (`1 == 1.0`, `-0.0 == 0.0`, `NaN == NaN`).
    #[must_use]
    pub fn canonical_cmp(&self, other: &Self) -> Ordering {
        let by_kind = self.kind().cmp(&other.kind());
        if by_kind != Ordering::Equal {
            return by_kind;
        }
        match (self, other) {
            (Self::Boolean(a), Self::Boolean(b)) => a.cmp(b),
            // Both NaN: equal (kinds matched above).
            (Self::Double(a), Self::Double(b)) if a.is_nan() && b.is_nan() => Ordering::Equal,
            (Self::Integer(a), Self::Integer(b)) => a.cmp(b),
            (Self::Double(a), Self::Double(b)) => cmp_doubles(*a, *b),
            (Self::Integer(a), Self::Double(b)) => cmp_int_double(*a, *b),
            (Self::Double(a), Self::Integer(b)) => cmp_int_double(*b, *a).reverse(),
            (Self::Timestamp(a), Self::Timestamp(b)) => a.cmp(b),
            (Self::String(a), Self::String(b)) => a.as_bytes().cmp(b.as_bytes()),
            (Self::Bytes(a), Self::Bytes(b)) => a.cmp(b),
            (Self::Reference(a), Self::Reference(b)) => cmp_reference(a, b),
            (Self::GeoPoint(a), Self::GeoPoint(b)) => a.cmp(b),
            (Self::Array(a), Self::Array(b)) => cmp_slices(a, b),
            (Self::Vector(a), Self::Vector(b)) => a.len().cmp(&b.len()).then_with(|| {
                a.iter()
                    .zip(b)
                    .map(|(x, y)| cmp_doubles(*x, *y))
                    .find(|o| *o != Ordering::Equal)
                    .unwrap_or(Ordering::Equal)
            }),
            (Self::Map(a), Self::Map(b)) => cmp_maps(a, b),
            // Kinds are equal here, so every remaining combination is unreachable.
            _ => Ordering::Equal,
        }
    }

    /// Whether two stored values are the same document content. Unlike `==`, every NaN
    /// equals every other NaN (Firestore stores a single NaN), and unlike
    /// [`canonical_cmp`](Self::canonical_cmp) an integer never equals a double and `-0.0`
    /// never equals `0.0`: rewriting a field with a different numeric representation is a
    /// real change.
    #[must_use]
    pub fn stored_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Double(a), Self::Double(b)) => double_bits_eq(*a, *b),
            (Self::Vector(a), Self::Vector(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| double_bits_eq(*x, *y))
            }
            (Self::Array(a), Self::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.stored_eq(y))
            }
            (Self::Map(a), Self::Map(b)) => stored_fields_eq(a, b),
            _ => self == other,
        }
    }

    /// Rewrites the value into the form Firestore stores: timestamps lose sub-microsecond
    /// precision, recursively through arrays and maps.
    pub fn normalize_for_storage(&mut self) {
        match self {
            Self::Timestamp(timestamp) => *timestamp = timestamp.truncated_to_micros(),
            Self::Array(items) => items.iter_mut().for_each(Self::normalize_for_storage),
            Self::Map(entries) => entries.values_mut().for_each(Self::normalize_for_storage),
            _ => {}
        }
    }

    /// Nesting depth: each map or array level adds one (`FS-LIMIT-NESTED-MAP-ARRAY-DEPTH`).
    #[must_use]
    pub fn nesting_depth(&self) -> u32 {
        let mut maximum = 0;
        let mut pending = vec![(self, 0_u32)];
        while let Some((value, parent_depth)) = pending.pop() {
            match value {
                Self::Array(items) => {
                    let depth = parent_depth.saturating_add(1);
                    maximum = maximum.max(depth);
                    pending.extend(items.iter().map(|item| (item, depth)));
                }
                Self::Map(entries) => {
                    let depth = parent_depth.saturating_add(1);
                    maximum = maximum.max(depth);
                    pending.extend(entries.values().map(|item| (item, depth)));
                }
                _ => {}
            }
        }
        maximum
    }
}

/// Borrowed Firestore index key. Equality and ordering both use canonical value order.
/// Numeric representations and NaN payloads that sort equally are equal keys.
#[derive(Debug, Clone, Copy)]
pub struct IndexValue<'a>(pub &'a Value);

impl PartialEq for IndexValue<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for IndexValue<'_> {}

/// [`Value::stored_eq`] over whole field trees.
#[must_use]
pub fn stored_fields_eq(a: &BTreeMap<String, Value>, b: &BTreeMap<String, Value>) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|((ka, va), (kb, vb))| ka == kb && va.stored_eq(vb))
}

/// [`Value::normalize_for_storage`] over a whole field tree.
pub fn normalize_fields_for_storage(fields: &mut BTreeMap<String, Value>) {
    fields.values_mut().for_each(Value::normalize_for_storage);
}

fn double_bits_eq(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

impl PartialOrd for IndexValue<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IndexValue<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.canonical_cmp(other.0)
    }
}

/// Doubles in canonical order: NaN is one value below every other double (as the type order
/// places it), `-0.0` equals `0.0`. Top-level doubles have NaN handled by kind before this;
/// vector components reach it directly, and stored vectors never hold NaN (production
/// refuses them), but the order stays total for any value the model can represent.
fn cmp_doubles(a: f64, b: f64) -> Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
    }
}

/// Exact comparison of an i64 with a non-NaN f64 without precision loss.
fn cmp_int_double(i: i64, d: f64) -> Ordering {
    if d.is_infinite() {
        return if d > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    // 2^63 exactly: every i64 is below it.
    if d >= 9_223_372_036_854_775_808.0 {
        return Ordering::Less;
    }
    if d < -9_223_372_036_854_775_808.0 {
        return Ordering::Greater;
    }
    // d is within i64 range; compare against its truncation, then the fractional remainder.
    #[allow(clippy::cast_possible_truncation)]
    let t = d.trunc() as i64;
    match i.cmp(&t) {
        Ordering::Equal => {
            let frac = d - d.trunc();
            if frac > 0.0 {
                Ordering::Less
            } else if frac < 0.0 {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }
        o => o,
    }
}

fn cmp_reference(a: &str, b: &str) -> Ordering {
    // References order by path segments; segment-wise byte order.
    a.split('/').cmp(b.split('/'))
}

fn cmp_slices(a: &[Value], b: &[Value]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let o = x.canonical_cmp(y);
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

fn cmp_maps(a: &BTreeMap<String, Value>, b: &BTreeMap<String, Value>) -> Ordering {
    for ((ka, va), (kb, vb)) in a.iter().zip(b) {
        let o = ka
            .as_bytes()
            .cmp(kb.as_bytes())
            .then_with(|| va.canonical_cmp(vb));
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

impl fmt::Display for ValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
