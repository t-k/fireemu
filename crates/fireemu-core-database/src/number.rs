//! Numbers of the Realtime Database.
//!
//! JSON numbers reach the core either as integers or as doubles. A double that holds an
//! integer in the safe JavaScript range (|v| <= 2^53) is normalized to [`Number::Int`], so
//! `1` and `1.0` are the same value, as they are for the JavaScript SDK. This is the
//! provisional rule of design memo Q7 until production's number form is observed.

use std::cmp::Ordering;

/// The largest integer a double holds exactly (2^53).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_992;

/// A finite number.
#[derive(Debug, Clone, Copy)]
pub enum Number {
    /// An integer.
    Int(i64),
    /// A finite double that is not an integer in the safe range.
    Double(f64),
}

impl Number {
    /// The number for `value`, or `None` when it is not finite.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn from_f64(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        if value.fract() == 0.0 && value.abs() <= MAX_SAFE_INTEGER as f64 {
            // In the safe range the conversion is exact; `-0.0` becomes `0`.
            return Some(Self::Int(value as i64));
        }
        Some(Self::Double(value))
    }

    /// The value as a double (rounded for integers beyond 2^53).
    #[allow(clippy::cast_precision_loss)]
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Double(d) => d,
        }
    }

    /// `self + delta` as `ServerValue.increment` computes it: integer addition while it does
    /// not overflow, double addition otherwise.
    pub fn increment(self, delta: Self) -> Option<Self> {
        if let (Self::Int(a), Self::Int(b)) = (self, delta) {
            if let Some(sum) = a.checked_add(b) {
                return Some(Self::Int(sum));
            }
        }
        Self::from_f64(self.as_f64() + delta.as_f64())
    }

    /// The exact numeric order, also between integers and doubles.
    pub fn total_cmp(self, other: Self) -> Ordering {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => a.cmp(&b),
            (Self::Double(a), Self::Double(b)) => a.total_cmp(&b),
            (Self::Int(a), Self::Double(b)) => cmp_int_double(a, b),
            (Self::Double(a), Self::Int(b)) => cmp_int_double(b, a).reverse(),
        }
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.total_cmp(*other) == Ordering::Equal
    }
}

/// The exact order of an integer and a finite double.
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn cmp_int_double(int: i64, double: f64) -> Ordering {
    // 2^63 is exact as a double; every i64 lies in [-2^63, 2^63).
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    if double >= TWO_POW_63 {
        return Ordering::Less;
    }
    if double < -TWO_POW_63 {
        return Ordering::Greater;
    }
    let whole = double.trunc();
    // `whole` is integral and inside the i64 range, so the cast is exact.
    match int.cmp(&(whole as i64)) {
        Ordering::Equal => 0.0_f64.total_cmp(&(double - whole)),
        unequal => unequal,
    }
}
