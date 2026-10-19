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
    pub fn from_f64(value: f64) -> Option<Self> {
        let _ = value;
        todo!()
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
    pub fn add(self, delta: Self) -> Option<Self> {
        let _ = delta;
        todo!()
    }

    /// The exact numeric order, also between integers and doubles.
    pub fn total_cmp(self, other: Self) -> Ordering {
        let _ = other;
        todo!()
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.total_cmp(*other) == Ordering::Equal
    }
}
