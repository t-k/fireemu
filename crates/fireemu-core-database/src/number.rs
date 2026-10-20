//! Numbers of the Realtime Database.
//!
//! JSON numbers reach the core either as integers or as doubles, and keep that type: `1.0`
//! stays a double, as the official emulator keeps it (owner ledger 1475, provisional until
//! production is observed). Values compare by number, so `1` equals `1.0` and `-0.0` equals
//! `0`.

use std::cmp::Ordering;

/// A finite number.
#[derive(Debug, Clone, Copy)]
pub enum Number {
    /// An integer.
    Int(i64),
    /// A finite double.
    Double(f64),
}

impl Number {
    /// Whether both are the same kind of number with the same value, doubles compared by
    /// their bits (so `0.0` and `-0.0` differ).
    pub fn same_form(self, other: Self) -> bool {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Double(a), Self::Double(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }

    /// The number for `value`, or `None` when it is not finite.
    pub fn from_f64(value: f64) -> Option<Self> {
        value.is_finite().then_some(Self::Double(value))
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
    /// not overflow, double addition otherwise. A double sum beyond the range stops at the
    /// largest double of its sign, as the official emulator answers.
    #[must_use]
    pub fn increment(self, delta: Self) -> Self {
        if let (Self::Int(a), Self::Int(b)) = (self, delta) {
            if let Some(sum) = a.checked_add(b) {
                return Self::Int(sum);
            }
        }
        let sum = self.as_f64() + delta.as_f64();
        Self::Double(if sum.is_finite() {
            sum
        } else {
            f64::MAX.copysign(sum)
        })
    }

    /// The exact numeric order, also between integers and doubles.
    pub fn total_cmp(self, other: Self) -> Ordering {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => a.cmp(&b),
            // Finite doubles always compare; -0.0 equals 0.0, as in JavaScript and Java.
            (Self::Double(a), Self::Double(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
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
