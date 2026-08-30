//! Explicit adapters for every source of nondeterminism (spec 2.2).
//!
//! The core never reads wall-clock time, thread-local RNGs or environment variables. Time is a
//! [`Clock`], identifiers come from an [`IdSource`], randomness from a [`DeterministicRng`].
//! The default implementations here are fully reproducible from a session seed.

use crate::ids::{CommandId, CorrelationId, EventId, InvocationId, SessionId, TransactionId};
use crate::time::LogicalInstant;

/// Source of the current logical time.
pub trait Clock {
    /// Current logical instant.
    fn now(&self) -> LogicalInstant;
}

/// Source of identifiers. Implementations must be deterministic given the same seed.
pub trait IdSource {
    /// Next dense command sequence number.
    fn next_command_id(&mut self) -> CommandId;
    /// Next event identifier.
    fn next_event_id(&mut self) -> EventId;
    /// Next invocation identifier.
    fn next_invocation_id(&mut self) -> InvocationId;
    /// Next transaction identifier.
    fn next_transaction_id(&mut self) -> TransactionId;
    /// Next correlation identifier for a fresh causal tree.
    fn next_correlation_id(&mut self) -> CorrelationId;
}

/// Deterministic pseudo-random source. Never used for security tokens.
pub trait DeterministicRng {
    /// Next 64-bit value.
    fn next_u64(&mut self) -> u64;

    /// Uniform-ish value in `0..bound`; returns 0 when `bound <= 1`.
    fn next_below(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }
        // Rejection sampling keeps the distribution unbiased without floating point.
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % bound;
            }
        }
    }
}

/// `SplitMix64`: small, fast, reproducible. Not cryptographic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator from a seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl DeterministicRng for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Identifier kinds mixed into the 128-bit ID so that counters of different kinds never
/// produce colliding values.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum IdKind {
    Event = 1,
    Invocation = 2,
    Transaction = 3,
    Correlation = 4,
}

/// Deterministic ID source: `(session, seed, kind, counter)` mixed into a 128-bit value.
///
/// Command IDs are dense (`1, 2, 3, ...`) because they double as the canonical trace order.
#[derive(Debug, Clone)]
pub struct DeterministicIdSource {
    session: SessionId,
    seed: u64,
    command_counter: u64,
    counters: [u64; 4],
}

impl DeterministicIdSource {
    /// Creates a source bound to a session and seed.
    #[must_use]
    pub const fn new(session: SessionId, seed: u64) -> Self {
        Self {
            session,
            seed,
            command_counter: 0,
            counters: [0; 4],
        }
    }

    fn next_mixed(&mut self, kind: IdKind) -> u128 {
        let slot = (kind as usize) - 1;
        self.counters[slot] = self.counters[slot].wrapping_add(1);
        let counter = self.counters[slot];
        // High 64 bits: hash of (session, seed, kind); low 64 bits: hash of counter under the
        // same key. Both halves go through SplitMix64 so that the value is well distributed but
        // still fully determined by the inputs.
        let session_hash = {
            let s = self.session.value();
            // Fold the 128-bit session ID into 64 bits; truncation is the intent here.
            #[allow(clippy::cast_possible_truncation)]
            let (lo, hi) = (s as u64, (s >> 64) as u64);
            let mut g =
                SplitMix64::new(lo ^ hi.rotate_left(17) ^ self.seed ^ ((kind as u64) << 56));
            g.next_u64()
        };
        let counter_hash = {
            let mut g = SplitMix64::new(session_hash ^ counter);
            g.next_u64()
        };
        (u128::from(session_hash) << 64) | u128::from(counter_hash)
    }
}

impl IdSource for DeterministicIdSource {
    fn next_command_id(&mut self) -> CommandId {
        self.command_counter = self.command_counter.wrapping_add(1);
        CommandId::new(self.command_counter)
    }

    fn next_event_id(&mut self) -> EventId {
        EventId::new(self.next_mixed(IdKind::Event))
    }

    fn next_invocation_id(&mut self) -> InvocationId {
        InvocationId::new(self.next_mixed(IdKind::Invocation))
    }

    fn next_transaction_id(&mut self) -> TransactionId {
        TransactionId::new(self.next_mixed(IdKind::Transaction))
    }

    fn next_correlation_id(&mut self) -> CorrelationId {
        CorrelationId::new(self.next_mixed(IdKind::Correlation))
    }
}
