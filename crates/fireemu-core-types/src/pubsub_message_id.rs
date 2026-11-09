//! The ids of published Pub/Sub messages, shared by the broker (`fireemu-core-pubsub`) and the
//! Functions runtime's own publish path.
//!
//! Production gives every published message a decimal id of seventeen digits, with no relation to
//! the order of publication. The four ids of the FUNCTIONS-EVENTS formal record of 2026-10-04 (run
//! `a9621bfae74fe9bc`, frames `6ac2a47f0000967f445e8b09`, `6ac2a51c000844422b7986d1`,
//! `6ac2ad01000c911a5d434439` and `6ac2ada10008c5a7380c87c6`, the `id` of a 2nd gen `CloudEvent`,
//! which is also the `messageId`) are `22254343790642112`, `22256683947060623`,
//! `22254564432090315` and `22255693239595822`: all in `2225e13..2226e13`. The FE v7 record of
//! 2026-10-05 (run `d3fd3faa3e0dc702`, frames 136, 138, 275 and 277 of its `production-run.json`)
//! gave `22257004445426262`, `22257876454937131`, `22256735573081501` and `22256872578522983`, in
//! the same range. What production guarantees is the form: a decimal of seventeen digits. The 2080
//! ids of the PUBSUB record of 2026-10-05 (run `148026092d56`, over REST and gRPC, another project)
//! are all seventeen digits too but range over `2131e13..2226e13`, so the range below is where the
//! FE frames fell, not a property production states. The counter of the emulator's state is mapped
//! into that range by a fixed permutation, so a recorded run replays with the same ids and two
//! messages of one counter never share an id.

use crate::determinism::{DeterministicRng, SplitMix64};

/// The first id of the range: `22250000000000000`, seventeen digits.
const FIRST: u64 = 22_250_000_000_000_000;
/// The width of the range, `10^13` (`2^13 * 5^13`): the ids stay below `22260000000000000`.
pub const SPAN: u64 = 10_000_000_000_000;
/// The step between the ids of consecutive counters. It is odd and not a multiple of 5, so it is
/// coprime to [`SPAN`]: the ids of `SPAN` consecutive counters are all different.
const STEP: u64 = 6_180_339_887_499;

/// The counters the Pub/Sub broker draws: `1..=BROKER_SPAN`, half of the `SPAN` counters whose ids
/// are all different. The other half, `BROKER_SPAN + 1..=SPAN`, belongs to the Functions runtime's
/// own publish path ([`runtime_message_id`]), so a message published through the control route and
/// one published through the broker can never share an id, whatever the order they arrive in. Two
/// messages of one topic with one id would make a handler that deduplicates by event id drop a
/// real message.
pub const BROKER_SPAN: u64 = SPAN / 2;

/// The id of the message that is `counter`th (counting from 1) in the broker's state. The broker
/// refuses to publish past `BROKER_SPAN` messages.
#[must_use]
pub fn pubsub_message_id(counter: u64) -> String {
    let offset = (u128::from(counter) * u128::from(STEP)) % u128::from(SPAN);
    (u128::from(FIRST) + offset).to_string()
}

/// The id of a message the Functions runtime publishes itself (the control route, with no broker
/// involved), `counter`th from 1: in the half of the id space the broker never uses. The runtime
/// cannot refuse a publish, so after `BROKER_SPAN` of them (5 * 10^12) its ids start again.
#[must_use]
pub fn runtime_message_id(counter: u64) -> String {
    let own = (counter.max(1) - 1) % BROKER_SPAN + 1;
    pubsub_message_id(BROKER_SPAN + own)
}

/// The position, in `0..BROKER_SPAN`, after `count` more runtime-published messages. A caller
/// keeps one position per session and advances it with this on every path that takes ids, so
/// the `n`th message after position `p` has the counter `p + n` and the positions repeat only
/// after `BROKER_SPAN` messages, never earlier at the end of a `u64`.
#[must_use]
pub fn next_runtime_position(position: u64, count: u64) -> u64 {
    let moved = (u128::from(position) + u128::from(count)) % u128::from(BROKER_SPAN);
    u64::try_from(moved).unwrap_or_default()
}

/// The multiplier and offset of `session`'s sequence: an affine permutation of the runtime half,
/// `position -> multiplier * position + offset (mod BROKER_SPAN)`. The multiplier is coprime to
/// `BROKER_SPAN` (`2^12 * 5^13`), so the map is a bijection and one session never repeats an id
/// inside `BROKER_SPAN` consecutive counters. Both numbers come from the session folded into a 64-bit key
/// through `SplitMix64`, so neighbouring sessions get unrelated multipliers: their sequences are
/// not shifted copies of each other (two sessions can share a key, but only by chance).
fn session_permutation(session: u128) -> (u128, u128) {
    // The session is below 2^64 in practice; the high half is folded in so that no session is
    // ignored.
    let lo = u64::try_from(session & u128::from(u64::MAX)).unwrap_or_default();
    let hi = u64::try_from(session >> 64).unwrap_or_default();
    let mut rng = SplitMix64::new(SplitMix64::new(lo).next_u64().wrapping_add(hi));
    let span = u128::from(BROKER_SPAN);
    let mut multiplier = u128::from(rng.next_u64()) | 1;
    // Odd and not a multiple of 5: coprime to the span's only prime factors (2 and 5), and so is
    // the residue modulo the span, which both factors divide.
    while multiplier % 5 == 0 {
        multiplier += 2;
    }
    let offset = u128::from(rng.next_u64()) % span;
    (multiplier % span, offset)
}

/// The id of a message the Functions runtime publishes itself in `session`, `counter`th. It lies
/// in the runtime's half of the id space, so it is never a broker id.
///
/// Collision policy. The runtime half holds `BROKER_SPAN` (5 * 10^12) ids, far fewer than the
/// sessions a daemon can draw, so two different sessions cannot be made disjoint for ever; what
/// is guaranteed is the following.
/// - Within one session, `BROKER_SPAN` consecutive counters (as integers, without wrapping a
///   `u64`) give `BROKER_SPAN` different ids; after that the ids repeat, since the runtime
///   cannot refuse a publish. A caller therefore keeps a position below `BROKER_SPAN`, takes
///   the counters `position + 1..=position + n` and stores [`next_runtime_position`], on every
///   path that takes ids.
/// - Different sessions get unrelated permutations of the half (not rotations of one sequence;
///   the session is folded into a 64-bit key, so two sessions can share one, but only by chance),
///   so the chance that two sessions give the same id to their first messages is about
///   `1 / BROKER_SPAN`, and a collision between the first `n` ids of two sessions is about
///   `n^2 / BROKER_SPAN`; it is not impossible.
/// - A pinned session (`daemon.seed`) is a fixed function of the counter, so a replay repeats its
///   ids exactly.
#[must_use]
pub fn session_runtime_message_id(session: u128, counter: u64) -> String {
    let (multiplier, offset) = session_permutation(session);
    // `multiplier < 5 * 10^12` and `counter < 2^64`: the product fits in 128 bits, and the
    // reduction below makes the counter a position modulo the span.
    let own = (multiplier * u128::from(counter) + offset) % u128::from(BROKER_SPAN) + 1;
    pubsub_message_id(BROKER_SPAN + u64::try_from(own).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::{pubsub_message_id, runtime_message_id, BROKER_SPAN, SPAN};
    use proptest::prelude::*;
    use std::collections::HashSet;

    /// The ids production gave in the FE v5 and v7 formal records (frames cited in the module docs).
    const PRODUCTION_IDS: [&str; 8] = [
        "22254343790642112",
        "22256683947060623",
        "22254564432090315",
        "22255693239595822",
        "22257004445426262",
        "22257876454937131",
        "22256735573081501",
        "22256872578522983",
    ];

    fn in_the_recorded_range(id: &str) -> bool {
        id.len() == 17
            && id.bytes().all(|byte| byte.is_ascii_digit())
            && ("22250000000000000".."22260000000000000").contains(&id)
    }

    #[test]
    fn the_recorded_production_ids_are_in_the_range_the_emulator_uses() {
        for id in PRODUCTION_IDS {
            assert!(in_the_recorded_range(id), "{id}");
        }
    }

    #[test]
    fn the_first_ids_are_seventeen_digit_decimal_strings_that_do_not_count() {
        let ids: Vec<String> = (1..=6).map(pubsub_message_id).collect();
        for id in &ids {
            assert!(in_the_recorded_range(id), "{id}");
        }
        assert_ne!(ids[0], "1");
        let mut sorted = ids.clone();
        sorted.sort();
        assert_ne!(
            ids, sorted,
            "the order of the ids is not the order of the messages"
        );
    }

    #[test]
    fn the_id_is_a_fixed_function_of_the_counter() {
        assert_eq!(pubsub_message_id(1), "22256180339887499");
        assert_eq!(pubsub_message_id(2), "22252360679774998");
        assert_eq!(pubsub_message_id(SPAN), "22250000000000000");
        assert_eq!(pubsub_message_id(7), pubsub_message_id(7));
    }

    #[test]
    fn a_hundred_thousand_consecutive_messages_have_different_ids() {
        let ids: HashSet<String> = (1..=100_000).map(pubsub_message_id).collect();
        assert_eq!(ids.len(), 100_000);
    }

    #[test]
    fn the_runtimes_ids_are_in_the_other_half_and_have_the_same_form() {
        assert_eq!(BROKER_SPAN * 2, SPAN);
        for counter in [
            0,
            1,
            2,
            3,
            1_000,
            BROKER_SPAN - 1,
            BROKER_SPAN,
            BROKER_SPAN + 1,
            u64::MAX,
        ] {
            assert!(
                in_the_recorded_range(&runtime_message_id(counter)),
                "{counter}"
            );
        }
        // A fixed function of the counter, counting from 1 (0 is treated as 1, which no caller uses).
        assert_eq!(runtime_message_id(1), pubsub_message_id(BROKER_SPAN + 1));
        assert_eq!(runtime_message_id(0), runtime_message_id(1));
        assert_eq!(runtime_message_id(BROKER_SPAN), pubsub_message_id(SPAN));
        // After BROKER_SPAN publishes the runtime's ids start again; it cannot refuse a publish.
        assert_eq!(runtime_message_id(BROKER_SPAN + 1), runtime_message_id(1));
        // The first ids of both paths, both counting from 1, differ (the collision this prevents).
        for counter in 1..=1000 {
            assert_ne!(
                pubsub_message_id(counter),
                runtime_message_id(counter),
                "{counter}"
            );
        }
    }

    proptest! {
        #[test]
        fn every_id_is_seventeen_digits_in_the_range(counter in 1_u64..u64::MAX) {
            prop_assert!(in_the_recorded_range(&pubsub_message_id(counter)));
        }

        #[test]
        fn counters_less_than_the_span_apart_never_share_an_id(first in 1_u64..1_000_000_000_000_000, gap in 1_u64..SPAN) {
            prop_assert_ne!(pubsub_message_id(first), pubsub_message_id(first + gap));
        }

        /// Whatever the order of publishes through the broker and through the runtime, and however
        /// many other events the runtime counts in between, no two messages share an id.
        #[test]
        fn interleaved_publishes_of_the_broker_and_the_runtime_never_share_an_id(
            steps in proptest::collection::vec((any::<bool>(), 1_u64..4), 1..400),
        ) {
            let mut broker = 0_u64;
            let mut runtime = 0_u64;
            let mut seen = HashSet::new();
            for (through_broker, skipped) in steps {
                let id = if through_broker {
                    broker += 1;
                    pubsub_message_id(broker)
                } else {
                    // Other events of the runtime advance its counter too: some counters are never an id.
                    runtime += skipped;
                    runtime_message_id(runtime)
                };
                prop_assert!(in_the_recorded_range(&id), "{id}");
                prop_assert!(seen.insert(id.clone()), "{id} was given twice");
            }
        }

        #[test]
        fn a_broker_id_never_equals_a_runtime_id(broker in 1_u64..=BROKER_SPAN, runtime in 1_u64..u64::MAX) {
            prop_assert_ne!(pubsub_message_id(broker), runtime_message_id(runtime));
        }
    }

    // ---- session_runtime_message_id ----

    use super::session_runtime_message_id as in_session;

    const PINNED_FIRST_IDS: [&str; 10] = [
        "22256173686882288",
        "22254193556835994",
        "22255209165547862",
        "22257067983734532",
        "22258447109971514",
        "22257408873504949",
        "22254521146506329",
        "22251836337370604",
        "22253932274567561",
        "22257880598311839",
    ];

    /// The two collisions the rotation `counter + session % BROKER_SPAN` had: sessions a span
    /// apart shared a whole sequence, and neighbouring sessions shared a shifted copy of it.
    #[test]
    fn sessions_do_not_share_or_shift_each_others_sequences() {
        assert_ne!(in_session(42, 1), in_session(5_000_000_000_042, 1));
        assert_ne!(in_session(41, 2), in_session(42, 1));
        // No id of one session's first 64 is any id of another's, for these neighbours.
        let first = |session: u128| -> HashSet<String> {
            (1..=64)
                .map(|counter| in_session(session, counter))
                .collect()
        };
        for (a, b) in [
            (41_u128, 42_u128),
            (42, 43),
            (42, 5_000_000_000_042),
            (0, 1),
            (u128::from(BROKER_SPAN) - 1, u128::from(BROKER_SPAN)),
            (u128::from(u64::MAX) - 1, u128::from(u64::MAX)),
        ] {
            assert_eq!(first(a).len(), 64, "{a}");
            assert!(first(a).is_disjoint(&first(b)), "{a} and {b} share an id");
        }
    }

    /// A session whose old shift was the span's last residue: consecutive publishes cross the
    /// wrap of the runtime half without repeating.
    #[test]
    fn the_last_residue_session_publishes_consecutive_distinct_ids() {
        let session = u128::from(BROKER_SPAN) - 1;
        let ids: HashSet<String> = (1..=1000)
            .map(|counter| in_session(session, counter))
            .collect();
        assert_eq!(ids.len(), 1000);
        for id in &ids {
            assert!(in_the_recorded_range(id), "{id}");
        }
    }

    /// The counter and session extremes neither overflow nor leave the runtime's half.
    #[test]
    fn extreme_counters_and_sessions_stay_in_the_runtime_half() {
        for session in [0_u128, 42, u128::from(u64::MAX), u128::MAX] {
            for counter in [
                0_u64,
                1,
                BROKER_SPAN,
                BROKER_SPAN + 1,
                u64::MAX - 1,
                u64::MAX,
            ] {
                let id = in_session(session, counter);
                assert!(in_the_recorded_range(&id), "{session} {counter}");
                for broker in [1_u64, 2, BROKER_SPAN] {
                    assert_ne!(id, pubsub_message_id(broker));
                }
            }
        }
    }

    /// The pinned seed 42 keeps these ids (a replay): the first three control publishes. The values
    /// are pins of the derivation above, not production ids (production ids are random).
    #[test]
    fn the_pinned_session_42_has_pinned_ids() {
        assert_eq!(in_session(42, 1), "22251127104849513");
        assert_eq!(in_session(42, 2), "22257962651021344");
        assert_eq!(in_session(42, 3), "22259798197193175");
    }

    /// The permutation of any session is a bijection of the runtime half: its multiplier is
    /// coprime to the span (odd, no factor 5) and both numbers are below the span.
    #[test]
    fn a_sessions_permutation_is_a_bijection_of_the_half() {
        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(&any::<u128>(), |session| {
                let (multiplier, offset) = super::session_permutation(session);
                prop_assert!(multiplier < u128::from(BROKER_SPAN));
                prop_assert!(offset < u128::from(BROKER_SPAN));
                prop_assert!(multiplier % 2 == 1, "{multiplier}");
                prop_assert!(multiplier % 5 != 0, "{multiplier}");
                Ok(())
            })
            .unwrap();
        // Sessions that differ only in their high half are different sessions.
        assert_ne!(in_session(7, 1), in_session(7 + (1_u128 << 64), 1));
        assert_ne!(
            super::session_permutation(7),
            super::session_permutation(7 + (1_u128 << 64))
        );
        assert_ne!(
            super::session_permutation(1_u128 << 64),
            super::session_permutation(1_u128 << 65)
        );
    }

    /// The first control-publish id of sessions 0 to 9, pinned: some of these sessions draw a
    /// multiplier that needs the coprimality adjustment, so the adjustment is pinned too.
    #[test]
    fn the_first_ids_of_the_first_sessions_are_pinned() {
        let ids: Vec<String> = (0_u128..10).map(|session| in_session(session, 1)).collect();
        assert_eq!(ids, PINNED_FIRST_IDS.map(str::to_owned));
    }

    /// The position of the runtime's messages advances by the count modulo the span and never
    /// leaves `0..BROKER_SPAN`, whatever the count.
    #[test]
    fn the_position_advances_modulo_the_span() {
        use super::next_runtime_position as next;
        assert_eq!(next(0, 0), 0);
        assert_eq!(next(0, 1), 1);
        assert_eq!(next(BROKER_SPAN - 1, 1), 0);
        assert_eq!(next(BROKER_SPAN - 1, 2), 1);
        assert_eq!(next(7, BROKER_SPAN), 7);
        assert!(next(BROKER_SPAN - 1, u64::MAX) < BROKER_SPAN);
    }

    proptest! {
        /// Within one session no two of up to a span's counters share an id.
        #[test]
        fn one_session_never_repeats_inside_the_span(
            session in any::<u128>(),
            first in 1_u64..u64::MAX / 2,
            gap in 1_u64..BROKER_SPAN,
        ) {
            prop_assert_ne!(in_session(session, first), in_session(session, first + gap));
        }

        /// Messages taken in calls of any sizes, from any position, including windows that cross
        /// the end of the span, never repeat an id: the generation (`position + n`) and the
        /// storage (`next_runtime_position`) agree.
        #[test]
        fn calls_of_any_sizes_across_the_end_of_the_span_never_repeat_an_id(
            session in any::<u128>(),
            start in prop_oneof![0_u64..1000, BROKER_SPAN - 1000..BROKER_SPAN],
            sizes in proptest::collection::vec(1_u64..40, 1..30),
        ) {
            let mut position = start;
            let mut seen = HashSet::new();
            for size in sizes {
                for n in 1..=size {
                    let id = in_session(session, position + n);
                    prop_assert!(seen.insert(id.clone()), "{id} repeated");
                }
                position = super::next_runtime_position(position, size);
                prop_assert!(position < BROKER_SPAN);
            }
        }

        /// Whatever the session and counter, a runtime id is never a broker id.
        #[test]
        fn a_session_id_is_never_a_broker_id(
            session in any::<u128>(),
            counter in any::<u64>(),
            broker in 1_u64..=BROKER_SPAN,
        ) {
            prop_assert_ne!(in_session(session, counter), pubsub_message_id(broker));
        }

        /// Sessions that differ, near each other or not, do not overlap in their first ids.
        #[test]
        fn different_sessions_do_not_overlap_in_their_first_ids(
            a in any::<u64>(),
            step in 1_u64..=1_000_000,
        ) {
            let b = a.wrapping_add(step);
            let first = |session: u64| -> HashSet<String> {
                (1..=32).map(|counter| in_session(u128::from(session), counter)).collect()
            };
            prop_assert!(first(a).is_disjoint(&first(b)));
        }
    }
}
