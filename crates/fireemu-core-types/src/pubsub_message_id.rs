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
}
