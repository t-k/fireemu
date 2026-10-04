//! The ids of published messages.
//!
//! Production gives every published message a decimal id of seventeen digits, with no relation to
//! the order of publication. The four ids of the FUNCTIONS-EVENTS formal record of 2026-10-04 (run
//! `a9621bfae74fe9bc`, frames `6ac2a47f0000967f445e8b09`, `6ac2a51c000844422b7986d1`,
//! `6ac2ad01000c911a5d434439` and `6ac2ada10008c5a7380c87c6`, the `id` of a 2nd gen CloudEvent,
//! which is also the `messageId`) are `22254343790642112`, `22256683947060623`,
//! `22254564432090315` and `22255693239595822`: all in `2225e13..2226e13`. The counter of the
//! emulator's state is mapped into the same range by a fixed permutation, so a recorded run replays
//! with the same ids and two messages of one state never share an id.

/// The first id of the range: `22250000000000000`, seventeen digits.
const FIRST: u64 = 22_250_000_000_000_000;
/// The width of the range, `10^13` (`2^13 * 5^13`): the ids stay below `22260000000000000`.
pub const SPAN: u64 = 10_000_000_000_000;
/// The step between the ids of consecutive counters. It is odd and not a multiple of 5, so it is
/// coprime to [`SPAN`]: the ids of `SPAN` consecutive counters are all different.
const STEP: u64 = 6_180_339_887_499;

/// The id of the message that is `counter`th (counting from 1) in the state.
#[must_use]
pub fn pubsub_message_id(counter: u64) -> String {
    let offset = (u128::from(counter) * u128::from(STEP)) % u128::from(SPAN);
    (u128::from(FIRST) + offset).to_string()
}

#[cfg(test)]
mod tests {
    use super::{pubsub_message_id, SPAN};
    use proptest::prelude::*;
    use std::collections::HashSet;

    /// The ids production gave in the 2026-10-04 formal record (frames cited in the module docs).
    const PRODUCTION_IDS: [&str; 4] = [
        "22254343790642112",
        "22256683947060623",
        "22254564432090315",
        "22255693239595822",
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
        assert_ne!(ids, sorted, "the order of the ids is not the order of the messages");
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

    proptest! {
        #[test]
        fn every_id_is_seventeen_digits_in_the_range(counter in 1_u64..u64::MAX) {
            prop_assert!(in_the_recorded_range(&pubsub_message_id(counter)));
        }

        #[test]
        fn counters_less_than_the_span_apart_never_share_an_id(first in 1_u64..1_000_000_000_000_000, gap in 1_u64..SPAN) {
            prop_assert_ne!(pubsub_message_id(first), pubsub_message_id(first + gap));
        }
    }
}
