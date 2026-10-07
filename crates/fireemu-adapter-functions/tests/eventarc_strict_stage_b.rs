//! The strict Eventarc surface against what production answered to the stage B recording (EVENTARC,
//! 2026-10-05, run `43a83839852f` of `fireemu-oracle-idp`): the first recording in which a channel was
//! created. `fixtures/eventarc-stage-b/rows.json` holds every Eventarc and Eventarc Publishing exchange of
//! it (233 rows, the raw bytes of each answer included; the Service Usage read is a different product).
//!
//! The rows are replayed in order through one server's state, as the recording ran: a creation starts an
//! operation, the reads that follow see it unfinished and then done at the instants they were made, the
//! channel appears in the reads and lists after it, a deletion removes it. Each request is made at the
//! instant the server saw it in the recording (the time of the answer less half its latency), and each operation takes
//! as long as the recorded one did (12 creations took 4.5 to 6.2 seconds, 12 deletions 3.7 to 4.2).
//!
//! The instant of a request is the one the server saw: for a creation and a deletion, the `createTime` of the
//! operation it started; for every other request, the time of the answer less 120 ms (the recorder opens a
//! connection for each request, so most of its latency is before the server sees the request: the creation
//! at row 68 was seen 105 ms before its answer, and the read at row 70 at least 106 ms before its answer).
//!
//! What cannot be reproduced value for value is masked by its format, never by its presence: a UID, a
//! timestamp, an operation name, the numeric suffix of a topic, a request ID and a page token are replaced
//! by a placeholder that records what was checked (a version 4 UUID; nine fractional digits; the four-part
//! operation name; three digits; 16 hex digits; the length and the alphabet of the token). Everything else
//! is compared exactly, member order and the bytes of the layout included: the length of each answer equals
//! the recorded `content-length`.
//!
//! The rows the strict surface does not reproduce are named in `NOT_REPRODUCED` with the reason; the test
//! fails when a row not named there diverges, and when a named row stops diverging.

mod eventarc_replay;

use eventarc_replay::{check, mask_text};

/// Rows the strict surface answers differently, with the reason.
const NOT_REPRODUCED: &[(u64, &str)] = &[
    (
        26,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        27,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        28,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        29,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        31,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        73,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        181,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        187,
        "ORDER: the order of a list of two channels or more: production's rule is not recoverable from the recording (neither the name, the creation time nor the UID), so fireemu lists in the order of creation",
    ),
    (
        35,
        "the project in the path is the project number: fireemu has no project number for a project",
    ),
    (
        36,
        "the project in the path is the project number: fireemu has no project number for a project",
    ),
    (
        172,
        "a ya29.-prefixed token that Google never issued: whether a token is valid is Google's state",
    ),
    (
        173,
        "a ya29.-prefixed token that Google never issued: whether a token is valid is Google's state",
    ),
    (
        179,
        "a real token of another scope: what a token may do is Google's state",
    ),
    (
        180,
        "a real token of another scope: what a token may do is Google's state",
    ),
];

#[test]
fn every_recorded_exchange_is_answered_as_production_answered() {
    check("eventarc-stage-b", 233, NOT_REPRODUCED);
}

#[test]
fn the_byte_comparison_masks_formats_only_and_sees_layout() {
    let uid = "123e4567-e89b-42d3-a456-426614174000";
    let other = "9b2f1c3d-0a4e-4f60-8a1b-0123456789ab";
    let a = format!("{{\n  \"uid\": \"{uid}\",\n  \"state\": \"ACTIVE\"\n}}\n");
    let b = format!("{{\n  \"uid\": \"{other}\",\n  \"state\": \"ACTIVE\"\n}}\n");
    // A UID of the right format is masked: two different UIDs compare equal.
    assert_eq!(mask_text(&a), mask_text(&b));
    // A value that is not of the format is not masked.
    let wrong = a.replace(uid, "not-a-uid");
    assert_ne!(mask_text(&a), mask_text(&wrong));
    // Indentation, line breaks, spacing and the trailing newline are compared.
    assert_ne!(
        mask_text(&a),
        mask_text(&a.replace("  \"state\"", "   \"state\""))
    );
    assert_ne!(mask_text(&a), mask_text(a.trim_end()));
    assert_ne!(mask_text(&a), mask_text(&a.replace(",\n", ", ")));
    assert_ne!(
        mask_text(&a),
        mask_text(&a.replace("\"uid\": ", "\"uid\":"))
    );
    // The members of an ErrorInfo's metadata may come in any order; nothing else may.
    let one = "{\n  \"metadata\": {\n    \"a\": \"1\",\n    \"b\": \"2\"\n  },\n  \"z\": 1\n}\n";
    let two = "{\n  \"metadata\": {\n    \"b\": \"2\",\n    \"a\": \"1\"\n  },\n  \"z\": 1\n}\n";
    assert_eq!(mask_text(one), mask_text(two));
    assert_ne!(mask_text(one), mask_text(&one.replace("\"2\"", "\"3\"")));
    assert_ne!(
        mask_text(one),
        mask_text(&one.replace("\"z\": 1", "\"y\": 1"))
    );
}
