//! Replays ordinary REST steps of the FS-ENT-ORACLE pipeline corpus (O-1, O-2 and O-3 programs,
//! `conformance/fs-ent-pipeline-requests.json`) against the in-process REST surface under both
//! profiles and compares each answer with the production recording
//! (`conformance/fs-ent-pipeline-production.json`): the status, the result documents as a
//! multiset (order and framing are not compared) and the whole error body. Every difference is
//! named in the allowlist below with its reason, and each listed row must still differ, so the
//! list cannot hide a row that has started to match. Compact framing steps are explicitly
//! delegated to the actual-binary comparator and are not counted as matches here.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::json_syntax::KeyOrder;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};

const DOCS: &str = "projects/demo-app/databases/(default)/documents";

/// (Notes on what the replay assumes: a collection group's order by parent document, string
/// order of the parent path, is generalized from the few parents of O-9 `cg-main` and O-9b
/// `cg-parent`; CRC-32 ties and non-ASCII IDs are not observed.)
///
/// Programs that fireemu does not answer like production yet. They are replayed and compared
/// like the rest, but a difference in them is not an unexpected one; each program must still
/// differ in at least one row, so remove a program from this list when the work that makes it
/// match lands. (O-6 and O-7 were listed here until their stages ran; the rows that still
/// differ are named in the lists below, each with its reason. `nesting-main` is not listed:
/// every nesting probe this surface can take matches production.)
const PENDING_PROGRAMS: &[&str] = &[
    "fs-ent-pipeline/o8c/collections-main",
    "fs-ent-pipeline/o8d/stages-main",
];

/// The rows of a pending program that match production today, per profile (strict, emulator):
/// the commits that seed or write, the refusals the validators already answer, and the select
/// `__name__` forms. Every other row of a pending program must differ. A row that stops
/// matching, or starts to, fails the replay until this table is updated, so the work that
/// implements a stage cannot drop or gain a match unnoticed.
const PENDING_MATCHES: &[(&str, &[&str], &[&str])] = &[
    (
        "fs-ent-pipeline/o8c/collections-main",
        &[
            "array-length-ok",
            "array-length-empty",
            "array-length-null",
            "array-length-absent",
            "array-length-string",
            "array-length-none",
            "array-reverse-none",
            "array-first-ok",
            "array-first-empty",
            "array-first-null",
            "array-first-absent",
            "array-first-int",
            "array-last-ok",
            "array-last-empty",
            "array-last-null",
            "array-last-absent",
            "array-last-int",
            "array-get-first",
            "array-get-last",
            "array-get-negative",
            "array-get-out-of-range",
            "array-get-null-index",
            "array-get-null-array",
            "array-get-absent",
            "array-get-double-index",
            "array-get-int-array",
            "array-get-one",
            "array-concat-two",
            "array-concat-three",
            "array-concat-with-empty",
            "array-concat-null",
            "array-concat-absent",
            "array-concat-string",
            "array-concat-one",
            "array-reverse-ok",
            "array-reverse-empty",
            "array-reverse-null",
            "array-reverse-absent",
            "array-reverse-int",
            "map-get-key",
            "map-get-missing-key",
            "map-get-dotted-key",
            "map-get-nested-map",
            "map-get-empty-map",
            "map-get-null-map",
            "map-get-absent-map",
            "map-get-null-key",
            "map-get-int-key",
            "map-get-array-map",
            "map-get-one",
            "map-merge-two",
            "map-merge-later-wins",
            "map-merge-three",
            "map-merge-with-empty",
            "map-merge-not-deep",
            "map-merge-null",
            "map-merge-absent",
            "map-merge-array",
            "map-merge-one",
            "map-set-add",
            "map-set-overwrite",
            "map-set-two-pairs",
            "map-set-null-value",
            "map-set-int-key",
            "map-set-null-map",
            "map-set-absent-map",
            "map-set-two",
            "map-remove-one",
            "map-remove-missing",
            "map-remove-two",
            "map-remove-null-map",
            "map-remove-absent-map",
            "map-remove-int-key",
            "map-remove-map-only",
            "map-keys-ok",
            "map-keys-empty",
            "map-keys-null",
            "map-keys-absent",
            "map-keys-array",
            "map-keys-none",
            "map-values-ok",
            "map-values-empty",
            "map-values-null",
            "map-values-absent",
            "map-values-array",
            "map-values-none",
            "map-entries-ok",
            "map-entries-empty",
            "map-entries-null",
            "map-entries-absent",
            "map-entries-array",
            "map-entries-none",
            "map-set-odd-entries",
            "array-slice-from",
            "array-slice-with-length",
            "array-slice-negative-offset",
            "array-slice-beyond",
            "array-slice-null",
            "array-slice-absent",
            "array-slice-int-array",
            "array-index-of-first",
            "array-index-of-last",
            "array-index-of-none",
            "array-index-of-null-search",
            "array-index-of-direction-invalid",
            "array-index-of-null-array",
            "array-index-of-absent-array",
            "array-index-of-int-array",
            "array-index-of-two",
            "array-first-n-ok",
            "array-first-n-zero",
            "array-first-n-negative",
            "array-first-n-more-than-length",
            "array-first-n-null",
            "array-first-n-absent",
            "array-first-n-double-n",
            "array-first-n-one",
            "array-last-n-ok",
            "array-last-n-zero",
            "array-last-n-negative",
            "array-last-n-more-than-length",
            "array-last-n-null",
            "array-last-n-absent",
            "array-last-n-double-n",
            "array-last-n-one",
            "join-ok",
            "join-empty-array",
            "join-null-element",
            "join-null-element-no-text",
            "join-int-elements",
            "join-null-delimiter",
            "join-null-array",
            "join-absent",
            "join-one",
            "maximum-n-ok",
            "maximum-n-more-than-length",
            "maximum-n-zero",
            "maximum-n-null",
            "maximum-n-absent",
            "maximum-n-int-array",
            "minimum-n-ok",
            "minimum-n-more-than-length",
            "minimum-n-zero",
            "minimum-n-null",
            "minimum-n-absent",
            "minimum-n-int-array",
        ],
        &[
            "array-length-ok",
            "array-length-empty",
            "array-length-null",
            "array-length-absent",
            "array-length-string",
            "array-length-none",
            "array-first-ok",
            "array-first-empty",
            "array-first-null",
            "array-first-absent",
            "array-first-int",
            "array-last-ok",
            "array-last-empty",
            "array-last-null",
            "array-last-absent",
            "array-last-int",
            "array-get-first",
            "array-get-last",
            "array-get-negative",
            "array-get-out-of-range",
            "array-get-null-index",
            "array-get-null-array",
            "array-get-absent",
            "array-get-double-index",
            "array-get-int-array",
            "array-get-one",
            "array-concat-two",
            "array-concat-three",
            "array-concat-with-empty",
            "array-concat-null",
            "array-concat-absent",
            "array-concat-string",
            "array-concat-one",
            "array-reverse-ok",
            "array-reverse-empty",
            "array-reverse-null",
            "array-reverse-absent",
            "array-reverse-int",
            "map-get-key",
            "map-get-missing-key",
            "map-get-dotted-key",
            "map-get-nested-map",
            "map-get-empty-map",
            "map-get-null-map",
            "map-get-absent-map",
            "map-get-null-key",
            "map-get-int-key",
            "map-get-array-map",
            "map-get-one",
            "map-merge-two",
            "map-merge-later-wins",
            "map-merge-three",
            "map-merge-with-empty",
            "map-merge-not-deep",
            "map-merge-null",
            "map-merge-absent",
            "map-merge-array",
            "map-merge-one",
            "map-set-add",
            "map-set-overwrite",
            "map-set-two-pairs",
            "map-set-odd-entries",
            "map-set-null-value",
            "map-set-int-key",
            "map-set-null-map",
            "map-set-absent-map",
            "map-set-two",
            "map-remove-one",
            "map-remove-missing",
            "map-remove-two",
            "map-remove-null-map",
            "map-remove-absent-map",
            "map-remove-int-key",
            "map-remove-map-only",
            "map-keys-ok",
            "map-keys-empty",
            "map-keys-null",
            "map-keys-absent",
            "map-keys-array",
            "map-keys-none",
            "map-values-ok",
            "map-values-empty",
            "map-values-null",
            "map-values-absent",
            "map-values-array",
            "map-values-none",
            "map-entries-ok",
            "map-entries-empty",
            "map-entries-null",
            "map-entries-absent",
            "map-entries-array",
            "map-entries-none",
            "array-slice-from",
            "array-slice-with-length",
            "array-slice-negative-offset",
            "array-slice-beyond",
            "array-slice-null",
            "array-slice-absent",
            "array-slice-int-array",
            "array-index-of-first",
            "array-index-of-last",
            "array-index-of-none",
            "array-index-of-null-search",
            "array-index-of-direction-invalid",
            "array-index-of-null-array",
            "array-index-of-absent-array",
            "array-index-of-int-array",
            "array-index-of-two",
            "array-first-n-ok",
            "array-first-n-zero",
            "array-first-n-negative",
            "array-first-n-more-than-length",
            "array-first-n-null",
            "array-first-n-absent",
            "array-first-n-double-n",
            "array-first-n-one",
            "array-last-n-ok",
            "array-last-n-zero",
            "array-last-n-negative",
            "array-last-n-more-than-length",
            "array-last-n-null",
            "array-last-n-absent",
            "array-last-n-double-n",
            "array-last-n-one",
            "join-ok",
            "join-empty-array",
            "join-null-element",
            "join-null-element-no-text",
            "join-int-elements",
            "join-null-delimiter",
            "join-null-array",
            "join-absent",
            "join-one",
            "maximum-n-ok",
            "maximum-n-more-than-length",
            "maximum-n-zero",
            "maximum-n-null",
            "maximum-n-absent",
            "maximum-n-int-array",
            "minimum-n-ok",
            "minimum-n-more-than-length",
            "minimum-n-zero",
            "minimum-n-null",
            "minimum-n-absent",
            "minimum-n-int-array",
        ],
    ),
    (
        "fs-ent-pipeline/o8d/stages-main",
        &[
            "sample-documents-2",
            "sample-documents-0",
            "sample-documents-10",
            "sample-documents-negative",
            "sample-documents-fraction",
            "sample-percent-0",
            "sample-percent-50",
            "sample-percent-100",
            "sample-percent-150",
            "sample-percent-negative",
            "sample-mode-invalid",
            "sample-mode-int",
            "sample-rate-string",
            "sample-one-argument",
            "sample-three-arguments",
            "sample-after-where",
            "sample-then-limit",
            "unnest-tags",
            "unnest-empty-array",
            "unnest-null",
            "unnest-string",
            "unnest-absent",
            "unnest-index-field",
            "unnest-alias-is-field",
            "unnest-alias-is-other-field",
            "unnest-dotted-alias",
            "unnest-reserved-alias",
            "unnest-index-is-alias",
            "unnest-literal-array",
            "unnest-then-where",
            "unnest-twice",
            "unnest-one-argument",
            "unnest-three-arguments",
            "union-other",
            "union-itself",
            "union-then-sort",
            "union-then-limit",
            "union-inner-where",
            "union-inner-select",
            "union-empty-input",
            "union-of-union",
            "union-after-select",
            "union-int-argument",
            "union-no-arguments",
            "union-two-arguments",
            "union-no-stages",
        ],
        &[
            "sample-documents-2",
            "sample-documents-0",
            "sample-documents-10",
            "sample-documents-negative",
            "sample-documents-fraction",
            "sample-percent-0",
            "sample-percent-50",
            "sample-percent-100",
            "sample-percent-150",
            "sample-percent-negative",
            "sample-mode-invalid",
            "sample-mode-int",
            "sample-rate-string",
            "sample-one-argument",
            "sample-three-arguments",
            "sample-after-where",
            "sample-then-limit",
            "unnest-tags",
            "unnest-empty-array",
            "unnest-null",
            "unnest-string",
            "unnest-absent",
            "unnest-index-field",
            "unnest-alias-is-field",
            "unnest-alias-is-other-field",
            "unnest-dotted-alias",
            "unnest-reserved-alias",
            "unnest-index-is-alias",
            "unnest-literal-array",
            "unnest-then-where",
            "unnest-twice",
            "unnest-one-argument",
            "unnest-three-arguments",
            "union-other",
            "union-itself",
            "union-then-sort",
            "union-then-limit",
            "union-inner-where",
            "union-inner-select",
            "union-empty-input",
            "union-of-union",
            "union-after-select",
            "union-int-argument",
            "union-no-arguments",
            "union-two-arguments",
            "union-no-stages",
        ],
    ),
];

/// The sample set a random draw may return: the members of the input and how many to expect.
struct SampleOf {
    count: usize,
    members: &'static [&'static str],
}

/// Rows whose production answer differs between two recordings of the same request. They are
/// judged by rule, never against one recording: a `sample` returns that many distinct members of
/// its input in any order, and a difference of two timestamps taken from the request clock is an
/// integer whatever its value.
enum Nondeterministic {
    Sample(SampleOf),
    ClockSeconds,
}

const SU: &[&str] = &[
    "{docs}/su/a",
    "{docs}/su/b",
    "{docs}/su/c",
    "{docs}/su/d",
    "{docs}/su/e",
];
const SU_AFTER_N_1: &[&str] = &["{docs}/su/b", "{docs}/su/c", "{docs}/su/d", "{docs}/su/e"];

fn nondeterministic(row: &str) -> Option<Nondeterministic> {
    Some(match row {
        "fs-ent-pipeline/o8d/stages-main#sample-documents-2" => {
            Nondeterministic::Sample(SampleOf {
                count: 2,
                members: SU,
            })
        }
        "fs-ent-pipeline/o8d/stages-main#sample-documents-10" => {
            Nondeterministic::Sample(SampleOf {
                count: 5,
                members: SU,
            })
        }
        "fs-ent-pipeline/o8d/stages-main#sample-percent-50" => Nondeterministic::Sample(SampleOf {
            count: usize::MAX,
            members: SU,
        }),
        "fs-ent-pipeline/o8d/stages-main#sample-after-where" => {
            Nondeterministic::Sample(SampleOf {
                count: 2,
                members: SU_AFTER_N_1,
            })
        }
        "fs-ent-pipeline/o8d/stages-main#sample-then-limit" => Nondeterministic::Sample(SampleOf {
            count: 1,
            members: SU,
        }),
        "fs-ent-pipeline/o8c/timestamps-main#timestamp-diff-now" => Nondeterministic::ClockSeconds,
        _ => return None,
    })
}

// The retained percent=1 observation contains every eligible input row in scan order.
fn sample_timestamp(value: Option<&Value>, placeholder: &str, recorded: bool) -> bool {
    let Some(text) = value.and_then(Value::as_str) else {
        return false;
    };
    if recorded && text == placeholder {
        return true;
    }
    chrono::DateTime::parse_from_rfc3339(text).is_ok_and(|time| {
        fireemu_core_firestore::value::Timestamp::new(
            time.timestamp(),
            time.timestamp_subsec_nanos(),
        )
        .is_ok()
    })
}

fn sample_contract(
    rule: &SampleOf,
    body: &Value,
    source: &[Value],
    percent: bool,
    recorded: bool,
) -> bool {
    let Some(parts) = body.as_array() else {
        return false;
    };
    let [part] = parts.as_slice() else {
        return false;
    };
    let Some(unit) = part.as_object() else {
        return false;
    };
    if unit
        .keys()
        .any(|key| key != "executionTime" && key != "results")
        || !sample_timestamp(unit.get("executionTime"), "<t1>", recorded)
    {
        return false;
    }
    let rows: &[Value] = match part.get("results") {
        None => &[],
        Some(Value::Array(rows)) => rows,
        _ => return false,
    };
    if (!percent && rows.len() != rule.count) || rows.len() > rule.members.len() {
        return false;
    }
    let mut seen = HashSet::new();
    let mut previous = None;
    for row in rows {
        if !sample_timestamp(row.get("createTime"), "<t2>", recorded)
            || !sample_timestamp(row.get("updateTime"), "<t2>", recorded)
        {
            return false;
        }
        let Some(name) = row.get("name").and_then(Value::as_str).map(relative) else {
            return false;
        };
        if !rule.members.contains(&name.as_str()) || !seen.insert(name) {
            return false;
        }
        let Some(position) = source
            .iter()
            .position(|input| normalize(input) == normalize(row))
        else {
            return false;
        };
        if percent && previous.is_some_and(|last| last >= position) {
            return false;
        }
        previous = Some(position);
    }
    true
}

/// The clock of the in-process server under test, in seconds since the epoch (`state()` starts
/// its `VirtualClock` here); a clock row is judged against it, not against the wall clock.
const REPLAY_CLOCK_SECONDS: i64 = 1_788_004_860;

/// How far a clock row may be from the clock it is judged against: two minutes. The two
/// recordings are a minute apart; a time-zone offset (hours), a millisecond-scale answer or zero
/// is far outside it.
const CLOCK_WINDOW_SECONDS: i64 = 120;

/// Whether an answer satisfies the rule of its row.
/// `now` is the clock in seconds since the epoch that a clock row is judged against.
fn satisfies(rule: &Nondeterministic, status: u16, body: &Value, now: i64) -> bool {
    satisfies_in(rule, status, body, now, false)
}

fn satisfies_in(
    rule: &Nondeterministic,
    status: u16,
    body: &Value,
    now: i64,
    recorded: bool,
) -> bool {
    if status != 200 {
        return false;
    }
    let results: Vec<&Value> = body
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|element| element["results"].as_array().into_iter().flatten())
        .collect();
    match rule {
        Nondeterministic::Sample(sample) => {
            let production = read("fs-ent-pipeline-production.json");
            let source_body = &production["programs"]["fs-ent-pipeline/o8d/stages-main"]["steps"]
                ["sample-percent-100"]["body"];
            let source: Vec<Value> = source_body
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|part| part["results"].as_array().into_iter().flatten().cloned())
                .collect();
            sample_contract(sample, body, &source, sample.count == usize::MAX, recorded)
        }
        Nondeterministic::ClockSeconds => {
            let [result] = results.as_slice() else {
                return false;
            };
            let fields = result["fields"].as_object();
            fields.is_some_and(|fields| {
                fields.len() == 1
                    && fields["v"]["integerValue"].as_str().is_some_and(|text| {
                        text.parse::<i64>()
                            .is_ok_and(|seconds| (seconds - now).abs() <= CLOCK_WINDOW_SECONDS)
                    })
            })
        }
    }
}

/// Rows that differ from production, with the reason, the same under both profiles: functions and
/// stages outside the finite local subset (PX1b-d and later slices), which fireemu refuses with
/// UNIMPLEMENTED where production answers, and the result order without a sort.
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[
    (
        "fs-ent-pipeline/o4/stages#select-empty-then-unknown-function",
        "fireemu cannot tell a function that does not exist from one it does not run: strict refuses it as unobserved, the emulator profile answers the empty select's text first",
    ),
    (
        "fs-ent-pipeline/o6/sort-wire-errors#expression-unknown-fn",
        "the \"did you mean\" hint of an unknown function name is not reproduced (the function library is outside this subset)",
    ),
    (
        "fs-ent-pipeline/o7/aggregate-args#accumulator-unknown",
        "the \"did you mean\" hint of an unknown function name is not reproduced (the function library is outside this subset)",
    ),
    (
        "fs-ent-pipeline/o7/aggregate-args#nested-aggregate",
        "a nested aggregate evaluates `sum` as the array function `array_sum` in production; not reproduced",
    ),
];

/// Rows whose 200 answer holds other rows or another order than production's because the cut or
/// the order depends on what production has not shown (see the reason); both profiles answer 200
/// with the number of results pinned in the third member.
const UNOBSERVED_ORDER_ROWS: &[(&str, &str, usize)] = &[
    (
        "fs-ent-pipeline/o6/sort-kinds-cross#v-desc",
        "a descending sort of 16 documents puts a null before a missing key where the scan order puts the missing one first, as 6- and 8-document sorts did not; the rule for the order of tied keys beyond the scan order is not observed",
        16,
    ),
    (
        "fs-ent-pipeline/o6/sort-ties#g-asc-limit2",
        "a limit after a sort cuts a group of rows tied on every sort key in an order other than the scan order (production orders a tie group differently for different limits)",
        2,
    ),
    (
        "fs-ent-pipeline/o7/aggregate-basic#around-where-two-sort",
        "the order of an aggregate's groups is production's own and unobserved, so a sort whose keys tie between groups differs",
        4,
    ),
    (
        "fs-ent-pipeline/o7/aggregate-basic#around-where-one-limit",
        "the order of an aggregate's groups is production's own and unobserved, so a limit after the groups keeps other groups",
        2,
    ),
    (
        "fs-ent-pipeline/o7/aggregate-basic#around-where-two-limit",
        "the order of an aggregate's groups is production's own and unobserved, so a limit after the groups keeps other groups",
        2,
    ),
    (
        "fs-ent-pipeline/o7/aggregate-basic#aggregate-then-offset",
        "the order of an aggregate's groups is production's own and unobserved, so an offset after the groups skips other groups",
        2,
    ),
];

/// Rows of recorded programs whose production answer fireemu does not give, each pinned by the
/// status it answers now under strict and under the emulator profile (so a change in either
/// shows): the HTTP 500 faults of `dupquote-main`, the base64 forms production refuses in
/// and the base64 forms production refuses in `base64-main`.
const UNMODELLED_PRODUCTION_ROWS: &[(&str, &str, u16, u16)] = &[
    (
        "fs-ent-pipeline/o8a/dupquote-main#same-1",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict matches the recorded INTERNAL and the emulator profile keeps the official emulator's 400",
        500,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#same-2",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict matches the recorded INTERNAL and the emulator profile keeps the official emulator's 400",
        500,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#same-3",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict matches the recorded INTERNAL and the emulator profile keeps the official emulator's 400",
        500,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#different-values",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict matches the recorded INTERNAL and the emulator profile keeps the official emulator's 400",
        500,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#swapped-order",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict matches the recorded INTERNAL and the emulator profile keeps the official emulator's 400",
        500,
        400,
    ),

];

/// Rows that only the emulator profile answers differently: strict matches. The profile keeps the
/// official emulator's text (status 400), as it never refuses more than the official emulator.
const EMULATOR_ONLY_DIFFERENCES: &[(&str, &str)] = &[
    (
        "fs-ent-pipeline/o8a/precedence-main#top-level-unknown",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
    (
        "fs-ent-pipeline/o8a/precedence-main#stage-unknown-member",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
    (
        "fs-ent-pipeline/o8a/precedence-main#bad-integer",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
    (
        "fs-ent-pipeline/o8a/precedence-main#string-number",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
    (
        "fs-ent-pipeline/o8a/precedence-main#unknown-value-type",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
    (
        "fs-ent-pipeline/o8a/precedence-main#malformed-and-unknown-stage",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
    (
        "fs-ent-pipeline/o8a/precedence-main#malformed-and-unknown-function",
        "the emulator profile answers the official emulator 1.22.0's one text, \"Payload isn't valid for request.\", for a body its transcoder rejects, where production names the field (strict answers production's text)",
    ),
];

/// A fixture with the key order of its objects as written.
fn read_ordered(name: &str) -> (Value, KeyOrder) {
    let path = format!("{}/../../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(&text).unwrap()
}

fn read(name: &str) -> Value {
    let path = format!("{}/../../conformance/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
        .unwrap()
}

fn state(strict: bool) -> RestState {
    state_at(strict, i128::from(REPLAY_CLOCK_SECONDS) * 1_000_000_000)
}

fn state_at(strict: bool, clock_nanos: i128) -> RestState {
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Enterprise,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
        clock_nanos,
    ))));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn call(s: &RestState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    call_ordered(s, method, path, body, &KeyOrder::default())
}

/// A request whose body keeps the key order it was written in.
fn call_ordered(
    s: &RestState,
    method: &str,
    path: &str,
    body: &Value,
    key_order: &KeyOrder,
) -> (u16, Value) {
    let r = s.handle(&RestRequest {
        method: method.to_owned(),
        path: format!("/v1/{path}"),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body: body.clone(),
        batch_field_order: Vec::new(),
        key_order: key_order.clone(),
    });
    (r.status, r.body)
}

/// `{docs}` placeholders filled with this surface's documents path.
fn fill(value: &Value) -> Value {
    serde_json::from_str(&value.to_string().replace("{docs}", DOCS)).unwrap()
}

/// A documents path of any project and database written as `{docs}`.
fn relative(name: &str) -> String {
    match name.find("/documents") {
        Some(at) if name.starts_with("projects/") => format!("{{docs}}{}", &name[at + 10..]),
        _ => name.to_owned(),
    }
}

/// A timestamp without trailing zero fractions.
fn timestamp(text: &str) -> String {
    match text.strip_suffix('Z').and_then(|t| t.split_once('.')) {
        Some((whole, fraction)) => {
            let fraction = fraction.trim_end_matches('0');
            if fraction.is_empty() {
                format!("{whole}Z")
            } else {
                format!("{whole}.{fraction}Z")
            }
        }
        None => text.to_owned(),
    }
}

/// A double as its bits (the sign of zero kept, every NaN one value).
fn double(value: &Value) -> Value {
    let d = match value {
        Value::String(text) => match text.as_str() {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            other => other.parse().unwrap(),
        },
        other => other.as_f64().unwrap(),
    };
    json!(if d.is_nan() {
        "NaN".to_owned()
    } else {
        format!("{:#x}", d.to_bits())
    })
}

/// An error message in a comparable form. A missing-separator refusal names the document parent
/// and the index where the separator is missing, which is that name's length: the recorded
/// name carries the placeholder project ID while production counted the real one, so the
/// name is written relative to its documents root and the index is left out (fireemu's index
/// is pinned against its own name in the local tests).
fn message(text: &str) -> String {
    let parent = text
        .strip_prefix("Document parent name \"")
        .and_then(|rest| rest.split_once("\" lacks \"/\" at index "))
        .filter(|(_, index)| {
            index
                .strip_suffix('.')
                .is_some_and(|n| n.parse::<usize>().is_ok())
        });
    // A full resource name in a path refusal (O-9 `cg-main#anc-full-name`) names the project and
    // database of the run.
    let path = text
        .strip_prefix("Document path name \"")
        .and_then(|rest| rest.split_once("\" lacks \"/\" at index "))
        .filter(|(name, _)| name.starts_with("projects/"));
    if let Some((name, index)) = path {
        return format!(
            "Document path name \"{}\" lacks \"/\" at index {index}",
            relative(name)
        );
    }
    match parent {
        Some((name, _)) => format!(
            "Document parent name \"{}\" lacks \"/\" at index <n>.",
            relative(name)
        ),
        None => text.to_owned(),
    }
}

/// A Firestore value or document in a comparable form.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, inner) in map {
                let inner = match key.as_str() {
                    "doubleValue" | "latitude" | "longitude" => double(inner),
                    // A field may be called `name` (an alias in an aggregate or distinct answer).
                    "referenceValue" | "name" if inner.is_string() => {
                        json!(relative(inner.as_str().unwrap()))
                    }
                    "timestampValue" => json!(timestamp(inner.as_str().unwrap())),
                    "createTime" | "updateTime" => json!("<t>"),
                    "message" if inner.is_string() => json!(message(inner.as_str().unwrap())),
                    _ => normalize(inner),
                };
                out.insert(key.clone(), inner);
            }
            // An empty map or array may leave its member out.
            if let Some(Value::Object(fields)) = out.get("mapValue") {
                if fields.is_empty() {
                    out.insert("mapValue".to_owned(), json!({"fields": {}}));
                }
            }
            if let Some(Value::Object(values)) = out.get("arrayValue") {
                if values.is_empty() {
                    out.insert("arrayValue".to_owned(), json!({"values": []}));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

/// The documents of a runQuery answer, normalized and sorted (the read time is not compared).
fn query_documents(body: &Value) -> Vec<String> {
    let mut documents: Vec<String> = body
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|element| element.get("document"))
        .map(|document| normalize(document).to_string())
        .collect();
    documents.sort();
    documents
}

/// The comparable answer of an executePipeline step: the status, and the result documents as
/// a sorted list or the error body.
/// The comparable form of an answer: the status and the error body, or the results as a multiset
/// (production's order without a sort is its own), or in order when `ordered` (the pipeline has
/// a `sort` stage).
fn answer_in(status: u16, body: &Value, ordered: bool) -> Value {
    if status != 200 {
        return json!({"status": status, "body": normalize(body)});
    }
    let mut results: Vec<String> = body
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|element| element["results"].as_array().cloned().unwrap_or_default())
        .map(|result| normalize(&result).to_string())
        .collect();
    if !ordered {
        results.sort();
    }
    json!({"status": 200, "results": results})
}

/// Compare only the recorded `current_timestamp` recipe against its configured request clock.
fn current_timestamp_matches(
    status: u16,
    body: &Value,
    expected_status: u16,
    expected: &Value,
    clock_nanos: i128,
) -> bool {
    const LEAF: &str = "/0/results/0/fields/v/timestampValue";
    if status != 200
        || status != expected_status
        || framing(body) != framing(expected)
        || expected.pointer(LEAF).and_then(Value::as_str) != Some("<t2>")
    {
        return false;
    }
    let Some(text) = body.pointer(LEAF).and_then(Value::as_str) else {
        return false;
    };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(text) else {
        return false;
    };
    if fireemu_core_firestore::value::Timestamp::new(
        parsed.timestamp(),
        parsed.timestamp_subsec_nanos(),
    )
    .is_err()
    {
        return false;
    }
    let seconds = clock_nanos.div_euclid(1_000_000_000);
    let nanos = clock_nanos.rem_euclid(1_000_000_000) / 1_000 * 1_000;
    if i128::from(parsed.timestamp()) != seconds
        || i128::from(parsed.timestamp_subsec_nanos()) != nanos
    {
        return false;
    }
    let mut actual = body.clone();
    let mut recorded = expected.clone();
    *actual.pointer_mut(LEAF).unwrap() = json!("<clock>");
    *recorded.pointer_mut(LEAF).unwrap() = json!("<clock>");
    answer_in(status, &actual, true) == answer_in(expected_status, &recorded, true)
}

/// How an answer is cut into array elements: the number of results in each.
fn framing(body: &Value) -> Vec<usize> {
    body.as_array()
        .into_iter()
        .flatten()
        .map(|element| element["results"].as_array().map_or(0, Vec::len))
        .collect()
}

// Exact measured compatibility debt, not a production-parity approval.
#[derive(Clone)]
struct O5Difference {
    row: String,
    category: String,
    reason: String,
    production: Value,
    strict: Value,
    emulator: Option<Value>,
}

const O5_INTERNAL_ROW: &str = "fs-ent-pipeline/o5/appendix#proposed-select-duplicate-quoted-path";
const O5_REFERENCE_ENV_ROW: &str = "fs-ent-pipeline/o5/appendix#proposed-reference-empty-segment";
const O8A_INTERNAL_ROWS: &[&str] = &[
    "fs-ent-pipeline/o8a/dupquote-main#same-1",
    "fs-ent-pipeline/o8a/dupquote-main#same-2",
    "fs-ent-pipeline/o8a/dupquote-main#same-3",
    "fs-ent-pipeline/o8a/dupquote-main#different-values",
    "fs-ent-pipeline/o8a/dupquote-main#swapped-order",
];

fn recorded_internal_answer() -> Value {
    json!({"status":500,"body":[{"error":{"code":500,"message":"An internal error occurred.","status":"INTERNAL"}}]})
}

fn validate_o5_pin(row: &O5Difference) {
    if row.row == O5_INTERNAL_ROW {
        assert_eq!(row.category, "unknown-production-outcome");
        assert_eq!(row.production, recorded_internal_answer());
        assert_eq!(row.strict, row.production);
    } else if row.row == O5_REFERENCE_ENV_ROW {
        assert_eq!(row.category, "environment-reference-comparison");
        assert_eq!(row.strict["status"], 400);
        assert_eq!(Some(&row.strict), row.emulator.as_ref());
        assert_ne!(row.strict, row.production);
    } else {
        assert_ne!(
            row.category, "unknown-production-outcome",
            "unknown row: {}",
            row.row
        );
        if row.strict == row.production {
            assert!(
                row.emulator
                    .as_ref()
                    .is_some_and(|answer| answer != &row.production),
                "matched strict row must retain emulator debt: {}",
                row.row
            );
        } else {
            assert_eq!(row.strict["status"], 501, "strict debt: {}", row.row);
            assert_eq!(
                row.strict["body"][0]["error"]["status"], "UNIMPLEMENTED",
                "strict debt: {}",
                row.row
            );
        }
    }
    if let Some(emulator) = &row.emulator {
        assert_ne!(
            emulator, &row.production,
            "stale emulator debt: {}",
            row.row
        );
    }
}

fn o5_pinned_match_valid(row: &O5Difference, strict: bool, matches: bool) -> bool {
    let pinned = if strict {
        Some(&row.strict)
    } else {
        row.emulator.as_ref()
    };
    matches == pinned.is_some_and(|answer| answer == &row.production)
}

fn o8a_internal_binding_valid(row: &str, production: &Value) -> bool {
    O8A_INTERNAL_ROWS.contains(&row) && *production == recorded_internal_answer()
}

fn take_debt_string(object: &mut serde_json::Map<String, Value>, key: &str) -> String {
    match object.remove(key) {
        Some(Value::String(value)) => value,
        _ => panic!("required O5 debt string: {key}"),
    }
}

fn parse_o5_differences(text: &str) -> Vec<O5Difference> {
    let (value, order) =
        fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(text.as_bytes())
            .expect("O5 debt JSON parses");
    value
        .as_array()
        .expect("O5 debt array root")
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let mut object = row.as_object().expect("O5 debt object entry").clone();
            let pointer = format!("/{index}");
            let keys = order.keys(&pointer).expect("O5 debt wire keys");
            assert_eq!(
                keys.len(),
                object.len(),
                "duplicate O5 debt member: {index}"
            );
            assert_eq!(
                keys.iter().collect::<HashSet<_>>().len(),
                keys.len(),
                "duplicate O5 debt wire key: {index}"
            );
            assert!(
                keys.iter().all(|key| object.contains_key(key)),
                "O5 debt key mismatch: {index}"
            );
            let row = take_debt_string(&mut object, "row");
            let category = take_debt_string(&mut object, "category");
            let reason = take_debt_string(&mut object, "reason");
            let production = object
                .remove("production")
                .expect("required production answer");
            let strict = object.remove("strict").expect("required strict answer");
            let emulator = object.remove("emulator").filter(|value| !value.is_null());
            assert!(object.is_empty(), "unknown O5 debt member: {row}");
            O5Difference {
                row,
                category,
                reason,
                production,
                strict,
                emulator,
            }
        })
        .collect()
}

#[test]
fn o5_debt_schema_rejects_missing_unknown_duplicate_and_wrong_types() {
    let valid = json!([{"row":"x","category":"x","reason":"x","production":{},"strict":{}}]);
    assert!(parse_o5_differences(&valid.to_string())[0]
        .emulator
        .is_none());
    let mut with_null = valid.clone();
    with_null[0]["emulator"] = Value::Null;
    assert!(parse_o5_differences(&with_null.to_string())[0]
        .emulator
        .is_none());
    let mut with_answer = valid.clone();
    with_answer[0]["emulator"] = json!({"status":400});
    assert_eq!(
        parse_o5_differences(&with_answer.to_string())[0].emulator,
        Some(json!({"status":400}))
    );
    let mut invalid = vec![json!({}).to_string(), json!([0]).to_string()];
    for key in ["row", "category", "reason", "production", "strict"] {
        let mut missing = valid.clone();
        missing[0].as_object_mut().unwrap().remove(key);
        invalid.push(missing.to_string());
    }
    for key in ["row", "category", "reason"] {
        let mut wrong = valid.clone();
        wrong[0][key] = json!(42);
        invalid.push(wrong.to_string());
    }
    let mut unknown = valid;
    unknown[0]["other"] = Value::Null;
    invalid.push(unknown.to_string());
    invalid.push(
        r#"[{"row":"x","row":"y","category":"x","reason":"x","production":{},"strict":{}}]"#
            .to_owned(),
    );
    for text in invalid {
        assert!(
            std::panic::catch_unwind(|| parse_o5_differences(&text)).is_err(),
            "invalid schema accepted: {text}"
        );
    }
}

fn o5_difference_rows() -> Vec<O5Difference> {
    parse_o5_differences(include_str!("pipeline_o5_known_differences.json"))
}

fn o5_differences() -> BTreeMap<String, O5Difference> {
    let rows = o5_difference_rows();
    // (A run that regenerates the debt file counts what is there.)
    if std::env::var_os("REGENERATE_O5_DEBT").is_none() {
        assert_eq!(rows.len(), 67, "finite O5 debt inventory");
        assert_eq!(
            rows.iter().filter(|row| row.emulator.is_some()).count(),
            62,
            "finite emulator debt inventory"
        );
    }
    let mut table = BTreeMap::new();
    let mut unknown = 0;
    for row in rows {
        assert!(
            row.row.starts_with("fs-ent-pipeline/o5/"),
            "foreign debt: {}",
            row.row
        );
        assert!(
            !KNOWN_DIFFERENCES.iter().any(|(known, _)| *known == row.row),
            "old debt replaced: {}",
            row.row
        );
        assert!(!row.reason.trim().is_empty(), "missing reason: {}", row.row);
        assert!(
            matches!(
                row.category.as_str(),
                "unsupported-subset"
                    | "validation-order-or-subset"
                    | "arity-wording"
                    | "environment-reference-comparison"
                    | "missing-error-info"
                    | "unsupported-current-document"
                    | "unknown-production-outcome"
            ),
            "unknown category: {}",
            row.row
        );
        validate_o5_pin(&row);
        if row.production["status"] == 500 {
            unknown += 1;
            assert_eq!(
                row.row,
                "fs-ent-pipeline/o5/appendix#proposed-select-duplicate-quoted-path"
            );
            assert_eq!(row.category, "unknown-production-outcome");
            assert_eq!(row.production["body"][0]["error"]["status"], "INTERNAL");
        }
        assert!(
            table.insert(row.row.clone(), row).is_none(),
            "duplicate O5 debt row"
        );
    }
    assert_eq!(
        unknown, 1,
        "one merged unknown production row, not two raw captures"
    );
    table
}

#[test]
fn o5_recorded_internal_is_a_strict_match_and_emulator_debt() {
    let table = o5_differences();
    let row = &table["fs-ent-pipeline/o5/appendix#proposed-select-duplicate-quoted-path"];
    assert_eq!(row.category, "unknown-production-outcome");
    assert_eq!(row.strict, row.production);
    assert_eq!(row.strict["status"], 500);
    assert_eq!(row.strict["body"][0]["error"]["status"], "INTERNAL");
    assert_eq!(row.emulator.as_ref().unwrap()["status"], 400);
}

#[test]
fn zero_counts_match_the_recorded_production_answers() {
    let (requests, order) = read_ordered("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    let id = "fs-ent-pipeline/o5/appendix";
    let (p, program) = requests["programs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .find(|(_, program)| program["id"] == id)
        .unwrap();
    let mut differences = Vec::new();
    for strict in [true, false] {
        let s = state(strict);
        for seed in program["seed"].as_array().unwrap() {
            let (status, body) = call(
                &s,
                "PATCH",
                &format!("{DOCS}/{}", seed[0].as_str().unwrap()),
                &json!({"fields": fill(&seed[1])}),
            );
            assert_eq!(status, 200, "seed: {body}");
        }
        for id in ["proposed-limit-zero", "proposed-offset-zero"] {
            let (n, step) = program["steps"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .find(|(_, step)| step["id"] == id)
                .unwrap();
            let (status, body) = call_ordered(
                &s,
                "POST",
                &format!("{DOCS}:executePipeline"),
                &fill(&step["body"]),
                &order.rebased(&format!("/programs/{p}/steps/{n}/body"), ""),
            );
            let expected = &production["programs"]["fs-ent-pipeline/o5/appendix"]["steps"][id];
            let got = answer_in(status, &body, true);
            let want = answer_in(
                u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                &expected["body"],
                true,
            );
            if got != want || framing(&body) != framing(&expected["body"]) {
                differences.push(format!("strict={strict}, {id}: got {got}, want {want}"));
            }
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

/// Executes the recorded REST body through either real adapter route.
fn internal_case(strict: bool, family: &str, step_id: &str, grpc: bool) -> (u16, Value) {
    internal_case_at(
        strict,
        family,
        step_id,
        grpc,
        i128::from(REPLAY_CLOCK_SECONDS) * 1_000_000_000,
    )
}

fn internal_case_at(
    strict: bool,
    family: &str,
    step_id: &str,
    grpc: bool,
    clock_nanos: i128,
) -> (u16, Value) {
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let (requests, order) = read_ordered("fs-ent-pipeline-requests.json");
    let program_id = format!("fs-ent-pipeline/{family}");
    let (p, program) = requests["programs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .find(|(_, program)| program["id"] == program_id)
        .unwrap();
    let (n, step) = program["steps"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .find(|(_, step)| step["id"] == step_id)
        .unwrap();
    let s = state_at(strict, clock_nanos);
    for seed in program["seed"].as_array().unwrap() {
        let mut fields = fill(&seed[1]);
        if std::env::var_os("FIREEMU_INTERNAL_DIAGNOSTIC_CASE").is_some() {
            fields["i"] = json!({"stringValue": "private-value-marker"});
        }
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/{}", seed[0].as_str().unwrap()),
            &json!({"fields": fields}),
        );
        assert_eq!(status, 200, "seed: {body}");
    }
    let body = fill(&step["body"]);
    if !grpc {
        return call_ordered(
            &s,
            "POST",
            &format!("{DOCS}:executePipeline"),
            &body,
            &order.rebased(&format!("/programs/{p}/steps/{n}/body"), ""),
        );
    }
    let req = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
        "projects/demo-app/databases/(default)",
        &body,
    )
    .unwrap();
    let service = GatewayService::local((*s.gateway).clone(), Arc::clone(&s.local));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        use tokio_stream::StreamExt as _;
        let mut stream = Firestore::execute_pipeline(&service, tonic::Request::new(req))
            .await?
            .into_inner();
        let mut responses = Vec::new();
        while let Some(response) = stream.next().await {
            responses.push(response?);
        }
        Ok::<_, tonic::Status>(responses)
    });
    match result {
        Ok(responses) => {
            use fireemu_proto_firestore::google::firestore::v1::value::ValueType;
            let timestamp = responses
                .iter()
                .flat_map(|response| &response.results)
                .filter_map(|result| result.fields.get("v"))
                .find_map(|value| match &value.value_type {
                    Some(ValueType::TimestampValue(timestamp)) => {
                        Some((timestamp.seconds, timestamp.nanos))
                    }
                    _ => None,
                });
            (
                200,
                json!({"timestamp": timestamp, "resultCount": responses.iter().map(|response| response.results.len()).sum::<usize>(), "fieldNames": responses.iter().flat_map(|response| &response.results).flat_map(|result| result.fields.keys()).collect::<Vec<_>>()}),
            )
        }
        Err(error) => (
            match error.code() {
                tonic::Code::Internal => 500,
                tonic::Code::InvalidArgument => 400,
                tonic::Code::Unimplemented => 501,
                other => panic!("unexpected grpc status {other:?}"),
            },
            json!({"grpcMessage": error.message()}),
        ),
    }
}

#[test]
fn unknown_add_fields_precedes_later_stage_arity_on_both_transports() {
    let message = "The function 'nope_fn' does not exist.";
    for step in [
        "add-fields-unknown-then-aggregate-one",
        "add-fields-unknown-then-limit-string",
    ] {
        for grpc in [false, true] {
            let (status, body) = internal_case(true, "o5/stage-order", step, grpc);
            assert_eq!(status, 400, "{step} grpc={grpc}: {body}");
            if grpc {
                assert_eq!(body["grpcMessage"], message, "{step}");
            } else {
                assert_eq!(body[0]["error"]["message"], message, "{step}");
            }
        }
    }
}

#[test]
fn recorded_unknown_refusals_match_both_profiles_and_transports() {
    let cases = [
        (
            "o5/function-order",
            "select-unknown-function",
            "The function 'nope_fn' does not exist.",
        ),
        (
            "o5/function-order",
            "select-capitalized-name",
            "The function 'Equal' does not exist, did you mean 'equal'?",
        ),
        (
            "o5/function-order",
            "where-unknown-then-select-empty",
            "The function 'nope_fn' does not exist.",
        ),
        (
            "o5/stage-order",
            "add-fields-unknown-then-aggregate-one",
            "The function 'nope_fn' does not exist.",
        ),
    ];
    for (family, step, expected) in cases {
        for strict in [true, false] {
            for grpc in [false, true] {
                let (status, body) = internal_case(strict, family, step, grpc);
                assert_eq!(status, 400, "{step} strict={strict} grpc={grpc}: {body}");
                let message = if grpc {
                    &body["grpcMessage"]
                } else {
                    &body[0]["error"]["message"]
                };
                assert_eq!(message, expected, "{step} strict={strict} grpc={grpc}");
            }
        }
    }
}

#[test]
fn unknown_before_stage_arity_preserves_unobserved_and_emulator_boundaries() {
    let requests = read("fs-ent-pipeline-requests.json");
    let program = requests["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|program| program["id"] == "fs-ent-pipeline/o5/stage-order")
        .unwrap();
    let step = program["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "add-fields-unknown-then-aggregate-one")
        .unwrap();
    let base = fill(&step["body"]);
    let mut unrecorded_name = base.clone();
    unrecorded_name["structuredPipeline"]["pipeline"]["stages"][1]["args"][0]["mapValue"]
        ["fields"]["a"]["functionValue"]["name"] = json!("geo_distance");
    let mut invalid_input = base.clone();
    invalid_input["structuredPipeline"]["pipeline"]["stages"][0]["args"][0] =
        json!({"stringValue":"bad"});
    let mut outer_arity = base.clone();
    outer_arity["structuredPipeline"]["pipeline"]["stages"][1]["args"]
        .as_array_mut()
        .unwrap()
        .push(json!({"integerValue":"1"}));
    for (name, body) in [
        ("known unsupported", unrecorded_name),
        ("invalid input", invalid_input),
        ("outer arity", outer_arity),
    ] {
        let (status, answer) = call(
            &state(true),
            "POST",
            &format!("{DOCS}:executePipeline"),
            &body,
        );
        assert_eq!(status, 501, "{name}: {answer}");
    }
    let (status, answer) = call(
        &state(false),
        "POST",
        &format!("{DOCS}:executePipeline"),
        &base,
    );
    assert_eq!(status, 400, "emulator: {answer}");
    assert!(answer[0]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("aggregate"));
}

#[test]
fn observed_internal_fixtures_and_pict_cases() {
    let fixture = read("fs-ent-pipeline-production.json");
    let mut failures = Vec::new();
    for (family, step) in [
        ("o8a/dupquote-main", "same-1"),
        ("o8a/dupquote-main", "same-2"),
        ("o8a/dupquote-main", "same-3"),
        ("o8a/dupquote-main", "different-values"),
        ("o8a/dupquote-main", "swapped-order"),
        ("o5/appendix", "proposed-select-duplicate-quoted-path"),
        ("o8c/collections-main", "array-reverse-none"),
        ("o8c/collections-main", "array-reverse-int"),
    ] {
        let (status, body) = internal_case(true, family, step, false);
        let expected = &fixture["programs"][format!("fs-ent-pipeline/{family}")]["steps"][step];
        let got = json!({"status": status, "body": body});
        let want = json!({"status": expected["status"], "body": expected["body"]});
        if got != want {
            failures.push(format!("{family}#{step}: got {got}, want {want}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // The nine generated PICT rows, in seed/table order.
    for (strict, family, step, grpc, expected) in [
        (true, "o8a/dupquote-main", "same-1", false, 500),
        (
            true,
            "o8c/collections-main",
            "array-reverse-none",
            false,
            500,
        ),
        (false, "o8a/dupquote-main", "same-1", false, 400),
        (
            false,
            "o8c/collections-main",
            "array-reverse-none",
            false,
            501,
        ),
        (true, "o8a/dupquote-main", "same-1", true, 500),
        (
            true,
            "o8c/collections-main",
            "array-reverse-none",
            true,
            500,
        ),
        (true, "o8a/dupquote-main", "dotted", false, 200),
        (
            true,
            "o8c/collections-main",
            "array-reverse-int",
            false,
            400,
        ),
        (false, "o8a/dupquote-main", "dotted", true, 200),
    ] {
        let (actual, body) = internal_case(strict, family, step, grpc);
        assert_eq!(
            actual, expected,
            "strict={strict} grpc={grpc} {family}#{step}"
        );
        if grpc && expected == 500 {
            assert_eq!(body["grpcMessage"], "An internal error occurred.");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn quoted_alias_collision_is_structural(alias in "[a-z]{1,8}") {
        let fields = json!({(alias.clone()): {"fieldReferenceValue":"i"}, (format!("`{alias}`")): {"fieldReferenceValue":"i"}});
        let body = json!({"structuredPipeline":{"pipeline":{"stages":[
            {"name":"collection","args":[{"referenceValue":"/dq"}]},
            {"name":"select","args":[{"mapValue":{"fields":fields}}]}
        ]}}});
        let strict = call(&state(true), "POST", &format!("{DOCS}:executePipeline"), &body).0;
        let emulator = call(&state(false), "POST", &format!("{DOCS}:executePipeline"), &body).0;
        prop_assert_eq!(strict, 500);
        prop_assert_eq!(emulator, 400);
    }
}

#[test]
fn observed_internal_near_misses_do_not_gain_internal() {
    let collection = json!({"name":"collection","args":[{"referenceValue":"/dq"}]});
    let select = |fields: Value| json!({"name":"select","args":[{"mapValue":{"fields":fields}}]});
    let cases = [
        vec![
            collection.clone(),
            select(json!({"v":{"functionValue":{"name":"other_unknown_function","args":[]}}})),
        ],
        vec![
            collection.clone(),
            json!({"name":"unknown_stage","args":[]}),
            select(json!({"v":{"functionValue":{"name":"array_reverse","args":[]}}})),
        ],
        vec![
            json!({"name":"collection","args":[{"stringValue":"invalid"}]}),
            select(json!({"a":{"fieldReferenceValue":"i"},"`a`":{"fieldReferenceValue":"i"}})),
        ],
    ];
    for stages in cases {
        let body = json!({"structuredPipeline":{"pipeline":{"stages":stages}}});
        let (status, _) = call(
            &state(true),
            "POST",
            &format!("{DOCS}:executePipeline"),
            &body,
        );
        assert_ne!(
            status, 500,
            "unobserved or invalid input must keep its earlier refusal"
        );
    }
}

#[test]
fn array_reverse_with_options_keeps_its_previous_refusal() {
    let body = json!({"structuredPipeline":{"pipeline":{"stages":[
        {"name":"collection","args":[{"referenceValue":"/dq"}]},
        {"name":"select","args":[{"mapValue":{"fields":{"v":{"functionValue":{
            "name":"array_reverse","args":[],"options":{"extra":{"stringValue":"x"}}
        }}}}}]}
    ]}}});
    for strict in [true, false] {
        let (status, body) = call(
            &state(strict),
            "POST",
            &format!("{DOCS}:executePipeline"),
            &body,
        );
        assert_eq!(status, 501, "strict={strict}");
        assert_eq!(body[0]["error"]["status"], "UNIMPLEMENTED");
        assert_eq!(
            body[0]["error"]["message"],
            "function \"array_reverse\" is unsupported locally"
        );
    }
}

#[test]
fn observed_internal_console_diagnostics_are_safe() {
    if let Ok(case) = std::env::var("FIREEMU_INTERNAL_DIAGNOSTIC_CASE") {
        let (family, step) = match case.as_str() {
            "duplicate" | "emulator" => ("o8a/dupquote-main", "same-1"),
            "array" => ("o8c/collections-main", "array-reverse-none"),
            _ => panic!("unknown diagnostic case"),
        };
        let strict = case != "emulator";
        let (status, _) = internal_case(strict, family, step, false);
        assert_eq!(status, if strict { 500 } else { 400 });
        return;
    }
    for (case, expected) in [
        ("duplicate", "duplicate quoted select alias"),
        ("array", "array_reverse requires an argument"),
        ("emulator", ""),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "observed_internal_console_diagnostics_are_safe",
                "--nocapture",
            ])
            .env("FIREEMU_INTERNAL_DIAGNOSTIC_CASE", case)
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{case}: {stderr}");
        if expected.is_empty() {
            assert!(stderr.is_empty(), "{stderr}");
        } else {
            assert!(stderr.contains(expected), "{case}: {stderr}");
            assert!(!stderr.contains("Bearer"));
            assert!(!stderr.contains("private-value-marker"));
            assert!(!stderr.contains("demo-app"));
        }
    }
}

// The binary-level Node comparator owns compact framing: this in-process REST harness cannot
// observe transport framing or reconstruct the discarded production bodies. These identities
// are delegated, not counted as matches, and the full 1951-row binary comparison remains required.
fn compact_delegation(program: &Value, recorded: &Value) -> Result<Option<Vec<String>>, String> {
    let id = program["id"].as_str().ok_or("missing program id")?;
    let entries: &[(&str, &str, &str)] = match id {
        "fs-ent-pipeline/o8a/framing-small" => &[
            ("f5-rest", "read", "executePipeline"),
            ("f50-rest", "read", "executePipeline"),
            ("f500-rest", "read", "executePipeline"),
            ("f5000-rest", "read", "executePipeline"),
            ("f5000-select-rest", "read", "executePipeline"),
            ("f5000-limit-rest", "read", "executePipeline"),
        ],
        "fs-ent-pipeline/o8a/framing-large" => &[
            ("seed-l12-1", "seed", "commit"),
            ("seed-l12-2", "seed", "commit"),
            ("seed-l12-3", "seed", "commit"),
            ("seed-l3-1", "seed", "commit"),
            ("seed-l3-2", "seed", "commit"),
            ("seed-l3-3", "seed", "commit"),
            ("seed-m30-1", "seed", "commit"),
            ("seed-m30-2", "seed", "commit"),
            ("seed-m30-3", "seed", "commit"),
            ("l12-rest", "read", "executePipeline"),
            ("l3-rest", "read", "executePipeline"),
            ("m30-rest", "read", "executePipeline"),
        ],
        _ if recorded.get("compactFramingVersion").is_some() => {
            return Err(format!("unexpected compact program: {id}"));
        }
        _ => return Ok(None),
    };
    if recorded["compactFramingVersion"] != 1 {
        return Err(format!("invalid compact version: {id}"));
    }
    let steps = program["steps"].as_array().ok_or("missing steps")?;
    if steps.len() != entries.len() {
        return Err(format!("compact step count changed: {id}"));
    }
    let mut rows = Vec::new();
    for (step_id, kind, rpc) in entries {
        let matches: Vec<_> = steps.iter().filter(|step| step["id"] == *step_id).collect();
        if matches.len() != 1
            || matches[0]["rpc"] != *rpc
            || recorded["steps"][*step_id]["kind"] != *kind
        {
            return Err(format!("compact contract changed: {id}#{step_id}"));
        }
        rows.push(format!("{id}#{step_id}"));
    }
    Ok(Some(rows))
}

#[test]
fn compact_delegation_rejects_missing_extra_and_changed_kinds() {
    let requests = read("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    for row in include_str!("pipeline_compact.generated.tsv")
        .lines()
        .skip(1)
    {
        let columns: Vec<_> = row.split('\t').collect();
        let [size, profile, variant] = columns.as_slice() else {
            panic!("invalid PICT row: {row}");
        };
        assert!(["strict", "emulator"].contains(profile));
        let id = format!("fs-ent-pipeline/o8a/framing-{size}");
        let mut program = requests["programs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|program| program["id"] == id)
            .unwrap()
            .clone();
        let mut recorded = production["programs"][&id].clone();
        match *variant {
            "valid" => (),
            "missing" => {
                program["steps"].as_array_mut().unwrap().pop();
            }
            "extra" => {
                program["steps"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":"extra", "rpc":"commit"}));
            }
            "duplicate" => {
                let first = program["steps"][0]["id"].clone();
                program["steps"][1]["id"] = first;
            }
            "version" => {
                recorded["compactFramingVersion"] = json!(2);
            }
            "unknown" => {
                program["id"] = json!("unexpected-compact-program");
            }
            "kind" => {
                let step_id = program["steps"][0]["id"].as_str().unwrap();
                recorded["steps"][step_id]["kind"] = json!("unexpected");
            }
            "rpc" => {
                program["steps"][0]["rpc"] = json!("unexpected");
            }
            _ => panic!("unknown variant: {variant}"),
        }
        let result = compact_delegation(&program, &recorded);
        if *variant == "valid" {
            assert_eq!(
                result.unwrap().unwrap().len(),
                if *size == "small" { 6 } else { 12 },
                "{row}"
            );
        } else {
            assert!(result.is_err(), "{row}");
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_pipeline_corpus_replays_as_production_answered() {
    let (requests, order) = read_ordered("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    // A stopped run's private fixture (`fixture.partial.json`) is never replayed as production:
    // it holds programs finished by one recording, without the second recording's rows.
    assert!(production.get("partial").is_none(), "a partial fixture");
    assert!(
        production["programs"]
            .as_object()
            .is_some_and(|programs| programs.values().all(|p| p.get("recordings").is_none())),
        "a partial fixture"
    );
    let debts = o5_differences();
    let mut failures = Vec::new();
    // What each profile answers for a debt row, kept to regenerate the debt file
    // (`REGENERATE_O5_DEBT=<path>`; review the result before it replaces the committed file).
    let mut answers: BTreeMap<(bool, String), Value> = BTreeMap::new();
    for strict in [true, false] {
        let mut differing = Vec::new();
        let mut not_replayable = Vec::new();
        let mut delegated_compact = Vec::new();
        let mut compared = 0;
        let mut seen = HashSet::new();
        let pending = |row: &str| {
            let program = row.split('#').next().unwrap_or(row);
            PENDING_PROGRAMS.contains(&program)
        };
        for (p, program) in requests["programs"].as_array().unwrap().iter().enumerate() {
            let id = program["id"].as_str().unwrap();
            if let Some(rows) = compact_delegation(program, &production["programs"][id]).unwrap() {
                delegated_compact.extend(rows);
                continue;
            }
            // Each program runs on its own database, as the recorder cleans its collections
            // between programs (several programs seed the same collection names).
            let s = state(strict);
            for seed in program["seed"].as_array().unwrap() {
                let (status, body) = call(
                    &s,
                    "PATCH",
                    &format!("{DOCS}/{}", seed[0].as_str().unwrap()),
                    &json!({"fields": fill(&seed[1])}),
                );
                assert_eq!(status, 200, "{id} seed: {body}");
            }
            let recorded = &production["programs"][id]["steps"];
            for (n, step) in program["steps"].as_array().unwrap().iter().enumerate() {
                let step_id = step["id"].as_str().unwrap();
                let row = format!("{id}#{step_id}");
                let rpc = step["rpc"].as_str().unwrap();
                let (status, body) = if rpc == "get" {
                    let parent = step["parent"].as_str().unwrap();
                    call(&s, "GET", &format!("{DOCS}/{parent}"), &Value::Null)
                } else if let Some(raw) = step["rawBody"].as_str() {
                    // A body sent as written (O-8A): the in-process surface takes a parsed
                    // body, so a text that is not JSON cannot be replayed here.
                    let text = raw.replace("{docs}", DOCS);
                    let Ok((value, key_order)) =
                        fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(
                            text.as_bytes(),
                        )
                    else {
                        not_replayable.push(row);
                        continue;
                    };
                    call_ordered(&s, "POST", &format!("{DOCS}:{rpc}"), &value, &key_order)
                } else {
                    call_ordered(
                        &s,
                        "POST",
                        &format!("{DOCS}:{rpc}"),
                        &fill(&step["body"]),
                        &order.rebased(&format!("/programs/{p}/steps/{n}/body"), ""),
                    )
                };
                let expected = &recorded[step_id];
                // The order of every pipeline answer is compared: a read without a sort is in
                // production's scan order (ascending CRC-32 of the document ID, O-9), which
                // fireemu reproduces. The groups of an aggregate come in an order of their own
                // (not the scan order, nor a sort of the keys: production's is unobserved), so
                // such an answer is a multiset unless a `sort` follows the grouping.
                let stages = step["body"]["structuredPipeline"]["pipeline"]["stages"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let grouped_at = stages.iter().position(|stage| {
                    stage["name"] == "aggregate"
                        && stage["args"][1]["mapValue"]["fields"]
                            .as_object()
                            .is_some_and(|groups| !groups.is_empty())
                });
                let ordered = rpc == "executePipeline"
                    && grouped_at.is_none_or(|at| stages[at..].iter().any(|s| s["name"] == "sort"));
                assert!(!expected.is_null(), "{row} has no production row");
                let matches = if rpc == "commit" {
                    u64::from(status) == expected["status"].as_u64().unwrap()
                } else if rpc == "get" {
                    // A document read: the status and the normalized document.
                    json!({"status": status, "body": normalize(&body)})
                        == json!({"status": expected["status"], "body": normalize(&expected["body"])})
                } else if rpc == "runQuery" {
                    json!({"status": status, "documents": query_documents(&body)})
                        == json!({"status": expected["status"], "documents": query_documents(&expected["body"])})
                } else {
                    answer_in(status, &body, ordered)
                        == answer_in(
                            u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                            &expected["body"],
                            ordered,
                        )
                };
                let matches = if row == "fs-ent-pipeline/o5/function-names#fn-current_document"
                    && status == 200
                {
                    let (document_status, document) =
                        call(&s, "GET", &format!("{DOCS}/fx5/d"), &json!({}));
                    let mut actual = body.clone();
                    let mut recorded_body = expected["body"].clone();
                    let mut metadata_matches = document_status == 200;
                    for (key, document_key) in [
                        ("__create_time__", "createTime"),
                        ("__update_time__", "updateTime"),
                    ] {
                        let pointer =
                            format!("/0/results/0/fields/v/mapValue/fields/{key}/timestampValue");
                        let actual_time = actual.pointer(&pointer).and_then(Value::as_str);
                        let document_time = document[document_key].as_str();
                        metadata_matches &= actual_time.is_some() && actual_time == document_time;
                        metadata_matches &=
                            recorded_body.pointer(&pointer).and_then(Value::as_str) == Some("<t2>");
                        if let (Some(a), Some(b)) = (
                            actual.pointer_mut(&pointer),
                            recorded_body.pointer_mut(&pointer),
                        ) {
                            *a = json!("<document-time>");
                            *b = json!("<document-time>");
                        } else {
                            metadata_matches = false;
                        }
                    }
                    metadata_matches
                        && answer_in(status, &actual, ordered)
                            == answer_in(200, &recorded_body, ordered)
                } else if row == "fs-ent-pipeline/o8c/timestamps-main#current-timestamp-ok" {
                    current_timestamp_matches(
                        status,
                        &body,
                        u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                        &expected["body"],
                        i128::from(REPLAY_CLOCK_SECONDS) * 1_000_000_000,
                    )
                } else {
                    match nondeterministic(&row) {
                        Some(rule) => satisfies(&rule, status, &body, REPLAY_CLOCK_SECONDS),
                        None => matches,
                    }
                };
                compared += 1;
                seen.insert(row.clone());
                if pending(&row) {
                    let program = row.split('#').next().unwrap_or(&row);
                    let pinned = is_pinned(PENDING_MATCHES, program, step_id, strict);
                    if let Some(failure) = pin_failure(&row, strict, matches, pinned) {
                        failures.push(failure);
                    }
                }
                if rpc == "executePipeline" && matches && status == 200 {
                    // Production packs a small answer into one response (FS-ENT-ORACLE O-1,
                    // results/metadata): the number of array elements and the results each
                    // holds are part of the answer.
                    let got = framing(&body);
                    let want = if row.ends_with("#sample-percent-50") {
                        let count = got.iter().sum();
                        vec![count]
                    } else {
                        framing(&expected["body"])
                    };
                    if got != want {
                        failures.push(format!(
                            "strict={strict} {row}: framing {got:?}, production {want:?}"
                        ));
                    }
                }
                let got = answer_in(status, &body, ordered);
                let want = answer_in(
                    u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
                    &expected["body"],
                    ordered,
                );
                if O8A_INTERNAL_ROWS.contains(&row.as_str())
                    && !o8a_internal_binding_valid(&row, &want)
                {
                    failures.push(format!("{row}: recorded INTERNAL binding changed: {want}"));
                }
                if debts.contains_key(&row) {
                    answers.insert((strict, row.clone()), got.clone());
                }
                if let Some(debt) = debts.get(&row) {
                    if debt.production != want {
                        failures.push(format!(
                            "strict={strict} {row}: production binding changed: {want}"
                        ));
                    }
                    let pinned = if strict {
                        Some(&debt.strict)
                    } else {
                        debt.emulator.as_ref()
                    };
                    if let Some(pinned) = pinned {
                        if got != *pinned {
                            failures.push(format!(
                                "strict={strict} {row}: pinned local debt answer changed: {got}"
                            ));
                        }
                        if !o5_pinned_match_valid(debt, strict, matches) {
                            failures
                                .push(format!("strict={strict} {row}: debt match status changed"));
                        }
                    } else if !matches {
                        failures.push(format!(
                            "strict={strict} {row}: unlisted profile differs: {got}"
                        ));
                    }
                }
                if !matches {
                    differing.push((
                        row,
                        answer_in(status, &body, ordered),
                        answer_in(
                            u16::try_from(expected["status"].as_u64().unwrap_or(0)).unwrap(),
                            &expected["body"],
                            ordered,
                        ),
                    ));
                }
            }
        }
        if let Ok(path) = std::env::var("DUMP_REPLAY_DIFFS") {
            let rows: Vec<Value> = differing
                .iter()
                .map(|(row, got, want)| json!({"row": row, "got": got, "want": want}))
                .collect();
            std::fs::write(
                format!("{path}.{}", if strict { "strict" } else { "emulator" }),
                serde_json::to_string_pretty(&rows).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            delegated_compact.len(),
            18,
            "strict={strict}: compact delegation changed"
        );
        assert_eq!(delegated_compact.iter().collect::<HashSet<_>>().len(), 18);
        assert!(compared > 200, "{compared}");
        // The O-8A bodies that are not JSON, or nest deeper than the parser takes, are the only rows
        // this surface cannot take.
        assert_eq!(
            not_replayable,
            [
                "fs-ent-pipeline/o8a/precedence-main#empty-body",
                "fs-ent-pipeline/o8a/precedence-main#not-json",
                "fs-ent-pipeline/o8a/precedence-main#truncated",
                // Nesting probes deeper than the 100 levels the request parser takes.
                "fs-ent-pipeline/o8a/nesting-main#chain-32",
                "fs-ent-pipeline/o8a/nesting-main#chain-33",
                "fs-ent-pipeline/o8a/nesting-main#chain-47",
                "fs-ent-pipeline/o8a/nesting-main#chain-48",
                "fs-ent-pipeline/o8a/nesting-main#chain-100",
            ],
            "strict={strict}"
        );
        let known = |row: &str| {
            KNOWN_DIFFERENCES.iter().any(|(known, _)| row == *known)
                || UNMODELLED_PRODUCTION_ROWS
                    .iter()
                    .any(|(known, _, _, _)| row == *known)
                || UNOBSERVED_ORDER_ROWS
                    .iter()
                    .any(|(known, _, _)| row == *known)
                || (!strict
                    && EMULATOR_ONLY_DIFFERENCES
                        .iter()
                        .any(|(known, _)| row == *known))
        };
        failures.extend(pin_problems(
            PENDING_MATCHES,
            PENDING_PROGRAMS,
            &seen,
            strict,
        ));
        for program in PENDING_PROGRAMS {
            let has_gap = differing
                .iter()
                .any(|(row, _, _)| row.split('#').next() == Some(*program));
            let expected_gap = expected_program_gap(program, strict);
            if program_gap_changed(has_gap, expected_gap) {
                failures.push(format!(
                    "strict={strict}: pending program gap changed for {program}: expected {expected_gap}, got {has_gap}"
                ));
            }
        }
        failures.extend(base64_pin_problems(strict, &seen, &differing));
        let unexpected: Vec<_> = differing
            .iter()
            .filter(|(row, _, _)| {
                !known(row)
                    && !row.starts_with("fs-ent-pipeline/o8a/base64-main#")
                    && !pending(row)
                    && !debts
                        .get(row)
                        .is_some_and(|debt| strict || debt.emulator.is_some())
            })
            .collect();
        for row in debts.keys().filter(|row| !seen.contains(*row)) {
            failures.push(format!(
                "strict={strict}: debt row absent from corpus: {row}"
            ));
        }
        let mut stale = Vec::new();
        let mut changed_known = Vec::new();
        for (known, reason) in KNOWN_DIFFERENCES {
            let Some((_, got, _)) = differing.iter().find(|(row, _, _)| row == known) else {
                stale.push(json!({"row": known, "reason": reason}));
                continue;
            };
            let pinned = if *known == "fs-ent-pipeline/o4/stages#select-empty-then-unknown-function"
                && !strict
            {
                got["status"] == 400
                    && got["body"][0]["error"]["message"]
                        == "The 'select(...)' stage requires at least one field."
            } else {
                got["status"] == 501 && got["body"][0]["error"]["status"] == "UNIMPLEMENTED"
            };
            if !pinned {
                changed_known.push(json!({"row": known, "reason": reason, "local": got}));
            }
        }
        // An unobserved-order row must still answer 200 with its pinned count and differ.
        for (known, reason, strict_status, emulator_status) in UNMODELLED_PRODUCTION_ROWS {
            let want = if strict {
                strict_status
            } else {
                emulator_status
            };
            if strict && O8A_INTERNAL_ROWS.contains(known) {
                if *strict_status != 500
                    || !seen.contains(*known)
                    || differing.iter().any(|(row, _, _)| row == known)
                {
                    changed_known.push(json!({"row": known, "reason": reason}));
                }
                continue;
            }
            match differing.iter().find(|(row, _, _)| row == known) {
                Some((_, got, _)) if got["status"] == *want => {}
                Some((_, got, _)) => {
                    changed_known.push(json!({"row": known, "reason": reason, "local": got}));
                }
                None => stale.push(json!({"row": known, "reason": reason})),
            }
        }
        for (known, reason, count) in UNOBSERVED_ORDER_ROWS {
            match differing.iter().find(|(row, _, _)| row == known) {
                Some((_, got, _))
                    if got["status"] == 200
                        && got["results"].as_array().map(Vec::len) == Some(*count) => {}
                Some((_, got, _)) => {
                    changed_known.push(json!({"row": known, "reason": reason, "local": got}));
                }
                None => stale.push(json!({"row": known, "reason": reason})),
            }
        }
        if !unexpected.is_empty() || !stale.is_empty() || !changed_known.is_empty() {
            failures.push(format!(
                "strict={strict}: unexpected={}, stale={}, changedKnown={}; stale rows {:?}; changed rows {:?}",
                unexpected.len(),
                stale.len(),
                changed_known.len(),
                stale.iter().map(|row| row["row"].clone()).collect::<Vec<_>>(),
                changed_known.iter().map(|row| row["row"].clone()).collect::<Vec<_>>()
            ));
        }
    }
    if let Ok(path) = std::env::var("REGENERATE_O5_DEBT") {
        let rows: Vec<Value> = o5_difference_rows()
            .iter()
            .filter_map(|debt| regenerate_o5_row(debt, &answers))
            .collect();
        std::fs::write(&path, serde_json::to_string_pretty(&rows).unwrap()).unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn regenerate_o5_row(
    debt: &O5Difference,
    answers: &BTreeMap<(bool, String), Value>,
) -> Option<Value> {
    let strict = answers
        .get(&(true, debt.row.clone()))
        .unwrap_or_else(|| panic!("missing strict capture: {}", debt.row));
    let emulator = answers
        .get(&(false, debt.row.clone()))
        .unwrap_or_else(|| panic!("missing emulator capture: {}", debt.row));
    if *strict == debt.production
        && *emulator == debt.production
        && debt.category != "unknown-production-outcome"
    {
        return None;
    }
    Some(
        json!({"row": debt.row, "category": debt.category, "reason": debt.reason,
        "production": debt.production, "strict": strict,
        "emulator": if *emulator == debt.production { Value::Null } else { emulator.clone() }}),
    )
}

#[test]
fn o5_and_duplicate_internal_pins_reject_unobserved_matches() {
    let rows = o5_difference_rows();
    let unknown = rows
        .iter()
        .find(|row| row.row == O5_INTERNAL_ROW)
        .unwrap()
        .clone();
    validate_o5_pin(&unknown);
    for invalid in [
        O5Difference {
            row: "fs-ent-pipeline/o5/other#unknown".to_owned(),
            ..unknown.clone()
        },
        O5Difference {
            category: "unsupported-subset".to_owned(),
            ..unknown.clone()
        },
        O5Difference {
            production: json!({"status":500}),
            ..unknown.clone()
        },
        O5Difference {
            strict: json!({"status":501}),
            ..unknown.clone()
        },
        O5Difference {
            emulator: Some(unknown.production.clone()),
            ..unknown.clone()
        },
    ] {
        assert!(std::panic::catch_unwind(|| validate_o5_pin(&invalid)).is_err());
    }
    let ordinary = rows
        .iter()
        .find(|row| row.row != O5_INTERNAL_ROW && row.strict != row.production)
        .unwrap()
        .clone();
    validate_o5_pin(&ordinary);
    let stale = O5Difference {
        strict: ordinary.production.clone(),
        emulator: None,
        ..ordinary.clone()
    };
    assert!(std::panic::catch_unwind(|| validate_o5_pin(&stale)).is_err());
    assert!(o5_pinned_match_valid(&unknown, true, true));
    assert!(!o5_pinned_match_valid(&unknown, false, true));
    let matched = rows
        .iter()
        .find(|row| row.row.ends_with("#fn-make_struct"))
        .unwrap();
    validate_o5_pin(matched);
    assert!(o5_pinned_match_valid(matched, true, true));
    assert!(!o5_pinned_match_valid(matched, false, true));
    let reference = rows
        .iter()
        .find(|row| row.row == O5_REFERENCE_ENV_ROW)
        .unwrap();
    validate_o5_pin(reference);
    assert!(!o5_pinned_match_valid(reference, true, true));
    assert!(!o5_pinned_match_valid(reference, false, true));
    assert!(!o5_pinned_match_valid(&ordinary, true, true));
    assert!(!o5_pinned_match_valid(&ordinary, false, true));
    for row in O8A_INTERNAL_ROWS {
        assert!(o8a_internal_binding_valid(row, &recorded_internal_answer()));
        assert!(!o8a_internal_binding_valid(row, &json!({"status":500})));
    }
    assert!(!o8a_internal_binding_valid(
        "not-recorded",
        &recorded_internal_answer()
    ));
}

#[test]
fn o5_regeneration_requires_both_profiles_and_retains_unknown() {
    let rows = o5_difference_rows();
    let unknown = rows
        .iter()
        .find(|row| row.row == O5_INTERNAL_ROW)
        .unwrap()
        .clone();
    let mut answers = BTreeMap::new();
    answers.insert((true, unknown.row.clone()), unknown.production.clone());
    assert!(std::panic::catch_unwind(|| regenerate_o5_row(&unknown, &answers)).is_err());
    answers.insert((false, unknown.row.clone()), unknown.production.clone());
    let kept = regenerate_o5_row(&unknown, &answers).unwrap();
    assert_eq!(kept["row"], O5_INTERNAL_ROW);
    assert_eq!(kept["category"], "unknown-production-outcome");
    assert_eq!(kept["production"], unknown.production);
    let ordinary = rows
        .iter()
        .find(|row| row.row != O5_INTERNAL_ROW)
        .unwrap()
        .clone();
    let both = BTreeMap::from([
        ((true, ordinary.row.clone()), ordinary.production.clone()),
        ((false, ordinary.row.clone()), ordinary.production.clone()),
    ]);
    assert!(regenerate_o5_row(&ordinary, &both).is_none());
}

const BASE64_ROWS: &[&str] = &[
    "write-lf",
    "get-lf",
    "write-cr",
    "get-cr",
    "write-crlf",
    "get-crlf",
    "write-mime-76",
    "get-mime-76",
    "write-mime-76-lf",
    "get-mime-76-lf",
    "write-mixed-plus-underscore",
    "get-mixed-plus-underscore",
    "write-mixed-minus-slash",
    "get-mixed-minus-slash",
    "write-proto-name",
    "get-proto-name",
    "cursor-lf",
    "cursor-crlf",
];

fn base64_pin_problems(
    strict: bool,
    seen: &HashSet<String>,
    differing: &[(String, Value, Value)],
) -> Vec<String> {
    let prefix = "fs-ent-pipeline/o8a/base64-main#";
    let pins: Value =
        serde_json::from_str(include_str!("pipeline_base64_differences.json")).unwrap();
    let expected = pins[if strict { "strict" } else { "emulator" }]
        .as_array()
        .unwrap();
    let mut problems = Vec::new();
    for suffix in BASE64_ROWS {
        let row = format!("{prefix}{suffix}");
        if !seen.contains(&row) {
            problems.push(format!("strict={strict}: missing base64 row {row}"));
        }
        let actual = differing.iter().find(|(id, _, _)| *id == row);
        let pin = expected.iter().find(|item| item["row"] == row);
        match (actual, pin) {
            (None, None) => {}
            (Some((_, got, want)), Some(pin)) if *got == pin["got"] && *want == pin["want"] => {}
            _ => problems.push(format!("strict={strict}: base64 pin changed {row}")),
        }
    }
    for (row, _, _) in differing
        .iter()
        .filter(|(row, _, _)| row.starts_with(prefix))
    {
        if !BASE64_ROWS
            .iter()
            .any(|suffix| row == &format!("{prefix}{suffix}"))
        {
            problems.push(format!(
                "strict={strict}: unexpected base64 difference {row}"
            ));
        }
    }
    problems
}

#[test]
fn base64_pins_reject_missing_and_changed_profile_answers() {
    let pins: Value =
        serde_json::from_str(include_str!("pipeline_base64_differences.json")).unwrap();
    let seen: HashSet<String> = BASE64_ROWS
        .iter()
        .map(|suffix| format!("fs-ent-pipeline/o8a/base64-main#{suffix}"))
        .collect();
    for (strict, profile, count) in [(true, "strict", 7), (false, "emulator", 16)] {
        let differences: Vec<(String, Value, Value)> = pins[profile]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["row"].as_str().unwrap().to_owned(),
                    p["got"].clone(),
                    p["want"].clone(),
                )
            })
            .collect();
        assert_eq!(differences.len(), count);
        assert!(base64_pin_problems(strict, &seen, &differences).is_empty());
        let mut missing_seen = seen.clone();
        missing_seen.remove("fs-ent-pipeline/o8a/base64-main#write-lf");
        assert!(!base64_pin_problems(strict, &missing_seen, &differences).is_empty());
        let mut missing_difference = differences.clone();
        missing_difference.pop();
        assert!(!base64_pin_problems(strict, &seen, &missing_difference).is_empty());
        let mut changed = differences.clone();
        changed[0].1 = json!({"status": 200});
        assert!(!base64_pin_problems(strict, &seen, &changed).is_empty());
    }
}

fn program_gap_changed(has_gap: bool, expected_gap: bool) -> bool {
    has_gap != expected_gap
}

fn expected_program_gap(program: &str, strict: bool) -> bool {
    match (program, strict) {
        ("fs-ent-pipeline/o8c/collections-main", true) | ("fs-ent-pipeline/o8d/stages-main", _) => {
            false
        }
        ("fs-ent-pipeline/o8c/collections-main", false) => true,
        _ => panic!("unknown pinned program: {program}"),
    }
}

#[test]
fn pinned_program_gaps_are_profile_specific() {
    assert!(!program_gap_changed(false, false));
    assert!(program_gap_changed(true, false));
    assert!(program_gap_changed(false, true));
    assert!(!program_gap_changed(true, true));
    let collections = "fs-ent-pipeline/o8c/collections-main";
    let stages = "fs-ent-pipeline/o8d/stages-main";
    assert!(!expected_program_gap(collections, true));
    assert!(expected_program_gap(collections, false));
    assert!(!expected_program_gap(stages, true));
    assert!(!expected_program_gap(stages, false));
    assert!(std::panic::catch_unwind(|| expected_program_gap("unknown", true)).is_err());
    assert!(std::panic::catch_unwind(|| expected_program_gap("unknown", false)).is_err());
    assert!(is_pinned(
        PENDING_MATCHES,
        collections,
        "array-reverse-none",
        true
    ));
    assert!(!is_pinned(
        PENDING_MATCHES,
        collections,
        "array-reverse-none",
        false
    ));
    for strict in [true, false] {
        assert!(is_pinned(PENDING_MATCHES, stages, "unnest-tags", strict));
        assert!(!is_pinned(PENDING_MATCHES, stages, "sample", strict));
    }
}

/// Whether a step of a pending program is pinned as matching production in a profile.
fn is_pinned(
    table: &[(&str, &[&str], &[&str])],
    program: &str,
    step_id: &str,
    strict: bool,
) -> bool {
    table.iter().any(|(id, strict_rows, emulator_rows)| {
        *id == program && (if strict { strict_rows } else { emulator_rows }).contains(&step_id)
    })
}

/// The failure of a pending row whose match with production differs from its pin.
fn pin_failure(row: &str, strict: bool, matches: bool, pinned: bool) -> Option<String> {
    (matches != pinned).then(|| {
        format!(
            "strict={strict} {row}: pending row {} production, pinned {}",
            if matches { "matches" } else { "differs from" },
            if pinned { "matching" } else { "differing" },
        )
    })
}

/// The pins stay meaningful: each names a pending program once, each step it lists is replayed in
/// this profile (a renamed or no longer replayable step would never be compared), and no step is
/// listed twice.
fn pin_problems(
    table: &[(&str, &[&str], &[&str])],
    pending: &[&str],
    seen: &HashSet<String>,
    strict: bool,
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut pinned_programs = HashSet::new();
    for (program, strict_rows, emulator_rows) in table {
        if !pinned_programs.insert(*program) {
            problems.push(format!("strict={strict}: pins listed twice: {program}"));
        }
        if !pending.contains(program) {
            problems.push(format!(
                "strict={strict}: pins of a program that is not pending: {program}"
            ));
        }
        for rows in [strict_rows, emulator_rows] {
            let mut listed = HashSet::new();
            for step_id in *rows {
                if !listed.insert(*step_id) {
                    problems.push(format!(
                        "strict={strict}: pin listed twice: {program}#{step_id}"
                    ));
                }
            }
        }
        let pinned_here = if strict { *strict_rows } else { *emulator_rows };
        for step_id in pinned_here {
            if !seen.contains(&format!("{program}#{step_id}")) {
                problems.push(format!(
                    "strict={strict}: pinned step is not replayed: {program}#{step_id}"
                ));
            }
        }
    }
    problems
}

#[test]
fn the_pending_pins_fail_in_both_directions_and_check_themselves() {
    let table: &[(&str, &[&str], &[&str])] = &[("p/a", &["s1", "s2"], &["s1"])];
    // A pin applies to its own program, step and profile only.
    assert!(is_pinned(table, "p/a", "s1", true));
    assert!(is_pinned(table, "p/a", "s2", true));
    assert!(!is_pinned(table, "p/a", "s2", false));
    assert!(is_pinned(table, "p/a", "s1", false));
    assert!(!is_pinned(table, "p/a", "s3", true));
    assert!(!is_pinned(table, "p/b", "s1", true));
    assert!(!is_pinned(&[], "p/a", "s1", true));
    // A pinned row that differs, and an unpinned row that matches, both fail; the rest pass.
    assert!(pin_failure("p/a#s1", true, false, true).is_some_and(|f| f.contains("differs from")));
    assert!(pin_failure("p/a#s3", false, true, false).is_some_and(|f| f.contains("matches")));
    assert!(pin_failure("p/a#s1", true, true, true).is_none());
    assert!(pin_failure("p/a#s3", true, false, false).is_none());
    // The table checks itself.
    let seen: HashSet<String> = ["p/a#s1", "p/a#s2"].map(String::from).into();
    assert!(pin_problems(table, &["p/a"], &seen, true).is_empty());
    assert!(pin_problems(&[], &["p/a"], &seen, true).is_empty());
    let problems = |table: &[(&str, &[&str], &[&str])], pending: &[&str], strict| {
        pin_problems(table, pending, &seen, strict).join(";")
    };
    assert!(problems(table, &[], true).contains("not pending: p/a"));
    assert!(problems(&[table[0], table[0]], &["p/a"], true).contains("pins listed twice: p/a"));
    let twice: &[(&str, &[&str], &[&str])] = &[("p/a", &["s1", "s1"], &[])];
    assert!(problems(twice, &["p/a"], true).contains("pin listed twice: p/a#s1"));
    let renamed: &[(&str, &[&str], &[&str])] = &[("p/a", &["s9"], &[])];
    assert!(problems(renamed, &["p/a"], true).contains("not replayed: p/a#s9"));
    // A step is checked in the profile that pins it: s2 is replayed, and the emulator pins only s1.
    let emulator_only: &[(&str, &[&str], &[&str])] = &[("p/a", &[], &["s9"])];
    assert!(problems(emulator_only, &["p/a"], true).is_empty());
    assert!(problems(emulator_only, &["p/a"], false).contains("not replayed: p/a#s9"));
}

/// The six rows judged by rule accept both recordings of production and refuse the near misses.
#[test]
#[allow(clippy::too_many_lines)]
fn the_nondeterministic_rows_accept_both_recordings_and_refuse_near_misses() {
    let production = read("fs-ent-pipeline-production.json");
    let mut checked = 0;
    let mut compact_checked = 0;
    for (id, program) in production["programs"].as_object().unwrap() {
        let Some(second) = program["second"].as_object() else {
            continue;
        };
        if id == "fs-ent-pipeline/o8a/framing-small" {
            assert_eq!(program["compactFramingVersion"], 1);
            let steps = [
                "f500-rest",
                "f500-grpc",
                "f5000-rest",
                "f5000-grpc",
                "f5000-select-rest",
                "f5000-limit-rest",
                "f5000-limit-grpc",
            ];
            assert_eq!(second.len(), steps.len());
            for step in steps {
                let again = second
                    .get(step)
                    .expect("missing compact framing second observation");
                assert_eq!(program["steps"][step]["kind"], "read", "{step}");
                assert_eq!(again["kind"], "read", "{step}");
                compact_checked += 1;
            }
            continue;
        }
        for (step, again) in second {
            let row = format!("{id}#{step}");
            let rule = nondeterministic(&row).unwrap_or_else(|| panic!("no rule for {row}"));
            // A clock row is judged against the first recording's own value (the day it was
            // taken), so the check does not age; the second recording is a minute later.
            let now = program["steps"][step]["body"][0]["results"][0]["fields"]["v"]
                ["integerValue"]
                .as_str()
                .map_or(0, |text| text.parse::<i64>().unwrap());
            for recording in [&program["steps"][step], again] {
                let status = u16::try_from(recording["status"].as_u64().unwrap()).unwrap();
                assert!(
                    satisfies_in(&rule, status, &recording["body"], now, true),
                    "{row}"
                );
            }
            // A refusal is no answer to a request production accepted.
            assert!(!satisfies(&rule, 400, &json!([]), now), "{row}");
            assert!(!satisfies(&rule, 200, &json!([]), now), "{row}");
            checked += 1;
        }
    }
    // Five `sample` rows and the clock row: the fixture lists no other row that differs.
    assert_eq!(checked, 6);
    assert_eq!(compact_checked, 7);

    let clock = |value: &Value| json!([{"results": [{"fields": {"v": value}}]}]);
    let now = 1_793_029_330;
    let integer = |seconds: i64| json!({"integerValue": seconds.to_string()});
    let clock_ok = |value: &Value, now: i64| {
        satisfies(&Nondeterministic::ClockSeconds, 200, &clock(value), now)
    };
    assert!(clock_ok(&integer(now), now));
    assert!(clock_ok(&integer(now + 57), now), "a minute later");
    assert!(
        clock_ok(&integer(now - CLOCK_WINDOW_SECONDS), now),
        "edge of the window"
    );
    assert!(
        !clock_ok(&integer(now + CLOCK_WINDOW_SECONDS + 1), now),
        "just past the window"
    );
    assert!(clock_ok(&integer(now + 60), now), "a minute ahead");
    assert!(!clock_ok(&integer(now + 3600), now), "an hour ahead");
    assert!(
        !clock_ok(&integer(now + 32_400), now),
        "a time-zone offset of nine hours"
    );
    assert!(!clock_ok(&integer(0), now), "zero");
    assert!(!clock_ok(&integer(-1), now), "negative");
    assert!(!clock_ok(&integer(now * 1000), now), "milliseconds");
    assert!(
        !clock_ok(&json!({"stringValue": now.to_string()}), now),
        "a string"
    );
    assert!(!clock_ok(&json!({"doubleValue": 1.5}), now), "a double");
    // Exactly one result with exactly one field, and a 200 status.
    let extra_field = json!([{"results": [{"fields": {"v": integer(now), "w": integer(now)}}]}]);
    assert!(!satisfies(
        &Nondeterministic::ClockSeconds,
        200,
        &extra_field,
        now
    ));
    let two_results = json!([{"results": [
        {"fields": {"v": integer(now)}},
        {"fields": {"v": integer(now)}}
    ]}]);
    assert!(!satisfies(
        &Nondeterministic::ClockSeconds,
        200,
        &two_results,
        now
    ));
    assert!(!satisfies(
        &Nondeterministic::ClockSeconds,
        200,
        &json!([]),
        now
    ));
    assert!(satisfies(
        &Nondeterministic::ClockSeconds,
        200,
        &clock(&integer(now)),
        now
    ));
    assert!(!satisfies(
        &Nondeterministic::ClockSeconds,
        400,
        &clock(&integer(now)),
        now
    ));
    // The replay judges against the clock of its own server.
    assert!(clock_ok(
        &integer(REPLAY_CLOCK_SECONDS + 5),
        REPLAY_CLOCK_SECONDS
    ));
}

#[test]
fn timestamp_recorded_clock_request_reaches_rest_and_grpc() {
    for (clock, seconds, nanos) in [
        (1_000_001_234_i128, 1_i64, 1_000_i32),
        (-1_i128, -1_i64, 999_999_000_i32),
    ] {
        let (status, body) = internal_case_at(
            false,
            "o8c/timestamps-main",
            "current-timestamp-ok",
            false,
            clock,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(framing(&body), vec![1]);
        assert_eq!(
            body.pointer("/0/results/0/fields")
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            vec!["v"]
        );
        let value = body
            .pointer("/0/results/0/fields/v/timestampValue")
            .and_then(Value::as_str)
            .unwrap();
        let parsed = chrono::DateTime::parse_from_rfc3339(value).unwrap();
        assert_eq!(
            (parsed.timestamp(), parsed.timestamp_subsec_nanos()),
            (seconds, u32::try_from(nanos).unwrap())
        );
        let (status, body) = internal_case_at(
            false,
            "o8c/timestamps-main",
            "current-timestamp-ok",
            true,
            clock,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["resultCount"], 1);
        assert_eq!(body["fieldNames"], json!(["v"]));
        assert_eq!(body["timestamp"], json!([seconds, nanos]));
    }
}

#[test]
fn current_timestamp_comparison_checks_clock_and_full_shape() {
    let want =
        json!([{"executionTime":"<t1>","results":[{"fields":{"v":{"timestampValue":"<t2>"}}}]}]);
    for (clock, value) in [
        (1_000_001_234_i128, "1970-01-01T00:00:01.000001Z"),
        (-1, "1969-12-31T23:59:59.999999Z"),
    ] {
        let got = json!([{"executionTime":"ignored", "results":[{"fields":{"v":{"timestampValue":value}}}]}]);
        assert!(current_timestamp_matches(200, &got, 200, &want, clock));
        for bad in [
            json!([{"results":[{"fields":{"v":{"timestampValue":"2000-01-01T00:00:00Z"}}}]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":"1970-01-01T01:00:01.000001Z"}}}]}]),
            json!([{"results":[{"fields":{"v":{"integerValue":"1"}}}]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":123}}}]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":"not-a-time"}}}]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":"<t2>"}}}]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":"1970-01-01T00:00:01.000002Z"}}}]}]),
            json!([{"results":[]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":value},"extra":{"integerValue":"1"}}}]}]),
            json!([{"results":[{"fields":{"v":{"timestampValue":value}}},{"fields":{"v":{"timestampValue":value}}}]}]),
        ] {
            assert!(
                !current_timestamp_matches(200, &bad, 200, &want, clock),
                "{bad}"
            );
        }
        assert!(!current_timestamp_matches(400, &got, 200, &want, clock));
        assert!(!current_timestamp_matches(200, &got, 200, &want, i128::MIN));
        assert!(!current_timestamp_matches(200, &got, 200, &want, i128::MAX));
        let other =
            json!([{"results":[{"fields":{"v":{"timestampValue":"2000-01-01T00:00:00Z"}}}]}]);
        assert_ne!(answer_in(200, &got, true), answer_in(200, &other, true));
    }
}

#[test]
fn map_set_odd_count_recorded_refusal_and_shape_gate_pict() {
    use fireemu_adapter_grpc::pipeline_shape::{shape_of_json, shape_of_request, RefusalGate};
    use tonic::{Code, Status};
    const MESSAGE: &str = "'map_set' function must have an odd number of arguments";
    let fixture = read("fs-ent-pipeline-requests.json");
    let program = fixture["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "fs-ent-pipeline/o8c/collections-main")
        .unwrap();
    let step = program["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "map-set-odd-entries")
        .unwrap();
    let body = fill(&step["body"]);
    let cases = [
        (true, false, false),
        (true, true, false),
        (true, false, true),
        (true, true, true),
        (false, false, false),
        (false, true, false),
        (false, false, true),
    ];
    for (strict, grpc, near) in cases {
        if !near {
            let (status, response) =
                internal_case(strict, "o8c/collections-main", "map-set-odd-entries", grpc);
            assert_eq!(status, 400, "strict={strict} grpc={grpc}: {response}");
            let message = if grpc {
                response["grpcMessage"].as_str()
            } else {
                response.pointer("/0/error/message").and_then(Value::as_str)
            };
            assert_eq!(message, Some(MESSAGE));
            if !grpc {
                let production = read("fs-ent-pipeline-production.json");
                let expected = &production["programs"]["fs-ent-pipeline/o8c/collections-main"]
                    ["steps"]["map-set-odd-entries"];
                assert_eq!(response, expected["body"], "recorded REST error envelope");
            }
        }
        let mut chosen = body.clone();
        if near {
            *chosen.pointer_mut("/structuredPipeline/pipeline/stages/1/args/0/mapValue/fields/v/functionValue/args/3").unwrap() = json!({"integerValue":"1"});
        }
        let shape = if grpc {
            let request = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
                "projects/demo-app/databases/(default)",
                &chosen,
            )
            .unwrap();
            shape_of_request(&request)
        } else {
            let (parsed, order) = fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(
                chosen.to_string().as_bytes(),
            )
            .unwrap();
            shape_of_json(&parsed, &order)
        };
        let gate = if strict {
            RefusalGate::Recorded(shape, "projects/demo-app/databases/(default)".into())
        } else {
            RefusalGate::Open
        };
        let expected = if strict && near {
            Code::Unimplemented
        } else {
            Code::InvalidArgument
        };
        assert_eq!(
            gate.answer(Status::invalid_argument(MESSAGE)).code(),
            expected,
            "strict={strict} grpc={grpc} near={near}"
        );
        if strict {
            assert_eq!(
                gate.answer(Status::invalid_argument(format!("{MESSAGE}!")))
                    .code(),
                Code::Unimplemented
            );
        }
    }
}

#[test]
fn map_set_odd_count_recorded_grpc_is_invalid_argument() {
    let (status, body) = internal_case(true, "o8c/collections-main", "map-set-odd-entries", true);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["grpcMessage"],
        "'map_set' function must have an odd number of arguments"
    );
}

#[test]
fn map_set_odd_count_near_shape_remains_refused_by_strict_routes() {
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let fixture = read("fs-ent-pipeline-requests.json");
    let program = fixture["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "fs-ent-pipeline/o8c/collections-main")
        .unwrap();
    let step = program["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "map-set-odd-entries")
        .unwrap();
    let mut body = fill(&step["body"]);
    *body
        .pointer_mut(
            "/structuredPipeline/pipeline/stages/1/args/0/mapValue/fields/v/functionValue/args/3",
        )
        .unwrap() = json!({"integerValue":"1"});
    for strict in [true, false] {
        let s = state(strict);
        let (status, _) = call(&s, "POST", &format!("{DOCS}:executePipeline"), &body);
        assert_eq!(
            status,
            if strict { 501 } else { 400 },
            "REST strict={strict}"
        );
        let req = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
            "projects/demo-app/databases/(default)",
            &body,
        )
        .unwrap();
        let service = GatewayService::local((*s.gateway).clone(), Arc::clone(&s.local));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let code = runtime.block_on(async {
            use tokio_stream::StreamExt as _;
            match Firestore::execute_pipeline(&service, tonic::Request::new(req)).await {
                Err(error) => error.code(),
                Ok(response) => response
                    .into_inner()
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err()
                    .code(),
            }
        });
        assert_eq!(
            code,
            if strict {
                tonic::Code::Unimplemented
            } else {
                tonic::Code::InvalidArgument
            },
            "gRPC strict={strict}"
        );
    }
}

#[test]
fn recorded_unnest_sixteen_cases_replay_in_both_profiles() {
    let production = read("fs-ent-pipeline-production.json");
    let ids = [
        "unnest-tags",
        "unnest-empty-array",
        "unnest-null",
        "unnest-string",
        "unnest-absent",
        "unnest-index-field",
        "unnest-alias-is-field",
        "unnest-alias-is-other-field",
        "unnest-dotted-alias",
        "unnest-reserved-alias",
        "unnest-index-is-alias",
        "unnest-literal-array",
        "unnest-then-where",
        "unnest-twice",
        "unnest-one-argument",
        "unnest-three-arguments",
    ];
    let mut failures = Vec::new();
    for strict in [true, false] {
        for id in ids {
            let (status, body) = internal_case(strict, "o8d/stages-main", id, false);
            let expected = &production["programs"]["fs-ent-pipeline/o8d/stages-main"]["steps"][id];
            let expected_status = u16::try_from(expected["status"].as_u64().unwrap()).unwrap();
            if answer_in(status, &body, true) != answer_in(expected_status, &expected["body"], true)
                || framing(&body) != framing(&expected["body"])
            {
                failures.push(format!(
                    "strict={strict} {id}: got {} expected {}",
                    answer_in(status, &body, true),
                    answer_in(expected_status, &expected["body"], true)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn recorded_unnest_grpc_preserves_rows_order_and_errors() {
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let requests = read("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    let program = requests["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "fs-ent-pipeline/o8d/stages-main")
        .unwrap();
    for strict in [true, false] {
        for id in ["unnest-tags", "unnest-index-field"] {
            let state = state(strict);
            for seed in program["seed"].as_array().unwrap() {
                let (status, body) = call(
                    &state,
                    "PATCH",
                    &format!("{DOCS}/{}", seed[0].as_str().unwrap()),
                    &json!({"fields": fill(&seed[1])}),
                );
                assert_eq!(status, 200, "{body}");
            }
            let step = program["steps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["id"] == id)
                .unwrap();
            let body = fill(&step["body"]);
            let req = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
                "projects/demo-app/databases/(default)",
                &body,
            )
            .unwrap();
            let service = GatewayService::local((*state.gateway).clone(), Arc::clone(&state.local));
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let responses = rt.block_on(async {
                use tokio_stream::StreamExt as _;
                let mut stream = Firestore::execute_pipeline(&service, tonic::Request::new(req))
                    .await
                    .unwrap()
                    .into_inner();
                let mut out = Vec::new();
                while let Some(response) = stream.next().await {
                    out.push(fireemu_adapter_grpc::rest::pipeline_json::response_to_json(
                        &response.unwrap(),
                    ));
                }
                Value::Array(out)
            });
            let expected =
                &production["programs"]["fs-ent-pipeline/o8d/stages-main"]["steps"][id]["body"];
            assert_eq!(
                answer_in(200, &responses, true),
                answer_in(200, expected, true),
                "{id} strict={strict}"
            );
            assert_eq!(framing(&responses), framing(expected));
        }
        for id in [
            "unnest-dotted-alias",
            "unnest-reserved-alias",
            "unnest-index-is-alias",
            "unnest-one-argument",
            "unnest-three-arguments",
        ] {
            let (status, _) = internal_case(strict, "o8d/stages-main", id, true);
            assert_eq!(status, 400, "{id} strict={strict}");
        }
    }
}

#[test]
fn recorded_union_thirteen_cases_replay_in_both_profiles() {
    let production = read("fs-ent-pipeline-production.json");
    let ids = [
        "union-other",
        "union-itself",
        "union-then-sort",
        "union-then-limit",
        "union-inner-where",
        "union-inner-select",
        "union-empty-input",
        "union-of-union",
        "union-after-select",
        "union-int-argument",
        "union-no-arguments",
        "union-two-arguments",
        "union-no-stages",
    ];
    let mut failures = Vec::new();
    for strict in [true, false] {
        for id in ids {
            let (status, body) = internal_case(strict, "o8d/stages-main", id, false);
            let expected = &production["programs"]["fs-ent-pipeline/o8d/stages-main"]["steps"][id];
            let expected_status = u16::try_from(expected["status"].as_u64().unwrap()).unwrap();
            if answer_in(status, &body, true) != answer_in(expected_status, &expected["body"], true)
                || framing(&body) != framing(&expected["body"])
            {
                failures.push(format!(
                    "strict={strict} {id}: got {} expected {}",
                    answer_in(status, &body, true),
                    answer_in(expected_status, &expected["body"], true)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn recorded_union_grpc_preserves_rows_order_and_errors() {
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let requests = read("fs-ent-pipeline-requests.json");
    let production = read("fs-ent-pipeline-production.json");
    let program = requests["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "fs-ent-pipeline/o8d/stages-main")
        .unwrap();
    for strict in [true, false] {
        for id in [
            "union-other",
            "union-inner-select",
            "union-of-union",
            "union-then-limit",
        ] {
            let state = state(strict);
            for seed in program["seed"].as_array().unwrap() {
                let (status, body) = call(
                    &state,
                    "PATCH",
                    &format!("{DOCS}/{}", seed[0].as_str().unwrap()),
                    &json!({"fields": fill(&seed[1])}),
                );
                assert_eq!(status, 200, "{body}");
            }
            let step = program["steps"]
                .as_array()
                .unwrap()
                .iter()
                .find(|step| step["id"] == id)
                .unwrap();
            let body = fill(&step["body"]);
            let req = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
                "projects/demo-app/databases/(default)",
                &body,
            )
            .unwrap();
            let service = GatewayService::local((*state.gateway).clone(), Arc::clone(&state.local));
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let responses = rt.block_on(async {
                use tokio_stream::StreamExt as _;
                let mut stream = Firestore::execute_pipeline(&service, tonic::Request::new(req))
                    .await
                    .unwrap()
                    .into_inner();
                let mut out = Vec::new();
                while let Some(response) = stream.next().await {
                    out.push(fireemu_adapter_grpc::rest::pipeline_json::response_to_json(
                        &response.unwrap(),
                    ));
                }
                Value::Array(out)
            });
            let expected =
                &production["programs"]["fs-ent-pipeline/o8d/stages-main"]["steps"][id]["body"];
            assert_eq!(
                answer_in(200, &responses, true),
                answer_in(200, expected, true),
                "{id} strict={strict}"
            );
            assert_eq!(framing(&responses), framing(expected));
        }
        for id in [
            "union-int-argument",
            "union-no-arguments",
            "union-two-arguments",
            "union-no-stages",
        ] {
            let (status, _) = internal_case(strict, "o8d/stages-main", id, true);
            assert_eq!(status, 400, "{id} strict={strict}");
        }
    }
}

#[test]
fn union_direct_grpc_and_rest_depth_are_bounded_before_shape_walk() {
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_proto_firestore::google::firestore::v1 as pb;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let collection = || pb::pipeline::Stage {
        name: "collection".to_owned(),
        args: vec![pb::Value {
            value_type: Some(pb::value::ValueType::ReferenceValue("/su".to_owned())),
        }],
        ..Default::default()
    };
    let mut nested = pb::Pipeline {
        stages: vec![collection()],
    };
    for _ in 0..40 {
        nested = pb::Pipeline {
            stages: vec![
                collection(),
                pb::pipeline::Stage {
                    name: "union".to_owned(),
                    args: vec![pb::Value {
                        value_type: Some(pb::value::ValueType::PipelineValue(nested)),
                    }],
                    ..Default::default()
                },
            ],
        };
    }
    let req = pb::ExecutePipelineRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(nested),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    };
    let state = state(true);
    let service = GatewayService::local((*state.gateway).clone(), Arc::clone(&state.local));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let code = rt.block_on(async {
        match Firestore::execute_pipeline(&service, tonic::Request::new(req)).await {
            Err(status) => status.code(),
            Ok(_) => panic!("deep union was accepted"),
        }
    });
    assert_eq!(code, tonic::Code::Unimplemented);

    let mut child = json!({"stages":[{"name":"collection","args":[{"referenceValue":"/su"}]}]});
    for _ in 0..40 {
        child = json!({"stages":[{"name":"collection","args":[{"referenceValue":"/su"}]},{"name":"union","args":[{"pipelineValue":child}]}]});
    }
    let body = json!({"structuredPipeline":{"pipeline":child}});
    let (status, _) = call(&state, "POST", &format!("{DOCS}:executePipeline"), &body);
    assert_eq!(status, 501);
}

#[test]
fn union_relative_child_source_does_not_allow_foreign_literal_reference() {
    let s = state(true);
    let query = |reference: &str| {
        json!({"structuredPipeline":{"pipeline":{"stages":[
            {"name":"collection","args":[{"referenceValue":"/left"}]},
            {"name":"union","args":[{"pipelineValue":{"stages":[
                {"name":"collection","args":[{"referenceValue":"/right"}]},
                {"name":"select","args":[{"mapValue":{"fields":{"v":{"referenceValue":reference}}}}]}
            ]}}]}
        ]}}})
    };
    let (ok, _) = call(
        &s,
        "POST",
        &format!("{DOCS}:executePipeline"),
        &query("projects/demo-app/databases/(default)/documents/right/doc"),
    );
    assert_eq!(ok, 200);
    let (foreign, _) = call(
        &s,
        "POST",
        &format!("{DOCS}:executePipeline"),
        &query("projects/foreign/databases/(default)/documents/right/doc"),
    );
    assert_eq!(foreign, 501);
}

#[test]
fn union_limit_zero_still_denies_nonowner_on_both_routes() {
    use fireemu_adapter_grpc::rules::{RulesEnforcer, TokenSemantics};
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_core_auth::{mfa::TotpPolicy, store::AuthStore};
    use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let mut s = state(true);
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
    let auth = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let loaded = Arc::new(RulesetSlot::new(LoadedRules::from_source("rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }").unwrap()));
    let rules = Arc::new(
        RulesEnforcer::new(loaded, auth, clock).with_token_semantics(TokenSemantics::Firestore),
    );
    s.rules = Some(rules.clone());
    let body = json!({"structuredPipeline":{"pipeline":{"stages":[
        {"name":"collection","args":[{"referenceValue":"/left"}]},
        {"name":"union","args":[{"pipelineValue":{"stages":[{"name":"collection","args":[{"referenceValue":"/right"}]}]}}]},
        {"name":"limit","args":[{"integerValue":"0"}]}
    ]}}});
    let rest = s.handle(&RestRequest {
        method: "POST".to_owned(),
        path: format!("/v1/{DOCS}:executePipeline"),
        query: String::new(),
        authorization: None,
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body: body.clone(),
        batch_field_order: Vec::new(),
        key_order: KeyOrder::default(),
    });
    assert_eq!(rest.status, 403);
    let request = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
        "projects/demo-app/databases/(default)",
        &body,
    )
    .unwrap();
    let service =
        GatewayService::local((*s.gateway).clone(), Arc::clone(&s.local)).with_rules(rules);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let code = rt.block_on(async {
        match Firestore::execute_pipeline(&service, tonic::Request::new(request)).await {
            Err(error) => error.code(),
            Ok(_) => panic!("nonowner accepted"),
        }
    });
    assert_eq!(code, tonic::Code::PermissionDenied);
}

#[test]
#[allow(clippy::too_many_lines)]
fn union_generated_route_combinations() {
    use fireemu_adapter_grpc::rules::{RulesEnforcer, TokenSemantics};
    use fireemu_adapter_grpc::service::GatewayService;
    use fireemu_core_auth::{mfa::TotpPolicy, store::AuthStore};
    use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    let cases = [
        ("different", "plain", "none", "allow", "rest", "strict"),
        ("same", "plain", "none", "allow", "grpc", "strict"),
        ("empty", "plain", "none", "allow", "rest", "strict"),
        ("different", "where", "none", "allow", "rest", "strict"),
        ("different", "select", "none", "allow", "rest", "strict"),
        ("different", "nested", "none", "allow", "rest", "strict"),
        (
            "different",
            "plain",
            "prefix_limit",
            "allow",
            "rest",
            "strict",
        ),
        (
            "different",
            "plain",
            "suffix_limit",
            "allow",
            "rest",
            "strict",
        ),
        ("different", "plain", "blocking", "allow", "rest", "strict"),
        ("different", "plain", "none", "deny", "grpc", "strict"),
        ("different", "plain", "none", "allow", "rest", "ordinary"),
        (
            "empty",
            "select",
            "prefix_limit",
            "deny",
            "grpc",
            "ordinary",
        ),
        ("same", "nested", "blocking", "deny", "grpc", "ordinary"),
        ("empty", "where", "suffix_limit", "deny", "grpc", "ordinary"),
        ("same", "nested", "prefix_limit", "deny", "rest", "ordinary"),
        (
            "empty",
            "nested",
            "suffix_limit",
            "deny",
            "grpc",
            "ordinary",
        ),
        ("same", "select", "suffix_limit", "deny", "rest", "ordinary"),
        ("same", "where", "blocking", "deny", "rest", "ordinary"),
        ("empty", "select", "blocking", "allow", "grpc", "strict"),
        ("empty", "where", "prefix_limit", "allow", "grpc", "strict"),
    ];
    for (branch, child, boundary, guard, transport, profile) in cases {
        let mut s = state(profile == "strict");
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let auth = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let loaded = Arc::new(RulesetSlot::new(LoadedRules::from_source("rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }").unwrap()));
        let rules = Arc::new(
            RulesEnforcer::new(loaded, auth, clock).with_token_semantics(TokenSemantics::Firestore),
        );
        s.rules = Some(rules.clone());
        for (name, n) in [("left/a", 1), ("right/b", 2)] {
            let (status, _) = call(
                &s,
                "PATCH",
                &format!("{DOCS}/{name}"),
                &json!({"fields":{"n":{"integerValue":n.to_string()}}}),
            );
            assert_eq!(status, 200);
        }
        let collection = |name: &str| json!({"name":"collection","args":[{"referenceValue":format!("/{name}")}]});
        let source = match branch {
            "different" => "right",
            "same" => "left",
            "empty" => "empty",
            _ => unreachable!(),
        };
        let mut child_stages = vec![collection(source)];
        if child == "where" {
            child_stages.push(json!({"name":"where","args":[{"functionValue":{"name":"equal","args":[{"fieldReferenceValue":"n"},{"integerValue":"2"}]}}]}));
        }
        if child == "select" {
            child_stages.push(json!({"name":"select","args":[{"mapValue":{"fields":{"n":{"fieldReferenceValue":"n"}}}}]}));
        }
        if child == "nested" {
            child_stages.push(
                json!({"name":"union","args":[{"pipelineValue":{"stages":[collection("left")]}}]}),
            );
        }
        let mut stages = vec![collection("left")];
        if boundary == "prefix_limit" {
            stages.push(json!({"name":"limit","args":[{"integerValue":"1"}]}));
        }
        stages.push(json!({"name":"union","args":[{"pipelineValue":{"stages":child_stages}}]}));
        if boundary == "suffix_limit" {
            stages.push(json!({"name":"limit","args":[{"integerValue":"2"}]}));
        }
        if boundary == "blocking" {
            stages.push(json!({"name":"sort","args":[{"mapValue":{"fields":{"direction":{"stringValue":"ascending"},"expression":{"fieldReferenceValue":"n"}}}}]}));
        }
        let body = json!({"structuredPipeline":{"pipeline":{"stages":stages}}});
        let result = if transport == "rest" {
            let response = s.handle(&RestRequest {
                method: "POST".to_owned(),
                path: format!("/v1/{DOCS}:executePipeline"),
                query: String::new(),
                authorization: (guard == "allow").then(|| "Bearer owner".to_owned()),
                origin: None,
                remote_peer: false,
                browser_metadata: false,
                app_check: Vec::new(),
                body: body.clone(),
                batch_field_order: Vec::new(),
                key_order: KeyOrder::default(),
            });
            if guard == "deny" {
                assert_eq!(
                    response.status, 403,
                    "{branch} {child} {boundary} {transport} {profile}"
                );
                continue;
            }
            assert_eq!(response.status, 200, "{:?}", response.body);
            response.body
        } else {
            let req = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
                "projects/demo-app/databases/(default)",
                &body,
            )
            .unwrap();
            let service =
                GatewayService::local((*s.gateway).clone(), Arc::clone(&s.local)).with_rules(rules);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let response = rt.block_on(async {
                use tokio_stream::StreamExt as _;
                let mut request = tonic::Request::new(req);
                if guard == "allow" {
                    request
                        .metadata_mut()
                        .insert("authorization", "Bearer owner".parse().unwrap());
                }
                match Firestore::execute_pipeline(&service, request).await {
                    Err(error) => Err(error.code()),
                    Ok(response) => {
                        let mut stream = response.into_inner();
                        let mut items = Vec::new();
                        while let Some(item) = stream.next().await {
                            items.push(
                                fireemu_adapter_grpc::rest::pipeline_json::response_to_json(
                                    &item.unwrap(),
                                ),
                            );
                        }
                        Ok(Value::Array(items))
                    }
                }
            });
            if guard == "deny" {
                assert_eq!(response.unwrap_err(), tonic::Code::PermissionDenied);
                continue;
            }
            response.unwrap()
        };
        let mut expected = vec![1];
        let right = match branch {
            "different" => Some(2),
            "same" => Some(1),
            "empty" => None,
            _ => unreachable!(),
        };
        if let Some(n) = right {
            if child != "where" || n == 2 {
                expected.push(n);
            }
        }
        if child == "nested" {
            expected.push(1);
        }
        if boundary == "suffix_limit" {
            expected.truncate(2);
        }
        if boundary == "blocking" {
            expected.sort_unstable();
        }
        let got = result
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|response| response["results"].as_array().into_iter().flatten())
            .map(|row| {
                row["fields"]["n"]["integerValue"]
                    .as_str()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            got, expected,
            "{branch} {child} {boundary} {guard} {transport} {profile}"
        );
    }
}

#[test]
fn recorded_literal_key_eleven_refusals_match_production() {
    let production = read("fs-ent-pipeline-production.json");
    let cases = [
        ("o5/value-shapes", "keys-empty-and-reserved"),
        ("o5/value-shapes", "keys-two-reserved"),
        ("o5/value-shapes", "keys-reserved-inner-and-outer"),
        ("o5/value-shapes", "key-name"),
        ("o5/value-shapes", "key-inner-name"),
        ("o5/literal-keys", "key-reserved-with-field"),
        ("o5/literal-keys", "key-empty-with-field"),
        ("o5/literal-keys", "key-type-with-field"),
        ("o5/literal-keys", "key-dotted-with-function"),
        ("o5/literal-keys", "nested-key-name-with-field"),
        ("o5/literal-keys", "array-of-map-reserved-key-with-field"),
    ];
    let mut failures = Vec::new();
    for (family, id) in cases {
        let expected = &production["programs"][format!("fs-ent-pipeline/{family}")]["steps"][id];
        for strict in [true, false] {
            let (status, body) = internal_case(strict, family, id, false);
            if status != 400 || body != expected["body"] {
                failures.push(format!("{family}#{id} strict={strict}: {status} {body}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn recorded_literal_key_grpc_refusals_keep_messages_where_order_is_observable() {
    let production = read("fs-ent-pipeline-production.json");
    let cases = [
        ("o5/value-shapes", "keys-empty-and-reserved"),
        ("o5/value-shapes", "keys-two-reserved"),
        ("o5/value-shapes", "keys-reserved-inner-and-outer"),
        ("o5/value-shapes", "key-name"),
        ("o5/value-shapes", "key-inner-name"),
        ("o5/literal-keys", "key-reserved-with-field"),
        ("o5/literal-keys", "key-empty-with-field"),
        ("o5/literal-keys", "key-type-with-field"),
        ("o5/literal-keys", "key-dotted-with-function"),
        ("o5/literal-keys", "nested-key-name-with-field"),
        ("o5/literal-keys", "array-of-map-reserved-key-with-field"),
    ];
    let mut failures = Vec::new();
    for (family, id) in cases {
        for strict in [true, false] {
            let (status, body) = internal_case(strict, family, id, true);
            let unordered = matches!(
                id,
                "keys-empty-and-reserved" | "keys-two-reserved" | "keys-reserved-inner-and-outer"
            );
            let wanted = if strict && unordered { 501 } else { 400 };
            if status != wanted {
                failures.push(format!("{family}#{id} strict={strict}: {status} {body}"));
                continue;
            }
            if !unordered {
                let expected = &production["programs"][format!("fs-ent-pipeline/{family}")]
                    ["steps"][id]["body"][0]["error"]["message"];
                if &body["grpcMessage"] != expected {
                    failures.push(format!("{family}#{id} strict={strict}: {body}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn sample_contract_rejects_typed_row_and_framing_near_misses() {
    let production = read("fs-ent-pipeline-production.json");
    let body = &production["programs"]["fs-ent-pipeline/o8d/stages-main"]["steps"]
        ["sample-percent-100"]["body"];
    let rows: Vec<Value> = body
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|part| part["results"].as_array().into_iter().flatten().cloned())
        .collect();
    assert_eq!(rows.len(), 5);
    let sample = |items: Vec<Value>| json!([{"executionTime":"<t1>", "results": items}]);
    let rule = SampleOf {
        count: 2,
        members: SU,
    };
    let good = sample(vec![rows[0].clone(), rows[1].clone()]);
    assert!(sample_contract(&rule, &good, &rows, false, true));
    let mut bad = good.clone();
    bad[0]["results"][0]["fields"]["n"] = json!({"stringValue":"1"});
    assert!(!sample_contract(&rule, &bad, &rows, false, true));
    let mut bad = good.clone();
    bad[0]["results"][0]["createTime"] = json!(1);
    assert!(!sample_contract(&rule, &bad, &rows, false, true));
    let mut bad = good.clone();
    bad[0]["results"][0]["name"] = json!("projects/p/databases/d/documents/su/unknown");
    assert!(!sample_contract(&rule, &bad, &rows, false, true));
    assert!(!sample_contract(
        &rule,
        &sample(vec![rows[0].clone(), rows[0].clone()]),
        &rows,
        false,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &sample(vec![rows[0].clone()]),
        &rows,
        false,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &json!([{"executionTime":"<t1>","results":[rows[0].clone()]},{"executionTime":"<t1>","results":[rows[1].clone()]}]),
        &rows,
        false,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &json!([{"executionTime":"<t1>","results":[rows[0].clone(),rows[1].clone()]},{"executionTime":"<t1>","results":[]}]),
        &rows,
        false,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &sample(vec![rows[1].clone(), rows[0].clone()]),
        &rows,
        true,
        true
    ));
    assert!(sample_contract(
        &rule,
        &sample(vec![rows[0].clone()]),
        &rows,
        true,
        true
    ));
    assert!(sample_contract(
        &rule,
        &sample(rows.clone()),
        &rows,
        true,
        true
    ));
    assert!(sample_contract(&rule, &sample(vec![]), &rows, true, true));
    assert!(!sample_contract(&rule, &json!([null]), &rows, true, true));
    assert!(!sample_contract(&rule, &good, &rows, false, false));
    let mut live = good.clone();
    live[0]["executionTime"] = json!("2026-01-01T00:00:00Z");
    for row in live[0]["results"].as_array_mut().unwrap() {
        row["createTime"] = json!("2026-01-01T00:00:00Z");
        row["updateTime"] = json!("2026-01-01T00:00:00Z");
    }
    assert!(sample_contract(&rule, &live, &rows, false, false));
    live[0]["results"][0]["createTime"] = json!("<t2>");
    assert!(!sample_contract(&rule, &live, &rows, false, false));

    assert!(!sample_contract(&rule, &json!([{}]), &rows, true, true));
    assert!(!sample_contract(
        &rule,
        &json!([{"error":{"message":"bad"}}]),
        &rows,
        true,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &json!([{"executionTime":"broken"}]),
        &rows,
        true,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &json!([{"executionTime":7}]),
        &rows,
        true,
        true
    ));
    assert!(!sample_contract(
        &rule,
        &json!([{"executionTime":"<t1>","error":{}}]),
        &rows,
        true,
        true
    ));
    let mut bad = good.clone();
    bad[0]["results"][0]["createTime"] = json!("broken");
    assert!(!sample_contract(&rule, &bad, &rows, false, true));
    let mut bad = good.clone();
    bad[0]["results"][0]["updateTime"] = json!("broken");
    assert!(!sample_contract(&rule, &bad, &rows, false, true));
    let mut bad = good.clone();
    bad[0]["results"][0]
        .as_object_mut()
        .unwrap()
        .remove("updateTime");
    assert!(!sample_contract(&rule, &bad, &rows, false, true));
}
