//! Replays the FS-ENT-ORACLE pipeline corpus (every REST step of the O-1, O-2 and O-3 programs,
//! `conformance/fs-ent-pipeline-requests.json`) against the in-process REST surface under both
//! profiles and compares each answer with the production recording
//! (`conformance/fs-ent-pipeline-production.json`): the status, the result documents as a
//! multiset (order and framing are not compared) and the whole error body. Every difference is
//! named in the allowlist below with its reason, and each listed row must still differ, so the
//! list cannot hide a row that has started to match.

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
    "fs-ent-pipeline/o8c/timestamps-main",
    "fs-ent-pipeline/o8c/collections-main",
    "fs-ent-pipeline/o8d/stages-main",
];

/// The rows of a pending program that match production today, per profile (strict, emulator):
/// the commits that seed or write, the refusals the validators already answer, and the select
/// `__name__` forms. Every other row of a pending program must differ. A row that stops
/// matching, or starts to, fails the replay until this table is updated, so the work that
/// implements a stage cannot drop or gain a match unnoticed.
const PENDING_MATCHES: &[(&str, &[&str], &[&str])] = &[];

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
            count: 2,
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
        Nondeterministic::Sample(SampleOf { count, members }) => {
            let names: Vec<String> = results
                .iter()
                .map(|result| relative(result["name"].as_str().unwrap_or("")))
                .collect();
            let distinct: HashSet<&String> = names.iter().collect();
            names.len() == *count
                && distinct.len() == names.len()
                && names.iter().all(|name| members.contains(&name.as_str()))
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
        "fs-ent-pipeline/px1/select#is-error-sqrt-s",
        "sqrt is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#select-sqrt-a",
        "sqrt is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/static-refusals#where-sqrt-a",
        "sqrt is outside the subset",
    ),
    (
        "fs-ent-pipeline/px1/where#sqrt-s-positive",
        "sqrt is outside the subset",
    ),
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
/// `base64-main`, and the `regex_*` rows of `strings-main`.
const UNMODELLED_PRODUCTION_ROWS: &[(&str, &str, u16, u16)] = &[
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-match",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-no-match",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-anchored",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-anchored-no",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-case-sensitive",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-case-flag",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-empty-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-invalid-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-unicode",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-null-input",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-null-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-absent",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-int-input",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-int-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-contains-one",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-full",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-partial",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-anchors",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-empty-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-invalid-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-null",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-absent",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-int",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-match-one",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-first",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-none",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-group",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-empty-match",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-invalid-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-null",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-absent",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-int",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-all",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-none",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-overlapping",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-empty-match",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-invalid-pattern",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-null",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-absent",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8b/strings-main#regex-find-all-int",
        "the four regex_* functions need a regular-expression engine (RE2 syntax) that the std-only core does not have; they stay unsupported until the dependency is decided",
        501,
        501,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#same-1",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict answers UNIMPLEMENTED and the emulator profile the official emulator's 400",
        501,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#same-2",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict answers UNIMPLEMENTED and the emulator profile the official emulator's 400",
        501,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#same-3",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict answers UNIMPLEMENTED and the emulator profile the official emulator's 400",
        501,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#different-values",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict answers UNIMPLEMENTED and the emulator profile the official emulator's 400",
        501,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/dupquote-main#swapped-order",
        "production answered HTTP 500 INTERNAL in both recordings for an alias and the same alias in quotes (an observed server fault, not a validation answer); strict answers UNIMPLEMENTED and the emulator profile the official emulator's 400",
        501,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-lf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-lf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-cr",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-cr",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-crlf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-crlf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-mime-76",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-mime-76",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-mime-76-lf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-mime-76-lf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-mixed-plus-underscore",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-mixed-plus-underscore",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-mixed-minus-slash",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-mixed-minus-slash",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#write-proto-name",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        400,
        400,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#get-proto-name",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        404,
        404,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#cursor-lf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
    ),
    (
        "fs-ent-pipeline/o8a/base64-main#cursor-crlf",
        "the local REST write and read paths accept base64 that production refuses (line breaks, mixed alphabets, a proto field name); production's decoder is unmodelled (docs.local issue rest-base64)",
        200,
        200,
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
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(REPLAY_CLOCK_SECONDS),
    )));
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

/// How an answer is cut into array elements: the number of results in each.
fn framing(body: &Value) -> Vec<usize> {
    body.as_array()
        .into_iter()
        .flatten()
        .map(|element| element["results"].as_array().map_or(0, Vec::len))
        .collect()
}

// Exact measured compatibility debt, not a production-parity approval.
struct O5Difference {
    row: String,
    category: String,
    reason: String,
    production: Value,
    strict: Value,
    emulator: Option<Value>,
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
        assert_eq!(rows.len(), 223, "finite O5 debt inventory");
        assert_eq!(
            rows.iter().filter(|row| row.emulator.is_some()).count(),
            156,
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
        assert_eq!(row.strict["status"], 501, "strict debt: {}", row.row);
        assert_eq!(
            row.strict["body"][0]["error"]["status"], "UNIMPLEMENTED",
            "strict debt: {}",
            row.row
        );
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
        let mut compared = 0;
        let mut seen = HashSet::new();
        let pending = |row: &str| {
            let program = row.split('#').next().unwrap_or(row);
            PENDING_PROGRAMS.contains(&program)
        };
        for (p, program) in requests["programs"].as_array().unwrap().iter().enumerate() {
            let id = program["id"].as_str().unwrap();
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
                let matches = match nondeterministic(&row) {
                    Some(rule) => satisfies(&rule, status, &body, REPLAY_CLOCK_SECONDS),
                    None => matches,
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
                    let want = framing(&expected["body"]);
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
                        if matches || got == want {
                            failures.push(format!(
                                "strict={strict} {row}: stale debt now matches production"
                            ));
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
            if !differing
                .iter()
                .any(|(row, _, _)| row.split('#').next() == Some(*program))
            {
                failures.push(format!(
                    "strict={strict}: pending program no longer differs, remove it: {program}"
                ));
            }
        }
        let unexpected: Vec<_> = differing
            .iter()
            .filter(|(row, _, _)| {
                !known(row)
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
            .into_iter()
            .filter_map(|debt| {
                let strict = answers.get(&(true, debt.row.clone()))?;
                let emulator = answers.get(&(false, debt.row.clone()))?;
                if *strict == debt.production && *emulator == debt.production {
                    return None;
                }
                let mut row = serde_json::Map::new();
                row.insert("row".into(), json!(debt.row));
                row.insert("category".into(), json!(debt.category));
                row.insert("reason".into(), json!(debt.reason));
                row.insert("production".into(), debt.production.clone());
                row.insert("strict".into(), strict.clone());
                row.insert(
                    "emulator".into(),
                    if *emulator == debt.production {
                        Value::Null
                    } else {
                        emulator.clone()
                    },
                );
                Some(Value::Object(row))
            })
            .collect();
        std::fs::write(&path, serde_json::to_string_pretty(&rows).unwrap()).unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
    for (id, program) in production["programs"].as_object().unwrap() {
        let Some(second) = program["second"].as_object() else {
            continue;
        };
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
                assert!(satisfies(&rule, status, &recording["body"], now), "{row}");
            }
            // A refusal is no answer to a request production accepted.
            assert!(!satisfies(&rule, 400, &json!([]), now), "{row}");
            assert!(!satisfies(&rule, 200, &json!([]), now), "{row}");
            checked += 1;
        }
    }
    // Five `sample` rows and the clock row: the fixture lists no other row that differs.
    assert_eq!(checked, 6);

    let named = |names: &[&str]| {
        json!([{
            "results": names
                .iter()
                .map(|name| json!({"name": format!("projects/p/databases/d/documents/su/{name}"), "fields": {}}))
                .collect::<Vec<_>>()
        }])
    };
    let two = Nondeterministic::Sample(SampleOf {
        count: 2,
        members: SU,
    });
    assert!(satisfies(&two, 200, &named(&["e", "a"]), 0));
    assert!(!satisfies(&two, 200, &named(&["a"]), 0), "too few");
    assert!(
        !satisfies(&two, 200, &named(&["a", "b", "c"]), 0),
        "too many"
    );
    assert!(!satisfies(&two, 200, &named(&["a", "a"]), 0), "a repeat");
    assert!(
        !satisfies(&two, 200, &named(&["a", "z"]), 0),
        "not a member"
    );
    let filtered = Nondeterministic::Sample(SampleOf {
        count: 2,
        members: SU_AFTER_N_1,
    });
    assert!(
        !satisfies(&filtered, 200, &named(&["a", "b"]), 0),
        "filtered out"
    );

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
    assert!(satisfies(&two, 200, &named(&["e", "a"]), 0));
    assert!(
        !satisfies(&two, 400, &named(&["e", "a"]), 0),
        "a refusal with a body"
    );
    // The replay judges against the clock of its own server.
    assert!(clock_ok(
        &integer(REPLAY_CLOCK_SECONDS + 5),
        REPLAY_CLOCK_SECONDS
    ));
}
