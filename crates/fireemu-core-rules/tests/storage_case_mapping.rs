//! The Storage Rules `lower()` and `upper()` on letters that are not ASCII (STORAGE-RULES-CASE).
//!
//! Production, recorded on 2026-11-11 (two recordings, two rulesets of 41 rows per recording, 82
//! observations, none unknown), changes ASCII letters only: `"E-acute".lower()` stays, `"ss".upper()`
//! of the sharp s stays, the dotted capital I, the dotless i, the Greek letters, the final sigma, a
//! combining sequence, the capital sharp s and the fullwidth letters keep their case, and nothing is
//! composed or normalized. The one disagreement between the recordings, the ASCII control
//! `ctl-lower-i` (403 in recording 1, 200 in recording 2), was a release still being propagated: the
//! same run measured the old ruleset still served 14 to 20 seconds after a release, and the row was
//! read 18.6 seconds after it. A stale ruleset can turn an allow into a 403 and never a 403 into a
//! 200, so a 200 in either recording settles a row. Firestore Rules were recorded the same way on
//! 2026-11-08, and the shared evaluator already does this for both services.
//!
//! Each row of the table gives the answer under three candidates: ascii (only A-Z and a-z change),
//! full (the full Unicode default mapping) and simple (the one-character mapping). Only ascii is
//! asserted; the other two columns document what the recording refuted (fifteen rows that full or
//! simple would allow were refused in both recordings, and rows that ascii allows were answered 200).
//!
//! The rows are generated from the plan (`conformance/src/storage-rules-s9/plan-case.mjs`);
//! `conformance/src/storage-rules-case-rust.test.mjs` compares this table with the plan row by row,
//! and `conformance/src/storage-rules-case-recorded.test.mjs` reads the published recording
//! (`conformance/storage-rules-case-production.json`) against the same plan.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{
    evaluate_request_with, Decision, DocumentAccess, Method, RequestContext, RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::RulesValue;

struct NoDocuments;

impl DocumentAccess for NoDocuments {
    fn get(&self, _: &[String]) -> Option<RulesValue> {
        None
    }
}

#[derive(Clone, Copy)]
enum Kind {
    /// The condition holds only literals; the object is `x`.
    Literal,
    /// The condition reads the captured last segment `n`.
    Capture,
    /// The condition reads `resource.name`.
    Resource,
}

struct Row {
    id: &'static str,
    kind: Kind,
    /// The last segment of the object name.
    leaf: &'static str,
    condition: &'static str,
    /// Whether the rule allows, under [ascii, full, simple].
    allowed: [bool; 3],
}

const fn row(
    id: &'static str,
    kind: Kind,
    leaf: &'static str,
    condition: &'static str,
    allowed: [bool; 3],
) -> Row {
    Row {
        id,
        kind,
        leaf,
        condition,
        allowed,
    }
}

const PREFIX: &str = "storage-rules-case/sr-00000000/rec1";

fn allows(row: &Row) -> bool {
    let (pattern, name) = match row.kind {
        Kind::Literal | Kind::Resource => (
            "{allPaths=**}".to_owned(),
            format!("{PREFIX}/{}/{}", row.id, row.leaf),
        ),
        Kind::Capture => ("{n}".to_owned(), row.leaf.to_owned()),
    };
    let source = format!(
        "rules_version = '2';\nservice firebase.storage {{ match /b/{{bucket}}/o {{ match /{pattern} {{ allow get: if {}; }} }} }}",
        row.condition
    );
    let ruleset = parse_ruleset(&source).unwrap_or_else(|e| panic!("{}: {e:?}", row.id));
    let resource = RulesValue::Map(BTreeMap::from([
        ("name".to_owned(), RulesValue::String(name.clone())),
        ("size".to_owned(), RulesValue::Int(1)),
        ("metadata".to_owned(), RulesValue::Map(BTreeMap::new())),
    ]));
    let context = RequestContext {
        service: RulesService::Storage,
        method: Method::Get,
        path: format!("/b/bkt/o/{name}"),
        auth: None,
        resource: Some(resource),
        request_resource: Some(RulesValue::Null),
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    matches!(
        evaluate_request_with(&ruleset, &context, Some(&NoDocuments)).decision,
        Decision::Allow
    )
}

/// The rows the evaluator answers differently from the ascii column (none today).
fn rows_against_ascii() -> Vec<&'static str> {
    ROWS.iter()
        .filter(|row| allows(row) != row.allowed[0])
        .map(|row| row.id)
        .collect()
}

#[test]
fn the_table_holds_every_row_once_with_controls_the_same_under_every_candidate() {
    let mut ids: Vec<&str> = ROWS.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), ROWS.len());
    assert_eq!(ROWS.len(), ROW_COUNT);
    for row in ROWS.iter().filter(|r| r.id.starts_with("ctl-")) {
        assert_eq!(row.allowed[0], row.allowed[1], "{}", row.id);
        assert_eq!(row.allowed[0], row.allowed[2], "{}", row.id);
    }
}

#[test]
fn the_controls_hold() {
    for row in ROWS.iter().filter(|r| r.id.starts_with("ctl-")) {
        assert_eq!(allows(row), row.allowed[0], "{}", row.id);
    }
}

#[test]
fn only_ascii_letters_change_under_storage_rules() {
    assert_eq!(rows_against_ascii(), Vec::<&str>::new());
}

#[test]
fn the_rows_that_tell_the_candidates_apart_are_answered_the_ascii_way() {
    // Rows on which ascii and at least one other candidate differ: the recording refuted the others.
    let telling: Vec<&Row> = ROWS
        .iter()
        .filter(|r| r.allowed[0] != r.allowed[1] || r.allowed[0] != r.allowed[2])
        .collect();
    assert_eq!(telling.len(), 27);
    for row in telling {
        assert_eq!(allows(row), row.allowed[0], "{}", row.id);
    }
}

const ROW_COUNT: usize = 41;

#[rustfmt::skip]
const ROWS: &[Row] = &[
    row("ctl-upper-true", Kind::Literal, "x", "'abc'.upper() == 'ABC'", [true, true, true]),
    row("ctl-upper-false", Kind::Literal, "x", "'abc'.upper() == 'abc'", [false, false, false]),
    row("ctl-lower-true", Kind::Literal, "x", "'ABC'.lower() == 'abc'", [true, true, true]),
    row("ctl-ascii-other", Kind::Literal, "x", "'aB1-_ z'.upper() == 'AB1-_ Z'", [true, true, true]),
    row("ctl-lower-i", Kind::Literal, "x", "'I'.lower() == 'i'", [true, true, true]),
    row("ctl-size-nonascii", Kind::Literal, "x", "'\u{c9}'.size() == 1", [true, true, true]),
    row("ctl-size-emoji", Kind::Literal, "x", "'\u{1f525}'.size() == 2", [true, true, true]),
    row("acute-lower-same", Kind::Literal, "x", "'\u{c9}'.lower() == '\u{c9}'", [true, false, false]),
    row("acute-lower-mapped", Kind::Literal, "x", "'\u{c9}'.lower() == '\u{e9}'", [false, true, true]),
    row("acute-upper-mapped", Kind::Literal, "x", "'\u{e9}'.upper() == '\u{c9}'", [false, true, true]),
    row("acute-upper-same", Kind::Literal, "x", "'\u{e9}'.upper() == '\u{e9}'", [true, false, false]),
    row("sharp-upper-full", Kind::Literal, "x", "'\u{df}'.upper() == 'SS'", [false, true, false]),
    row("sharp-upper-same", Kind::Literal, "x", "'\u{df}'.upper() == '\u{df}'", [true, false, true]),
    row("dotted-lower-full", Kind::Literal, "x", "'\u{130}'.lower().size() == 2", [false, true, false]),
    row("dotted-lower-simple", Kind::Literal, "x", "'\u{130}'.lower() == 'i'", [false, false, true]),
    row("dotted-lower-same", Kind::Literal, "x", "'\u{130}'.lower() == '\u{130}'", [true, false, false]),
    row("dotless-upper-mapped", Kind::Literal, "x", "'\u{131}'.upper() == 'I'", [false, true, true]),
    row("dotless-upper-same", Kind::Literal, "x", "'\u{131}'.upper() == '\u{131}'", [true, false, false]),
    row("sigma-final", Kind::Literal, "x", "'\u{391}\u{3a3}'.lower() == '\u{3b1}\u{3c2}'", [false, true, false]),
    row("sigma-plain", Kind::Literal, "x", "'\u{391}\u{3a3}'.lower() == '\u{3b1}\u{3c3}'", [false, false, true]),
    row("sigma-same", Kind::Literal, "x", "'\u{391}\u{3a3}'.lower() == '\u{391}\u{3a3}'", [true, false, false]),
    row("alpha-lower-mapped", Kind::Literal, "x", "'\u{391}'.lower() == '\u{3b1}'", [false, true, true]),
    row("alpha-lower-same", Kind::Literal, "x", "'\u{391}'.lower() == '\u{391}'", [true, false, false]),
    row("rt-lower-same", Kind::Capture, "\u{c9}", "n.lower() == '\u{c9}'", [true, false, false]),
    row("rt-lower-mapped", Kind::Capture, "\u{c9}", "n.lower() == '\u{e9}'", [false, true, true]),
    row("rt-upper-sharp-full", Kind::Capture, "\u{df}", "n.upper() == 'SS'", [false, true, false]),
    row("rt-upper-sharp-same", Kind::Capture, "\u{df}", "n.upper() == '\u{df}'", [true, false, true]),
    row("rt-res-lower-same", Kind::Resource, "\u{c9}", "resource.name.lower() == resource.name", [true, false, false]),
    row("rt-res-lower-differs", Kind::Resource, "\u{c9}", "resource.name.lower() != resource.name", [false, true, true]),
    row("capsharp-lower-mapped", Kind::Literal, "x", "'\u{1e9e}'.lower() == '\u{df}'", [false, true, true]),
    row("capsharp-lower-same", Kind::Literal, "x", "'\u{1e9e}'.lower() == '\u{1e9e}'", [true, false, false]),
    row("comb-upper", Kind::Literal, "x", "'e\u{301}'.upper() == 'E\u{301}'", [true, true, true]),
    row("comb-upper-composed", Kind::Literal, "x", "'e\u{301}'.upper() == '\u{c9}'", [false, false, false]),
    row("emoji-upper", Kind::Literal, "x", "'\u{1f525}a'.upper() == '\u{1f525}A'", [true, true, true]),
    row("emoji-upper-unchanged", Kind::Literal, "x", "'\u{1f525}a'.upper() == '\u{1f525}a'", [false, false, false]),
    row("emoji-lower-size", Kind::Literal, "x", "'A\u{1f525}B'.lower().size() == 4", [true, true, true]),
    row("fullwidth-upper-mapped", Kind::Literal, "x", "'\u{ff41}'.upper() == '\u{ff21}'", [false, true, true]),
    row("fullwidth-upper-same", Kind::Literal, "x", "'\u{ff41}'.upper() == '\u{ff41}'", [true, false, false]),
    row("fullwidth-lower-mapped", Kind::Literal, "x", "'\u{ff21}'.lower() == '\u{ff41}'", [false, true, true]),
    row("ctl-wide-upper-true", Kind::Literal, "x", "'abc'.upper() == 'ABC'", [true, true, true]),
    row("ctl-wide-upper-false", Kind::Literal, "x", "'abc'.upper() == 'abc'", [false, false, false]),
];
