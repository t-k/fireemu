//! Differential coverage for inherited index overrides and complete write accounting.
//! Generated small documents cover successful accounting; explicit witnesses cover entry-count and individual-entry-byte refusals. Other refusal families are outside this generator.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{IndexFieldMode, IndexQueryScope, IndexSet};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, LimitScope, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

type Modes = Vec<(IndexQueryScope, IndexFieldMode)>;

fn group() -> CollectionId {
    CollectionId::try_new("items").unwrap()
}

fn document(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        &format!("items/document{index}"),
    )
    .unwrap()
}

fn field(segments: &[&str]) -> FieldPath {
    FieldPath::from_segments(segments.iter().copied()).unwrap()
}

fn modes(code: u8) -> Modes {
    use IndexFieldMode::{Ascending, Contains, Descending, Vector};
    use IndexQueryScope::{Collection, CollectionGroup};
    match code % 7 {
        0 => vec![],
        1 => vec![(Collection, Ascending)],
        2 => vec![(Collection, Descending)],
        3 => vec![(Collection, Contains)],
        4 => vec![(CollectionGroup, Ascending), (CollectionGroup, Contains)],
        5 => vec![
            (CollectionGroup, Descending),
            (Collection, Contains),
            (Collection, Ascending),
            (Collection, Ascending),
        ],
        _ => vec![(Collection, Vector { dimension: 3 })],
    }
}

/// The original algorithm: scan every override and select the longest segment prefix.
fn scan_modes(indexes: &IndexSet, collection: &CollectionId, path: &FieldPath) -> Modes {
    indexes
        .single_field_overrides()
        .filter(|(candidate, prefix, _)| {
            *candidate == collection.as_str() && path.segments().starts_with(prefix)
        })
        .max_by_key(|(_, prefix, _)| prefix.len())
        .map_or_else(
            || {
                vec![
                    (IndexQueryScope::Collection, IndexFieldMode::Ascending),
                    (IndexQueryScope::Collection, IndexFieldMode::Descending),
                    (IndexQueryScope::Collection, IndexFieldMode::Contains),
                ]
            },
            |(_, _, modes)| modes.to_vec(),
        )
}

/// Materialize the scan result for every map container and leaf. Reference modes are selected independently, then accounting uses the unchanged public API with exact entries.
fn reference_catalog(indexes: &IndexSet, fields: &BTreeMap<String, Value>) -> IndexSet {
    fn visit(
        indexes: &IndexSet,
        reference: &mut IndexSet,
        fields: &BTreeMap<String, Value>,
        segments: &mut Vec<String>,
    ) {
        for (name, value) in fields {
            segments.push(name.clone());
            let path = FieldPath::from_segments(segments.iter().map(String::as_str)).unwrap();
            let expected = scan_modes(indexes, &group(), &path);
            assert_eq!(indexes.single_field_modes(&group(), &path), expected);
            reference.set_single_field_indexes(&group(), &path, expected);
            if let Value::Map(children) = value {
                visit(indexes, reference, children, segments);
            }
            segments.pop();
        }
    }
    let mut reference = IndexSet::default();
    for composite in indexes.composites() {
        reference.add_composite(composite.clone());
    }
    visit(indexes, &mut reference, fields, &mut Vec::new());
    reference
}

fn assert_usage(indexes: &IndexSet, fields: &BTreeMap<String, Value>) {
    let reference = reference_catalog(indexes, fields);
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        assert_eq!(
            indexes.document_index_usage_in(&document(0), fields, scope),
            reference.document_index_usage_in(&document(0), fields, scope),
            "scope={scope:?}"
        );
    }
}

fn fields(seed: i64) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "map".into(),
            Value::Map(BTreeMap::from([
                (
                    "child".into(),
                    Value::Array(vec![
                        Value::Integer(seed),
                        Value::Integer(seed),
                        Value::Integer(seed + 1),
                    ]),
                ),
                ("sibling".into(), Value::Integer(seed)),
            ])),
        ),
        ("map.child".into(), Value::String(format!("literal{seed}"))),
        ("*".into(), Value::Integer(seed)),
        (
            "tick`slash\\".into(),
            Value::Array(vec![Value::Integer(seed)]),
        ),
        (
            "chain".into(),
            Value::Map(BTreeMap::from([(
                "level".into(),
                Value::Map(BTreeMap::from([(
                    "deep".into(),
                    Value::Map(BTreeMap::from([("leaf".into(), Value::Integer(seed))])),
                )])),
            )])),
        ),
    ])
}

/// Segment names that override paths are generated from. Each entry is one segment, so a
/// dotted name such as `map.child` stays a single literal field.
const SEGMENT_NAMES: [&str; 10] = [
    "map",
    "child",
    "sibling",
    "map.child",
    "*",
    "tick`slash\\",
    "chain",
    "level",
    "deep",
    "leaf",
];

/// Builds an override path from indexes into [`SEGMENT_NAMES`]; one to four segments.
fn path_for(indexes: &[usize]) -> FieldPath {
    FieldPath::from_segments(indexes.iter().map(|&index| SEGMENT_NAMES[index])).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]
    #[test]
    fn generated_catalog_changes_preserve_complete_usage(
        operations in proptest::collection::vec(
            (
                0u8..5,
                any::<bool>(),
                proptest::collection::vec(0usize..SEGMENT_NAMES.len(), 1..=4),
                0u8..7,
            ),
            1..40,
        ),
        seed in -100i64..100,
    ) {
        let mut indexes = IndexSet::default();
        let other = CollectionId::try_new("unrelated").unwrap();
        let fields = fields(seed);
        for (operation, unrelated, segments, mode) in operations {
            let collection = if unrelated { &other } else { &group() };
            let path = path_for(&segments);
            match operation {
                0 => indexes.set_default_single_field_indexes(collection, modes(mode)),
                1 | 2 => indexes.set_single_field_indexes(collection, &path, modes(mode)),
                3 => { indexes.clear_single_field_override(collection, &path); },
                _ => {
                    indexes = IndexSet::default();
                    indexes.set_single_field_indexes(collection, &path, modes(mode));
                }
            }
            assert_usage(&indexes, &fields);
        }
    }
}

/// An override on the top of a four-level chain must reach the leaf through every
/// intermediate level, not only through the direct parent.
#[test]
fn grandparent_override_is_inherited_through_every_intermediate_level() {
    let fields = fields(3);
    let mut indexes = IndexSet::default();
    indexes.set_single_field_indexes(&group(), &field(&["chain"]), modes(3));
    for depth in [2usize, 3, 4] {
        let segments = ["chain", "level", "deep", "leaf"];
        let path = field(&segments[..depth]);
        assert_eq!(indexes.single_field_modes(&group(), &path), modes(3));
        assert_eq!(
            indexes.single_field_modes(&group(), &path),
            scan_modes(&indexes, &group(), &path)
        );
    }
    assert_usage(&indexes, &fields);
}

#[test]
fn inherited_override_refusal_boundaries_match_scan_in_both_profiles() {
    for count in [19_999usize, 20_000] {
        let fields = BTreeMap::from([(
            "map".into(),
            Value::Map(BTreeMap::from([(
                "child".into(),
                Value::Array(
                    (0..count)
                        .map(|n| Value::Integer(i64::try_from(n).unwrap()))
                        .collect(),
                ),
            )])),
        )]);
        let mut indexes = IndexSet::default();
        indexes.set_default_single_field_indexes(&group(), vec![]);
        indexes.set_single_field_indexes(&group(), &field(&["map"]), modes(3));
        indexes.set_single_field_indexes(
            &group(),
            &field(&["map", "child"]),
            vec![
                (IndexQueryScope::Collection, IndexFieldMode::Contains),
                (IndexQueryScope::Collection, IndexFieldMode::Ascending),
                (IndexQueryScope::Collection, IndexFieldMode::Descending),
            ],
        );
        assert_usage(&indexes, &fields);
        let result = indexes.document_index_usage(&document(0), &fields);
        assert_eq!(result.is_err(), count == 20_000);
        if let Err(error) = result {
            assert!(error.to_string().contains("too many index entries"));
        }
        assert!(indexes
            .document_index_usage_in(&document(0), &fields, LimitScope::OfficialEmulator)
            .is_ok());
    }
}

#[test]
fn inherited_override_entry_bytes_refusal_matches_scan() {
    let document = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        &format!(
            "{}/{}/items/{}",
            "x".repeat(1_000),
            "y".repeat(1_000),
            "z".repeat(1_000)
        ),
    )
    .unwrap();
    let fields = BTreeMap::from([(
        "map".into(),
        Value::Map(BTreeMap::from([(
            "child".into(),
            Value::String("v".repeat(1_500)),
        )])),
    )]);
    for disabled in [false, true] {
        let mut indexes = IndexSet::default();
        indexes.set_single_field_indexes(
            &group(),
            &field(&["map"]),
            if disabled { vec![] } else { modes(1) },
        );
        let reference = reference_catalog(&indexes, &fields);
        for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
            let actual = indexes.document_index_usage_in(&document, &fields, scope);
            assert_eq!(
                actual,
                reference.document_index_usage_in(&document, &fields, scope)
            );
            assert_eq!(
                actual.is_err(),
                !disabled && scope == LimitScope::Production
            );
            if let Err(error) = actual {
                assert!(error.to_string().contains("Index entry is too large."));
            }
        }
    }
}

fn write(fields: BTreeMap<String, Value>, index: usize) -> Write {
    Write {
        op: WriteOp::Set {
            path: document(index),
            fields,
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

#[test]
fn catalog_replacement_changes_the_next_commit_like_the_scan() {
    let fields = BTreeMap::from([(
        "map".into(),
        Value::Map(BTreeMap::from([(
            "child".into(),
            Value::Array((0..20_001).map(Value::Integer).collect()),
        )])),
    )]);
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut state = FirestoreState::with_limit_scope(scope);
        let mut reference = FirestoreState::with_limit_scope(scope);
        for (step, disabled) in [true, false, true].into_iter().enumerate() {
            let mut indexes = IndexSet::default();
            if disabled {
                indexes.set_single_field_indexes(&group(), &field(&["map"]), vec![]);
            }
            reference.set_index_catalog(reference_catalog(&indexes, &fields));
            state.set_index_catalog(indexes);
            let writes = [write(fields.clone(), 0)];
            let now = LogicalInstant::from_unix_seconds(i64::try_from(step).unwrap());
            let actual = state.commit(&writes, None, now);
            let expected = reference.commit(&writes, None, now);
            assert_eq!(actual, expected);
            assert_eq!(
                actual.is_err(),
                !disabled && scope == LimitScope::Production
            );
        }
    }
}

#[test]
fn seeded_pairwise_override_cases_match_scan() {
    for row in PICT_CASES.trim().lines().skip(1) {
        let cells: Vec<_> = row.split_whitespace().collect();
        assert_eq!(cells.len(), 5);
        let path = match cells[2] {
            "nested" => field(&["map", "child"]),
            "dotted" => field(&["map.child"]),
            "star" => field(&["*"]),
            "escaped" => field(&["tick`slash\\"]),
            _ => panic!("unknown shape"),
        };
        let mode = match cells[1] {
            "empty" => 0,
            "ascending" => 1,
            "descending" => 2,
            "contains" => 3,
            "group" => 4,
            "mixed" => 5,
            _ => panic!("unknown mode"),
        };
        let mut indexes = IndexSet::default();
        match cells[0] {
            "builtin" => {}
            "wildcard" => indexes.set_default_single_field_indexes(&group(), modes(mode)),
            "parent" => {
                indexes.set_default_single_field_indexes(&group(), modes((mode + 1) % 7));
                indexes.set_single_field_indexes(&group(), &field(&["map"]), modes(mode));
            }
            "exact" => {
                indexes.set_default_single_field_indexes(&group(), modes((mode + 1) % 7));
                indexes.set_single_field_indexes(&group(), &path, modes(mode));
            }
            _ => panic!("unknown specificity"),
        }
        match cells[4] {
            "retain" => {}
            "clear" => {
                indexes.clear_single_field_override(&group(), &path);
            }
            "replace" => indexes.set_single_field_indexes(&group(), &path, modes((mode + 1) % 7)),
            _ => panic!("unknown operation"),
        }
        let scope = match cells[3] {
            "production" => LimitScope::Production,
            "emulator" => LimitScope::OfficialEmulator,
            _ => panic!("unknown profile"),
        };
        let fields = fields(7);
        let reference = reference_catalog(&indexes, &fields);
        assert_eq!(
            indexes.document_index_usage_in(&document(0), &fields, scope),
            reference.document_index_usage_in(&document(0), &fields, scope),
            "{row}"
        );
    }
}

/// Every map container and leaf path in the document, in visit order.
fn document_field_paths(fields: &BTreeMap<String, Value>) -> Vec<FieldPath> {
    fn visit(
        fields: &BTreeMap<String, Value>,
        segments: &mut Vec<String>,
        out: &mut Vec<FieldPath>,
    ) {
        for (name, value) in fields {
            segments.push(name.clone());
            out.push(FieldPath::from_segments(segments.iter().map(String::as_str)).unwrap());
            if let Value::Map(children) = value {
                visit(children, segments, out);
            }
            segments.pop();
        }
    }
    let mut out = Vec::new();
    visit(fields, &mut Vec::new(), &mut out);
    out
}

const SAMPLES: usize = 7;
const SELECTION_ITERATIONS: u32 = 20;

/// The original full-scan selection for each path.
fn scan_selection(indexes: &IndexSet, paths: &[FieldPath]) -> Vec<Modes> {
    paths
        .iter()
        .map(|path| scan_modes(indexes, &group(), path))
        .collect()
}

/// The current lookup, which walks up from the exact path to the first override.
fn lookup_selection(indexes: &IndexSet, paths: &[FieldPath]) -> Vec<Modes> {
    paths
        .iter()
        .map(|path| indexes.single_field_modes(&group(), path))
        .collect()
}

fn scaling_catalog(count: usize, same_group: bool) -> IndexSet {
    let mut indexes = IndexSet::default();
    for n in 0..count {
        let collection = if same_group {
            group()
        } else {
            CollectionId::try_new(format!("other{n}")).unwrap()
        };
        indexes.set_single_field_indexes(&collection, &field(&[&format!("unrelated{n}")]), vec![]);
    }
    indexes
}

/// Times the old full scan oracle and the current lookup over the same catalog and paths.
fn report_selection_timing(
    indexes: &IndexSet,
    fields: &BTreeMap<String, Value>,
    count: usize,
    same_group: bool,
) {
    let selection_paths = document_field_paths(fields);
    let expected_selection = scan_selection(indexes, &selection_paths);
    assert_eq!(
        lookup_selection(indexes, &selection_paths),
        expected_selection
    );
    let mut scan_samples = Vec::new();
    let mut lookup_samples = Vec::new();
    let mut scan_checksum = 0usize;
    let mut lookup_checksum = 0usize;
    for sample in 0..=SAMPLES {
        let start = Instant::now();
        for _ in 0..SELECTION_ITERATIONS {
            scan_checksum += black_box(scan_selection(
                black_box(indexes),
                black_box(&selection_paths),
            ))
            .len();
        }
        let scan_ns = start.elapsed().as_nanos() / u128::from(SELECTION_ITERATIONS);
        let start = Instant::now();
        for _ in 0..SELECTION_ITERATIONS {
            lookup_checksum += black_box(lookup_selection(
                black_box(indexes),
                black_box(&selection_paths),
            ))
            .len();
        }
        let lookup_ns = start.elapsed().as_nanos() / u128::from(SELECTION_ITERATIONS);
        if sample > 0 {
            scan_samples.push(scan_ns);
            lookup_samples.push(lookup_ns);
        }
    }
    // The loop above runs one warm-up sample plus SAMPLES measured samples.
    let expected_checksum = selection_paths.len() * SELECTION_ITERATIONS as usize * (SAMPLES + 1);
    assert_eq!(scan_checksum, expected_checksum);
    assert_eq!(lookup_checksum, expected_checksum);
    scan_samples.sort_unstable();
    lookup_samples.sort_unstable();
    println!(
        "selection catalog={count} same_group={same_group} paths={} scan_oracle_ns={} lookup_ns={} scan_samples={scan_samples:?} lookup_samples={lookup_samples:?}",
        selection_paths.len(),
        scan_samples[SAMPLES / 2],
        lookup_samples[SAMPLES / 2]
    );
}

/// Run explicitly in release mode. Fixture construction is outside timed sections.
#[test]
#[ignore = "release measurement; run alone with --release --ignored --nocapture"]
fn release_catalog_scaling() {
    const USAGE_ITERATIONS: u32 = 100;
    assert!(
        !black_box(cfg!(debug_assertions)),
        "measurement requires --release"
    );
    let fields: BTreeMap<_, _> = (0..100)
        .map(|n| (format!("field{n}"), Value::Integer(n)))
        .collect();
    let writes: Vec<_> = (0..500).map(|n| write(fields.clone(), n)).collect();
    let document = document(0);
    for same_group in [false, true] {
        for count in [0, 50, 100, 200, 1_024] {
            let indexes = scaling_catalog(count, same_group);
            report_selection_timing(&indexes, &fields, count, same_group);
            for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
                let expected = IndexSet::default()
                    .document_index_usage_in(&document, &fields, scope)
                    .unwrap();
                assert_eq!(
                    indexes
                        .document_index_usage_in(&document, &fields, scope)
                        .unwrap(),
                    expected
                );
                let mut usage_samples = Vec::new();
                let mut commit_samples = Vec::new();
                for sample in 0..=SAMPLES {
                    let start = Instant::now();
                    for _ in 0..USAGE_ITERATIONS {
                        let usage = black_box(
                            indexes
                                .document_index_usage_in(
                                    black_box(&document),
                                    black_box(&fields),
                                    scope,
                                )
                                .unwrap(),
                        );
                        assert_eq!(usage, expected);
                    }
                    let usage_ns = start.elapsed().as_nanos() / u128::from(USAGE_ITERATIONS);
                    let mut state = FirestoreState::with_limit_scope(scope);
                    state.set_index_catalog(indexes.clone());
                    let start = Instant::now();
                    let result = black_box(
                        state
                            .commit(black_box(&writes), None, LogicalInstant::UNIX_EPOCH)
                            .unwrap(),
                    );
                    let commit_ns = start.elapsed().as_nanos();
                    assert_eq!(result.write_results.len(), 500);
                    if sample > 0 {
                        usage_samples.push(usage_ns);
                        commit_samples.push(commit_ns);
                    }
                }
                usage_samples.sort_unstable();
                commit_samples.sort_unstable();
                println!(
                    "catalog={count} same_group={same_group} scope={scope:?} usage_ns={} commit_500_ns={} usage_samples={usage_samples:?} commit_samples={commit_samples:?} usage={expected:?}",
                    usage_samples[SAMPLES / 2],
                    commit_samples[SAMPLES / 2]
                );
            }
        }
    }
}

// PICT pairwise coverage with mandatory default, explicit-empty, quoted/group, wildcard,
// and replacement seeds. The generated table is retained to make every replay reproducible.
const PICT_CASES: &str = "
Specificity	Mode	Shape	Profile	Operation
builtin	ascending	nested	production	retain
exact	empty	nested	production	retain
parent	group	dotted	emulator	clear
wildcard	mixed	star	production	replace
exact	contains	escaped	emulator	replace
parent	group	nested	production	retain
parent	contains	star	production	retain
builtin	mixed	star	emulator	clear
parent	descending	escaped	production	replace
parent	ascending	escaped	emulator	clear
exact	descending	star	emulator	clear
parent	empty	dotted	production	clear
exact	group	dotted	emulator	replace
wildcard	ascending	dotted	emulator	retain
builtin	descending	dotted	production	retain
wildcard	descending	nested	emulator	replace
parent	mixed	nested	emulator	clear
exact	mixed	dotted	emulator	retain
builtin	empty	star	emulator	replace
builtin	mixed	escaped	emulator	retain
exact	ascending	star	emulator	replace
builtin	group	escaped	production	retain
wildcard	contains	nested	production	clear
wildcard	group	star	production	clear
wildcard	empty	escaped	production	retain
builtin	contains	dotted	production	retain
";
