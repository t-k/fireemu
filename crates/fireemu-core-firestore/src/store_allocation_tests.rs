//! Actual requested heap bytes retained by the store, decomposed by ownership teardown.
//! Helper buffers and formatting stay outside measured scopes. These are allocator-request
//! bytes, including container capacity, rather than RSS or the logical history charges. The peak reflects this test allocator,
//! including its allocate/copy/free realloc, rather than the production System allocator.

use super::*;
use allocation_counter::{measure, AllocationInfo};
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use proptest::prelude::*;
use std::hint::black_box;

const BATCH_SIZE: usize = 500;
const FIELD_COUNT: usize = 5;

#[derive(Debug)]
struct Component {
    name: &'static str,
    bytes: u64,
    blocks: u64,
}

#[derive(Debug)]
struct AllocationReport {
    documents: usize,
    payload_bytes: usize,
    depth: usize,
    setup: AllocationInfo,
    shared_paths: usize,
    components: Vec<Component>,
}

fn fixture(
    documents: usize,
    payload_bytes: usize,
    depth: usize,
) -> (FirestoreState, AllocationInfo) {
    let mut retained = None;
    let setup = measure(|| {
        let mut state = FirestoreState::new();
        let project = ProjectId::try_new("demo-app").unwrap();
        let database = DatabaseId::default_database();
        let prefix = "parents/p/".repeat(depth - 1);
        for start in (0..documents).step_by(BATCH_SIZE) {
            let writes: Vec<_> = (start..documents.min(start + BATCH_SIZE))
                .map(|index| {
                    let index_value = i64::try_from(index).unwrap();
                    Write {
                        op: WriteOp::Set {
                            path: DocumentPath::parse(
                                &project,
                                &database,
                                &format!("{prefix}items/{index:09}"),
                            )
                            .unwrap(),
                            fields: BTreeMap::from([
                                ("i".into(), Value::Integer(index_value)),
                                ("bucket".into(), Value::Integer(index_value % 100)),
                                ("score".into(), Value::Integer(index_value)),
                                ("owner".into(), Value::String("u".into())),
                                ("payload".into(), Value::String("x".repeat(payload_bytes))),
                            ]),
                            update_mask: None,
                        },
                        precondition: None,
                        transforms: Vec::new(),
                    }
                })
                .collect();
            // The request and its event references are released inside this scope.
            drop(
                state
                    .commit(
                        &writes,
                        None,
                        LogicalInstant::from_unix_seconds(1_788_000_000),
                    )
                    .unwrap(),
            );
        }
        retained = Some(black_box(state));
    });
    (retained.unwrap(), setup)
}

fn release(name: &'static str, run: impl FnOnce()) -> Component {
    let info = measure(run);
    assert_eq!(info.bytes_total, 0, "{name} allocated during release");
    assert_eq!(info.count_total, 0, "{name} allocated during release");
    Component {
        name,
        bytes: u64::try_from(-info.bytes_current).unwrap(),
        blocks: u64::try_from(-info.count_current).unwrap(),
    }
}

fn collect_trie_paths(trie: &ListingTrie, paths: &mut Vec<Arc<DocumentPath>>) {
    for collection in trie.collections.values() {
        for node in collection.documents.values() {
            paths.extend(node.retained_here.iter().map(Arc::clone));
            paths.extend(node.representative.iter().map(Arc::clone));
            collect_trie_paths(&node.children, paths);
        }
    }
}

fn allocation_report(documents: usize, payload_bytes: usize, depth: usize) -> AllocationReport {
    let (mut state, setup) = fixture(documents, payload_bytes, depth);
    assert_eq!(state.history.len(), documents);
    assert_eq!(state.retained_versions(), documents);

    // Pin actual allocations by identity, not semantic path equality. One allocation
    // referenced by several maps is charged only after its last pin is released.
    let mut path_pins = Vec::new();
    for scope in [
        &state.direct_collection_paths,
        &state.live_direct_collection_paths,
    ] {
        for paths in scope.values() {
            path_pins.extend(paths.iter().map(Arc::clone));
        }
    }
    for scope in [
        &state.collection_group_paths,
        &state.live_collection_group_paths,
    ] {
        for paths in scope.values() {
            path_pins.extend(paths.iter().map(Arc::clone));
        }
    }
    path_pins.extend(state.live_paths.iter().map(Arc::clone));
    collect_trie_paths(&state.listing_trie, &mut path_pins);
    path_pins.sort_unstable_by_key(|path| Arc::as_ptr(path) as usize);
    path_pins.dedup_by(|left, right| Arc::ptr_eq(left, right));
    let shared_paths = path_pins.len();
    let mut document_pins: Vec<_> = state
        .history
        .values()
        .flat_map(|versions| {
            versions
                .iter()
                .filter_map(|(_, document)| document.as_ref())
        })
        .map(|document| Some(Arc::clone(document)))
        .collect();
    let mut document_paths = Vec::with_capacity(documents);
    let mut field_maps = Vec::with_capacity(documents);
    let mut field_names = Vec::with_capacity(documents * FIELD_COUNT);
    let mut field_values = Vec::with_capacity(documents * FIELD_COUNT);
    let mut components = Vec::with_capacity(16);

    components.push(release("history_keys_and_versions", || {
        drop(std::mem::take(&mut state.history));
    }));
    components.push(release("retained_direct_collection_nodes", || {
        drop(std::mem::take(&mut state.direct_collection_paths));
    }));
    components.push(release("retained_collection_group_nodes", || {
        drop(std::mem::take(&mut state.collection_group_paths));
    }));
    components.push(release("live_direct_collection_nodes", || {
        drop(std::mem::take(&mut state.live_direct_collection_paths));
    }));
    components.push(release("live_collection_group_nodes", || {
        drop(std::mem::take(&mut state.live_collection_group_paths));
    }));
    components.push(release("live_path_nodes", || {
        drop(std::mem::take(&mut state.live_paths));
    }));
    components.push(release("listing_trie_nodes_and_keys", || {
        drop(std::mem::take(&mut state.listing_trie));
    }));
    components.push(release("commit_times", || {
        drop(std::mem::take(&mut state.commit_times));
    }));
    components.push(release("compactable_paths", || {
        drop(std::mem::take(&mut state.compactable));
    }));
    components.push(release("shared_path_allocations", || {
        for path in path_pins.drain(..) {
            drop(path);
        }
    }));
    for pin in &document_pins {
        assert_eq!(Arc::strong_count(pin.as_ref().unwrap()), 1);
    }
    components.push(release("document_arc_blocks", || {
        for pin in &mut document_pins {
            let document = Arc::try_unwrap(pin.take().unwrap()).unwrap();
            document_paths.push(document.path);
            field_maps.push(document.fields);
        }
    }));
    components.push(release("document_paths", || {
        for path in document_paths.drain(..) {
            drop(path);
        }
    }));
    components.push(release("field_tree_nodes", || {
        for fields in field_maps.drain(..) {
            for (name, value) in fields {
                field_names.push(name);
                field_values.push(value);
            }
        }
    }));
    components.push(release("field_name_strings", || {
        for name in field_names.drain(..) {
            drop(name);
        }
    }));
    components.push(release("field_values", || {
        for value in field_values.drain(..) {
            drop(value);
        }
    }));
    components.push(release("catalog_and_other_roots", || drop(state)));

    assert_eq!(
        components
            .iter()
            .map(|component| component.bytes)
            .sum::<u64>(),
        u64::try_from(setup.bytes_current).unwrap(),
        "unattributed or multiply attributed retained bytes"
    );
    assert_eq!(
        components
            .iter()
            .map(|component| component.blocks)
            .sum::<u64>(),
        u64::try_from(setup.count_current).unwrap(),
        "unattributed or multiply attributed retained blocks"
    );
    // Independently check whole-state teardown, without any helper references.
    let (whole, whole_setup) = fixture(documents, payload_bytes, depth);
    let whole_release = release("whole_store", || drop(whole));
    assert_eq!(whole_setup.bytes_current, setup.bytes_current);
    assert_eq!(whole_setup.count_current, setup.count_current);
    assert_eq!(
        whole_release.bytes,
        u64::try_from(setup.bytes_current).unwrap()
    );
    assert_eq!(
        whole_release.blocks,
        u64::try_from(setup.count_current).unwrap()
    );

    AllocationReport {
        documents,
        payload_bytes,
        depth,
        setup,
        shared_paths,
        components,
    }
}

fn print_report(report: &AllocationReport) {
    println!(
        "allocation_report documents={} payload_bytes={} depth={} batch_size={} retained_bytes={} retained_blocks={} allocated_bytes={} instrumented_peak_bytes={} shared_paths={}",
        report.documents, report.payload_bytes, report.depth, BATCH_SIZE,
        report.setup.bytes_current, report.setup.count_current, report.setup.bytes_total,
        report.setup.bytes_max, report.shared_paths,
    );
    for component in &report.components {
        println!(
            "allocation_component name={} bytes={} blocks={}",
            component.name, component.bytes, component.blocks,
        );
    }
}

#[test]
fn allocator_controls_count_retention_and_release() {
    assert_eq!(measure(|| {}), AllocationInfo::default());
    let mut held = None;
    let info = measure(|| held = Some(black_box(vec![7_u8; 4096])));
    assert_eq!(info.bytes_total, 4096);
    assert_eq!(info.bytes_current, 4096);
    assert_eq!(info.count_current, 1);
    let released = release("known_vector", || drop(held.take()));
    assert_eq!(released.bytes, 4096);
    assert_eq!(released.blocks, 1);
    assert_eq!(measure(|| {}), AllocationInfo::default());
}

#[test]
fn allocator_control_excludes_other_threads() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let start = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let finish = Arc::new(AtomicBool::new(false));
    let worker = {
        let start = Arc::clone(&start);
        let ready = Arc::clone(&ready);
        let finish = Arc::clone(&finish);
        std::thread::spawn(move || {
            while !start.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let held = black_box(vec![3_u8; 64 * 1024]);
            ready.store(true, Ordering::Release);
            while !finish.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            drop(held);
        })
    };
    let info = measure(|| {
        start.store(true, Ordering::Release);
        while !ready.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        drop(black_box(vec![5_u8; 123]));
    });
    finish.store(true, Ordering::Release);
    worker.join().unwrap();
    assert_eq!(info.bytes_total, 123);
    assert_eq!(info.bytes_max, 123);
    assert_eq!(info.bytes_current, 0);
}

#[test]
fn retained_allocation_breakdown() {
    let reports = [0, 1000, 2000].map(|documents| allocation_report(documents, 16, 1));
    for report in &reports {
        print_report(&report);
    }
    for report in &reports {
        // The measured baseline was about 2057 bytes/document with three path graphs.
        // Sharing them should save 334 bytes/document. Leave container-layout headroom
        // while rejecting restoration of either redundant whole path graph.
        let maximum = report.documents * 1800 + 4096;
        assert!(
            report.setup.bytes_current <= i64::try_from(maximum).unwrap(),
            "retained bytes {} exceed the measured allocation budget {maximum}",
            report.setup.bytes_current,
        );
    }
}

#[test]
#[ignore = "exploratory allocation report; the short regression runs in the pr profile"]
fn retained_allocation_large_corpus() {
    for payload in [16, 1024] {
        print_report(&allocation_report(10_000, payload, 1));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn ownership_teardown_conserves_bytes(
        documents in 0_usize..65,
        payload in 0_usize..65,
        depth in 1_usize..4,
    ) {
        let report = allocation_report(documents, payload, depth);
        prop_assert_eq!(report.documents, documents);
        prop_assert!(report.setup.bytes_current >= 0);
    }
}
