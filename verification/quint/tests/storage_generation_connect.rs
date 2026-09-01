//! Conformance boundary tests for production storage generation allocation and restore.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::storage_generation::{
    ProjectionFault, StorageGenerationConnectDriver, StorageGenerationDriver,
    StorageGenerationState, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/StorageGeneration.qnt")
}

fn empty_state() -> StorageGenerationState {
    StorageGenerationState {
        exists: false,
        generation: 0,
        metageneration: 0,
        high_water: 0,
        issued: BTreeSet::new(),
    }
}

fn initialized_driver() -> StorageGenerationDriver {
    let mut driver = StorageGenerationDriver::new();
    driver.init().expect("initialize storage generation driver");
    driver
}

#[test]
fn real_store_preserves_generation_and_metageneration_contracts() {
    let mut driver = initialized_driver();
    assert_eq!(driver.project().expect("empty projection"), empty_state());

    driver.put_data().expect("first object write");
    assert_eq!(
        driver.project().expect("first write projection"),
        StorageGenerationState {
            exists: true,
            generation: 1,
            metageneration: 1,
            high_water: 1,
            issued: BTreeSet::from([1]),
        }
    );

    driver.patch_metadata().expect("metadata update");
    let patched = driver.project().expect("metadata projection");
    assert_eq!((patched.generation, patched.metageneration), (1, 2));
    assert_eq!(patched.high_water, 1);
    assert_eq!(patched.issued, BTreeSet::from([1]));

    driver.delete().expect("delete current object");
    driver.put_data().expect("write after delete");
    let replaced = driver.project().expect("replacement projection");
    assert_eq!((replaced.generation, replaced.metageneration), (2, 1));
    assert_eq!(replaced.issued, BTreeSet::from([1, 2]));
}

#[test]
fn older_snapshot_restore_does_not_reuse_a_generation() {
    let mut driver = initialized_driver();
    driver.put_data().expect("captured write");
    driver.capture_snapshot().expect("capture generation one");
    driver.put_data().expect("later write");
    driver
        .restore_snapshot()
        .expect("restore older visible object");
    let restored = driver.project().expect("restored projection");
    assert_eq!((restored.generation, restored.high_water), (1, 2));
    assert_eq!(restored.issued, BTreeSet::from([1, 2]));

    driver.put_data().expect("write after restore");
    assert_eq!(driver.project().expect("post-restore write").generation, 3);
}

#[test]
fn imported_high_water_survives_a_pre_import_snapshot_restore() {
    let mut driver = initialized_driver();
    driver.capture_snapshot().expect("capture empty store");
    driver.import_data().expect("install generation two");
    let imported = driver.project().expect("import projection");
    assert_eq!((imported.generation, imported.metageneration), (2, 2));
    assert_eq!(imported.high_water, 2);

    driver
        .restore_snapshot()
        .expect("restore pre-import snapshot");
    let restored = driver.project().expect("post-import restore");
    assert!(!restored.exists);
    assert_eq!(restored.high_water, 2);
    assert_eq!(restored.issued, BTreeSet::from([2]));

    driver.put_data().expect("write after imported high-water");
    let written = driver.project().expect("post-import write");
    assert_eq!(written.generation, 3);
    assert_eq!(written.issued, BTreeSet::from([2, 3]));
}

#[test]
fn disabled_actions_preserve_the_production_projection() {
    let mut driver = initialized_driver();
    for action in [
        StorageGenerationDriver::patch_metadata,
        StorageGenerationDriver::delete,
        StorageGenerationDriver::restore_snapshot,
    ] {
        let before = driver.project().expect("projection before rejection");
        assert!(action(&mut driver).is_err());
        assert_eq!(
            driver.project().expect("projection after rejection"),
            before
        );
    }
}

#[test]
fn modeled_actions_include_import_high_water() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "PutData",
            "PatchMetadata",
            "Delete",
            "CaptureSnapshot",
            "RestoreSnapshot",
            "ImportData",
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 5] = [
    ProjectionFault::Exists,
    ProjectionFault::Generation,
    ProjectionFault::Metageneration,
    ProjectionFault::HighWater,
    ProjectionFault::Issued,
];

#[test]
fn projection_fault_changes_exactly_one_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        driver.put_data().expect("fault fixture write");
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("exists", baseline.exists != perturbed.exists),
            ("generation", baseline.generation != perturbed.generation),
            (
                "metageneration",
                baseline.metageneration != perturbed.metageneration,
            ),
            ("highWater", baseline.high_water != perturbed.high_water),
            ("issued", baseline.issued != perturbed.issued),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 5] = [
    "write",
    "metadata",
    "deleteThenPut",
    "snapshotRestore",
    "importRestore",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = StorageGenerationDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("StorageGeneration scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("StorageGenerationScenarios".to_owned()),
                test: scenario.to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        run_test(driver, config)
            .unwrap_or_else(|error| panic!("scenario {scenario} failed: {error:#}"));
    }
    assert_eq!(
        recorded.lock().expect("action recorder lock").clone(),
        MODELED_ACTIONS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn every_projection_field_detects_drift() {
    for fault in PROJECTION_FAULTS {
        let driver = StorageGenerationDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("StorageGeneration projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("StorageGenerationScenarios".to_owned()),
                test: "write".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str, driver: StorageGenerationConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("StorageGeneration generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("StorageGenerationConnect".to_owned()),
            init: Some("init".to_owned()),
            step: Some("step".to_owned()),
            max_samples: Some(100),
            max_steps: Some(20),
            seed: seed.to_owned(),
        },
    };
    run_test(driver, config).map_err(|error| format!("seed {seed}: {error:#}"))
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_the_real_store() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, StorageGenerationConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
