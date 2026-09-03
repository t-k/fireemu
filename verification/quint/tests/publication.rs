//! Atomic Quint evidence publication contracts.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fireemu_verification_quint::publication::publish_evidence;

const MODELS: [&str; 14] = [
    "AtomicCommitOutbox",
    "AtomicExportPublication",
    "AuthTotp",
    "AwaitIdle",
    "CompatibilitySelection",
    "EventDelivery",
    "FirestoreListenRefresh",
    "RegexAuthorization",
    "RegexEvaluationCache",
    "RegexLinearRepeat",
    "RulesetActivation",
    "SessionEpoch",
    "StorageGeneration",
    "TransactionConditionalLock",
];

#[test]
fn publication_replaces_one_complete_snapshot_and_preserves_the_source() {
    let temporary = OwnedTestDirectory::create("success");
    let source = temporary.path.join("source");
    let target = temporary.path.join("target");
    write_complete_set(&source, "new");
    write_complete_set(&target, "old");

    publish_evidence(&source, &target).expect("complete publication must succeed");

    assert_complete_set(&source, "new");
    assert_complete_set(&target, "new");
}

#[test]
fn incomplete_publication_leaves_the_complete_target_unchanged() {
    let temporary = OwnedTestDirectory::create("incomplete");
    let source = temporary.path.join("source");
    let target = temporary.path.join("target");
    write_complete_set(&source, "new");
    write_complete_set(&target, "old");
    fs::remove_file(source.join("EventDelivery.json")).expect("remove source evidence");

    let error = publish_evidence(&source, &target).expect_err("incomplete source must fail");

    assert!(error.contains("incomplete evidence source"));
    assert_complete_set(&target, "old");
}

fn write_complete_set(directory: &Path, marker: &str) {
    fs::create_dir(directory).expect("create evidence directory");
    fs::write(directory.join("cargo-authority.json"), marker).expect("write Cargo authority");
    for model in MODELS {
        fs::write(
            directory.join(format!("{model}.json")),
            format!("{marker}:{model}"),
        )
        .expect("write model evidence");
    }
}

fn assert_complete_set(directory: &Path, marker: &str) {
    assert_eq!(
        fs::read_to_string(directory.join("cargo-authority.json")).expect("read Cargo authority"),
        marker
    );
    for model in MODELS {
        assert_eq!(
            fs::read_to_string(directory.join(format!("{model}.json")))
                .expect("read model evidence"),
            format!("{marker}:{model}")
        );
    }
}

struct OwnedTestDirectory {
    path: PathBuf,
}

impl OwnedTestDirectory {
    fn create(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after the epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fireemu-quint-publication-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temporary test directory");
        Self { path }
    }
}

impl Drop for OwnedTestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
