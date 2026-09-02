//! Atomic export publication capability tests.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use fireemu_export_publication::PublicationStage;

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use trusted_temp::TrustedTempDir;

struct TestRoot(TrustedTempDir);

impl TestRoot {
    fn new(label: &str) -> Self {
        Self(TrustedTempDir::new(&format!("publication-{label}")))
    }

    fn target(&self) -> PathBuf {
        self.0.join("export")
    }
}

fn write(path: &Path, name: &str, value: &str) {
    std::fs::write(path.join(name), value).expect("write stage marker");
}

fn create_private_dir(path: &Path) {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).expect("create private directory");
}

#[test]
fn trusted_test_root_is_owner_only_and_cleans_up_during_unwind() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut created = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let root = TrustedTempDir::new("publication-unwind");
        created = Some(root.path().to_owned());
        let mode = std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        panic!("exercise cleanup");
    }));

    assert!(panic.is_err());
    assert!(!created.unwrap().exists());
}

#[test]
fn partial_stage_is_invisible_and_drop_cleans_it() {
    let root = TestRoot::new("partial");
    let target = root.target();
    std::fs::create_dir(&target).expect("create old target");
    write(&target, "marker", "old");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("create private stage");
    let stage_path = stage.root().to_owned();
    write(stage.root(), "marker", "partial");
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "old"
    );
    drop(stage);
    assert!(!stage_path.exists());
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "old"
    );
}

#[test]
fn only_a_completed_stage_can_atomically_replace_the_target() {
    let root = TestRoot::new("publish");
    let target = root.target();
    std::fs::create_dir(&target).expect("create old target");
    write(&target, "marker", "old");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("create private stage");
    write(stage.root(), "marker", "new");
    stage.complete().publish().expect("publish completed stage");
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "new"
    );
}

#[test]
fn target_replacement_is_refused_and_attacker_tree_is_preserved() {
    let root = TestRoot::new("replace");
    let target = root.target();
    let displaced = root.0.join("displaced");
    std::fs::create_dir(&target).expect("create old target");
    write(&target, "marker", "old");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("create private stage");
    write(stage.root(), "marker", "new");
    std::fs::rename(&target, &displaced).expect("move original target");
    std::fs::create_dir(&target).expect("create attacker target");
    write(&target, "marker", "attacker");
    assert!(stage.complete().publish().is_err());
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "attacker"
    );
    assert_eq!(
        std::fs::read_to_string(displaced.join("marker")).unwrap(),
        "old"
    );
}

#[cfg(unix)]
#[test]
fn stage_is_owner_only_at_creation_time() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TestRoot::new("mode");
    let stage = PublicationStage::create(&root.target(), |_| Ok(())).expect("create private stage");
    let mode = std::fs::metadata(stage.root())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn drop_never_removes_a_replacement_at_the_stage_path() {
    let root = TestRoot::new("drop-identity");
    let stage = PublicationStage::create(&root.target(), |_| Ok(())).expect("create private stage");
    let stage_path = stage.root().to_owned();
    let moved = root.0.join("moved-stage");
    std::fs::rename(&stage_path, &moved).expect("move owned stage");
    std::fs::create_dir(&stage_path).expect("create replacement stage path");
    write(&stage_path, "attacker", "preserved");

    drop(stage);

    assert_eq!(
        std::fs::read_to_string(stage_path.join("attacker")).unwrap(),
        "preserved"
    );
}

#[test]
fn completed_stage_replacement_is_never_published() {
    let root = TestRoot::new("complete-stage-identity");
    let target = root.target();
    let moved = root.0.join("moved-stage");
    std::fs::create_dir(&target).expect("create old target");
    write(&target, "marker", "old");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("create private stage");
    let stage_path = stage.root().to_owned();
    write(stage.root(), "marker", "new");
    let complete = stage.complete();
    std::fs::rename(&stage_path, &moved).expect("move completed stage");
    std::fs::create_dir(&stage_path).expect("create replacement stage path");
    write(&stage_path, "marker", "attacker");

    let error = complete.publish().unwrap_err();

    assert!(error.contains("owned export stage changed"), "{error}");
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "old"
    );
    assert_eq!(
        std::fs::read_to_string(stage_path.join("marker")).unwrap(),
        "attacker"
    );
    assert_eq!(
        std::fs::read_to_string(moved.join("marker")).unwrap(),
        "new"
    );
}

#[cfg(unix)]
#[test]
fn other_user_writable_parent_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TestRoot::new("writable-parent");
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o777))
        .expect("make parent writable");

    let error = PublicationStage::create(&root.target(), |_| Ok(())).unwrap_err();

    assert!(error.contains("other users"), "{error}");
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))
        .expect("restore private mode");
}

#[test]
fn other_user_writable_namespace_ancestor_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TestRoot::new("writable-ancestor");
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o777))
        .expect("make ancestor writable");

    let error = PublicationStage::create(&parent.join("export"), |_| Ok(())).unwrap_err();

    assert!(error.contains("namespace ancestor"), "{error}");
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700))
        .expect("restore private mode");
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_namespace_ancestor_is_refused() {
    let root = TestRoot::new("acl-ancestor");
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    let status = std::process::Command::new("chmod")
        .args(["+a", "everyone allow add_file,delete_child"])
        .arg(&root.0)
        .status()
        .expect("run chmod");
    assert!(status.success(), "install test ACL");

    let error = PublicationStage::create(&parent.join("export"), |_| Ok(())).unwrap_err();

    assert!(error.contains("extended ACL"), "{error}");
    let _ = std::process::Command::new("chmod")
        .arg("-N")
        .arg(&root.0)
        .status();
}

#[cfg(unix)]
#[test]
fn symlinked_parent_is_refused_without_creating_a_stage() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new("parent-symlink");
    let real = root.0.join("real-parent");
    let linked = root.0.join("linked-parent");
    std::fs::create_dir(&real).expect("create real parent");
    symlink(&real, &linked).expect("create parent symlink");

    let error = PublicationStage::create(&linked.join("export"), |_| Ok(())).unwrap_err();

    assert!(error.contains("parent is a symlink"), "{error}");
    assert!(std::fs::read_dir(&real).unwrap().next().is_none());
}
