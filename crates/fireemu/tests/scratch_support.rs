//! The test scratch helpers in `tests/scratch`: what they remove, and what they leave alone.

mod scratch;

use proptest::prelude::*;
use scratch::{hub_locator, locator_names_pid, remove_killed_daemon_locator, remove_tree, Scratch};

#[test]
fn a_scratch_directory_is_removed_when_it_is_dropped() {
    let path;
    {
        let dir = Scratch::new("scratch-support", "dropped");
        path = dir.to_path_buf();
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/file"), "x").unwrap();
        assert!(path.is_dir());
    }
    assert!(!path.exists());
}

#[test]
fn a_scratch_directory_is_removed_when_the_test_panics() {
    let path = std::sync::Mutex::new(None);
    let outcome = std::panic::catch_unwind(|| {
        let dir = Scratch::new("scratch-support", "panicked");
        *path.lock().unwrap() = Some(dir.to_path_buf());
        panic!("an assertion failed before the last line");
    });
    assert!(outcome.is_err());
    let path = path.into_inner().unwrap().unwrap();
    assert!(!path.exists());
}

#[test]
fn a_new_scratch_directory_starts_empty() {
    let first = Scratch::new("scratch-support", "reused");
    std::fs::write(first.join("left-over"), "x").unwrap();
    std::mem::forget(first);
    let second = Scratch::new("scratch-support", "reused");
    assert_eq!(std::fs::read_dir(&*second).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn read_only_directories_inside_are_removed_too() {
    use std::os::unix::fs::PermissionsExt as _;

    let path;
    {
        let dir = Scratch::new("scratch-support", "read-only");
        path = dir.to_path_buf();
        let inner = dir.join("locked");
        std::fs::create_dir_all(inner.join("deeper")).unwrap();
        std::fs::write(inner.join("deeper/file"), "x").unwrap();
        std::fs::set_permissions(inner.join("deeper"), std::fs::Permissions::from_mode(0o500))
            .unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_inside_is_removed_without_touching_its_target() {
    let target = Scratch::new("scratch-support", "link-target");
    std::fs::write(target.join("kept"), "x").unwrap();
    {
        let dir = Scratch::new("scratch-support", "link-holder");
        std::os::unix::fs::symlink(&*target, dir.join("link")).unwrap();
    }
    assert!(target.join("kept").is_file());
}

#[test]
fn removing_a_missing_tree_is_a_no_op() {
    let dir = Scratch::new("scratch-support", "missing");
    let missing = dir.join("never-created");
    remove_tree(&missing);
    assert!(!missing.exists());
}

#[test]
fn a_killed_daemons_locator_is_removed_only_when_it_names_that_daemon() {
    let project = format!("demo-scratch-support-{}", std::process::id());
    let locator = hub_locator(&project);
    assert_eq!(locator.parent(), Some(std::env::temp_dir().as_path()));
    assert_eq!(
        locator.file_name().and_then(|name| name.to_str()),
        Some(format!("hub-{project}.json").as_str())
    );

    std::fs::write(&locator, r#"{"version":"x","pid":4242}"#).unwrap();
    remove_killed_daemon_locator(&project, 4243);
    assert!(locator.is_file(), "a locator of another process is kept");
    remove_killed_daemon_locator(&project, 4242);
    assert!(!locator.exists(), "the killed daemon's locator is removed");
    remove_killed_daemon_locator(&project, 4242);
}

#[test]
fn only_a_regular_locator_file_with_that_pid_counts_as_the_daemons() {
    let dir = Scratch::new("scratch-support", "locators");
    let path = dir.join("hub-demo.json");
    for (body, pid, expected) in [
        (r#"{"pid":7}"#, 7, true),
        (r#"{"pid":7}"#, 8, false),
        (r#"{"pid":"7"}"#, 7, false),
        (r#"{"pid":-7}"#, 7, false),
        (r#"{"pid":7.5}"#, 7, false),
        (r#"{"other":7}"#, 7, false),
        (r"[7]", 7, false),
        ("not json", 7, false),
        ("", 7, false),
        (r#"{"pid":4294967295}"#, u32::MAX, true),
        (r#"{"pid":4294967296}"#, 0, false),
    ] {
        std::fs::write(&path, body).unwrap();
        assert_eq!(
            locator_names_pid(&path, pid),
            expected,
            "{body} for pid {pid}"
        );
    }
    std::fs::remove_file(&path).unwrap();
    assert!(!locator_names_pid(&path, 7), "a missing file");
    std::fs::create_dir(&path).unwrap();
    assert!(!locator_names_pid(&path, 7), "a directory");
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_named_like_the_locator_is_not_the_daemons() {
    let dir = Scratch::new("scratch-support", "locator-link");
    let real = dir.join("real.json");
    std::fs::write(&real, r#"{"pid":7}"#).unwrap();
    let link = dir.join("hub-demo.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(!locator_names_pid(&link, 7));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever `pid` a locator records, it names the daemon exactly when it is that pid.
    #[test]
    fn a_locator_names_a_daemon_exactly_when_the_pids_are_equal(written in any::<u64>(), asked in any::<u32>(), same in any::<bool>()) {
        let written = if same { u64::from(asked) } else { written };
        let dir = Scratch::new("scratch-support", "locator-property");
        let path = dir.join("hub-demo.json");
        std::fs::write(&path, format!(r#"{{"version":"x","pid":{written}}}"#)).unwrap();
        prop_assert_eq!(locator_names_pid(&path, asked), written == u64::from(asked));
    }

    /// Bytes that are not a locator document never count as one, and reading them never panics.
    #[test]
    fn arbitrary_bytes_name_a_daemon_only_as_a_document_with_that_pid(body in proptest::collection::vec(any::<u8>(), 0..64), asked in any::<u32>()) {
        let dir = Scratch::new("scratch-support", "locator-bytes");
        let path = dir.join("hub-demo.json");
        std::fs::write(&path, &body).unwrap();
        let expected = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value.get("pid").and_then(serde_json::Value::as_u64))
            == Some(u64::from(asked));
        prop_assert_eq!(locator_names_pid(&path, asked), expected);
    }
}
