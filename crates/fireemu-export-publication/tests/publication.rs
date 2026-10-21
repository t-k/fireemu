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

/// A real macOS ACL entry on a directory (`chmod +a`), removed again on drop.
#[cfg(target_os = "macos")]
struct Acl<'a>(&'a Path);

#[cfg(target_os = "macos")]
impl<'a> Acl<'a> {
    fn install(dir: &'a Path, entry: &str) -> Self {
        let status = std::process::Command::new("chmod")
            .args(["+a", entry])
            .arg(dir)
            .status()
            .expect("run chmod");
        assert!(status.success(), "install test ACL {entry:?}");
        Self(dir)
    }
}

#[cfg(target_os = "macos")]
impl Drop for Acl<'_> {
    fn drop(&mut self) {
        let _ = std::process::Command::new("chmod")
            .arg("-N")
            .arg(self.0)
            .status();
    }
}

/// Creates a stage under `root` while `entry` is the ACL of `root` (an ancestor of the export).
#[cfg(target_os = "macos")]
fn create_stage_under_acl(label: &str, entry: &str) -> Result<(), String> {
    let root = TestRoot::new(label);
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    let _acl = Acl::install(&root.0, entry);
    PublicationStage::create(&parent.join("export"), |_| Ok(())).map(|_| ())
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_namespace_ancestor_is_refused() {
    let error =
        create_stage_under_acl("acl-ancestor", "everyone allow add_file,delete_child").unwrap_err();

    assert!(error.contains("extended ACL"), "{error}");
    // The diagnostic names the entry and a way out.
    assert!(error.contains("group:everyone allow"), "{error}");
    assert!(error.contains("delete_child"), "{error}");
    assert!(error.contains("$TMPDIR"), "{error}");
}

/// The reproduction of the macOS home directory: `group:everyone deny delete` only removes rights.
#[cfg(target_os = "macos")]
#[test]
fn a_deny_only_acl_on_an_ancestor_is_accepted() {
    create_stage_under_acl("acl-deny-delete", "everyone deny delete")
        .expect("a deny entry is safe");
}

#[cfg(target_os = "macos")]
#[test]
fn a_deny_entry_of_every_permission_is_accepted() {
    create_stage_under_acl(
        "acl-deny-everything",
        "everyone deny write,append,delete,delete_child,add_file,add_subdirectory,writeattr,writeextattr,writesecurity,chown",
    )
    .expect("a deny entry is safe");
}

#[cfg(target_os = "macos")]
#[test]
fn another_users_write_allow_on_an_ancestor_is_refused() {
    let error =
        create_stage_under_acl("acl-other-write", "nobody allow write,add_file").unwrap_err();

    assert!(error.contains("extended ACL"), "{error}");
    assert!(error.contains("nobody"), "{error}");
}

/// A read-only allow is refused too: the kernel grants rights `exacl` does not report, so an allow
/// entry of another principal is not proven harmless by the permissions that are visible.
#[cfg(target_os = "macos")]
#[test]
fn a_read_only_allow_on_an_ancestor_is_refused() {
    let error = create_stage_under_acl(
        "acl-read-only",
        "everyone allow list,search,readattr,readextattr,readsecurity",
    )
    .unwrap_err();

    assert!(error.contains("group:everyone allow"), "{error}");
}

/// A raw ACE with a `KAUTH_ACE_GENERIC_*` right, which `exacl` reports as no permissions at all and
/// the kernel expands into real ones, set through the C library from Python (the crate itself stays
/// free of unsafe code).
#[cfg(target_os = "macos")]
const RAW_ACE_SCRIPT: &str = r#"
import ctypes, ctypes.util, struct, sys, pwd
path, user, rights, kind = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), sys.argv[4]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.acl_copy_int_native.restype = ctypes.c_void_p
libc.acl_copy_int_native.argtypes = [ctypes.c_void_p]
libc.acl_set_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
libc.mbr_uid_to_uuid.argtypes = [ctypes.c_uint, ctypes.c_char * 16]
guid = (ctypes.c_char * 16)()
assert libc.mbr_uid_to_uuid(pwd.getpwnam(user).pw_uid, guid) == 0
flags = 1 if kind == "allow" else 2
ace = bytes(guid) + struct.pack("<II", flags, rights)
filesec = struct.pack("<I", 0x012CC16D) + b"\x00" * 32 + struct.pack("<II", 1, 0) + ace
buf = ctypes.create_string_buffer(filesec, len(filesec))
acl = libc.acl_copy_int_native(ctypes.cast(buf, ctypes.c_void_p))
assert acl, ctypes.get_errno()
assert libc.acl_set_file(path.encode(), 0x100, ctypes.c_void_p(acl)) == 0, ctypes.get_errno()
"#;

#[cfg(target_os = "macos")]
fn install_raw_ace(dir: &Path, user: &str, rights: u32, kind: &str) {
    let output = std::process::Command::new("python3")
        .args(["-c", RAW_ACE_SCRIPT])
        .arg(dir)
        .arg(user)
        .arg(format!("{rights:#x}"))
        .arg(kind)
        .output()
        .expect("run python3");
    assert!(
        output.status.success(),
        "install raw ACE: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `user:nobody allow GENERIC_ALL` (`KAUTH_ACE_GENERIC_ALL`, 1 << 21) on an ancestor.
#[cfg(target_os = "macos")]
#[test]
fn an_ancestor_with_a_raw_generic_allow_ace_is_refused() {
    let root = TestRoot::new("acl-generic-all");
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    install_raw_ace(&root.0, "nobody", 1 << 21, "allow");
    // The premise: `exacl` sees an allow entry with no permissions at all.
    let seen = exacl::getfacl(&root.0, None).expect("read the ACL");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].allow && seen[0].perms.is_empty(), "{seen:?}");
    let _cleanup = Acl(&root.0);

    let error = PublicationStage::create(&parent.join("export"), |_| Ok(())).unwrap_err();

    assert!(error.contains("user:nobody allow"), "{error}");
    assert!(error.contains("no permissions are visible"), "{error}");
}

/// The same for the other generic rights, and a generic deny is still only a deny.
#[cfg(target_os = "macos")]
#[test]
fn each_raw_generic_allow_ace_is_refused_and_a_raw_generic_deny_is_accepted() {
    for (name, bit) in [
        ("execute", 1u32 << 22),
        ("write", 1 << 23),
        ("read", 1 << 24),
    ] {
        let root = TestRoot::new(&format!("acl-generic-{name}"));
        let parent = root.0.join("private-parent");
        create_private_dir(&parent);
        install_raw_ace(&root.0, "nobody", bit, "allow");
        let _cleanup = Acl(&root.0);
        let error = PublicationStage::create(&parent.join("export"), |_| Ok(())).unwrap_err();
        assert!(error.contains("user:nobody allow"), "{name}: {error}");
    }
    let root = TestRoot::new("acl-generic-deny");
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    install_raw_ace(&root.0, "nobody", 1 << 23, "deny");
    let _cleanup = Acl(&root.0);
    PublicationStage::create(&parent.join("export"), |_| Ok(())).expect("a deny entry is safe");
}

/// An inheritable `deny delete` on an accepted ancestor reaches the stage: the stage's ACL is
/// cleared as it is created, so the rename that publishes it and the cleanup still work.
#[cfg(target_os = "macos")]
#[test]
fn an_inherited_deny_delete_does_not_break_the_stage_or_its_publication() {
    let root = TestRoot::new("acl-inherited-deny");
    let _acl = Acl::install(
        &root.0,
        "everyone deny delete,file_inherit,directory_inherit",
    );
    // The directories made below inherit the entry, the export parent among them.
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    create_private_dir(&parent.join("inner"));
    assert!(
        !exacl::getfacl(parent.join("inner"), None)
            .expect("read the parent ACL")
            .is_empty(),
        "the premise: the export parent inherited the entry"
    );
    let target = parent.join("inner").join("export");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("an inherited deny is safe");
    assert_eq!(
        exacl::getfacl(stage.root(), None).expect("read the stage ACL"),
        Vec::new(),
        "the stage starts with no ACL"
    );
    write(stage.root(), "marker", "exported");
    assert_eq!(
        exacl::getfacl(stage.root().join("marker"), None).expect("read the file ACL"),
        Vec::new(),
        "and so do the files made in it"
    );
    stage.complete().publish().expect("the stage is published");

    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "exported"
    );
    let leftovers: Vec<_> = std::fs::read_dir(parent.join("inner"))
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("fireemu-stage")
        })
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// How a step that depends on the machine (a disk image tool that can be busy) is attempted: a bounded
/// number of tries, with a growing wait between them. `sleep` is injected so the policy can be tested
/// without waiting.
const ENVIRONMENT_ATTEMPTS: u32 = 6;
const ENVIRONMENT_BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(250);

/// Runs `attempt` until it succeeds or `attempts` tries have failed; between two tries it waits
/// `step * (number of failures so far)`. The error is every failure message, in order, so that an
/// environment that never recovers is reported with what it said each time.
fn retry_with_backoff<T>(
    attempts: u32,
    step: std::time::Duration,
    mut sleep: impl FnMut(std::time::Duration),
    mut attempt: impl FnMut() -> Result<T, String>,
) -> Result<T, Vec<String>> {
    let mut failures = Vec::new();
    for tried in 1..=attempts {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(message) => failures.push(message),
        }
        if tried < attempts {
            sleep(step * tried);
        }
    }
    Err(failures)
}

/// A disk image mounted below `dir` (a stand-in for a USB stick, an SD card or an external drive),
/// detached on drop. `owners` is `hdiutil attach -owners`: off mounts the volume with ownership
/// ignored (`MNT_IGNORE_OWNERSHIP`), which is what exFAT and a "no ownership" external APFS volume are.
#[cfg(target_os = "macos")]
struct Volume {
    mount: PathBuf,
}

#[cfg(target_os = "macos")]
impl Volume {
    /// `None` when `hdiutil` cannot be run at all (the test then says so and passes vacuously).
    fn attach(dir: &Path, fs: &str, owners: bool) -> Option<Self> {
        use std::process::Command;

        let image = dir.join("volume.dmg");
        let mount = dir.join("volume");
        // `hdiutil` can answer "Resource busy" on a shared runner whose disk image subsystem is
        // occupied; that says nothing about the product, so the step is tried again a bounded number
        // of times, and a failure that stays is reported as an environment failure with every answer.
        let hdiutil = |what: &str, args: &[&std::ffi::OsStr], before_retry: &dyn Fn()| {
            retry_with_backoff(
                ENVIRONMENT_ATTEMPTS,
                ENVIRONMENT_BACKOFF_STEP,
                std::thread::sleep,
                || {
                    before_retry();
                    match Command::new("hdiutil").args(args).output() {
                        Ok(output) if output.status.success() => Ok(()),
                        Ok(output) => Err(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
                        Err(error) => Err(format!("cannot run hdiutil: {error}")),
                    }
                },
            )
            .map_err(|failures| {
                format!(
                    "hdiutil {what} failed {} times; this is an environment failure, not a product failure: {failures:?}",
                    failures.len()
                )
            })
        };
        if let Err(error) = Command::new("hdiutil").arg("help").output() {
            eprintln!("SKIPPED: hdiutil cannot be run ({error}); the {fs} case is not tested");
            return None;
        }
        let size = std::ffi::OsStr::new("16m");
        let create_args: Vec<&std::ffi::OsStr> = vec![
            "create".as_ref(),
            "-size".as_ref(),
            size,
            "-fs".as_ref(),
            fs.as_ref(),
            "-volname".as_ref(),
            "FIREEMU".as_ref(),
            image.as_os_str(),
        ];
        // A failed create can leave a half-written image behind, which the next try would refuse.
        if let Err(error) = hdiutil("create", &create_args, &|| {
            let _ = std::fs::remove_file(&image);
        }) {
            panic!("{error}");
        }
        create_private_dir(&mount);
        let attach_args: Vec<&std::ffi::OsStr> = vec![
            "attach".as_ref(),
            "-nobrowse".as_ref(),
            "-owners".as_ref(),
            if owners { "on" } else { "off" }.as_ref(),
            "-mountpoint".as_ref(),
            mount.as_os_str(),
            image.as_os_str(),
        ];
        if let Err(error) = hdiutil("attach", &attach_args, &|| {}) {
            panic!("{error}");
        }
        Some(Self { mount })
    }
}

#[cfg(target_os = "macos")]
impl Drop for Volume {
    fn drop(&mut self) {
        // A detach can meet the same busy subsystem as the attach did; it is tried again a bounded
        // number of times, and a mount that stays is left to the runner (the image is in the test's
        // own temporary directory).
        let _ = retry_with_backoff(
            ENVIRONMENT_ATTEMPTS,
            ENVIRONMENT_BACKOFF_STEP,
            std::thread::sleep,
            || {
                let output = std::process::Command::new("hdiutil")
                    .args(["detach", "-force"])
                    .arg(&self.mount)
                    .output()
                    .map_err(|error| error.to_string())?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
                }
            },
        );
    }
}

/// An export onto a volume that ignores ownership is refused before anything is written: the owner
/// and the mode of its directories say nothing about who can change them.
#[cfg(target_os = "macos")]
fn assert_refused_for_ignoring_ownership(fs: &str) {
    let root = TestRoot::new("ownership-ignored");
    let Some(volume) = Volume::attach(&root.0, fs, false) else {
        return;
    };
    let parent = volume.mount.join("private-parent");
    create_private_dir(&parent);
    let error = PublicationStage::create(&parent.join("export"), |_| Ok(())).unwrap_err();
    assert!(error.contains("ignores ownership"), "{error}");
    assert!(
        error.contains("choose a destination on a volume that enforces it"),
        "{error}"
    );
    let mount_point = std::fs::canonicalize(&volume.mount).expect("resolve the mount point");
    assert!(
        error.contains(&mount_point.display().to_string()),
        "{error}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&parent).unwrap().flatten().collect();
    assert!(leftovers.is_empty(), "nothing is created: {leftovers:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn an_apfs_volume_that_ignores_ownership_is_refused() {
    assert_refused_for_ignoring_ownership("APFS");
}

/// A missing parent below a volume that ignores ownership is refused before anything is created there:
/// the chain is validated first, the directories are made afterwards.
#[cfg(target_os = "macos")]
#[test]
fn a_missing_parent_on_a_volume_that_ignores_ownership_creates_nothing() {
    let root = TestRoot::new("ownership-missing-parent");
    let Some(volume) = Volume::attach(&root.0, "APFS", false) else {
        return;
    };
    let error =
        PublicationStage::create(&volume.mount.join("a").join("b").join("export"), |_| Ok(()))
            .unwrap_err();
    assert!(error.contains("ignores ownership"), "{error}");
    let leftovers: Vec<_> = std::fs::read_dir(&volume.mount)
        .unwrap()
        .flatten()
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "nothing is created: {leftovers:?}");
}

/// On a volume that enforces ownership a missing parent is made, private, and the export publishes.
#[cfg(target_os = "macos")]
#[test]
fn a_missing_parent_on_a_volume_that_enforces_ownership_is_made_private() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TestRoot::new("ownership-make-parent");
    let Some(volume) = Volume::attach(&root.0, "APFS", true) else {
        return;
    };
    let target = volume.mount.join("a").join("b").join("export");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("the parent is made");
    for directory in ["a", "a/b"] {
        let mode = std::fs::metadata(volume.mount.join(directory))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700, "{directory}");
    }
    write(stage.root(), "marker", "exported");
    stage.complete().publish().expect("the stage is published");
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "exported"
    );
}

/// An existing destination that is itself a mount point of a volume that ignores ownership is refused,
/// although its parent is a trusted directory.
#[cfg(target_os = "macos")]
#[test]
fn a_destination_that_is_a_mount_point_of_such_a_volume_is_refused() {
    let root = TestRoot::new("ownership-destination");
    let Some(volume) = Volume::attach(&root.0, "APFS", false) else {
        return;
    };
    // The mount point is the destination: its parent (the test root) is trusted.
    let error = PublicationStage::create(&volume.mount, |_| Ok(())).unwrap_err();
    assert!(error.contains("ignores ownership"), "{error}");
    let mount_point = std::fs::canonicalize(&volume.mount).expect("resolve the mount point");
    assert!(
        error.contains(&mount_point.display().to_string()),
        "{error}"
    );
}

/// exFAT cannot hold an ACL and has no atomic rename, and is always mounted without ownership: it is
/// refused at the first ancestor, before either matters. (Mounted with `-owners on` its root belongs to
/// an unknown uid, which an unprivileged test cannot write to, so the ACL-less case is covered by the
/// `acl` unit tests that pass the system calls in.)
#[cfg(target_os = "macos")]
#[test]
fn an_exfat_volume_mounted_without_ownership_is_refused() {
    assert_refused_for_ignoring_ownership("ExFAT");
}

/// An APFS volume that enforces ownership takes an export and publishes it.
#[cfg(target_os = "macos")]
#[test]
fn an_apfs_volume_that_enforces_ownership_takes_an_export() {
    let root = TestRoot::new("ownership-enforced");
    let Some(volume) = Volume::attach(&root.0, "APFS", true) else {
        return;
    };
    let parent = volume.mount.join("private-parent");
    create_private_dir(&parent);
    let target = parent.join("export");
    let stage = PublicationStage::create(&target, |_| Ok(())).expect("ownership is enforced here");
    write(stage.root(), "marker", "exported");
    stage.complete().publish().expect("the stage is published");
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "exported"
    );
}

/// The owner and root hold their rights anyway: their entries, named by the system's user database,
/// are accepted.
#[cfg(target_os = "macos")]
#[test]
fn the_current_users_and_roots_mutating_allow_on_an_ancestor_is_accepted() {
    let output = std::process::Command::new("id")
        .arg("-un")
        .output()
        .expect("run id");
    let me = String::from_utf8(output.stdout).expect("user name");
    let me = me.trim();
    create_stage_under_acl(
        "acl-me-write",
        &format!("{me} allow write,add_file,delete_child"),
    )
    .expect("the current user may be given rights");
    create_stage_under_acl("acl-root-write", "root allow write,add_file,delete_child")
        .expect("root may be given rights");
}

/// A mutating right a group holds is a right other users may hold.
#[cfg(target_os = "macos")]
#[test]
fn a_group_write_allow_on_an_ancestor_is_refused() {
    let error =
        create_stage_under_acl("acl-group-write", "group:staff allow delete_child").unwrap_err();

    assert!(error.contains("staff"), "{error}");
}

/// Every mutating right is refused, one at a time, so a right dropped from the classification is
/// seen.
#[cfg(target_os = "macos")]
#[test]
fn each_mutating_right_on_an_everyone_allow_is_refused() {
    for right in [
        "write",
        "append",
        "delete",
        "delete_child",
        "add_file",
        "add_subdirectory",
        "writeattr",
        "writeextattr",
        "writesecurity",
        "chown",
    ] {
        let error = create_stage_under_acl("acl-each-right", &format!("everyone allow {right}"))
            .unwrap_err();
        assert!(error.contains("extended ACL"), "{right}: {error}");
    }
}

/// A stage name that is already taken is skipped, and the taken one is left alone.
#[cfg(unix)]
#[test]
fn a_taken_stage_name_is_skipped() {
    let root = TestRoot::new("taken-stage-name");
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    let taken: Vec<PathBuf> = (1..=8)
        .map(|id| parent.join(format!(".export.fireemu-stage-{}-{id}", std::process::id())))
        .collect();
    for path in &taken {
        create_private_dir(path);
        std::fs::write(path.join("owned-by-someone-else"), "keep").expect("mark the taken name");
    }

    let stage = PublicationStage::create(&parent.join("export"), |_| Ok(()))
        .expect("a free stage name is found");

    assert!(
        taken.iter().all(|path| path != stage.root()),
        "{:?}",
        stage.root()
    );
    for path in &taken {
        assert_eq!(
            std::fs::read_to_string(path.join("owned-by-someone-else")).unwrap(),
            "keep"
        );
    }
}

/// A stage that cannot be created for another reason than a taken name is reported as such.
#[cfg(unix)]
#[test]
fn a_stage_that_cannot_be_created_is_reported_with_its_reason() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = TestRoot::new("unwritable-parent");
    let parent = root.0.join("private-parent");
    create_private_dir(&parent);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500))
        .expect("make the parent read-only");

    let error = PublicationStage::create(&parent.join("export"), |_| Ok(())).unwrap_err();

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restore the parent");
    assert!(
        error.contains("cannot create private export stage"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_parent_is_followed_only_from_a_directory_no_one_else_can_write() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let root = TestRoot::new("parent-symlink");
    let real = root.0.join("real-parent");
    let holder = root.0.join("holder");
    let linked = holder.join("linked-parent");
    std::fs::create_dir(&real).expect("create real parent");
    create_private_dir(&holder);
    symlink(&real, &linked).expect("create parent symlink");

    // The user's own link in a directory others can write: refused, nothing made.
    std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = PublicationStage::create(&linked.join("export"), |_| Ok(())).unwrap_err();
    std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(error.contains("symlink"), "{error}");
    assert!(std::fs::read_dir(&real).unwrap().next().is_none());

    // In a private directory of the user's own it is followed: the stage is made in the
    // directory it points to.
    let stage = PublicationStage::create(&linked.join("export"), |_| Ok(())).unwrap();
    assert_eq!(
        stage.root().parent().unwrap(),
        std::fs::canonicalize(&real).unwrap()
    );
}

/// EXPREL-2: a one-element relative target has the empty path as its parent.
///
/// `Path::new("out").parent()` is `Some("")`, `lstat("")` is ENOENT, and although
/// `DirBuilder::create("")` succeeds, restricting the permissions of "" fails with ENOENT. A
/// caller that passed a bare directory name therefore lost the export at the last moment. The
/// stage resolves the target against the working directory before looking at its parent.
///
/// The working directory is process-global; nextest runs each test in its own process.
#[test]
fn a_bare_relative_target_is_resolved_against_the_working_directory() {
    let root = TestRoot::new("bare-relative");
    let previous = std::env::current_dir().expect("the working directory is readable");
    std::env::set_current_dir(root.0.path()).expect("enter the scratch directory");

    let stage = PublicationStage::create(Path::new("out"), |_| Ok(()));

    let stage = match stage {
        Ok(stage) => stage,
        Err(error) => {
            std::env::set_current_dir(&previous).expect("restore the working directory");
            panic!("a bare relative target must be publishable: {error}");
        }
    };
    assert!(!stage.target_was_present());
    write(stage.root(), "marker", "published");
    let published = stage.complete().publish();
    std::env::set_current_dir(&previous).expect("restore the working directory");
    published.expect("the stage publishes");

    assert_eq!(
        std::fs::read_to_string(root.0.path().join("out").join("marker"))
            .expect("the published marker is readable"),
        "published"
    );
}

#[test]
fn a_step_that_succeeds_at_once_is_tried_once_and_never_waits() {
    let mut calls = 0;
    let mut waits = Vec::new();
    let result = retry_with_backoff(
        ENVIRONMENT_ATTEMPTS,
        ENVIRONMENT_BACKOFF_STEP,
        |wait| waits.push(wait),
        || {
            calls += 1;
            Ok::<_, String>(7)
        },
    );
    assert_eq!(result, Ok(7));
    assert_eq!(calls, 1);
    assert!(waits.is_empty(), "{waits:?}");
}

#[test]
fn a_step_that_recovers_is_retried_with_growing_waits_and_then_succeeds() {
    let mut calls = 0;
    let mut waits = Vec::new();
    let result = retry_with_backoff(
        ENVIRONMENT_ATTEMPTS,
        ENVIRONMENT_BACKOFF_STEP,
        |wait| waits.push(wait),
        || {
            calls += 1;
            if calls < 3 {
                Err(format!("busy {calls}"))
            } else {
                Ok(calls)
            }
        },
    );
    assert_eq!(result, Ok(3));
    assert_eq!(calls, 3);
    assert_eq!(
        waits,
        vec![ENVIRONMENT_BACKOFF_STEP, ENVIRONMENT_BACKOFF_STEP * 2]
    );
}

#[test]
fn a_step_that_never_recovers_fails_after_the_bound_with_every_message() {
    let mut calls = 0_u32;
    let mut waits = Vec::new();
    let result: Result<(), Vec<String>> = retry_with_backoff(
        ENVIRONMENT_ATTEMPTS,
        ENVIRONMENT_BACKOFF_STEP,
        |wait| waits.push(wait),
        || {
            calls += 1;
            Err(format!("Resource busy {calls}"))
        },
    );
    let failures = result.unwrap_err();
    assert_eq!(calls, ENVIRONMENT_ATTEMPTS);
    assert_eq!(failures.len(), ENVIRONMENT_ATTEMPTS as usize);
    assert_eq!(
        failures.first().map(String::as_str),
        Some("Resource busy 1")
    );
    assert_eq!(failures.last().map(String::as_str), Some("Resource busy 6"));
    // One wait between two tries, none after the last: the wait never exceeds the bound it advertises.
    assert_eq!(waits.len(), ENVIRONMENT_ATTEMPTS as usize - 1);
    let total: std::time::Duration = waits.iter().sum();
    assert!(total <= std::time::Duration::from_secs(10), "{total:?}");
    assert!(total >= std::time::Duration::from_secs(1), "{total:?}");
}

#[test]
fn a_single_attempt_is_not_retried() {
    let mut waits = 0;
    let result: Result<(), Vec<String>> = retry_with_backoff(
        1,
        ENVIRONMENT_BACKOFF_STEP,
        |_| waits += 1,
        || Err("busy".to_owned()),
    );
    assert_eq!(result.unwrap_err(), vec!["busy".to_owned()]);
    assert_eq!(waits, 0);
}

#[test]
fn preflight_is_read_only_for_missing_and_existing_destinations() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = TestRoot::new("preflight-read-only");
    let missing = root.0.join("missing/parents/export");
    fireemu_export_publication::preflight(&missing).unwrap();
    assert!(!root.0.join("missing").exists());
    let target = root.target();
    create_private_dir(&target);
    write(&target, "marker", "unchanged");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode();
    fireemu_export_publication::preflight(&target).unwrap();
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "unchanged"
    );
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode(),
        mode
    );
    assert_eq!(std::fs::read_dir(root.0.path()).unwrap().count(), 1);
}

/// Outside a shared directory only the user or root could have made the target, so a
/// group-writable export directory of the user's own (umask 002) keeps working.
#[test]
fn an_existing_target_of_the_users_own_outside_a_shared_directory_may_be_group_writable() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = TestRoot::new("own-open-target");
    let target = root.target();
    create_private_dir(&target);
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o775)).unwrap();
    fireemu_export_publication::preflight(&target).unwrap();
    let stage = PublicationStage::create(&target, |_| Ok(())).unwrap();
    assert!(stage.target_was_present());
}

#[test]
fn preflight_refuses_unsafe_ancestors_without_creating_missing_parents() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = TestRoot::new("preflight-unsafe");
    for mode in [0o775, 0o1777] {
        std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let result = fireemu_export_publication::preflight(&root.0.join("missing/export"));
        std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.unwrap_err().contains("namespace ancestor"));
        assert!(!root.0.join("missing").exists());
    }
}

#[test]
fn preflight_refuses_symlink_target_and_parent_and_non_directory() {
    use std::os::unix::fs::symlink;
    let root = TestRoot::new("preflight-types");
    let real = root.0.join("real");
    create_private_dir(&real);
    let link = root.0.join("link");
    symlink(&real, &link).unwrap();
    assert!(fireemu_export_publication::preflight(&link)
        .unwrap_err()
        .contains("symlink"));
    // The user's own link in a private directory is followed; preflight returns the path
    // with the link resolved.
    assert_eq!(
        fireemu_export_publication::preflight(&link.join("export")).unwrap(),
        std::fs::canonicalize(&real).unwrap().join("export")
    );
    let file = root.0.join("file");
    std::fs::write(&file, "unchanged").unwrap();
    assert!(fireemu_export_publication::preflight(&file)
        .unwrap_err()
        .contains("directory"));
    assert_eq!(std::fs::read_to_string(file).unwrap(), "unchanged");
}

#[test]
fn preflight_does_not_replace_publication_time_validation() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = TestRoot::new("preflight-revalidate");
    fireemu_export_publication::preflight(&root.target()).unwrap();
    std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let result = PublicationStage::create(&root.target(), |_| Ok(()));
    std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.unwrap_err().contains("namespace ancestor"));
    assert!(!root.target().exists());
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(24))]
    #[test]
    fn preflight_matches_ancestor_write_policy_without_side_effects(
        shared_bits in 0u32..=0o77,
        depth in 1usize..5,
    ) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = TestRoot::new("preflight-property");
        let mut target = root.0.path().to_path_buf();
        for _ in 0..depth { target.push("missing"); }
        target.push("export");
        std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o700 | shared_bits)).unwrap();
        let result = fireemu_export_publication::preflight(&target);
        std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        proptest::prop_assert_eq!(result.is_ok(), shared_bits & 0o22 == 0);
        proptest::prop_assert_eq!(std::fs::read_dir(root.0.path()).unwrap().count(), 0);
    }
}

#[test]
fn preflight_refuses_a_parent_that_cannot_create_the_export() {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }
    let root = TestRoot::new("preflight-readonly");
    std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = fireemu_export_publication::preflight(&root.0.join("missing/export"));
    std::fs::set_permissions(root.0.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result.is_err(),
        "a known unwritable parent must fail preflight"
    );
    assert!(!root.0.join("missing").exists());
}

/// A stage created for the path a preflight resolved uses the directory that preflight holds:
/// once the directory is renamed away and a link put in its place, nothing goes through the link
/// (r3 ruling 2). The stage is made in the held directory; where a later step still names it by
/// path (the macOS stage ACL, the caller's writes into the stage), that step fails instead.
#[cfg(unix)]
#[test]
fn a_stage_for_a_preflighted_path_uses_the_held_directory() {
    use std::os::unix::fs::symlink;
    let root = TestRoot::new("held-parent");
    let parent = root.0.join("parent");
    create_private_dir(&parent);
    let elsewhere = root.0.join("elsewhere");
    create_private_dir(&elsewhere);
    let resolved = fireemu_export_publication::preflight(&parent.join("export")).unwrap();
    let moved = root.0.join("moved");
    std::fs::rename(&parent, &moved).unwrap();
    symlink(&elsewhere, &parent).unwrap();
    match PublicationStage::create(&resolved, |_| Ok(())) {
        Ok(stage) => {
            assert_eq!(
                std::fs::read_dir(&moved).unwrap().count(),
                1,
                "the stage is in the held directory"
            );
            drop(stage);
        }
        Err(error) => assert!(error.contains("stage"), "{error}"),
    }
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing went through the link"
    );
    assert!(!elsewhere.join("export").exists());
}

/// The stage names the target it replaces by its resolved path, which is where a caller reads
/// the previous export from (r2 review S1).
#[cfg(unix)]
#[test]
fn a_stage_names_its_target_by_the_resolved_path() {
    use std::os::unix::fs::symlink;
    let root = TestRoot::new("resolved-target");
    let real = root.0.join("real");
    create_private_dir(&real);
    symlink(&real, root.0.join("link")).unwrap();
    let stage = PublicationStage::create(&root.0.join("link/export"), |_| Ok(())).unwrap();
    assert_eq!(
        stage.target(),
        std::fs::canonicalize(&real).unwrap().join("export")
    );
}

/// A second preflight of the same path replaces the directory the first one held: a stage of the
/// resolved path then goes to the directory the latest preflight walked.
#[cfg(unix)]
#[test]
fn the_latest_preflight_of_a_path_is_the_one_held() {
    let root = TestRoot::new("held-latest");
    let parent = root.0.join("parent");
    create_private_dir(&parent);
    let resolved = fireemu_export_publication::preflight(&parent.join("export")).unwrap();
    let old = root.0.join("old");
    std::fs::rename(&parent, &old).unwrap();
    create_private_dir(&parent);
    assert_eq!(
        fireemu_export_publication::preflight(&parent.join("export")).unwrap(),
        resolved
    );
    let stage = PublicationStage::create(&resolved, |_| Ok(())).unwrap();
    assert_eq!(
        std::fs::read_dir(&parent).unwrap().count(),
        1,
        "the stage is in the new parent"
    );
    assert_eq!(std::fs::read_dir(&old).unwrap().count(), 0);
    drop(stage);
}

/// The missing names a preflight recorded are walked again when the export runs: a directory
/// made meanwhile (by an earlier export of the same path, or by the user) is entered and judged,
/// a missing one is made, and a link is refused (r3 review M1).
#[cfg(unix)]
#[test]
fn missing_names_made_after_the_preflight_are_entered_and_links_refused() {
    use std::os::unix::fs::symlink;
    let root = TestRoot::new("held-missing");
    let publish = |path: &Path| {
        let stage = PublicationStage::create(path, |_| Ok(()))?;
        write(stage.root(), "firebase-export-metadata.json", "{}");
        stage.complete().publish()
    };
    // The same preflighted path exported twice.
    let twice = fireemu_export_publication::preflight(&root.0.join("new/data")).unwrap();
    publish(&twice).unwrap();
    publish(&twice).unwrap();
    assert!(twice.join("firebase-export-metadata.json").is_file());
    // A `mkdir` between the preflight and the export.
    let made = fireemu_export_publication::preflight(&root.0.join("new2/data")).unwrap();
    create_private_dir(&root.0.join("new2"));
    publish(&made).unwrap();
    assert!(made.join("firebase-export-metadata.json").is_file());
    // A link planted at a missing name.
    let victim = root.0.join("victim");
    create_private_dir(&victim);
    let linked = fireemu_export_publication::preflight(&root.0.join("new3/data")).unwrap();
    symlink(&victim, root.0.join("new3")).unwrap();
    let error = publish(&linked).unwrap_err();
    assert!(error.contains("symlink"), "{error}");
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
}

/// After the held directory is renamed away and its old name recreated with the predictable
/// stage names planted as links to a victim, nothing reaches the victim (r3 review M2): the stage
/// is made and written through the held directory's descriptors, and on macOS the stage ACL step
/// refuses because the old path no longer names the stage.
#[cfg(unix)]
#[test]
fn a_renamed_held_directory_never_lets_the_export_through_a_planted_stage_name() {
    use std::os::unix::fs::symlink;
    let root = TestRoot::new("held-renamed");
    let base = root.0.join("base");
    create_private_dir(&base);
    let victim = root.0.join("victim");
    create_private_dir(&victim);
    #[cfg(target_os = "macos")]
    let acl_set = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone deny delete"])
        .arg(&victim)
        .status()
        .is_ok_and(|status| status.success());
    let resolved = fireemu_export_publication::preflight(&base.join("data")).unwrap();
    let moved = root.0.join("moved");
    std::fs::rename(&base, &moved).unwrap();
    create_private_dir(&base);
    for id in 1..=16 {
        symlink(
            &victim,
            base.join(format!(".data.fireemu-stage-{}-{id}", std::process::id())),
        )
        .unwrap();
    }
    match PublicationStage::create(&resolved, |_| Ok(())) {
        Ok(stage) => {
            let tree = stage.stage_dir().unwrap();
            tree.create_dir(Path::new("auth_export")).unwrap();
            std::io::Write::write_all(
                &mut tree
                    .create_file(Path::new("firebase-export-metadata.json"))
                    .unwrap(),
                b"{}",
            )
            .unwrap();
            stage.complete().publish().unwrap();
            assert!(moved.join("data/firebase-export-metadata.json").is_file());
        }
        Err(error) => {
            eprintln!("refused: {error}");
            assert!(error.contains("no longer named"), "{error}");
        }
    }
    assert_eq!(
        std::fs::read_dir(&victim).unwrap().count(),
        0,
        "the victim is untouched"
    );
    #[cfg(target_os = "macos")]
    if acl_set {
        let listing = std::process::Command::new("/bin/ls")
            .args(["-led"])
            .arg(&victim)
            .output()
            .unwrap();
        let _ = std::process::Command::new("/bin/chmod")
            .args(["-N"])
            .arg(&victim)
            .status();
        assert!(
            String::from_utf8_lossy(&listing.stdout).contains("deny delete"),
            "the victim's ACL survives"
        );
    }
}

/// The stage's writer works through held descriptors: a link planted inside the stage at a file
/// name is replaced, never followed, and a link at a directory name is refused.
#[cfg(unix)]
#[test]
fn the_stage_writer_never_follows_a_link_planted_inside_the_stage() {
    use std::os::unix::fs::symlink;
    let root = TestRoot::new("stage-writer");
    let victim = root.0.join("victim");
    create_private_dir(&victim);
    write(&victim, "file", "victim");
    let stage = PublicationStage::create(&root.target(), |_| Ok(())).unwrap();
    symlink(victim.join("file"), stage.root().join("file")).unwrap();
    symlink(&victim, stage.root().join("dir")).unwrap();
    let tree = stage.stage_dir().unwrap();
    std::io::Write::write_all(&mut tree.create_file(Path::new("file")).unwrap(), b"export")
        .unwrap();
    assert!(tree.create_dir(Path::new("dir")).is_err());
    assert!(tree.create_file(Path::new("dir/inner")).is_err());
    assert!(tree.create_dir(Path::new("../escape")).is_err());
    assert_eq!(
        std::fs::read_to_string(victim.join("file")).unwrap(),
        "victim"
    );
    assert_eq!(
        std::fs::read_to_string(stage.root().join("file")).unwrap(),
        "export"
    );
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 1);
}
