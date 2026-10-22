//! macOS: the extended ACL of a descriptor through `acl_get_fd_np(3)`.

use std::ffi::c_int;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

/// Answers whether the file open on `descriptor` has an extended ACL with at least one entry.
///
/// - `Ok(false)`: the file has no extended ACL, or one with no entries.
/// - `Ok(true)`: the ACL has an entry. Any entry counts: allow or deny, inherited or not.
/// - `Err`: the ACL could not be read. A caller that guards secrets must treat this like an
///   entry and refuse the file.
///
/// The ACL is read from the open file itself (`acl_get_fd_np` with `ACL_TYPE_EXTENDED`), so no
/// path is looked up and the answer is about the file behind `descriptor` even if its path has
/// since been renamed or replaced.
pub fn fd_has_extended_acl(descriptor: BorrowedFd<'_>) -> io::Result<bool> {
    raw_fd_has_extended_acl(descriptor.as_raw_fd())
}

/// Removes all extended ACL entries from the object held by `descriptor`.
///
/// No path is resolved, even when the object's former name has been replaced. An unsupported
/// filesystem or any allocation/set error is returned to the caller; callers that require an
/// empty ACL must independently read it back with [`fd_has_extended_acl`].
pub fn clear_extended_acl(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    raw_clear_extended_acl(descriptor.as_raw_fd())
}

fn raw_clear_extended_acl(descriptor: c_int) -> io::Result<()> {
    ffi::ExtendedAcl::empty()?.apply_to_descriptor(descriptor)
}

/// [`fd_has_extended_acl`] on a raw descriptor number, which may be invalid.
///
/// This stays private: the public function takes a `BorrowedFd`, which guarantees that the
/// number is open for the duration of the call and not reused by another file.
fn raw_fd_has_extended_acl(descriptor: c_int) -> io::Result<bool> {
    match ffi::ExtendedAcl::of_descriptor(descriptor) {
        Ok(mut acl) => {
            let (status, error) = acl.first_entry_status();
            first_entry_answer(status, error)
        }
        Err(error) => absent_acl_answer(error),
    }
}

/// Classifies a NULL answer from `acl_get_fd_np`.
///
/// `ENOENT` means that the open file has no extended ACL: there is no path lookup that could
/// fail instead. Every other error means that the ACL is unreadable.
fn absent_acl_answer(error: io::Error) -> io::Result<bool> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Classifies the answer of `acl_get_entry(acl, ACL_FIRST_ENTRY, ..)`.
///
/// Darwin returns 0 when the entry exists, and -1 with `EINVAL` when the ACL has no entries.
/// Anything else is an unreadable ACL.
fn first_entry_answer(status: c_int, error: io::Error) -> io::Result<bool> {
    match status {
        0 => Ok(true),
        -1 if error.kind() == io::ErrorKind::InvalidInput => Ok(false),
        -1 => Err(error),
        other => Err(io::Error::other(format!(
            "acl_get_entry returned the undocumented status {other}"
        ))),
    }
}

/// The only unsafe code in the workspace: the C library's ACL calls.
///
/// Each call is in its own `unsafe` block with the reason it is sound. The declarations follow
/// `<sys/acl.h>` of the macOS SDK. `acl_t` and `acl_entry_t` are pointers to opaque structs,
/// declared here as `*mut c_void`. `acl_type_t` is a C enum whose values are all
/// non-negative, which the C compiler represents as `unsigned int`. The functions are in
/// libSystem, which every macOS binary links.
#[allow(unsafe_code)]
mod ffi {
    use std::ffi::{c_int, c_uint, c_void};
    use std::io;
    use std::ptr::{self, NonNull};

    /// `ACL_TYPE_EXTENDED` in `<sys/acl.h>`, the only type Darwin supports.
    const ACL_TYPE_EXTENDED: c_uint = 0x0000_0100;
    /// `ACL_FIRST_ENTRY` in `<sys/acl.h>`.
    const ACL_FIRST_ENTRY: c_int = 0;

    extern "C" {
        fn acl_init(count: c_int) -> *mut c_void;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_uint) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_uint) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry_p: *mut *mut c_void) -> c_int;
        fn acl_free(obj_p: *mut c_void) -> c_int;
    }

    /// An ACL returned by `acl_get_fd_np` or `acl_init`, owned and freed once on drop.
    ///
    /// The pointer makes this type neither `Send` nor `Sync`, so the ACL, including the
    /// entry cursor that `acl_get_entry` moves, is only ever used by one thread.
    pub(super) struct ExtendedAcl(NonNull<c_void>);

    impl ExtendedAcl {
        /// Allocates an owned, empty extended ACL.
        pub(super) fn empty() -> io::Result<Self> {
            // SAFETY: zero is a valid entry count. The function returns either NULL with errno,
            // read immediately, or an independent allocation owned by Self and freed once on drop.
            let acl = unsafe { acl_init(0) };
            NonNull::new(acl)
                .map(Self)
                .ok_or_else(io::Error::last_os_error)
        }

        /// Applies this live ACL to an open descriptor without retaining either argument.
        pub(super) fn apply_to_descriptor(&self, descriptor: c_int) -> io::Result<()> {
            // SAFETY: self owns the valid ACL for the duration of this call. The library copies
            // its entries, keeping neither pointer nor descriptor. An invalid descriptor returns
            // EBADF rather than accessing memory; the public API requires a live BorrowedFd.
            let status = unsafe { acl_set_fd_np(descriptor, self.0.as_ptr(), ACL_TYPE_EXTENDED) };
            if status == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        /// Reads the extended ACL of `descriptor`, or the error of a NULL answer.
        pub(super) fn of_descriptor(descriptor: c_int) -> io::Result<Self> {
            // SAFETY: `acl_get_fd_np` takes both arguments by value and keeps neither. Any
            // integer is an acceptable descriptor: one that is not open gives `EBADF`. It
            // either returns NULL and sets errno, which is read before any other call, or
            // returns a new ACL that the caller owns and must release with `acl_free`. `Self`
            // takes that ownership and `Drop` releases it exactly once.
            let acl = unsafe { acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) };
            NonNull::new(acl)
                .map(Self)
                .ok_or_else(io::Error::last_os_error)
        }

        /// Asks for the first entry: the status of `acl_get_entry` and the errno after it.
        ///
        /// The errno only means something when the status is -1.
        pub(super) fn first_entry_status(&mut self) -> (c_int, io::Error) {
            let mut entry: *mut c_void = ptr::null_mut();
            // SAFETY: `self.0` is the live ACL from `acl_get_fd_np`: it is freed only in
            // `Drop`, and `&mut self` keeps it alive and unshared during the call. `entry` is
            // a writable, pointer-sized local. `acl_get_entry` either stores in it a pointer
            // into the ACL, which is never dereferenced or freed here, or returns -1 and sets
            // errno. Besides `entry`, it writes only the ACL's own entry cursor.
            let status = unsafe { acl_get_entry(self.0.as_ptr(), ACL_FIRST_ENTRY, &raw mut entry) };
            (status, io::Error::last_os_error())
        }
    }

    impl Drop for ExtendedAcl {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from `acl_get_fd_np` or `acl_init`, is freed exactly once, and
            // is not used afterwards, because nothing else holds it. `acl_free` only fails
            // for a pointer that the ACL library did not allocate, so its status is ignored.
            unsafe { acl_free(self.0.as_ptr()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        absent_acl_answer, fd_has_extended_acl, first_entry_answer, raw_fd_has_extended_acl,
    };

    /// `EPERM`, `ENOENT`, `EBADF`, `ENOMEM`, `EACCES`, `EINVAL` and `ENOTSUP` in
    /// `<sys/errno.h>`.
    const EPERM: i32 = 1;
    const ENOENT: i32 = 2;
    const EBADF: i32 = 9;
    const ENOMEM: i32 = 12;
    const EACCES: i32 = 13;
    const EINVAL: i32 = 22;
    const ENOTSUP: i32 = 45;

    /// An owner-only scratch directory, removed with its ACLs on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "fireemu-fd-acl-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = Command::new("/bin/chmod").arg("-RN").arg(&self.0).status();
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn chmod(arguments: &[&str], path: &Path) {
        let status = Command::new("/bin/chmod")
            .args(arguments)
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "chmod {arguments:?} {}", path.display());
    }

    fn has_extended_acl(path: &Path) -> std::io::Result<bool> {
        let file = std::fs::File::open(path).unwrap();
        fd_has_extended_acl(file.as_fd())
    }

    #[test]
    fn a_file_and_a_directory_without_an_acl_have_no_entries() {
        let scratch = Scratch::new("none");
        let file = scratch.path().join("file");
        std::fs::write(&file, b"key").unwrap();
        assert!(!has_extended_acl(scratch.path()).unwrap());
        assert!(!has_extended_acl(&file).unwrap());
    }

    #[test]
    fn allow_deny_and_inherited_entries_are_detected() {
        let scratch = Scratch::new("entries");

        let allowed = scratch.path().join("allowed");
        std::fs::write(&allowed, b"key").unwrap();
        chmod(&["+a", "everyone allow read"], &allowed);
        assert!(has_extended_acl(&allowed).unwrap());

        let denied = scratch.path().join("denied");
        std::fs::write(&denied, b"key").unwrap();
        chmod(&["+a", "everyone deny delete"], &denied);
        assert!(has_extended_acl(&denied).unwrap());

        let parent = scratch.path().join("parent");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        chmod(
            &[
                "+a",
                "everyone allow list,add_file,add_subdirectory,read,file_inherit,directory_inherit",
            ],
            &parent,
        );
        assert!(has_extended_acl(&parent).unwrap());
        let inherited_file = parent.join("file");
        std::fs::write(&inherited_file, b"key").unwrap();
        assert!(has_extended_acl(&inherited_file).unwrap());
        let inherited_directory = parent.join("directory");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&inherited_directory)
            .unwrap();
        assert!(has_extended_acl(&inherited_directory).unwrap());
    }

    #[test]
    fn clearing_allow_deny_and_inherited_entries_leaves_empty_descriptors() {
        let scratch = Scratch::new("clear");
        for (name, entry) in [
            ("allow", "everyone allow read"),
            ("deny", "everyone deny delete"),
        ] {
            let path = scratch.path().join(name);
            std::fs::write(&path, b"key").unwrap();
            chmod(&["+a", entry], &path);
            let file = std::fs::File::open(&path).unwrap();
            assert!(fd_has_extended_acl(file.as_fd()).unwrap());
            super::clear_extended_acl(file.as_fd()).unwrap();
            assert!(!fd_has_extended_acl(file.as_fd()).unwrap());
            super::clear_extended_acl(file.as_fd()).unwrap();
            assert!(!fd_has_extended_acl(file.as_fd()).unwrap());
        }
        let parent = scratch.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        chmod(
            &[
                "+a",
                "everyone allow list,read,file_inherit,directory_inherit",
            ],
            &parent,
        );
        for (name, directory) in [("child-file", false), ("child-directory", true)] {
            let child = parent.join(name);
            if directory {
                std::fs::create_dir(&child).unwrap();
            } else {
                std::fs::write(&child, b"key").unwrap();
            }
            let file = std::fs::File::open(&child).unwrap();
            assert!(fd_has_extended_acl(file.as_fd()).unwrap());
            super::clear_extended_acl(file.as_fd()).unwrap();
            assert!(!fd_has_extended_acl(file.as_fd()).unwrap());
            assert!(has_extended_acl(&parent).unwrap());
        }
    }

    #[test]
    fn clearing_a_replaced_directory_changes_only_the_open_object() {
        let scratch = Scratch::new("clear-replaced");
        let path = scratch.path().join("stage");
        std::fs::create_dir(&path).unwrap();
        chmod(&["+a", "everyone allow read"], &path);
        let held = std::fs::File::open(&path).unwrap();
        let moved = scratch.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        chmod(&["+a", "everyone allow read"], &path);
        let victim_before = std::process::Command::new("/bin/ls")
            .arg("-lde")
            .arg(&path)
            .output()
            .unwrap()
            .stdout;
        assert!(fd_has_extended_acl(held.as_fd()).unwrap());
        super::clear_extended_acl(held.as_fd()).unwrap();
        assert!(!fd_has_extended_acl(held.as_fd()).unwrap());
        assert!(!has_extended_acl(&moved).unwrap());
        assert!(has_extended_acl(&path).unwrap());
        let victim_after = std::process::Command::new("/bin/ls")
            .arg("-lde")
            .arg(&path)
            .output()
            .unwrap()
            .stdout;
        assert_eq!(victim_before, victim_after);
    }

    #[test]
    fn clearing_an_invalid_descriptor_preserves_the_set_error() {
        let error = super::raw_clear_extended_acl(-1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(EBADF));
    }

    #[test]
    fn removing_every_entry_leaves_no_entries() {
        let scratch = Scratch::new("removed");
        let file = scratch.path().join("file");
        std::fs::write(&file, b"key").unwrap();
        chmod(&["+a", "everyone allow read"], &file);
        assert!(has_extended_acl(&file).unwrap());
        chmod(&["-N"], &file);
        assert!(!has_extended_acl(&file).unwrap());
    }

    #[test]
    fn the_answer_is_about_the_open_file_not_its_path() {
        let scratch = Scratch::new("descriptor");
        let path = scratch.path().join("file");
        std::fs::write(&path, b"first").unwrap();
        chmod(&["+a", "everyone allow read"], &path);
        let with_entry = std::fs::File::open(&path).unwrap();

        // Replace the path with a file that has no ACL. The descriptor still names the first.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"second").unwrap();
        assert!(!has_extended_acl(&path).unwrap());
        assert!(fd_has_extended_acl(with_entry.as_fd()).unwrap());

        // And the other way round: an entry added through the path shows on an open descriptor.
        let without_entry = std::fs::File::open(&path).unwrap();
        assert!(!fd_has_extended_acl(without_entry.as_fd()).unwrap());
        chmod(&["+a", "everyone deny delete"], &path);
        assert!(fd_has_extended_acl(without_entry.as_fd()).unwrap());
    }

    #[test]
    fn an_acl_the_owner_may_not_read_is_an_error_not_an_empty_acl() {
        // `everyone deny readsecurity` denies the owner too: `acl_get_fd_np` then returns NULL
        // with `EACCES`, while `fstat` on the same descriptor still succeeds. With an allow
        // entry behind the deny, this is an ACL that grants another user access and hides it,
        // so reading it must fail, never answer "no entries". The allow entry is added first:
        // once the deny is in place, `chmod +a` cannot read the ACL it extends and replaces
        // it with the new entry alone. `Scratch` removes both entries with `chmod -RN`, which
        // the owner may still run, even when an assertion fails.
        let scratch = Scratch::new("unreadable");
        let file = scratch.path().join("file");
        std::fs::write(&file, b"key").unwrap();
        let directory = scratch.path().join("directory");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();

        for (path, allow) in [
            (&file, "user:nobody allow read"),
            (&directory, "user:nobody allow list,search"),
        ] {
            chmod(&["+a", allow], path);
            assert!(has_extended_acl(path).unwrap());
            chmod(&["+a", "everyone deny readsecurity"], path);

            let opened = std::fs::File::open(path).unwrap();
            assert!(opened.metadata().is_ok(), "fstat of {}", path.display());
            let error = fd_has_extended_acl(opened.as_fd()).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(EACCES), "{}", path.display());
        }

        chmod(&["-N"], &file);
        assert!(!has_extended_acl(&file).unwrap());
    }

    #[test]
    fn concurrent_reads_of_one_descriptor_all_see_the_entry() {
        let scratch = Scratch::new("concurrent");
        let path = scratch.path().join("file");
        std::fs::write(&path, b"key").unwrap();
        chmod(&["+a", "everyone allow read"], &path);
        let file = std::fs::File::open(&path).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..500 {
                        assert!(fd_has_extended_acl(file.as_fd()).unwrap());
                    }
                });
            }
        });
    }

    #[test]
    fn a_descriptor_that_is_not_open_is_an_error_not_an_empty_acl() {
        let error = raw_fd_has_extended_acl(-1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(EBADF));
    }

    #[test]
    fn only_enoent_from_acl_get_fd_np_means_no_acl() {
        assert!(!absent_acl_answer(std::io::Error::from_raw_os_error(ENOENT)).unwrap());
        for errno in [EPERM, EBADF, ENOMEM, EACCES, EINVAL, ENOTSUP] {
            let error = absent_acl_answer(std::io::Error::from_raw_os_error(errno)).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }

    #[test]
    fn only_a_found_first_entry_or_einval_is_an_answer() {
        let errno = std::io::Error::from_raw_os_error;
        assert!(first_entry_answer(0, errno(0)).unwrap());
        assert!(first_entry_answer(0, errno(EINVAL)).unwrap());
        assert!(!first_entry_answer(-1, errno(EINVAL)).unwrap());
        for code in [ENOENT, EBADF, ENOMEM] {
            let error = first_entry_answer(-1, errno(code)).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
        }
        for status in [1, -2] {
            assert!(first_entry_answer(status, errno(EINVAL)).is_err());
        }
    }
}
