//! The macOS volume rule for the ancestors of an export.
//!
//! Staged cleanup is safe only if no other principal can replace an ancestor of the export. The
//! checks of the owner and of the mode of each ancestor say so only on a volume that enforces
//! ownership. A volume mounted with `MNT_IGNORE_OWNERSHIP` (exFAT and FAT always are; an external
//! APFS volume with "Ignore ownership on this volume" is) reports an owner and a mode that mean
//! nothing: any local user may change the directory whatever they say. Such a volume is refused,
//! and so is a volume whose mount flags cannot be read (fail closed).

use std::ffi::CStr;
use std::path::Path;

/// `MNT_IGNORE_OWNERSHIP` of `<sys/mount.h>`: the volume ignores the owner and the mode of its files.
pub(crate) const MNT_IGNORE_OWNERSHIP: u32 = 0x0020_0000;

/// What `statfs` says about the volume holding a path: its mount flags and where it is mounted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Mount {
    pub(crate) flags: u32,
    pub(crate) mounted_on: String,
}

/// Whether the volume with these mount flags enforces the owner and the mode of its files.
pub(crate) fn enforces_ownership(flags: u32) -> bool {
    flags & MNT_IGNORE_OWNERSHIP == 0
}

/// The mount flags and the mount point of the volume that holds `path`.
pub(crate) fn mount_of(path: &Path) -> Result<Mount, String> {
    let stat = rustix::fs::statfs(path).map_err(|error| error.to_string())?;
    // `f_mntonname` is a NUL-terminated array filled in by the kernel; an unterminated one is
    // reported as unreadable rather than read past its end.
    let bytes: Vec<u8> = stat
        .f_mntonname
        .iter()
        .map(|byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    let mounted_on = CStr::from_bytes_until_nul(&bytes)
        .map_err(|_| "the mount point of the volume is not NUL-terminated".to_owned())?
        .to_string_lossy()
        .into_owned();
    Ok(Mount {
        flags: stat.f_flags,
        mounted_on,
    })
}

/// Refuses `path` when its volume ignores ownership or cannot be inspected. `read` is
/// [`mount_of`] outside the tests.
pub(crate) fn require_ownership(
    path: &Path,
    read: &dyn Fn(&Path) -> Result<Mount, String>,
) -> Result<(), String> {
    let mount = read(path).map_err(|error| {
        format!(
            "cannot inspect the volume of export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    if enforces_ownership(mount.flags) {
        Ok(())
    } else {
        Err(format!(
            "export namespace ancestor {} is on the volume mounted at {}, which ignores ownership, so the owner and mode of its directories do not show who can change them and staged cleanup cannot be made safe; choose a destination on a volume that enforces it",
            path.display(),
            mount.mounted_on
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(flags: u32) -> Mount {
        Mount {
            flags,
            mounted_on: "/Volumes/STICK".to_owned(),
        }
    }

    #[test]
    fn a_volume_that_enforces_ownership_is_accepted() {
        let read = |_: &Path| Ok(mount(0x4b0_9218 & !MNT_IGNORE_OWNERSHIP));
        assert_eq!(require_ownership(Path::new("/a"), &read), Ok(()));
    }

    #[test]
    fn a_volume_that_ignores_ownership_is_refused_with_its_mount_point() {
        let read = |_: &Path| Ok(mount(0x4b0_9218 | MNT_IGNORE_OWNERSHIP));
        let error = require_ownership(Path::new("/Volumes/STICK/export"), &read).unwrap_err();
        assert!(error.contains("ignores ownership"), "{error}");
        assert!(error.contains("/Volumes/STICK/export"), "{error}");
        assert!(error.contains("mounted at /Volumes/STICK,"), "{error}");
        assert!(
            error.contains("choose a destination on a volume that enforces it"),
            "{error}"
        );
    }

    #[test]
    fn a_volume_that_cannot_be_inspected_is_refused() {
        let read = |_: &Path| Err("EIO".to_owned());
        let error = require_ownership(Path::new("/a"), &read).unwrap_err();
        assert!(error.contains("cannot inspect the volume"), "{error}");
        assert!(error.contains("EIO"), "{error}");
    }

    #[test]
    fn the_flag_is_the_documented_bit() {
        assert_eq!(MNT_IGNORE_OWNERSHIP, 1 << 21);
    }

    #[test]
    fn the_real_volume_of_the_temp_directory_is_readable_and_enforces_ownership() {
        let mount = mount_of(&std::env::temp_dir()).expect("statfs of the temp directory");
        assert!(mount.mounted_on.starts_with('/'), "{mount:?}");
        assert!(enforces_ownership(mount.flags), "{mount:?}");
    }

    #[test]
    fn a_path_that_does_not_exist_cannot_be_inspected() {
        let missing = std::env::temp_dir().join("fireemu-volume-missing-path");
        assert!(mount_of(&missing).is_err());
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// A volume enforces ownership if and only if the flag is not set, whatever the other
            /// mount flags say.
            #[test]
            fn ownership_is_enforced_exactly_when_the_flag_is_clear(flags in any::<u32>()) {
                prop_assert_eq!(enforces_ownership(flags), flags & (1 << 21) == 0);
                let decided = require_ownership(Path::new("/a"), &|_: &Path| Ok(mount(flags)));
                prop_assert_eq!(decided.is_ok(), flags & (1 << 21) == 0);
            }

            /// Setting the flag always refuses, clearing it always accepts, on any flags.
            #[test]
            fn toggling_the_flag_toggles_the_verdict(flags in any::<u32>()) {
                let with = require_ownership(Path::new("/a"), &|_: &Path| Ok(mount(flags | MNT_IGNORE_OWNERSHIP)));
                let without = require_ownership(Path::new("/a"), &|_: &Path| Ok(mount(flags & !MNT_IGNORE_OWNERSHIP)));
                prop_assert!(with.is_err());
                prop_assert!(without.is_ok());
            }

            /// A failure to read the mount is refused with its reason, never accepted.
            #[test]
            fn an_unreadable_mount_is_always_refused_with_its_reason(reason in "[A-Za-z0-9 ]{1,16}") {
                let error = require_ownership(Path::new("/a"), &|_: &Path| Err(reason.clone())).unwrap_err();
                prop_assert!(error.contains(&reason));
            }
        }
    }
}
