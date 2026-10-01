//! The macOS ACL rule for the ancestors of an export (`reject_extended_acl`'s decision).
//!
//! Staged cleanup is safe only if no other user can add, delete or replace entries of an ancestor
//! of the export. An ACL entry lowers that safety only when it is an `allow` entry that gives a
//! principal other than the owner or root a mutating right. A `deny` entry only removes rights, and
//! a read-only `allow` entry cannot change a directory. (A standard macOS home directory carries
//! `group:everyone deny delete`, so refusing every extended ACL refused every export under it.)
//!
//! The classification of permissions is a table that a compile-time check holds equal to every
//! permission `exacl` knows: a permission added by a new `exacl` is a compile error, never silently
//! allowed. Anything not listed as read-only is a mutating right. The decision fails closed: an
//! ACL that cannot be read, an entry of an unknown kind, and a user that does not resolve are
//! refused.

use std::path::Path;

use exacl::{AclEntry, AclEntryKind, Perm};

/// What a permission lets a principal do to the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    /// Reading, listing, searching or waiting: the directory's entries cannot change.
    ReadOnly,
    /// Changing the directory, its entries, its attributes, its ACL or its owner.
    Mutating,
}

/// Every permission `exacl` has, with its name and effect. [`ALL_CLASSIFIED`] holds this table
/// equal to `Perm::all()` at compile time.
const PERMISSIONS: [(Perm, &str, Effect); 14] = [
    (Perm::READ, "read", Effect::ReadOnly),
    (Perm::WRITE, "write/add_file", Effect::Mutating),
    (Perm::EXECUTE, "execute", Effect::ReadOnly),
    (Perm::DELETE, "delete", Effect::Mutating),
    (Perm::APPEND, "append/add_subdirectory", Effect::Mutating),
    (Perm::DELETE_CHILD, "delete_child", Effect::Mutating),
    (Perm::READATTR, "readattr", Effect::ReadOnly),
    (Perm::WRITEATTR, "writeattr", Effect::Mutating),
    (Perm::READEXTATTR, "readextattr", Effect::ReadOnly),
    (Perm::WRITEEXTATTR, "writeextattr", Effect::Mutating),
    (Perm::READSECURITY, "readsecurity", Effect::ReadOnly),
    (Perm::WRITESECURITY, "writesecurity", Effect::Mutating),
    (Perm::CHOWN, "chown", Effect::Mutating),
    (Perm::SYNC, "sync", Effect::ReadOnly),
];

/// The union of the classified permissions.
const ALL_CLASSIFIED: u32 = {
    let mut bits = 0;
    let mut index = 0;
    while index < PERMISSIONS.len() {
        bits |= PERMISSIONS[index].0.bits();
        index += 1;
    }
    bits
};

// A permission `exacl` adds is not in the table: classify it above (a new right is mutating
// unless it is proven read-only).
const _: () = assert!(
    ALL_CLASSIFIED == Perm::all().bits(),
    "every exacl permission must be classified in PERMISSIONS"
);

/// The names of the mutating permissions in `perms`. No two permissions of the table share a bit
/// on macOS, so each right is named once.
fn mutating_names(perms: Perm) -> Vec<&'static str> {
    PERMISSIONS
        .iter()
        .filter(|(perm, _, effect)| *effect == Effect::Mutating && perms.contains(*perm))
        .map(|(_, name, _)| *name)
        .collect()
}

/// Who an entry is for, relative to the principals that already control the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Principal {
    /// The owner of the directory, root, or the user running the export.
    Trusted,
    /// Anyone else: another user, or any group (a group may hold other users).
    Other,
    /// A user that does not resolve, or an entry of an unknown kind.
    Unknown,
}

/// The users who control the directory anyway.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Trusted {
    pub(crate) owner: u32,
    pub(crate) effective: u32,
}

impl Trusted {
    fn contains(self, uid: u32) -> bool {
        uid == 0 || uid == self.owner || uid == self.effective
    }
}

fn principal(
    entry: &AclEntry,
    trusted: Trusted,
    resolve: &dyn Fn(&str) -> Option<u32>,
) -> Principal {
    match entry.kind {
        // A group is never one user: anyone in it holds the right.
        AclEntryKind::Group => Principal::Other,
        AclEntryKind::User => {
            let uid = entry
                .name
                .parse::<u32>()
                .ok()
                .or_else(|| resolve(&entry.name));
            match uid {
                Some(uid) if trusted.contains(uid) => Principal::Trusted,
                Some(_) => Principal::Other,
                None => Principal::Unknown,
            }
        }
        AclEntryKind::Unknown => Principal::Unknown,
    }
}

/// The first entry of `entries` that makes the directory unsafe, described by its principal and
/// permissions.
fn unsafe_entry(
    entries: &[AclEntry],
    trusted: Trusted,
    resolve: &dyn Fn(&str) -> Option<u32>,
) -> Option<String> {
    entries.iter().find_map(|entry| {
        // A deny entry only removes rights.
        if !entry.allow {
            return None;
        }
        let rights = mutating_names(entry.perms);
        // A read-only allow entry cannot change the directory.
        if rights.is_empty() {
            return None;
        }
        match principal(entry, trusted, resolve) {
            Principal::Trusted => None,
            Principal::Other | Principal::Unknown => Some(format!(
                "{}:{} allow {}",
                kind_name(entry.kind),
                entry.name,
                rights.join(",")
            )),
        }
    })
}

fn kind_name(kind: AclEntryKind) -> &'static str {
    match kind {
        AclEntryKind::User => "user",
        AclEntryKind::Group => "group",
        AclEntryKind::Unknown => "unknown",
    }
}

/// Resolves a user name to its uid through the system's user database.
fn resolve_user(name: &str) -> Option<u32> {
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
}

/// Refuses an ancestor whose ACL lets another principal change it.
pub(crate) fn reject_unsafe_acl(path: &Path, trusted: Trusted) -> Result<(), String> {
    check(
        path,
        trusted,
        &|path| exacl::getfacl(path, None),
        &resolve_user,
    )
}

/// [`reject_unsafe_acl`] with the ACL reader and the user resolver given.
pub(crate) fn check(
    path: &Path,
    trusted: Trusted,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<AclEntry>>,
    resolve: &dyn Fn(&str) -> Option<u32>,
) -> Result<(), String> {
    let entries = read(path).map_err(|error| {
        format!(
            "cannot inspect the ACL on export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    match unsafe_entry(&entries, trusted, resolve) {
        None => Ok(()),
        Some(entry) => Err(format!(
            "export namespace ancestor {} has an extended ACL entry ({entry}) that lets another principal change it, so staged cleanup cannot be made safe; export to a directory whose ancestors carry no such entry, for example one under $TMPDIR",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUSTED: Trusted = Trusted {
        owner: 501,
        effective: 501,
    };

    fn resolve(name: &str) -> Option<u32> {
        match name {
            "alice" => Some(501),
            "bob" => Some(502),
            "root" => Some(0),
            _ => None,
        }
    }

    fn unsafe_of(entries: &[AclEntry]) -> Option<String> {
        unsafe_entry(entries, TRUSTED, &resolve)
    }

    fn allow_group(name: &str, perms: Perm) -> AclEntry {
        AclEntry::allow_group(name, perms, None)
    }

    fn allow_user(name: &str, perms: Perm) -> AclEntry {
        AclEntry::allow_user(name, perms, None)
    }

    #[test]
    fn the_standard_home_acl_is_accepted() {
        let home = [AclEntry::deny_group("everyone", Perm::DELETE, None)];
        assert_eq!(unsafe_of(&home), None);
    }

    #[test]
    fn every_deny_entry_is_accepted_whatever_it_denies() {
        let all = [
            AclEntry::deny_group("everyone", Perm::all(), None),
            AclEntry::deny_user("bob", Perm::all(), None),
            AclEntry::deny_user("nobody-here", Perm::all(), None),
        ];
        assert_eq!(unsafe_of(&all), None);
    }

    #[test]
    fn a_read_only_allow_is_accepted_for_anyone() {
        for perms in [
            Perm::READ,
            Perm::EXECUTE,
            Perm::READATTR,
            Perm::READEXTATTR,
            Perm::READSECURITY,
            Perm::SYNC,
            Perm::READ | Perm::EXECUTE | Perm::READATTR,
        ] {
            assert_eq!(
                unsafe_of(&[allow_group("everyone", perms)]),
                None,
                "{perms:?}"
            );
            assert_eq!(unsafe_of(&[allow_user("bob", perms)]), None, "{perms:?}");
            assert_eq!(
                unsafe_of(&[allow_user("nobody-here", perms)]),
                None,
                "{perms:?}"
            );
        }
    }

    #[test]
    fn each_permission_is_classified_by_its_effect() {
        for (perm, name, effect) in PERMISSIONS {
            let refused = unsafe_of(&[allow_group("everyone", perm)]);
            match effect {
                Effect::Mutating => {
                    let refused = refused.unwrap_or_else(|| panic!("{name} was accepted"));
                    assert!(refused.starts_with("group:everyone allow "), "{refused}");
                }
                Effect::ReadOnly => assert_eq!(refused, None, "{name}"),
            }
        }
    }

    #[test]
    fn a_mixed_entry_is_refused_and_names_only_the_mutating_rights() {
        let entry = allow_group("everyone", Perm::READ | Perm::WRITE | Perm::DELETE_CHILD);
        assert_eq!(
            unsafe_of(&[entry]).as_deref(),
            Some("group:everyone allow write/add_file,delete_child")
        );
    }

    #[test]
    fn the_owner_root_and_the_current_user_may_hold_mutating_rights() {
        for name in ["alice", "root", "501", "0"] {
            assert_eq!(unsafe_of(&[allow_user(name, Perm::all())]), None, "{name}");
        }
        // The owner of the directory and the user running the export are trusted each on their own.
        let distinct = Trusted {
            owner: 501,
            effective: 502,
        };
        assert_eq!(
            unsafe_entry(&[allow_user("bob", Perm::WRITE)], distinct, &resolve),
            None,
            "the current user"
        );
        assert_eq!(
            unsafe_entry(&[allow_user("alice", Perm::WRITE)], distinct, &resolve),
            None,
            "the owner"
        );
        assert!(
            unsafe_entry(&[allow_user("carol", Perm::WRITE)], distinct, &|_| Some(
                503
            ))
            .is_some(),
            "a third user"
        );
    }

    #[test]
    fn another_user_with_a_mutating_right_is_refused() {
        assert_eq!(
            unsafe_of(&[allow_user("bob", Perm::WRITE)]).as_deref(),
            Some("user:bob allow write/add_file")
        );
        assert!(unsafe_of(&[allow_user("503", Perm::DELETE)]).is_some());
    }

    #[test]
    fn a_group_with_a_mutating_right_is_refused_even_the_root_group() {
        assert!(unsafe_of(&[allow_group("wheel", Perm::DELETE_CHILD)]).is_some());
        assert!(unsafe_of(&[allow_group("admin", Perm::CHOWN)]).is_some());
    }

    #[test]
    fn a_user_that_does_not_resolve_is_refused_when_it_holds_a_mutating_right() {
        assert_eq!(
            unsafe_of(&[allow_user("nobody-here", Perm::APPEND)]).as_deref(),
            Some("user:nobody-here allow append/add_subdirectory")
        );
    }

    #[test]
    fn an_entry_of_an_unknown_kind_is_refused_when_it_holds_a_mutating_right() {
        let mut entry = allow_user("alice", Perm::WRITE);
        entry.kind = AclEntryKind::Unknown;
        assert_eq!(
            unsafe_of(&[entry]).as_deref(),
            Some("unknown:alice allow write/add_file")
        );
    }

    #[test]
    fn inheritance_flags_do_not_make_a_risky_entry_safe() {
        let mut entry = allow_group("everyone", Perm::WRITE);
        entry.flags = exacl::Flag::FILE_INHERIT | exacl::Flag::ONLY_INHERIT;
        assert!(unsafe_of(&[entry]).is_some());
    }

    #[test]
    fn the_first_unsafe_entry_is_reported_after_safe_ones() {
        let entries = [
            AclEntry::deny_group("everyone", Perm::DELETE, None),
            allow_group("everyone", Perm::READ),
            allow_user("bob", Perm::DELETE_CHILD),
        ];
        assert_eq!(
            unsafe_of(&entries).as_deref(),
            Some("user:bob allow delete_child")
        );
    }

    #[test]
    fn an_acl_that_cannot_be_read_is_refused() {
        let error = check(
            Path::new("/ancestor"),
            TRUSTED,
            &|_| Err(std::io::Error::other("unreadable")),
            &resolve,
        )
        .unwrap_err();
        assert!(error.contains("cannot inspect the ACL"), "{error}");
        assert!(error.contains("/ancestor"), "{error}");
    }

    #[test]
    fn the_diagnostic_names_the_entry_and_a_workaround() {
        let error = check(
            Path::new("/ancestor"),
            TRUSTED,
            &|_| Ok(vec![allow_group("everyone", Perm::WRITE)]),
            &resolve,
        )
        .unwrap_err();
        assert!(error.contains("extended ACL"), "{error}");
        assert!(
            error.contains("group:everyone allow write/add_file"),
            "{error}"
        );
        assert!(error.contains("$TMPDIR"), "{error}");
    }

    #[test]
    fn an_empty_acl_is_accepted() {
        assert_eq!(
            check(Path::new("/a"), TRUSTED, &|_| Ok(Vec::new()), &resolve),
            Ok(())
        );
    }
}
