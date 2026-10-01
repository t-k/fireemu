//! The macOS ACL rule for the ancestors of an export (`reject_unsafe_acl`'s decision).
//!
//! Staged cleanup is safe only if no other principal can add, delete or replace entries of an
//! ancestor of the export. The rule refuses every `allow` entry of a principal that is not the
//! owner of the directory, root or the user running the export, whatever permissions `exacl`
//! reports for it, and accepts `deny` entries (they only remove rights) and the entries of those
//! trusted principals. A standard macOS home directory carries `group:everyone deny delete`, so
//! this accepts it; refusing every extended ACL refused every export under it.
//!
//! The rule does not read the permissions of an `allow` entry, on purpose: the kernel also grants
//! rights `exacl` cannot report (`KAUTH_ACE_GENERIC_ALL`, `GENERIC_WRITE`, ... are expanded when
//! the ACL is evaluated, and `exacl` shows such an entry with no permissions at all). An `allow`
//! entry that looks harmless to `exacl` is therefore not proven harmless. The decision fails
//! closed: an ACL that cannot be read, an entry of an unknown kind and a principal that is not
//! one of the trusted users are refused.

use std::path::Path;

use exacl::{AclEntry, AclEntryKind};

/// The principals that already control a directory, by the names `exacl` reports for them.
///
/// A name is compared as a whole against the name the user database gives each trusted uid; no
/// name is parsed as a number or looked up again, so a user whose name is a digit string, or an
/// alias of another account, is not mistaken for a trusted uid.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Trusted {
    names: Vec<String>,
}

impl Trusted {
    /// The users that control a directory anyway: root, its owner and the user running the export.
    /// A uid the user database does not know contributes no name, so no entry is trusted for it.
    pub(crate) fn of_uids(
        owner: u32,
        effective: u32,
        name_of: &dyn Fn(u32) -> Option<String>,
    ) -> Self {
        let mut names = Vec::new();
        for uid in [0, owner, effective] {
            if let Some(name) = name_of(uid) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        Self { names }
    }

    fn contains(&self, name: &str) -> bool {
        self.names.iter().any(|trusted| trusted == name)
    }
}

/// The name the system's user database gives `uid`.
pub(crate) fn user_name(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

fn kind_name(kind: AclEntryKind) -> &'static str {
    match kind {
        AclEntryKind::User => "user",
        AclEntryKind::Group => "group",
        AclEntryKind::Unknown => "unknown",
    }
}

/// How an entry that makes the directory unsafe is shown: its principal and the permissions
/// `exacl` can see.
fn describe(entry: &AclEntry) -> String {
    let allow = if entry.allow { "allow" } else { "deny" };
    if entry.perms.is_empty() {
        format!(
            "{}:{} {allow} (no permissions are visible, which the kernel may still expand)",
            kind_name(entry.kind),
            entry.name
        )
    } else {
        format!(
            "{}:{} {allow} {}",
            kind_name(entry.kind),
            entry.name,
            entry.perms
        )
    }
}

/// The first entry of `entries` that makes the directory unsafe, described.
fn unsafe_entry(entries: &[AclEntry], trusted: &Trusted) -> Option<String> {
    entries.iter().find_map(|entry| {
        // An entry of an unknown kind cannot be judged, whatever `allow` says (`exacl` reports an
        // unknown tag as `allow == false`).
        if entry.kind == AclEntryKind::Unknown {
            return Some(describe(entry));
        }
        // A deny entry only removes rights.
        if !entry.allow {
            return None;
        }
        // An allow entry is safe only for a user that controls the directory anyway; a group is
        // never one user.
        if entry.kind == AclEntryKind::User && trusted.contains(&entry.name) {
            return None;
        }
        Some(describe(entry))
    })
}

/// Refuses an ancestor whose ACL lets another principal change it.
pub(crate) fn reject_unsafe_acl(path: &Path, trusted: &Trusted) -> Result<(), String> {
    check(path, trusted, &|path| exacl::getfacl(path, None))
}

/// [`reject_unsafe_acl`] with the ACL reader given.
pub(crate) fn check(
    path: &Path,
    trusted: &Trusted,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<AclEntry>>,
) -> Result<(), String> {
    let entries = read(path).map_err(|error| {
        format!(
            "cannot inspect the ACL on export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    match unsafe_entry(&entries, trusted) {
        None => Ok(()),
        Some(entry) => Err(format!(
            "export namespace ancestor {} has an extended ACL entry ({entry}) that may let another principal change it, so staged cleanup cannot be made safe; remove the entry (`chmod -a`), or export to a directory whose ancestors carry no allow entry, for example one under $TMPDIR",
            path.display()
        )),
    }
}

/// Clears the ACL of a stage just created, whatever it inherited from its parent, and checks that
/// it is empty: an inherited `allow` entry would make the export readable by others, and an
/// inherited `deny delete` would stop the rename and the cleanup.
pub(crate) fn clear_stage_acl(stage: &Path) -> Result<(), String> {
    let cleared = exacl::setfacl(&[stage], &[], None).map_err(|error| error.to_string());
    let left = exacl::getfacl(stage, None).map_err(|error| error.to_string());
    settle_stage_acl(cleared, left)
}

/// Decides from what the stage holds *after* the clear, never from the clear alone: a volume without
/// ACL support (exFAT, FAT: a USB stick, an SD card) fails `setfacl` with ENOTSUP, but nothing can be
/// inherited there, so a stage that reads back empty is safe. A stage that still has an entry, or
/// whose ACL cannot be read, is refused (a network filesystem may accept the call and keep the entry).
fn settle_stage_acl(
    cleared: Result<(), String>,
    left: Result<Vec<AclEntry>, String>,
) -> Result<(), String> {
    let clearing = cleared.err();
    match left {
        Ok(entries) if entries.is_empty() => Ok(()),
        Ok(_) => Err(match clearing {
            None => "the export stage still has an ACL after it was cleared".to_owned(),
            Some(error) => {
                format!("the export stage still has an ACL, and it could not be cleared: {error}")
            }
        }),
        Err(read) => Err(match clearing {
            None => format!("cannot inspect the ACL of the export stage: {read}"),
            Some(error) => format!(
                "cannot clear the ACL of the export stage ({error}) nor inspect it ({read})"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exacl::Perm;

    fn trusted() -> Trusted {
        Trusted::of_uids(501, 502, &|uid| match uid {
            0 => Some("root".to_owned()),
            501 => Some("alice".to_owned()),
            502 => Some("bob".to_owned()),
            _ => None,
        })
    }

    fn unsafe_of(entries: &[AclEntry]) -> Option<String> {
        unsafe_entry(entries, &trusted())
    }

    fn allow_group(name: &str, perms: Perm) -> AclEntry {
        AclEntry::allow_group(name, perms, None)
    }

    fn allow_user(name: &str, perms: Perm) -> AclEntry {
        AclEntry::allow_user(name, perms, None)
    }

    #[test]
    fn a_stage_that_reads_back_empty_is_settled_whether_or_not_the_clear_worked() {
        let unsupported = || Err("Operation not supported (os error 45)".to_owned());
        assert_eq!(settle_stage_acl(Ok(()), Ok(Vec::new())), Ok(()));
        assert_eq!(settle_stage_acl(unsupported(), Ok(Vec::new())), Ok(()));
    }

    #[test]
    fn a_stage_that_still_has_an_entry_is_refused_with_the_clear_error_attached() {
        let entry = || vec![AclEntry::deny_group("everyone", Perm::DELETE, None)];
        let plain = settle_stage_acl(Ok(()), Ok(entry())).unwrap_err();
        assert!(
            plain.contains("still has an ACL after it was cleared"),
            "{plain}"
        );
        let failed =
            settle_stage_acl(Err("Operation not supported".to_owned()), Ok(entry())).unwrap_err();
        assert!(failed.contains("could not be cleared"), "{failed}");
        assert!(failed.contains("Operation not supported"), "{failed}");
    }

    #[test]
    fn a_stage_whose_acl_cannot_be_read_is_refused_with_both_errors() {
        let only_read = settle_stage_acl(Ok(()), Err("EIO".to_owned())).unwrap_err();
        assert!(only_read.contains("cannot inspect the ACL"), "{only_read}");
        assert!(only_read.contains("EIO"), "{only_read}");
        let both = settle_stage_acl(Err("ENOTSUP".to_owned()), Err("EIO".to_owned())).unwrap_err();
        assert!(both.contains("ENOTSUP") && both.contains("EIO"), "{both}");
    }

    /// A directory that holds a real ACL entry and cannot be changed (`chflags uchg`), so `setfacl`
    /// fails while the entry stays: the case a network filesystem presents. Restored on drop.
    struct ImmutableWithAcl(std::path::PathBuf);

    impl ImmutableWithAcl {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fireemu-acl-immutable-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir(&path);
            std::fs::create_dir(&path).expect("create the directory");
            let guard = Self(path);
            for args in [
                vec![
                    "chmod".to_owned(),
                    "+a".to_owned(),
                    "everyone deny delete".to_owned(),
                ],
                vec!["chflags".to_owned(), "uchg".to_owned()],
            ] {
                let status = std::process::Command::new(&args[0])
                    .args(&args[1..])
                    .arg(&guard.0)
                    .status()
                    .expect("run the tool");
                assert!(status.success(), "{args:?}");
            }
            guard
        }
    }

    impl Drop for ImmutableWithAcl {
        fn drop(&mut self) {
            let _ = std::process::Command::new("chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status();
            let _ = std::process::Command::new("chmod")
                .arg("-N")
                .arg(&self.0)
                .status();
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn a_stage_whose_acl_cannot_be_cleared_and_stays_is_refused_with_the_clear_error() {
        let stage = ImmutableWithAcl::new();
        let error = clear_stage_acl(&stage.0).unwrap_err();
        assert!(error.contains("still has an ACL"), "{error}");
        assert!(error.contains("could not be cleared"), "{error}");
    }

    #[test]
    fn a_stage_that_can_be_neither_cleared_nor_read_is_refused_with_both_errors() {
        let missing = std::env::temp_dir().join(format!(
            "fireemu-acl-missing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let error = clear_stage_acl(&missing).unwrap_err();
        assert!(error.contains("nor inspect it"), "{error}");
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
            AclEntry::deny_user("carol", Perm::all(), None),
            AclEntry::deny_user("carol", Perm::empty(), None),
        ];
        assert_eq!(unsafe_of(&all), None);
    }

    /// The kernel expands rights `exacl` cannot report, so an allow entry is refused whatever
    /// permissions are visible, an empty set and the read-only ones included.
    #[test]
    fn an_allow_entry_of_an_untrusted_principal_is_refused_whatever_permissions_are_visible() {
        let every = [
            Perm::empty(),
            Perm::READ,
            Perm::EXECUTE,
            Perm::READATTR,
            Perm::READEXTATTR,
            Perm::READSECURITY,
            Perm::SYNC,
            Perm::READ | Perm::EXECUTE,
            Perm::WRITE,
            Perm::DELETE_CHILD,
            Perm::all(),
        ];
        for perms in every {
            assert!(
                unsafe_of(&[allow_group("everyone", perms)]).is_some(),
                "group {perms:?}"
            );
            assert!(
                unsafe_of(&[allow_user("carol", perms)]).is_some(),
                "user {perms:?}"
            );
        }
    }

    #[test]
    fn an_empty_rights_allow_entry_is_refused_and_says_why() {
        let refused = unsafe_of(&[allow_user("carol", Perm::empty())]).unwrap();
        assert_eq!(
            refused,
            "user:carol allow (no permissions are visible, which the kernel may still expand)"
        );
    }

    #[test]
    fn the_trusted_users_may_hold_any_allow_entry() {
        for name in ["root", "alice", "bob"] {
            for perms in [Perm::empty(), Perm::READ, Perm::all()] {
                assert_eq!(
                    unsafe_of(&[allow_user(name, perms)]),
                    None,
                    "{name} {perms:?}"
                );
            }
        }
    }

    #[test]
    fn a_group_named_like_a_trusted_user_is_not_trusted() {
        assert!(unsafe_of(&[allow_group("alice", Perm::READ)]).is_some());
        assert!(unsafe_of(&[allow_group("root", Perm::READ)]).is_some());
    }

    /// A name is not read as a number: the digits of a trusted uid, a signed number or a name with
    /// different case do not make a user trusted.
    #[test]
    fn a_numeric_or_differently_spelled_name_is_not_a_trusted_user() {
        for name in [
            "501", "+501", "0", "+0", "502", "Alice", "ALICE", "alice ", " alice", "",
        ] {
            assert!(
                unsafe_of(&[allow_user(name, Perm::READ)]).is_some(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_trusted_uid_the_user_database_does_not_know_trusts_no_name() {
        let none = Trusted::of_uids(501, 502, &|_| None);
        assert!(unsafe_entry(&[allow_user("root", Perm::READ)], &none).is_some());
        assert!(unsafe_entry(&[allow_user("501", Perm::READ)], &none).is_some());
    }

    #[test]
    fn the_owner_and_the_current_user_are_each_trusted() {
        let owner_only = Trusted::of_uids(501, 999, &|uid| match uid {
            0 => Some("root".to_owned()),
            501 => Some("alice".to_owned()),
            _ => None,
        });
        assert_eq!(
            unsafe_entry(&[allow_user("alice", Perm::WRITE)], &owner_only),
            None,
            "the owner"
        );
        let effective_only = Trusted::of_uids(999, 502, &|uid| match uid {
            0 => Some("root".to_owned()),
            502 => Some("bob".to_owned()),
            _ => None,
        });
        assert_eq!(
            unsafe_entry(&[allow_user("bob", Perm::WRITE)], &effective_only),
            None,
            "the user"
        );
        assert!(unsafe_entry(&[allow_user("alice", Perm::WRITE)], &effective_only).is_some());
    }

    /// `exacl` reports an unknown tag as `allow == false`: it is refused all the same, and an
    /// unknown kind that claims `allow` too.
    #[test]
    fn an_entry_of_an_unknown_kind_is_refused_in_either_shape() {
        for allow in [false, true] {
            let mut entry = allow_user("alice", Perm::empty());
            entry.kind = AclEntryKind::Unknown;
            entry.allow = allow;
            assert!(unsafe_of(&[entry]).is_some(), "allow={allow}");
        }
    }

    #[test]
    fn inheritance_flags_do_not_make_an_allow_entry_safe() {
        let mut entry = allow_group("everyone", Perm::READ);
        entry.flags = exacl::Flag::FILE_INHERIT | exacl::Flag::ONLY_INHERIT;
        assert!(unsafe_of(&[entry]).is_some());
    }

    #[test]
    fn the_first_unsafe_entry_is_reported_after_safe_ones() {
        let entries = [
            AclEntry::deny_group("everyone", Perm::DELETE, None),
            allow_user("alice", Perm::all()),
            allow_user("carol", Perm::empty()),
            allow_group("staff", Perm::WRITE),
        ];
        let refused = unsafe_of(&entries).unwrap();
        assert!(refused.starts_with("user:carol allow"), "{refused}");
    }

    #[test]
    fn an_acl_that_cannot_be_read_is_refused() {
        let error = check(Path::new("/ancestor"), &trusted(), &|_| {
            Err(std::io::Error::other("unreadable"))
        })
        .unwrap_err();
        assert!(error.contains("cannot inspect the ACL"), "{error}");
        assert!(error.contains("/ancestor"), "{error}");
    }

    #[test]
    fn the_diagnostic_names_the_entry_and_a_workaround() {
        let error = check(Path::new("/ancestor"), &trusted(), &|_| {
            Ok(vec![allow_group(
                "everyone",
                Perm::WRITE | Perm::DELETE_CHILD,
            )])
        })
        .unwrap_err();
        assert!(error.contains("extended ACL"), "{error}");
        assert!(error.contains("group:everyone allow"), "{error}");
        assert!(error.contains("delete_child"), "{error}");
        assert!(error.contains("chmod -a"), "{error}");
        assert!(error.contains("$TMPDIR"), "{error}");
    }

    #[test]
    fn an_empty_acl_is_accepted() {
        assert_eq!(
            check(Path::new("/a"), &trusted(), &|_| Ok(Vec::new())),
            Ok(())
        );
    }

    /// Properties over random ACL entry lists. The oracle restates the rule independently of
    /// `unsafe_entry`: a list is refused if and only if some entry is of an unknown kind or is an
    /// allow entry of anyone but a trusted user.
    mod properties {
        use super::*;
        use proptest::prelude::*;

        const TRUSTED_NAMES: [&str; 3] = ["root", "alice", "bob"];

        fn kind() -> impl Strategy<Value = AclEntryKind> {
            prop_oneof![
                Just(AclEntryKind::User),
                Just(AclEntryKind::Group),
                Just(AclEntryKind::Unknown)
            ]
        }

        fn name() -> impl Strategy<Value = String> {
            prop_oneof![
                prop::sample::select(TRUSTED_NAMES.to_vec()).prop_map(str::to_owned),
                prop::sample::select(vec![
                    "carol", "nobody", "everyone", "staff", "501", "+0", "Alice", ""
                ])
                .prop_map(str::to_owned),
                "[a-z0-9_+ -]{0,8}",
            ]
        }

        fn entry() -> impl Strategy<Value = AclEntry> {
            (kind(), name(), any::<u32>(), any::<bool>(), any::<u32>()).prop_map(
                |(kind, name, perms, allow, flags)| AclEntry {
                    kind,
                    name,
                    perms: Perm::from_bits_truncate(perms),
                    flags: exacl::Flag::from_bits_truncate(flags),
                    allow,
                },
            )
        }

        fn entries() -> impl Strategy<Value = Vec<AclEntry>> {
            prop::collection::vec(entry(), 0..8)
        }

        fn is_trusted_user(entry: &AclEntry) -> bool {
            entry.kind == AclEntryKind::User && TRUSTED_NAMES.contains(&entry.name.as_str())
        }

        fn refuses(entry: &AclEntry) -> bool {
            entry.kind == AclEntryKind::Unknown || (entry.allow && !is_trusted_user(entry))
        }

        /// The entry changed into one the rule accepts: a known kind, and a deny unless the user is
        /// trusted.
        fn made_safe(mut entry: AclEntry) -> AclEntry {
            if entry.kind == AclEntryKind::Unknown {
                entry.kind = AclEntryKind::User;
            }
            if entry.allow && !is_trusted_user(&entry) {
                entry.allow = false;
            }
            entry
        }

        fn decide(list: &[AclEntry]) -> Result<(), String> {
            check(Path::new("/ancestor"), &trusted(), &|_| Ok(list.to_vec()))
        }

        proptest! {
            /// The stage is settled if and only if it reads back empty, whatever the clear reported;
            /// every refusal names each error it was given.
            #[test]
            fn the_stage_is_settled_exactly_when_it_reads_back_empty(
                cleared in prop_oneof![Just(Ok(())), "[A-Za-z0-9 ]{1,12}".prop_map(Err)],
                left in prop_oneof![
                    entries().prop_map(Ok),
                    "[A-Za-z0-9 ]{1,12}".prop_map(Err),
                ],
            ) {
                let empty = matches!(&left, Ok(list) if list.is_empty());
                let verdict = settle_stage_acl(cleared.clone(), left.clone());
                prop_assert_eq!(verdict.is_ok(), empty);
                if let Err(message) = verdict {
                    if let Err(error) = &cleared {
                        prop_assert!(message.contains(error.as_str()), "{message}");
                    }
                    if let Err(error) = &left {
                        prop_assert!(message.contains(error.as_str()), "{message}");
                    }
                }
            }
        }

        proptest! {
            /// Refused if and only if some entry is an unknown kind or an untrusted allow.
            #[test]
            fn the_list_is_refused_exactly_when_an_entry_is_unsafe(list in entries()) {
                prop_assert_eq!(decide(&list).is_err(), list.iter().any(refuses));
            }

            /// A deny entry, or an allow entry of a trusted user, never makes an accepted list refused.
            #[test]
            fn adding_a_safe_entry_keeps_an_accepted_list_accepted(
                list in entries().prop_map(|list| list.into_iter().map(made_safe).collect::<Vec<_>>()),
                extra in entry(),
                at in any::<prop::sample::Index>(),
            ) {
                prop_assert!(decide(&list).is_ok());
                let mut grown = list.clone();
                grown.insert(at.index(list.len() + 1), made_safe(extra));
                prop_assert!(decide(&grown).is_ok());
            }

            /// An allow entry of an untrusted principal, or one of an unknown kind, always makes the
            /// list refused, wherever it sits.
            #[test]
            fn adding_an_unsafe_entry_always_refuses(
                list in entries(),
                extra in entry(),
                at in any::<prop::sample::Index>(),
                unknown_kind in any::<bool>(),
            ) {
                let mut risky = extra;
                if unknown_kind {
                    risky.kind = AclEntryKind::Unknown;
                } else {
                    risky.allow = true;
                    if risky.kind == AclEntryKind::Unknown {
                        risky.kind = AclEntryKind::User;
                    }
                    if is_trusted_user(&risky) {
                        risky.name = "carol".to_owned();
                    }
                }
                let mut grown = list.clone();
                grown.insert(at.index(list.len() + 1), risky);
                prop_assert!(decide(&grown).is_err());
            }

            /// The diagnostic names the first refusing entry, by kind and principal.
            #[test]
            fn the_diagnostic_names_the_first_refusing_entry(list in entries()) {
                if let Some(first) = list.iter().find(|entry| refuses(entry)) {
                    let error = decide(&list).unwrap_err();
                    let named = format!("{}:{} ", kind_name(first.kind), first.name);
                    prop_assert!(error.contains(&named), "{error} lacks {named}");
                    prop_assert!(error.contains("/ancestor"));
                    prop_assert!(error.contains("extended ACL"));
                }
            }

            /// An ACL that cannot be read is always refused, whatever it would have held.
            #[test]
            fn an_unreadable_acl_is_always_refused(_seed in any::<u8>()) {
                let error = check(Path::new("/ancestor"), &trusted(), &|_| {
                    Err(std::io::Error::other("unreadable"))
                })
                .unwrap_err();
                prop_assert!(error.contains("cannot inspect the ACL"));
            }
        }
    }
}
