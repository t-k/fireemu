//! Which configuration files `up` and `exec` load when neither `--config` nor `--firebase-json`
//! is given.
//!
//! A `fireemu.toml` or `fireemu.json` is looked for in the working directory only: its paths (`rules.source`,
//! `storage.rules`, `functions.source`) are read relative to the working directory, so one
//! found in a parent would point at the wrong files. A `firebase.json` is looked for the way
//! firebase-tools 15.28.2 finds it (`detectProjectRoot`): in the working directory, then in
//! each parent up to the filesystem root, and the first one found wins. Its paths are relative
//! to its own directory, which is also where `.firebaserc` is read from.
//!
//! Unlike firebase-tools, the search only loads files that a trusted user owns, because a
//! discovered file can name Functions code to run and the rules to enforce. The rule follows
//! git's ownership check (`safe.directory`). The trusted owners are the effective user, root,
//! and, when the effective user is root, the user `sudo` names in `SUDO_UID`.
//! - A candidate file whose owner is not trusted, or that any user can write, is skipped.
//!   Group write is allowed, because user-private groups (umask 002) make it the norm on
//!   Debian and Ubuntu.
//! - The walk stops before a parent directory whose owner is not trusted or that any user can
//!   write, such as `/tmp`.
//! - The working directory's owner is not checked, because the user chose to run there. A
//!   working directory any user can write is not searched at all.
//!
//! - The walk also stops, silently, at a parent it cannot inspect (one it may not enter).
//! - `.firebaserc` names only project and target aliases, never code or rules, so it is refused
//!   only when it, or its directory, can be written by any user.
//!
//! A skipped file ends the search as if nothing had been found, and the caller names it. Each
//! candidate is opened once: its owner and mode are read from the open handle and judged first,
//! and only then is its text read from the same handle, at most 16 MiB, so the decision and the
//! read see the same file and an untrusted file is never read. A symbolic link is judged by
//! its target, and the directory holding the target is not checked. Off Unix nothing is checked.
//! Files named with `--config` or `--firebase-json` are not checked either.

use std::path::{Path, PathBuf};

/// The canonical configuration file name.
pub(crate) const CANONICAL_FILE: &str = "fireemu.toml";
/// The legacy JSON configuration file name.
pub(crate) const JSON_FILE: &str = "fireemu.json";
/// The Firebase project configuration file name.
pub(crate) const FIREBASE_FILE: &str = "firebase.json";
/// The Firebase project aliases file name.
pub(crate) const FIREBASERC_FILE: &str = ".firebaserc";

/// The owner and the permission bits of a path, and whether it is a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stat {
    pub(crate) owner: u32,
    pub(crate) mode: u32,
    pub(crate) is_file: bool,
}

/// Whose files the search trusts: the effective user and root, and the user `sudo` ran as when
/// the effective user is root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Trust {
    pub(crate) euid: u32,
    pub(crate) sudo_uid: Option<u32>,
}

impl Trust {
    /// The trust of a process with effective user `euid` and the `SUDO_UID` value `sudo_uid`; a
    /// value that is not a user ID is ignored, and so is any value unless `euid` is root.
    pub(crate) fn new(euid: u32, sudo_uid: Option<&str>) -> Self {
        Self {
            euid,
            sudo_uid: if euid == 0 {
                sudo_uid.and_then(|text| text.parse().ok())
            } else {
                None
            },
        }
    }

    /// Whether files and directories `owner` owns are trusted.
    pub(crate) fn trusts(&self, owner: u32) -> bool {
        owner == self.euid || owner == 0 || Some(owner) == self.sudo_uid
    }
}

/// Why a candidate file may not be loaded, or `None` when it may.
pub(crate) fn untrusted_file(stat: &Stat, trust: &Trust) -> Option<String> {
    if !trust.trusts(stat.owner) {
        Some(format!(
            "is owned by an untrusted user (uid {})",
            stat.owner
        ))
    } else if stat.mode & 0o002 != 0 {
        Some("can be written by any user".to_owned())
    } else {
        None
    }
}

/// Why a directory may not be searched, or `None` when it may. The working directory's owner is
/// not checked.
pub(crate) fn untrusted_directory(stat: &Stat, trust: &Trust, working: bool) -> Option<String> {
    if !working && !trust.trusts(stat.owner) {
        Some(format!(
            "is owned by an untrusted user (uid {})",
            stat.owner
        ))
    } else if stat.mode & 0o002 != 0 {
        Some("can be written by any user".to_owned())
    } else {
        None
    }
}

/// The most a discovered file may hold. A larger one is refused rather than read, so a huge
/// (for example sparse) file cannot exhaust memory at startup.
pub(crate) const MAX_DISCOVERED_BYTES: u64 = 16 * 1024 * 1024;

/// A candidate opened once: its metadata from the open handle, and the read of its text from the
/// same handle, which runs only after the candidate has been judged.
pub(crate) struct Opened {
    pub(crate) stat: Stat,
    read: Box<dyn FnOnce() -> Result<String, String>>,
}

impl Opened {
    pub(crate) fn new(stat: Stat, read: impl FnOnce() -> Result<String, String> + 'static) -> Self {
        Self {
            stat,
            read: Box::new(read),
        }
    }

    /// Reads the text from the handle the candidate was judged by.
    pub(crate) fn read(self) -> Result<String, String> {
        (self.read)()
    }
}

/// What the search found. A found file carries the text it was judged by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Discovered {
    /// `fireemu.toml` or `fireemu.json` in the working directory: loaded as `--config` would load it.
    Canonical(PathBuf, Result<String, String>),
    /// The nearest `firebase.json`: loaded as `--firebase-json` would load it.
    FirebaseJson(PathBuf, Result<String, String>),
    /// Neither file: the built-in defaults apply.
    Nothing,
}

/// A candidate the search did not load, or a directory it did not search, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Skipped {
    pub(crate) path: PathBuf,
    pub(crate) reason: String,
}

/// The search's result: what it found, or what it refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Discovery {
    pub(crate) found: Discovered,
    pub(crate) skipped: Option<Skipped>,
}

/// Searches from the absolute working directory `cwd`. `stat` reads a directory's metadata,
/// `open` opens a candidate once (following symbolic links) and answers `None` when there is
/// no regular file to open. A file in the working directory is returned as a bare file name, one
/// in a parent as an absolute path.
pub(crate) fn discover(
    cwd: &Path,
    trust: &Trust,
    stat: impl Fn(&Path) -> Option<Stat>,
    open: impl Fn(&Path) -> Option<Opened>,
) -> Discovery {
    let nothing = |skipped| Discovery {
        found: Discovered::Nothing,
        skipped,
    };
    for (depth, dir) in cwd.ancestors().enumerate() {
        let working = depth == 0;
        let directory_reason = match stat(dir) {
            Some(dir_stat) => untrusted_directory(&dir_stat, trust, working),
            None => return nothing(None),
        };
        if working {
            if let Some(reason) = directory_reason {
                // A working directory anyone can write is not searched, whatever it holds.
                return nothing(Some(Skipped {
                    path: dir.to_path_buf(),
                    reason: format!("{reason}, so it is not searched"),
                }));
            }
        }
        let names: &[&str] = if working {
            &[CANONICAL_FILE, JSON_FILE, FIREBASE_FILE]
        } else {
            &[FIREBASE_FILE]
        };
        for name in names {
            let candidate = dir.join(name);
            let shown = if working {
                PathBuf::from(name)
            } else {
                candidate.clone()
            };
            if let Some(reason) = &directory_reason {
                // A parent the walk may not search: say so only when it holds a candidate.
                if stat(&candidate).is_some_and(|s| s.is_file) {
                    return nothing(Some(Skipped {
                        path: shown,
                        reason: format!("is in {}, which {reason}", dir.display()),
                    }));
                }
                continue;
            }
            let Some(opened) = open(&candidate).filter(|o| o.stat.is_file) else {
                continue;
            };
            if *name == CANONICAL_FILE && open(&dir.join(JSON_FILE)).is_some_and(|o| o.stat.is_file)
            {
                return Discovery {
                    found: Discovered::Canonical(shown, Err(format!("both {CANONICAL_FILE} and {JSON_FILE} exist; remove one or select a file with --config"))),
                    skipped: None,
                };
            }
            if let Some(reason) = untrusted_file(&opened.stat, trust) {
                return nothing(Some(Skipped {
                    path: shown,
                    reason,
                }));
            }
            return Discovery {
                found: if *name == CANONICAL_FILE || *name == JSON_FILE {
                    Discovered::Canonical(shown, opened.read())
                } else {
                    Discovered::FirebaseJson(shown, opened.read())
                },
                skipped: None,
            };
        }
        // The walk never searches above a directory it could not search.
        if directory_reason.is_some() {
            return nothing(None);
        }
    }
    nothing(None)
}

/// Reads the `.firebaserc` in `dir` (the discovered project directory, or the working directory
/// when nothing was found): `Ok(None)` when there is none, `Err` naming why it is refused. It
/// names only project and target aliases, never code or rules, so its owner is not checked (a
/// root container keeps the project of a bind-mounted checkout); a file or a directory any user
/// can write is refused.
pub(crate) fn read_firebaserc(
    dir: &Path,
    stat: impl Fn(&Path) -> Option<Stat>,
    open: impl Fn(&Path) -> Option<Opened>,
) -> Result<Option<Result<String, String>>, Skipped> {
    let path = dir.join(FIREBASERC_FILE);
    let Some(opened) = open(&path).filter(|o| o.stat.is_file) else {
        return Ok(None);
    };
    let reason = match stat(dir) {
        None => Some("is in a directory that cannot be inspected".to_owned()),
        Some(d) if world_writable(&d) => Some(format!(
            "is in {}, which can be written by any user",
            dir.display()
        )),
        Some(_) if world_writable(&opened.stat) => Some("can be written by any user".to_owned()),
        Some(_) => None,
    };
    match reason {
        Some(reason) => Err(Skipped { path, reason }),
        None => Ok(Some(opened.read())),
    }
}

fn world_writable(stat: &Stat) -> bool {
    stat.mode & 0o002 != 0
}

/// The trust of this process.
#[cfg(unix)]
pub(crate) fn current_trust() -> Trust {
    Trust::new(
        rustix::process::geteuid().as_raw(),
        std::env::var("SUDO_UID").ok().as_deref(),
    )
}

/// Ownership is not checked off Unix: every path reads as owned by root, unwritable by others.
#[cfg(not(unix))]
pub(crate) fn current_trust() -> Trust {
    Trust::new(0, None)
}

/// A directory's metadata, following symbolic links.
pub(crate) fn stat(path: &Path) -> Option<Stat> {
    std::fs::metadata(path).ok().map(|m| stat_of(&m))
}

#[cfg(unix)]
fn stat_of(metadata: &std::fs::Metadata) -> Stat {
    use std::os::unix::fs::MetadataExt as _;
    Stat {
        owner: metadata.uid(),
        mode: metadata.mode(),
        is_file: metadata.is_file(),
    }
}

#[cfg(not(unix))]
fn stat_of(metadata: &std::fs::Metadata) -> Stat {
    Stat {
        owner: 0,
        mode: 0,
        is_file: metadata.is_file(),
    }
}

/// Opens a candidate once and reads its metadata from the handle; the text is read from the same
/// handle only when the caller asks, at most [`MAX_DISCOVERED_BYTES`]. The open neither blocks
/// on a FIFO nor makes a terminal the controlling terminal.
pub(crate) fn open(path: &Path) -> Option<Opened> {
    use std::io::Read as _;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path).ok()?;
    let stat = stat_of(&file.metadata().ok()?);
    Some(Opened::new(stat, move || {
        if !stat.is_file {
            return Err("not a regular file".to_owned());
        }
        let mut bytes = Vec::new();
        file.take(MAX_DISCOVERED_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_DISCOVERED_BYTES {
            return Err(format!(
                "it is larger than {} MiB, the most a discovered configuration file may hold",
                MAX_DISCOVERED_BYTES / (1024 * 1024)
            ));
        }
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;

    const ME: u32 = 501;
    const OTHER: u32 = 502;
    const USER: Trust = Trust {
        euid: ME,
        sudo_uid: None,
    };

    fn dir(owner: u32, mode: u32) -> Stat {
        Stat {
            owner,
            mode: 0o040_000 | mode,
            is_file: false,
        }
    }

    fn file(owner: u32, mode: u32) -> Stat {
        Stat {
            owner,
            mode: 0o100_000 | mode,
            is_file: true,
        }
    }

    /// A tree where every directory on the way to `/p/app/sub` is the user's own, plus `extra`.
    struct Tree(BTreeMap<PathBuf, Stat>);

    impl Tree {
        fn new(extra: &[(&str, Stat)]) -> Self {
            let mut map: BTreeMap<PathBuf, Stat> = ["/", "/p", "/p/app", "/p/app/sub"]
                .iter()
                .map(|p| (PathBuf::from(p), dir(ME, 0o755)))
                .collect();
            for (path, stat) in extra {
                map.insert(PathBuf::from(path), *stat);
            }
            Self(map)
        }

        fn stat(&self) -> impl Fn(&Path) -> Option<Stat> + '_ {
            |path| self.0.get(path).copied()
        }

        fn open(&self) -> impl Fn(&Path) -> Option<Opened> + '_ {
            |path| {
                // `/` on every platform, so the expected texts read the same on Windows.
                let text = format!("text of {}", path.display()).replace('\\', "/");
                self.0
                    .get(path)
                    .map(|stat| Opened::new(*stat, move || Ok(text)))
            }
        }

        fn discover(&self, cwd: &str, trust: &Trust) -> Discovery {
            discover(Path::new(cwd), trust, self.stat(), self.open())
        }
    }

    fn found(discovery: Discovery) -> Discovered {
        assert_eq!(discovery.skipped, None);
        discovery.found
    }

    fn firebase_json(path: &str, from: &str) -> Discovered {
        Discovered::FirebaseJson(PathBuf::from(path), Ok(format!("text of {from}")))
    }

    #[test]
    fn the_trusted_owners() {
        for (euid, sudo, owner, trusted) in [
            (ME, None, ME, true),
            (ME, None, 0, true),
            (ME, None, OTHER, false),
            // SUDO_UID counts only for root.
            (ME, Some("502"), OTHER, false),
            (0, None, 0, true),
            (0, None, ME, false),
            (0, Some("501"), ME, true),
            (0, Some("501"), OTHER, false),
            (0, Some("not-a-uid"), ME, false),
            (0, Some(""), ME, false),
            (0, Some("-1"), ME, false),
        ] {
            let trust = Trust::new(euid, sudo);
            assert_eq!(
                trust.trusts(owner),
                trusted,
                "euid {euid}, SUDO_UID {sudo:?}, owner {owner}"
            );
        }
    }

    #[test]
    fn the_mode_table() {
        for (stat, working, directory, file_verdict) in [
            (dir(ME, 0o755), false, None, None),
            (dir(ME, 0o775), false, None, None),
            (dir(ME, 0o777), false, Some("any user"), Some("any user")),
            (dir(0, 0o1777), false, Some("any user"), Some("any user")),
            (dir(0, 0o755), false, None, None),
            (
                dir(OTHER, 0o755),
                false,
                Some("untrusted user"),
                Some("untrusted user"),
            ),
            // The working directory's owner is not checked; world write still is.
            (dir(OTHER, 0o755), true, None, Some("untrusted user")),
            (
                dir(OTHER, 0o777),
                true,
                Some("any user"),
                Some("untrusted user"),
            ),
            (file(ME, 0o644), false, None, None),
            (file(ME, 0o664), false, None, None),
            (file(0, 0o644), false, None, None),
            (file(ME, 0o646), false, Some("any user"), Some("any user")),
            (
                file(OTHER, 0o644),
                false,
                Some("untrusted user"),
                Some("untrusted user"),
            ),
        ] {
            let d = untrusted_directory(&stat, &USER, working);
            let f = untrusted_file(&stat, &USER);
            assert_eq!(
                d.is_some(),
                directory.is_some(),
                "{stat:?} {working}: {d:?}"
            );
            assert_eq!(f.is_some(), file_verdict.is_some(), "{stat:?}: {f:?}");
            if let (Some(d), Some(expected)) = (&d, directory) {
                assert!(d.contains(expected), "{d}");
            }
            if let (Some(f), Some(expected)) = (&f, file_verdict) {
                assert!(f.contains(expected), "{f}");
            }
        }
    }

    #[test]
    fn a_canonical_file_in_the_working_directory_wins_over_a_firebase_json_beside_it() {
        let tree = Tree::new(&[
            ("/p/app/fireemu.json", file(ME, 0o644)),
            ("/p/app/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            Discovered::Canonical(
                PathBuf::from("fireemu.json"),
                Ok("text of /p/app/fireemu.json".to_owned())
            )
        );
    }

    #[test]
    fn both_canonical_files_are_refused_without_reading_either() {
        for owner in [ME, OTHER] {
            let tree = Tree::new(&[
                ("/p/app/fireemu.toml", file(owner, 0o644)),
                ("/p/app/fireemu.json", file(ME, 0o644)),
            ]);
            let result = discover(
                Path::new("/p/app"),
                &USER,
                |path| tree.0.get(path).copied(),
                |path| {
                    tree.0
                        .get(path)
                        .copied()
                        .filter(|stat| stat.is_file)
                        .map(|stat| {
                            Opened::new(stat, || panic!("ambiguous configuration must not be read"))
                        })
                },
            );
            let Discovered::Canonical(_, Err(error)) = result.found else {
                panic!("both files must be refused: {result:?}");
            };
            assert!(
                error.contains("fireemu.toml")
                    && error.contains("fireemu.json")
                    && error.contains("remove one"),
                "{error}"
            );
        }
    }

    #[test]
    fn toml_discovery_preserves_trust_checks_and_parent_exclusion() {
        let tree = Tree::new(&[("/p/app/fireemu.toml", file(ME, 0o644))]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            Discovered::Canonical(
                PathBuf::from("fireemu.toml"),
                Ok("text of /p/app/fireemu.toml".to_owned())
            )
        );
        for stat in [file(OTHER, 0o644), file(ME, 0o666)] {
            let discovery = Tree::new(&[("/p/app/fireemu.toml", stat)]).discover("/p/app", &USER);
            assert_eq!(discovery.found, Discovered::Nothing);
            assert_eq!(
                discovery.skipped.unwrap().path,
                PathBuf::from("fireemu.toml")
            );
        }
        assert_eq!(
            found(Tree::new(&[("/p/fireemu.toml", file(ME, 0o644))]).discover("/p/app", &USER)),
            Discovered::Nothing
        );
    }

    #[test]
    fn a_firebase_json_in_the_working_directory_is_named_relatively() {
        let tree = Tree::new(&[("/p/app/firebase.json", file(ME, 0o664))]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            firebase_json("firebase.json", "/p/app/firebase.json")
        );
    }

    #[test]
    fn a_firebase_json_is_found_in_the_nearest_parent_as_firebase_tools_finds_it() {
        let tree = Tree::new(&[
            ("/p/firebase.json", file(ME, 0o644)),
            ("/p/app/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app/sub", &USER)),
            firebase_json("/p/app/firebase.json", "/p/app/firebase.json")
        );
    }

    #[test]
    fn root_owned_parents_and_files_are_searched_up_to_the_filesystem_root() {
        let tree = Tree::new(&[
            ("/", dir(0, 0o755)),
            ("/p", dir(0, 0o755)),
            ("/firebase.json", file(0, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            firebase_json("/firebase.json", "/firebase.json")
        );
    }

    #[test]
    fn a_root_owned_working_directory_with_root_owned_files_is_searched() {
        let tree = Tree::new(&[
            ("/p/app", dir(0, 0o755)),
            ("/p/app/firebase.json", file(0, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            firebase_json("firebase.json", "/p/app/firebase.json")
        );
    }

    #[test]
    fn a_working_directory_another_user_owns_is_searched_but_their_files_are_not_loaded() {
        let tree = Tree::new(&[
            ("/p/app", dir(OTHER, 0o755)),
            ("/p/app/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            firebase_json("firebase.json", "/p/app/firebase.json")
        );
        let tree = Tree::new(&[
            ("/p/app", dir(OTHER, 0o755)),
            ("/p/app/firebase.json", file(OTHER, 0o644)),
        ]);
        let discovery = tree.discover("/p/app", &USER);
        assert_eq!(discovery.found, Discovered::Nothing);
        assert!(discovery
            .skipped
            .unwrap()
            .reason
            .contains("untrusted user (uid 502)"));
    }

    #[test]
    fn under_sudo_the_invoking_users_files_are_loaded_and_others_are_not() {
        let sudo = Trust::new(0, Some("501"));
        let tree = Tree::new(&[("/p/app/firebase.json", file(ME, 0o644))]);
        assert_eq!(
            found(tree.discover("/p/app", &sudo)),
            firebase_json("firebase.json", "/p/app/firebase.json")
        );
        let tree = Tree::new(&[("/p/app/firebase.json", file(OTHER, 0o644))]);
        assert_eq!(tree.discover("/p/app", &sudo).found, Discovered::Nothing);
        // Root without SUDO_UID (a root container with a bind-mounted checkout) skips them.
        let tree = Tree::new(&[("/p/app/firebase.json", file(ME, 0o644))]);
        let discovery = tree.discover("/p/app", &Trust::new(0, None));
        assert_eq!(discovery.found, Discovered::Nothing);
        assert!(discovery.skipped.is_some());
    }

    #[test]
    fn a_canonical_file_in_a_parent_is_never_used() {
        let tree = Tree::new(&[("/p/fireemu.json", file(ME, 0o644))]);
        assert_eq!(found(tree.discover("/p/app", &USER)), Discovered::Nothing);
        let tree = Tree::new(&[
            ("/p/fireemu.json", file(ME, 0o644)),
            ("/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            firebase_json("/firebase.json", "/firebase.json")
        );
    }

    #[test]
    fn a_directory_named_firebase_json_is_skipped_as_firebase_tools_skips_it() {
        let tree = Tree::new(&[
            ("/p/app/firebase.json", dir(ME, 0o755)),
            ("/p/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(tree.discover("/p/app", &USER)),
            firebase_json("/p/firebase.json", "/p/firebase.json")
        );
    }

    #[test]
    fn nothing_is_found_without_either_file() {
        assert_eq!(
            found(Tree::new(&[]).discover("/p/app", &USER)),
            Discovered::Nothing
        );
    }

    #[test]
    fn a_world_writable_or_foreign_file_is_skipped_and_the_search_does_not_go_on() {
        let tree = Tree::new(&[
            ("/p/app/firebase.json", file(ME, 0o666)),
            ("/p/firebase.json", file(ME, 0o644)),
        ]);
        let discovery = tree.discover("/p/app", &USER);
        assert_eq!(discovery.found, Discovered::Nothing);
        assert_eq!(
            discovery.skipped.unwrap().path,
            PathBuf::from("firebase.json")
        );
        let tree = Tree::new(&[("/p/firebase.json", file(OTHER, 0o644))]);
        let discovery = tree.discover("/p/app", &USER);
        assert_eq!(discovery.found, Discovered::Nothing);
        let skipped = discovery.skipped.unwrap();
        assert_eq!(skipped.path, PathBuf::from("/p/firebase.json"));
        assert!(skipped.reason.contains("uid 502"), "{skipped:?}");
        // The canonical file follows the same rule.
        let tree = Tree::new(&[("/p/app/fireemu.json", file(ME, 0o666))]);
        let discovery = tree.discover("/p/app", &USER);
        assert_eq!(discovery.found, Discovered::Nothing);
        assert_eq!(
            discovery.skipped.unwrap().path,
            PathBuf::from("fireemu.json")
        );
    }

    #[test]
    fn the_walk_stops_before_a_sticky_world_writable_parent() {
        let tree = Tree::new(&[
            ("/p", dir(0, 0o1777)),
            ("/p/firebase.json", file(OTHER, 0o644)),
            ("/firebase.json", file(ME, 0o644)),
        ]);
        let discovery = tree.discover("/p/app", &USER);
        assert_eq!(discovery.found, Discovered::Nothing);
        let skipped = discovery.skipped.unwrap();
        assert_eq!(skipped.path, PathBuf::from("/p/firebase.json"));
        assert!(skipped.reason.contains("is in /p, which"), "{skipped:?}");
        // Without a candidate there the walk still stops, and says nothing.
        let tree = Tree::new(&[("/p", dir(0, 0o1777)), ("/firebase.json", file(ME, 0o644))]);
        assert_eq!(
            tree.discover("/p/app", &USER),
            Discovery {
                found: Discovered::Nothing,
                skipped: None
            }
        );
    }

    #[test]
    fn a_world_writable_working_directory_is_not_searched_and_says_so() {
        for extra in [&[][..], &[("/p/app/fireemu.json", file(ME, 0o644))][..]] {
            let mut entries = vec![("/p/app", dir(ME, 0o777))];
            entries.extend_from_slice(extra);
            entries.push(("/p/firebase.json", file(ME, 0o644)));
            let discovery = Tree::new(&entries).discover("/p/app", &USER);
            assert_eq!(discovery.found, Discovered::Nothing);
            let skipped = discovery.skipped.unwrap();
            assert_eq!(skipped.path, PathBuf::from("/p/app"));
            assert!(skipped.reason.contains("any user"), "{skipped:?}");
        }
    }

    #[test]
    fn the_decision_and_the_text_come_from_one_open() {
        // Each candidate is opened once; the text returned is the one read from that open.
        let opens = std::cell::RefCell::new(Vec::new());
        let tree = Tree::new(&[("/p/app/firebase.json", file(ME, 0o644))]);
        let discovery = discover(Path::new("/p/app"), &USER, tree.stat(), |path: &Path| {
            opens.borrow_mut().push(path.to_path_buf());
            let n = opens.borrow().len();
            Some(Opened::new(file(ME, 0o644), move || {
                Ok(format!("open #{n}"))
            }))
            .filter(|_| path.ends_with("firebase.json"))
        });
        let candidates = opens
            .borrow()
            .iter()
            .filter(|p| p.ends_with("firebase.json"))
            .count();
        assert_eq!(candidates, 1);
        let Discovered::FirebaseJson(_, Ok(text)) = discovery.found else {
            panic!("{discovery:?}");
        };
        assert_eq!(text, format!("open #{}", opens.borrow().len()));
    }

    /// An untrusted candidate is judged on its metadata alone and never read, so a huge file
    /// planted by someone else costs nothing.
    #[test]
    fn a_skipped_candidate_is_never_read() {
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        for (stat, dir_stat, loaded) in [
            (file(OTHER, 0o644), dir(ME, 0o755), false),
            (file(ME, 0o666), dir(ME, 0o755), false),
            (file(ME, 0o644), dir(ME, 0o777), false),
            (file(ME, 0o644), dir(ME, 0o755), true),
        ] {
            reads.set(0);
            let tree = Tree::new(&[("/p/app", dir_stat), ("/p/app/firebase.json", stat)]);
            let counter = reads.clone();
            let discovery = discover(Path::new("/p/app"), &USER, tree.stat(), |path: &Path| {
                let counter = counter.clone();
                tree.stat()(path).map(|s| {
                    Opened::new(s, move || {
                        counter.set(counter.get() + 1);
                        Ok("{}".to_owned())
                    })
                })
            });
            assert_eq!(discovery.found != Discovered::Nothing, loaded, "{stat:?}");
            assert_eq!(reads.get(), usize::from(loaded), "{stat:?} in {dir_stat:?}");
        }
    }

    #[test]
    fn a_firebaserc_is_read_unless_anyone_can_write_it_or_its_directory() {
        let read = |entries: &[(&str, Stat)]| {
            let tree = Tree::new(entries);
            read_firebaserc(Path::new("/p/app"), tree.stat(), tree.open())
        };
        assert_eq!(read(&[]), Ok(None));
        for owner in [ME, 0, OTHER] {
            for mode in [0o644, 0o664] {
                assert_eq!(
                    read(&[("/p/app/.firebaserc", file(owner, mode))]),
                    Ok(Some(Ok("text of /p/app/.firebaserc".to_owned()))),
                    "{owner} {mode:o}"
                );
            }
        }
        // A root container keeps the project of a checkout another uid owns.
        let foreign = [
            ("/p/app", dir(OTHER, 0o755)),
            ("/p/app/.firebaserc", file(OTHER, 0o644)),
        ];
        assert!(matches!(read(&foreign), Ok(Some(_))));
        let skipped = read(&[("/p/app/.firebaserc", file(ME, 0o666))]).unwrap_err();
        assert!(skipped.reason.contains("any user"), "{skipped:?}");
        let shared = [
            ("/p/app", dir(0, 0o1777)),
            ("/p/app/.firebaserc", file(ME, 0o644)),
        ];
        let skipped = read(&shared).unwrap_err();
        assert!(skipped.reason.contains("is in /p/app"), "{skipped:?}");
        let hidden = Tree::new(&[("/p/app/.firebaserc", file(ME, 0o644))]);
        let skipped = read_firebaserc(Path::new("/p/app"), |_| None, hidden.open()).unwrap_err();
        assert!(
            skipped.reason.contains("cannot be inspected"),
            "{skipped:?}"
        );
    }

    /// The real opener refuses to read past the cap, using a sparse file so the test writes
    /// nothing, and reads a file at the cap.
    #[test]
    fn the_opener_reads_at_most_the_cap() {
        let dir =
            std::env::temp_dir().join(format!("fireemu-discovery-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("firebase.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_DISCOVERED_BYTES + 1).unwrap();
        let error = open(&path).unwrap().read().unwrap_err();
        assert!(error.contains("larger than 16 MiB"), "{error}");
        file.set_len(MAX_DISCOVERED_BYTES).unwrap();
        let text = open(&path).unwrap().read().unwrap();
        assert_eq!(text.len() as u64, MAX_DISCOVERED_BYTES);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One directory level of the generated trees: who owns it and its mode, and the
    /// `fireemu.json` and `firebase.json` it may hold.
    fn level() -> impl Strategy<Value = (Stat, Option<Stat>, Option<Stat>)> {
        let owner = prop_oneof![Just(ME), Just(OTHER), Just(0)];
        let dir_mode = prop_oneof![Just(0o755), Just(0o775), Just(0o777), Just(0o1777)];
        let file_mode = prop_oneof![Just(0o644), Just(0o600), Just(0o664), Just(0o666)];
        let file_stat = (owner.clone(), file_mode).prop_map(|(o, m)| file(o, m));
        (
            (owner, dir_mode).prop_map(|(o, m)| dir(o, m)),
            proptest::option::weighted(0.3, file_stat.clone()),
            proptest::option::weighted(0.3, file_stat),
        )
    }

    fn trust() -> impl Strategy<Value = Trust> {
        (
            prop_oneof![Just(ME), Just(0)],
            prop_oneof![
                Just(None),
                Just(Some("501")),
                Just(Some("502")),
                Just(Some("x"))
            ],
        )
            .prop_map(|(euid, sudo)| Trust::new(euid, sudo))
    }

    proptest! {
        /// The trusted owners against a reference model over (euid, SUDO_UID, owner).
        #[test]
        fn trust_matches_the_reference_model(
            euid in prop_oneof![Just(0u32), Just(ME), Just(OTHER)],
            sudo in proptest::option::of(prop_oneof![Just("0".to_owned()), Just("501".to_owned()), Just("502".to_owned()), "[0-9a-z-]{0,4}"]),
            owner in prop_oneof![Just(0u32), Just(ME), Just(OTHER), any::<u32>()],
            mode in 0u32..0o10000,
        ) {
            let trust = Trust::new(euid, sudo.as_deref());
            let sudo_uid = sudo.as_deref().and_then(|s| s.parse::<u32>().ok());
            let trusted = owner == euid || owner == 0 || (euid == 0 && sudo_uid == Some(owner));
            prop_assert_eq!(trust.trusts(owner), trusted);
            let world = mode & 0o002 != 0;
            prop_assert_eq!(untrusted_file(&file(owner, mode), &trust).is_none(), trusted && !world);
            prop_assert_eq!(untrusted_directory(&dir(owner, mode), &trust, false).is_none(), trusted && !world);
            prop_assert_eq!(untrusted_directory(&dir(owner, mode), &trust, true).is_none(), !world);
        }

        /// Against a reference model: walk from the working directory upward. A world-writable
        /// working directory ends the search with a notice. In each directory the first
        /// candidate present decides: it is loaded when its directory and itself are trusted,
        /// and skipped otherwise. An untrusted parent with no candidate ends the walk.
        #[test]
        fn discovery_matches_the_reference_model(
            levels in proptest::collection::vec(level(), 1..7),
            trust in trust(),
        ) {
            // levels[0] is the root, levels[last] the working directory.
            let dirs: Vec<PathBuf> = (0..levels.len())
                .map(|i| {
                    let mut dir = PathBuf::from("/");
                    for j in 1..=i {
                        dir.push(format!("d{j}"));
                    }
                    dir
                })
                .collect();
            let mut present = BTreeMap::new();
            for (dir, (dir_stat, canonical, firebase)) in dirs.iter().zip(&levels) {
                present.insert(dir.clone(), *dir_stat);
                if let Some(s) = canonical {
                    present.insert(dir.join(CANONICAL_FILE), *s);
                }
                if let Some(s) = firebase {
                    present.insert(dir.join(FIREBASE_FILE), *s);
                }
            }
            let tree = Tree(present);
            let cwd = dirs.last().unwrap();
            let last = levels.len() - 1;
            let trusted = |owner| owner == trust.euid || owner == 0 || Some(owner) == trust.sudo_uid;
            let mut expected = (Discovered::Nothing, None::<PathBuf>);
            for i in (0..=last).rev() {
                let (dir_stat, canonical, firebase) = &levels[i];
                let world = dir_stat.mode & 0o002 != 0;
                if i == last && world {
                    expected = (Discovered::Nothing, Some(cwd.clone()));
                    break;
                }
                let dir_ok = !world && (i == last || trusted(dir_stat.owner));
                let candidate = if i == last && canonical.is_some() {
                    Some((CANONICAL_FILE, canonical.unwrap()))
                } else {
                    firebase.map(|s| (FIREBASE_FILE, s))
                };
                if let Some((name, s)) = candidate {
                    let shown = if i == last { PathBuf::from(name) } else { dirs[i].join(name) };
                    let file_ok = trusted(s.owner) && s.mode & 0o002 == 0;
                    let text = Ok(format!("text of {}", dirs[i].join(name).display()).replace('\\', "/"));
                    expected = if dir_ok && file_ok {
                        (if name == CANONICAL_FILE {
                            Discovered::Canonical(shown, text)
                        } else {
                            Discovered::FirebaseJson(shown, text)
                        }, None)
                    } else {
                        (Discovered::Nothing, Some(shown))
                    };
                    break;
                }
                if !dir_ok {
                    break;
                }
            }
            let discovery = tree.discover(cwd.to_str().unwrap(), &trust);
            prop_assert_eq!(&discovery.found, &expected.0);
            prop_assert_eq!(discovery.skipped.map(|s| s.path), expected.1);
        }
    }
}
