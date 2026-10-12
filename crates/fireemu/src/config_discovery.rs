//! Which configuration files `up` and `exec` load when neither `--config` nor `--firebase-json`
//! is given.
//!
//! A `fireemu.json` is looked for in the working directory only: its paths (`rules.source`,
//! `storage.rules`, `functions.source`) are read relative to the working directory, so one
//! found in a parent would point at the wrong files. A `firebase.json` is looked for the way
//! firebase-tools 15.28.2 finds it (`detectProjectRoot`): in the working directory, then in
//! each parent up to the filesystem root, and the first one found wins. Its paths are relative
//! to its own directory, which is also where `.firebaserc` is read from.
//!
//! Unlike firebase-tools, the search only trusts what the current user controls. A discovered
//! file can name Functions code to run and the rules to enforce, so a file planted by another
//! user in a shared parent such as `/tmp` must never be picked up. On Unix the walk stops before
//! it searches a directory that another user owns or that anyone can write, and a candidate file
//! that another user owns or that its group or anyone can write is skipped. In both cases the
//! search ends as if nothing was found, and the caller reports the skipped file. Files named with
//! `--config` or `--firebase-json` are not checked.

use std::path::{Path, PathBuf};

/// The canonical configuration file name.
pub(crate) const CANONICAL_FILE: &str = "fireemu.json";
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

/// Why a directory may not be searched, or `None` when the user `me` controls it: it is theirs
/// and nobody else can add or replace entries in it.
pub(crate) fn untrusted_directory(stat: &Stat, me: u32) -> Option<String> {
    if stat.owner != me {
        Some(format!("is owned by another user (uid {})", stat.owner))
    } else if stat.mode & 0o002 != 0 {
        Some("can be written by any user".to_owned())
    } else {
        None
    }
}

/// Why a candidate file may not be loaded, or `None` when only the user `me` can change it.
pub(crate) fn untrusted_file(stat: &Stat, me: u32) -> Option<String> {
    if stat.owner != me {
        Some(format!("is owned by another user (uid {})", stat.owner))
    } else if stat.mode & 0o022 != 0 {
        Some("can be written by its group or by any user".to_owned())
    } else {
        None
    }
}

/// What the search found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Discovered {
    /// `fireemu.json` in the working directory: loaded as `--config` would load it.
    Canonical(PathBuf),
    /// The nearest `firebase.json`: loaded as `--firebase-json` would load it.
    FirebaseJson(PathBuf),
    /// Neither file: the built-in defaults apply.
    Nothing,
}

/// A candidate the search did not load, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Skipped {
    pub(crate) path: PathBuf,
    pub(crate) reason: String,
}

impl std::fmt::Display for Skipped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.path.display(), self.reason)
    }
}

/// The search's result: what it found, or the candidate it refused to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Discovery {
    pub(crate) found: Discovered,
    pub(crate) skipped: Option<Skipped>,
}

/// Searches from the absolute working directory `cwd` for the user `me`; `stat` reads a path's
/// metadata (following symbolic links) or answers `None` when there is nothing to read. A file
/// in the working directory is returned as a bare file name, one in a parent as an absolute path.
pub(crate) fn discover(cwd: &Path, me: u32, stat: impl Fn(&Path) -> Option<Stat>) -> Discovery {
    let nothing = |skipped| Discovery {
        found: Discovered::Nothing,
        skipped,
    };
    for (depth, dir) in cwd.ancestors().enumerate() {
        let directory_reason = match stat(dir) {
            Some(dir_stat) => untrusted_directory(&dir_stat, me),
            None => return nothing(None),
        };
        let names: &[&str] = if depth == 0 {
            &[CANONICAL_FILE, FIREBASE_FILE]
        } else {
            &[FIREBASE_FILE]
        };
        for name in names {
            let candidate = dir.join(name);
            let Some(file) = stat(&candidate).filter(|s| s.is_file) else {
                continue;
            };
            let shown = if depth == 0 {
                PathBuf::from(name)
            } else {
                candidate.clone()
            };
            if let Some(reason) = &directory_reason {
                return nothing(Some(Skipped {
                    path: shown,
                    reason: format!("is in {}, which {reason}", dir.display()),
                }));
            }
            if let Some(reason) = untrusted_file(&file, me) {
                return nothing(Some(Skipped {
                    path: shown,
                    reason,
                }));
            }
            return Discovery {
                found: if *name == CANONICAL_FILE {
                    Discovered::Canonical(shown)
                } else {
                    Discovered::FirebaseJson(shown)
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

/// Why the `.firebaserc` in `dir` (the discovered project directory, or the working directory
/// when nothing was found) may not be read, under the same rules as the search.
pub(crate) fn untrusted_firebaserc(
    dir: &Path,
    me: u32,
    stat: impl Fn(&Path) -> Option<Stat>,
) -> Option<Skipped> {
    let path = dir.join(FIREBASERC_FILE);
    let file = stat(&path).filter(|s| s.is_file)?;
    let reason = match stat(dir).map(|d| untrusted_directory(&d, me)) {
        Some(Some(reason)) => format!("is in {}, which {reason}", dir.display()),
        None => "is in a directory that cannot be inspected".to_owned(),
        Some(None) => untrusted_file(&file, me)?,
    };
    Some(Skipped { path, reason })
}

/// The effective user, whose files the search trusts.
#[cfg(unix)]
pub(crate) fn current_user() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Ownership is not checked off Unix: every path reads as the current user's, unwritable by
/// others.
#[cfg(not(unix))]
pub(crate) fn current_user() -> u32 {
    0
}

/// The metadata `discover` reads, following symbolic links as the later read does.
#[cfg(unix)]
pub(crate) fn stat(path: &Path) -> Option<Stat> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).ok()?;
    Some(Stat {
        owner: metadata.uid(),
        mode: metadata.mode(),
        is_file: metadata.is_file(),
    })
}

/// The metadata `discover` reads; ownership is not checked off Unix.
#[cfg(not(unix))]
pub(crate) fn stat(path: &Path) -> Option<Stat> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(Stat {
        owner: 0,
        mode: 0,
        is_file: metadata.is_file(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;

    const ME: u32 = 501;
    const OTHER: u32 = 502;

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

    /// A tree where every directory on the way to `/p/app` is the user's own, plus `extra`.
    fn tree(extra: &[(&str, Stat)]) -> impl Fn(&Path) -> Option<Stat> {
        let mut map: BTreeMap<PathBuf, Stat> = ["/", "/p", "/p/app", "/p/app/sub"]
            .iter()
            .map(|p| (PathBuf::from(p), dir(ME, 0o755)))
            .collect();
        for (path, stat) in extra {
            map.insert(PathBuf::from(path), *stat);
        }
        move |path| map.get(path).copied()
    }

    fn found(discovery: Discovery) -> Discovered {
        assert_eq!(discovery.skipped, None);
        discovery.found
    }

    #[test]
    fn the_decision_table() {
        for (stat, directory, file_reason) in [
            (dir(ME, 0o755), None, None),
            (dir(ME, 0o700), None, None),
            (dir(ME, 0o775), None, Some("group")),
            (dir(ME, 0o777), Some("any user"), Some("group")),
            (dir(ME, 0o1777), Some("any user"), Some("group")),
            (
                dir(OTHER, 0o755),
                Some("another user"),
                Some("another user"),
            ),
            (dir(0, 0o755), Some("another user"), Some("another user")),
            (file(ME, 0o644), None, None),
            (file(ME, 0o600), None, None),
            (file(ME, 0o664), None, Some("group")),
            (file(ME, 0o646), Some("any user"), Some("group")),
            (
                file(OTHER, 0o644),
                Some("another user"),
                Some("another user"),
            ),
        ] {
            let d = untrusted_directory(&stat, ME);
            let f = untrusted_file(&stat, ME);
            assert_eq!(d.is_some(), directory.is_some(), "{stat:?}: {d:?}");
            assert_eq!(f.is_some(), file_reason.is_some(), "{stat:?}: {f:?}");
            if let (Some(d), Some(expected)) = (&d, directory) {
                assert!(d.contains(expected), "{d}");
            }
            if let (Some(f), Some(expected)) = (&f, file_reason) {
                assert!(f.contains(expected), "{f}");
            }
        }
    }

    #[test]
    fn a_canonical_file_in_the_working_directory_wins_over_a_firebase_json_beside_it() {
        let stat = tree(&[
            ("/p/app/fireemu.json", file(ME, 0o644)),
            ("/p/app/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, stat)),
            Discovered::Canonical(PathBuf::from("fireemu.json"))
        );
    }

    #[test]
    fn a_firebase_json_in_the_working_directory_is_named_relatively() {
        let stat = tree(&[("/p/app/firebase.json", file(ME, 0o644))]);
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, stat)),
            Discovered::FirebaseJson(PathBuf::from("firebase.json"))
        );
    }

    #[test]
    fn a_firebase_json_is_found_in_the_nearest_parent_as_firebase_tools_finds_it() {
        let stat = tree(&[
            ("/p/firebase.json", file(ME, 0o644)),
            ("/p/app/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(discover(Path::new("/p/app/sub"), ME, stat)),
            Discovered::FirebaseJson(PathBuf::from("/p/app/firebase.json"))
        );
    }

    #[test]
    fn the_filesystem_root_is_searched_too() {
        let stat = tree(&[("/firebase.json", file(ME, 0o644))]);
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, stat)),
            Discovered::FirebaseJson(PathBuf::from("/firebase.json"))
        );
    }

    #[test]
    fn a_canonical_file_in_a_parent_is_never_used() {
        let stat = tree(&[("/p/fireemu.json", file(ME, 0o644))]);
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, stat)),
            Discovered::Nothing
        );
        let stat = tree(&[
            ("/p/fireemu.json", file(ME, 0o644)),
            ("/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, stat)),
            Discovered::FirebaseJson(PathBuf::from("/firebase.json"))
        );
    }

    #[test]
    fn a_directory_named_firebase_json_is_skipped_as_firebase_tools_skips_it() {
        let stat = tree(&[
            ("/p/app/firebase.json", dir(ME, 0o755)),
            ("/p/firebase.json", file(ME, 0o644)),
        ]);
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, stat)),
            Discovered::FirebaseJson(PathBuf::from("/p/firebase.json"))
        );
    }

    #[test]
    fn nothing_is_found_without_either_file() {
        assert_eq!(
            found(discover(Path::new("/p/app"), ME, tree(&[]))),
            Discovered::Nothing
        );
    }

    #[test]
    fn a_file_another_user_owns_is_skipped_and_named() {
        let stat = tree(&[("/p/firebase.json", file(OTHER, 0o644))]);
        let discovery = discover(Path::new("/p/app"), ME, stat);
        assert_eq!(discovery.found, Discovered::Nothing);
        let skipped = discovery.skipped.unwrap();
        assert_eq!(skipped.path, PathBuf::from("/p/firebase.json"));
        assert!(
            skipped.reason.contains("another user (uid 502)"),
            "{skipped}"
        );
    }

    #[test]
    fn a_group_writable_file_is_skipped_and_the_search_does_not_go_on() {
        let stat = tree(&[
            ("/p/app/firebase.json", file(ME, 0o664)),
            ("/p/firebase.json", file(ME, 0o644)),
        ]);
        let discovery = discover(Path::new("/p/app"), ME, stat);
        assert_eq!(discovery.found, Discovered::Nothing);
        assert_eq!(
            discovery.skipped.unwrap().path,
            PathBuf::from("firebase.json")
        );
        // The canonical file follows the same rule.
        let stat = tree(&[("/p/app/fireemu.json", file(ME, 0o666))]);
        let discovery = discover(Path::new("/p/app"), ME, stat);
        assert_eq!(discovery.found, Discovered::Nothing);
        assert_eq!(
            discovery.skipped.unwrap().path,
            PathBuf::from("fireemu.json")
        );
    }

    #[test]
    fn the_walk_stops_before_a_sticky_world_writable_parent() {
        let stat = tree(&[
            ("/p", dir(0, 0o1777)),
            ("/p/firebase.json", file(OTHER, 0o644)),
            ("/firebase.json", file(ME, 0o644)),
        ]);
        let discovery = discover(Path::new("/p/app"), ME, stat);
        assert_eq!(discovery.found, Discovered::Nothing);
        let skipped = discovery.skipped.unwrap();
        assert_eq!(skipped.path, PathBuf::from("/p/firebase.json"));
        assert!(skipped.reason.contains("is in /p, which"), "{skipped}");
        // Without a candidate there the walk still stops, and says nothing.
        let stat = tree(&[("/p", dir(0, 0o1777)), ("/firebase.json", file(ME, 0o644))]);
        assert_eq!(
            discover(Path::new("/p/app"), ME, stat),
            Discovery {
                found: Discovered::Nothing,
                skipped: None
            }
        );
    }

    #[test]
    fn a_world_writable_working_directory_is_not_searched() {
        let stat = tree(&[
            ("/p/app", dir(ME, 0o777)),
            ("/p/app/fireemu.json", file(ME, 0o644)),
        ]);
        let discovery = discover(Path::new("/p/app"), ME, stat);
        assert_eq!(discovery.found, Discovered::Nothing);
        assert_eq!(
            discovery.skipped.unwrap().path,
            PathBuf::from("fireemu.json")
        );
    }

    #[test]
    fn a_firebaserc_is_read_only_from_a_directory_and_file_the_user_controls() {
        let mine = tree(&[("/p/app/.firebaserc", file(ME, 0o644))]);
        assert_eq!(untrusted_firebaserc(Path::new("/p/app"), ME, mine), None);
        let absent = tree(&[]);
        assert_eq!(untrusted_firebaserc(Path::new("/p/app"), ME, absent), None);
        let writable = tree(&[("/p/app/.firebaserc", file(ME, 0o666))]);
        assert!(untrusted_firebaserc(Path::new("/p/app"), ME, writable).is_some());
        let foreign = tree(&[("/p/app/.firebaserc", file(OTHER, 0o644))]);
        assert!(untrusted_firebaserc(Path::new("/p/app"), ME, foreign).is_some());
        let shared = tree(&[
            ("/p/app", dir(0, 0o1777)),
            ("/p/app/.firebaserc", file(ME, 0o644)),
        ]);
        let skipped = untrusted_firebaserc(Path::new("/p/app"), ME, shared).unwrap();
        assert!(skipped.reason.contains("is in /p/app"), "{skipped}");
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

    proptest! {
        /// Against a reference model: walk from the working directory upward; in each
        /// directory, the first candidate present decides (it is loaded when its directory
        /// and itself are trusted, and skipped otherwise); an untrusted directory with no
        /// candidate ends the walk.
        #[test]
        fn discovery_matches_the_reference_model(
            levels in proptest::collection::vec(level(), 1..7)
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
            let cwd = dirs.last().unwrap();
            let last = levels.len() - 1;
            let mut expected = (Discovered::Nothing, None::<PathBuf>);
            for i in (0..=last).rev() {
                let (dir_stat, canonical, firebase) = &levels[i];
                let dir_ok = dir_stat.owner == ME && dir_stat.mode & 0o002 == 0;
                let candidate = if i == last && canonical.is_some() {
                    Some((CANONICAL_FILE, canonical.unwrap()))
                } else {
                    firebase.map(|s| (FIREBASE_FILE, s))
                };
                if let Some((name, s)) = candidate {
                    let shown = if i == last { PathBuf::from(name) } else { dirs[i].join(name) };
                    let file_ok = s.owner == ME && s.mode & 0o022 == 0;
                    expected = if dir_ok && file_ok {
                        (if name == CANONICAL_FILE {
                            Discovered::Canonical(shown)
                        } else {
                            Discovered::FirebaseJson(shown)
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
            let probed = std::cell::RefCell::new(Vec::new());
            let discovery = discover(cwd, ME, |path: &Path| {
                probed.borrow_mut().push(path.to_path_buf());
                present.get(path).copied()
            });
            prop_assert_eq!(&discovery.found, &expected.0);
            prop_assert_eq!(discovery.skipped.map(|s| s.path), expected.1);
            // Only the working directory's ancestors and the two file names are probed.
            for path in probed.borrow().iter() {
                prop_assert!(
                    cwd.starts_with(path)
                        || (path.file_name().is_some_and(|n| n == CANONICAL_FILE || n == FIREBASE_FILE)
                            && cwd.starts_with(path.parent().unwrap()))
                );
            }
        }
    }
}
