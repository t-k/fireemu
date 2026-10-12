//! Which configuration files `up` and `exec` load when neither `--config` nor `--firebase-json`
//! is given.
//!
//! A `fireemu.json` is looked for in the working directory only: its paths (`rules.source`,
//! `storage.rules`, `functions.source`) are read relative to the working directory, so one
//! found in a parent would point at the wrong files. A `firebase.json` is looked for the way
//! firebase-tools 15.28.2 finds it (`detectProjectRoot`): in the working directory, then in
//! each parent up to the filesystem root, and the first one found wins. Its paths are relative
//! to its own directory, which is also where `.firebaserc` is read from.

use std::path::{Path, PathBuf};

/// The canonical configuration file name.
pub(crate) const CANONICAL_FILE: &str = "fireemu.json";
/// The Firebase project configuration file name.
pub(crate) const FIREBASE_FILE: &str = "firebase.json";

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

/// Searches from the absolute working directory `cwd`; `is_file` answers whether a path names
/// a regular file. A file in the working directory is returned as a bare file name, one in a
/// parent as an absolute path.
pub(crate) fn discover(cwd: &Path, is_file: impl Fn(&Path) -> bool) -> Discovered {
    if is_file(&cwd.join(CANONICAL_FILE)) {
        return Discovered::Canonical(PathBuf::from(CANONICAL_FILE));
    }
    for (depth, dir) in cwd.ancestors().enumerate() {
        if is_file(&dir.join(FIREBASE_FILE)) {
            return Discovered::FirebaseJson(if depth == 0 {
                PathBuf::from(FIREBASE_FILE)
            } else {
                dir.join(FIREBASE_FILE)
            });
        }
    }
    Discovered::Nothing
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    fn files(paths: &[&str]) -> impl Fn(&Path) -> bool {
        let set: BTreeSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
        move |path| set.contains(path)
    }

    #[test]
    fn a_canonical_file_in_the_working_directory_wins_over_a_firebase_json_beside_it() {
        let found = discover(
            Path::new("/p/app"),
            files(&["/p/app/fireemu.json", "/p/app/firebase.json"]),
        );
        assert_eq!(found, Discovered::Canonical(PathBuf::from("fireemu.json")));
    }

    #[test]
    fn a_firebase_json_in_the_working_directory_is_named_relatively() {
        let found = discover(Path::new("/p/app"), files(&["/p/app/firebase.json"]));
        assert_eq!(
            found,
            Discovered::FirebaseJson(PathBuf::from("firebase.json"))
        );
    }

    #[test]
    fn a_firebase_json_is_found_in_the_nearest_parent_as_firebase_tools_finds_it() {
        let found = discover(
            Path::new("/p/app/functions/src"),
            files(&["/p/firebase.json", "/p/app/firebase.json"]),
        );
        assert_eq!(
            found,
            Discovered::FirebaseJson(PathBuf::from("/p/app/firebase.json"))
        );
    }

    #[test]
    fn the_filesystem_root_is_searched_too() {
        let found = discover(Path::new("/p/app"), files(&["/firebase.json"]));
        assert_eq!(
            found,
            Discovered::FirebaseJson(PathBuf::from("/firebase.json"))
        );
    }

    #[test]
    fn a_canonical_file_in_a_parent_is_never_used() {
        let found = discover(Path::new("/p/app"), files(&["/p/fireemu.json"]));
        assert_eq!(found, Discovered::Nothing);
        let found = discover(
            Path::new("/p/app"),
            files(&["/p/fireemu.json", "/firebase.json"]),
        );
        assert_eq!(
            found,
            Discovered::FirebaseJson(PathBuf::from("/firebase.json"))
        );
    }

    #[test]
    fn nothing_is_found_without_either_file() {
        assert_eq!(
            discover(Path::new("/p/app"), files(&[])),
            Discovered::Nothing
        );
    }

    proptest! {
        /// Against a reference model: a working directory `depth` levels below the root, and
        /// for each level whether it holds `fireemu.json` and whether it holds `firebase.json`.
        #[test]
        fn discovery_matches_the_reference_model(
            levels in proptest::collection::vec((any::<bool>(), any::<bool>()), 1..7)
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
            let mut present = BTreeSet::new();
            for (dir, (canonical, firebase)) in dirs.iter().zip(&levels) {
                if *canonical {
                    present.insert(dir.join(CANONICAL_FILE));
                }
                if *firebase {
                    present.insert(dir.join(FIREBASE_FILE));
                }
            }
            let cwd = dirs.last().unwrap();
            let last = levels.len() - 1;
            let expected = if levels[last].0 {
                Discovered::Canonical(PathBuf::from(CANONICAL_FILE))
            } else if let Some(i) = (0..=last).rev().find(|&i| levels[i].1) {
                Discovered::FirebaseJson(if i == last {
                    PathBuf::from(FIREBASE_FILE)
                } else {
                    dirs[i].join(FIREBASE_FILE)
                })
            } else {
                Discovered::Nothing
            };
            let probed = std::cell::RefCell::new(Vec::new());
            let found = discover(cwd, |path: &Path| {
                probed.borrow_mut().push(path.to_path_buf());
                present.contains(path)
            });
            prop_assert_eq!(&found, &expected);
            // Only the two file names are ever probed, never a sibling or a child directory.
            for path in probed.borrow().iter() {
                let name = path.file_name().unwrap();
                prop_assert!(name == CANONICAL_FILE || name == FIREBASE_FILE);
                prop_assert!(cwd.starts_with(path.parent().unwrap()));
            }
        }
    }
}
