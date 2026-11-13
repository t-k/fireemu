//! Repository-local semantic source inventory derived from the Cargo authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use crate::cargo_authority::{AuthorityPackage, CargoAuthority};

pub(super) fn production_inputs(
    root: &Path,
    sources: &[&str],
    authority: &CargoAuthority,
) -> Result<BTreeSet<String>, String> {
    if authority.schema_version != 1
        || authority.root_package != "fireemu-verification-quint"
        || authority.target != "x86_64-unknown-linux-gnu"
    {
        return Err("unsupported source closure Cargo authority".to_owned());
    }
    let mut packages = BTreeMap::new();
    for package in &authority.packages {
        if packages.insert(package.id.as_str(), package).is_some() {
            return Err(format!("duplicate Cargo authority package {}", package.id));
        }
        if package.source.is_none() != package.manifest.is_some() {
            return Err(format!("unresolved local package {}", package.id));
        }
    }
    let mut pending = Vec::new();
    for source in sources {
        checked_path(root, source, false)?;
        let owner = authority
            .packages
            .iter()
            .filter_map(|package| {
                let manifest = Path::new(package.manifest.as_deref()?);
                let directory = manifest.parent()?;
                Path::new(source)
                    .starts_with(directory)
                    .then_some((directory.components().count(), package))
            })
            .max_by_key(|(depth, _)| *depth)
            .map(|(_, package)| package)
            .ok_or_else(|| format!("no Cargo authority owner for production source {source}"))?;
        pending.push(owner.id.as_str());
    }
    if pending.is_empty() {
        return Err("source closure has no production roots".to_owned());
    }
    let mut visited = BTreeSet::new();
    let mut inputs = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = packages
            .get(id)
            .ok_or_else(|| format!("unresolved source closure package {id}"))?;
        pending.extend(package.dependencies.iter().map(String::as_str));
        if let Some(manifest) = &package.manifest {
            inventory_package(root, package, manifest, &mut inputs)?;
        }
    }
    Ok(inputs)
}

fn inventory_package(
    root: &Path,
    package: &AuthorityPackage,
    manifest: &str,
    inputs: &mut BTreeSet<String>,
) -> Result<(), String> {
    checked_path(root, manifest, false)?;
    if Path::new(manifest)
        .file_name()
        .and_then(|name| name.to_str())
        != Some("Cargo.toml")
    {
        return Err(format!("invalid source closure manifest {manifest}"));
    }
    inputs.insert(manifest.to_owned());
    let directory = Path::new(manifest)
        .parent()
        .ok_or_else(|| format!("invalid manifest {manifest}"))?;
    inventory_directory(root, &portable(&directory.join("src"))?, inputs)?;
    let default_script = portable(&directory.join("build.rs"))?;
    match fs::symlink_metadata(root.join(&default_script)) {
        Ok(_) => {
            checked_path(root, &default_script, false)?;
            inputs.insert(default_script);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect default build script {default_script}: {error}"
            ))
        }
    }
    if let Some(script) = &package.build_script {
        checked_path(root, script, false)?;
        if !Path::new(script).starts_with(directory) {
            return Err(format!("build script escapes package: {script}"));
        }
        inputs.insert(script.clone());
    }
    Ok(())
}

fn inventory_directory(
    root: &Path,
    relative: &str,
    inputs: &mut BTreeSet<String>,
) -> Result<(), String> {
    checked_path(root, relative, true)?;
    let entries = fs::read_dir(root.join(relative))
        .map_err(|error| format!("cannot inventory {relative}: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inventory {relative}: {error}"))?;
        let child = portable(&Path::new(relative).join(entry.file_name()))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect {child}: {error}"))?;
        if metadata.is_dir() {
            inventory_directory(root, &child, inputs)?;
        } else {
            checked_path(root, &child, false)?;
            inputs.insert(child);
        }
    }
    Ok(())
}

pub(super) fn checked_path(root: &Path, relative: &str, directory: bool) -> Result<(), String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.contains('\\')
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(format!("unsafe bound input path: {relative}"));
    }
    let mut current = root.to_path_buf();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect bound input {relative}: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("symlink in bound input path: {relative}"));
        }
    }
    let metadata = fs::metadata(&current)
        .map_err(|error| format!("cannot inspect bound input {relative}: {error}"))?;
    if if directory {
        !metadata.is_dir()
    } else {
        !metadata.is_file()
    } {
        return Err(format!("bound input has invalid file type: {relative}"));
    }
    Ok(())
}

fn portable(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "non-UTF-8 source closure path".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        directory: tempfile::TempDir,
        authority: CargoAuthority,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary source inventory");
            let packages = ["root", "normal", "build", "dev", "unrelated"]
                .map(|name| {
                    let base = directory.path().join(name);
                    fs::create_dir_all(base.join("src")).expect("create src");
                    fs::write(base.join("Cargo.toml"), "[package]\n").expect("manifest");
                    fs::write(base.join("src/lib.rs"), "pub fn entry() {}\n").expect("source");
                    fs::write(base.join("src/helper.txt"), "semantic fixture\n")
                        .expect("non-Rust source");
                    AuthorityPackage {
                        id: name.to_owned(),
                        name: name.to_owned(),
                        version: "1".to_owned(),
                        source: None,
                        manifest: Some(format!("{name}/Cargo.toml")),
                        build_script: None,
                        features: vec![],
                        dependencies: match name {
                            "root" => vec!["normal".to_owned()],
                            "normal" => vec!["build".to_owned()],
                            _ => vec![],
                        },
                    }
                })
                .to_vec();
            Self {
                directory,
                authority: CargoAuthority {
                    schema_version: 1,
                    root_package: "fireemu-verification-quint".to_owned(),
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    packages,
                },
            }
        }

        fn inputs(&self) -> Result<BTreeSet<String>, String> {
            production_inputs(self.directory.path(), &["root/src/lib.rs"], &self.authority)
        }

        fn digests(&self) -> Result<BTreeMap<String, super::super::InputDigest>, String> {
            let inputs: Vec<_> = self.inputs()?.into_iter().collect();
            super::super::compute_digests(self.directory.path(), &inputs, None)
        }
    }

    type DeclarationCase<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a [&'a str]);

    #[test]
    fn test_only_declaration_shapes_preserve_reference_guards() {
        let cases: &[DeclarationCase<'_>] = &[
            (
                "non-mod.rs parent",
                &[
                    ("feature.rs", "#[cfg(test)]\nmod probe;"),
                    ("feature/probe.rs", ""),
                ],
                &["feature/probe.rs"],
            ),
            (
                "attributes after cfg with visibility and documentation",
                &[
                    (
                        "lib.rs",
                        "#[cfg(test)]\n#[allow(dead_code)]\n/// Probe.\npub(crate) mod probe;",
                    ),
                    ("probe.rs", ""),
                ],
                &["probe.rs"],
            ),
            (
                "multiline attributes after cfg",
                &[
                    (
                        "lib.rs",
                        "#[cfg(test)]\n#[allow(\n dead_code,\n)]\nmod probe;",
                    ),
                    ("probe.rs", ""),
                ],
                &["probe.rs"],
            ),
            (
                "inline test parent and nested inline module",
                &[
                    (
                        "feature.rs",
                        "#[cfg(test)] mod suite { mod nested { mod probe; } }",
                    ),
                    ("feature/suite/nested/probe.rs", ""),
                ],
                &["feature/suite/nested/probe.rs"],
            ),
            (
                "test declaration inside production inline parent",
                &[
                    ("feature.rs", "mod suite { #[cfg(test)] mod probe; }"),
                    ("feature/suite/probe.rs", ""),
                ],
                &["feature/suite/probe.rs"],
            ),
            (
                "external test parent propagates through mod.rs and file parents",
                &[
                    ("feature.rs", "#[cfg(test)] mod suite;"),
                    ("feature/suite/mod.rs", "mod probe;"),
                    ("feature/suite/probe.rs", "mod leaf;"),
                    ("feature/suite/probe/leaf.rs", ""),
                ],
                &[
                    "feature/suite/mod.rs",
                    "feature/suite/probe.rs",
                    "feature/suite/probe/leaf.rs",
                ],
            ),
            (
                "match arm named path does not retain every candidate",
                &[
                    (
                        "lib.rs",
                        "#[cfg(test)] mod probe; fn f() { match value { None => (), path => () } }",
                    ),
                    ("probe.rs", ""),
                ],
                &["probe.rs"],
            ),
        ];
        assert_declaration_cases(cases);
    }

    #[test]
    fn test_only_declaration_duplicates_preserve_guards() {
        let cases: &[DeclarationCase<'_>] = &[
            (
                "non-test duplicate declaration",
                &[
                    ("lib.rs", "#[cfg(test)] mod probe; mod probe;"),
                    ("probe.rs", ""),
                ],
                &[],
            ),
            (
                "non-test declaration in another source",
                &[
                    ("lib.rs", "#[cfg(test)] mod probe;"),
                    ("mod.rs", "mod probe;"),
                    ("probe.rs", ""),
                ],
                &[],
            ),
            (
                "non-test declaration outside guarded inline parent",
                &[
                    (
                        "lib.rs",
                        "#[cfg(test)] mod suite { mod probe; } mod suite { mod probe; }",
                    ),
                    ("suite/probe.rs", ""),
                ],
                &[],
            ),
            (
                "production inline parent remains bound",
                &[
                    ("feature.rs", "mod suite { mod probe; }"),
                    ("feature/suite/probe.rs", ""),
                ],
                &[],
            ),
        ];
        assert_declaration_cases(cases);
    }

    #[test]
    fn test_only_declaration_references_preserve_guards() {
        let cases: &[DeclarationCase<'_>] = &[
            (
                "path attribute before cfg",
                &[("lib.rs", "#[path = \"elsewhere.rs\"] #[cfg(test)] mod probe;"), ("probe.rs", "")],
                &[],
            ),
            (
                "path attribute after cfg",
                &[("lib.rs", "#[cfg(test)] #[path = \"elsewhere.rs\"] mod probe;"), ("probe.rs", "")],
                &[],
            ),
            (
                "redirected inline ancestor",
                &[("lib.rs", "#[cfg(test)] #[path = \"elsewhere\"] mod suite { mod probe; }"), ("suite/probe.rs", "")],
                &[],
            ),
            (
                "alternate literal path reference",
                &[("lib.rs", "#[cfg(test)] mod probe; #[path = \"probe.rs\"] mod other;"), ("probe.rs", "")],
                &[],
            ),
            (
                "computed path retains all candidates",
                &[("lib.rs", "#[cfg(test)] mod probe; #[path = env!(\"MODULE\")] mod other;"), ("probe.rs", "")],
                &[],
            ),
            (
                "literal include retains referenced candidate",
                &[("lib.rs", "#[cfg(test)] mod probe; include!(\"probe.rs\");"), ("probe.rs", "")],
                &[],
            ),
            (
                "manifest-relative include retains referenced candidate",
                &[("lib.rs", "#[cfg(test)] mod probe; include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/probe.rs\"));"), ("probe.rs", "")],
                &[],
            ),
            (
                "computed include retains all candidates",
                &[("lib.rs", "#[cfg(test)] mod probe; include!(env!(\"MODULE\"));"), ("probe.rs", "")],
                &[],
            ),
            (
                "retained parent restores inherited descendants",
                &[("lib.rs", "#[cfg(test)] mod suite; include!(\"suite/mod.rs\");"), ("suite/mod.rs", "mod probe;"), ("suite/probe.rs", "mod leaf;"), ("suite/probe/leaf.rs", "")],
                &[],
            ),
            (
                "retained parent preserves independently guarded child",
                &[("lib.rs", "#[cfg(test)] mod suite; mod suite;"), ("suite/mod.rs", "#[cfg(test)] mod probe;"), ("suite/probe.rs", "")],
                &["suite/probe.rs"],
            ),
            (
                "alternate reference retains inherited child",
                &[("lib.rs", "#[cfg(test)] mod suite; include!(\"suite/probe.rs\");"), ("suite/mod.rs", "mod probe;"), ("suite/probe.rs", "")],
                &[],
            ),
            (
                "unrecognized cfg remains bound",
                &[("lib.rs", "#[cfg(all(test))] mod probe;"), ("probe.rs", "")],
                &[],
            ),
            (
                "comments and literals cannot supply declarations",
                &[("lib.rs", "/* #[cfg(test)] mod probe; */ const TEXT: &str = r#\"#[cfg(test)] mod probe;\"#;"), ("probe.rs", "")],
                &[],
            ),
            (
                "macro bodies are not module scopes",
                &[("lib.rs", "emit! { #[cfg(test)] mod probe; }"), ("probe.rs", "")],
                &[],
            ),
            (
                "ambiguous module paths remain bound",
                &[("lib.rs", "#[cfg(test)] mod probe;"), ("probe.rs", ""), ("probe/mod.rs", "")],
                &[],
            ),
            (
                "unparsed production source retains every candidate",
                &[("lib.rs", "#[cfg(test)] mod probe;"), ("probe.rs", ""), ("other.rs", "/*")],
                &[],
            ),
        ];
        assert_declaration_cases(cases);
    }

    fn assert_declaration_cases(cases: &[DeclarationCase<'_>]) {
        let fixture = Fixture::new();
        for &(case, files, excluded) in cases {
            let sources: BTreeMap<_, _> = files
                .iter()
                .map(|(path, source)| (format!("root/src/{path}"), *source))
                .collect();
            let inputs = sources.keys().cloned().collect();
            let mut syntax = BTreeMap::new();
            let mut unparsed = BTreeSet::new();
            for (path, source) in &sources {
                if let Some(tokens) = super::super::tokenize_source(source) {
                    syntax.insert(path.as_str(), tokens);
                } else {
                    unparsed.insert(path.as_str());
                }
            }
            let mut candidates = super::super::test_module_candidates(
                &syntax,
                &fixture.authority,
                &inputs,
                &BTreeSet::new(),
            );
            if !super::super::retain_referenced_candidates(&syntax, &unparsed, &mut candidates) {
                candidates.clear();
            }
            assert_eq!(
                candidates.into_keys().collect::<BTreeSet<_>>(),
                excluded
                    .iter()
                    .map(|path| format!("root/src/{path}"))
                    .collect(),
                "{case}"
            );
        }
    }

    #[test]
    fn closure_is_sorted_transitive_and_excludes_unreachable_packages() {
        let fixture = Fixture::new();
        let inputs = fixture.inputs().expect("valid closure");
        assert_eq!(inputs.len(), 9);
        for package in ["root", "normal", "build"] {
            for file in ["Cargo.toml", "src/lib.rs", "src/helper.txt"] {
                assert!(inputs.contains(&format!("{package}/{file}")));
            }
        }
        assert!(!inputs
            .iter()
            .any(|path| path.starts_with("dev/") || path.starts_with("unrelated/")));
        let mut reordered = fixture.authority.clone();
        reordered.packages.reverse();
        assert_eq!(
            inputs,
            production_inputs(fixture.directory.path(), &["root/src/lib.rs"], &reordered)
                .expect("reordered graph")
        );
    }

    #[test]
    fn newly_added_default_build_scripts_change_the_inventory() {
        let fixture = Fixture::new();
        let baseline = fixture.inputs().expect("baseline inventory");
        fs::write(
            fixture.directory.path().join("normal/build.rs"),
            "fn main() {}\n",
        )
        .expect("new default build script");
        let changed = fixture.inputs().expect("changed inventory");
        assert_ne!(baseline, changed);
        assert!(changed.contains("normal/build.rs"));
    }

    #[test]
    fn custom_build_script_is_bound_and_missing_script_is_rejected() {
        let mut fixture = Fixture::new();
        fs::create_dir(fixture.directory.path().join("normal/build")).expect("build directory");
        fs::write(
            fixture.directory.path().join("normal/build/custom.rs"),
            "fn main() {}\n",
        )
        .expect("build script");
        fixture.authority.packages[1].build_script = Some("normal/build/custom.rs".to_owned());
        assert!(fixture
            .inputs()
            .expect("custom build closure")
            .contains("normal/build/custom.rs"));
        fs::remove_file(fixture.directory.path().join("normal/build/custom.rs"))
            .expect("remove script");
        assert!(fixture
            .inputs()
            .expect_err("missing build script")
            .contains("normal/build/custom.rs"));
    }

    #[test]
    fn incomplete_or_ambiguous_graphs_fail_closed() {
        let mut fixture = Fixture::new();
        fixture.authority.packages[0]
            .dependencies
            .push("missing".to_owned());
        assert!(fixture
            .inputs()
            .expect_err("missing dependency")
            .contains("unresolved source closure package"));
        fixture.authority.packages[0].dependencies.pop();
        fixture
            .authority
            .packages
            .push(fixture.authority.packages[0].clone());
        assert!(fixture
            .inputs()
            .expect_err("duplicate identity")
            .contains("duplicate Cargo authority package"));
        assert!(production_inputs(
            fixture.directory.path(),
            &["missing/src/lib.rs"],
            &fixture.authority
        )
        .is_err());
    }

    #[test]
    fn missing_roots_and_src_directories_are_rejected() {
        let fixture = Fixture::new();
        assert!(production_inputs(
            fixture.directory.path(),
            &["root/src/missing.rs"],
            &fixture.authority
        )
        .is_err());
        fs::remove_dir_all(fixture.directory.path().join("normal/src"))
            .expect("remove source tree");
        assert!(fixture
            .inputs()
            .expect_err("missing source tree")
            .contains("normal/src"));
    }

    #[test]
    fn escaping_and_absolute_paths_are_rejected() {
        let fixture = Fixture::new();
        for path in [
            "../root/src/lib.rs",
            "/root/src/lib.rs",
            "root/../root/src/lib.rs",
            "root\\src\\lib.rs",
        ] {
            assert!(
                production_inputs(fixture.directory.path(), &[path], &fixture.authority)
                    .expect_err("unsafe path")
                    .contains("unsafe bound input path")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_in_files_directories_and_source_ancestors_are_rejected() {
        let fixture = Fixture::new();
        let root = fixture.directory.path();
        std::os::unix::fs::symlink(
            root.join("unrelated/src/lib.rs"),
            root.join("normal/src/link.rs"),
        )
        .expect("file symlink");
        assert!(fixture
            .inputs()
            .expect_err("file symlink")
            .contains("symlink"));
        fs::remove_file(root.join("normal/src/link.rs")).expect("remove link");
        std::os::unix::fs::symlink(root.join("unrelated/src"), root.join("normal/src/nested"))
            .expect("directory symlink");
        assert!(fixture
            .inputs()
            .expect_err("directory symlink")
            .contains("symlink"));
        fs::remove_file(root.join("normal/src/nested")).expect("remove directory link");
        fs::rename(root.join("normal"), root.join("moved")).expect("move package");
        std::os::unix::fs::symlink(root.join("moved"), root.join("normal"))
            .expect("ancestor symlink");
        assert!(fixture
            .inputs()
            .expect_err("ancestor symlink")
            .contains("symlink"));
    }

    fn exercise_row(dependency: &str, operation: &str, safety: &str) {
        let fixture = Fixture::new();
        let baseline = fixture.digests().expect("baseline closure digests");
        assert_eq!(baseline, fixture.digests().expect("unchanged control"));
        let path = fixture
            .directory
            .path()
            .join(format!("{dependency}/src/helper.txt"));
        match safety {
            "regular" => match operation {
                "edit" => fs::write(&path, "changed semantics\n").expect("edit helper"),
                "add" => fs::write(
                    path.with_file_name("new-helper.rs"),
                    "pub fn new_helper() {}\n",
                )
                .expect("add helper"),
                "delete" => fs::remove_file(&path).expect("delete helper"),
                other => panic!("unknown operation {other}"),
            },
            #[cfg(unix)]
            "symlink" => {
                fs::remove_file(&path).expect("remove helper");
                std::os::unix::fs::symlink(
                    fixture.directory.path().join("unrelated/src/lib.rs"),
                    &path,
                )
                .expect("replace helper by symlink");
            }
            "escape" => {
                let error = production_inputs(
                    fixture.directory.path(),
                    &["../root/src/lib.rs"],
                    &fixture.authority,
                )
                .expect_err("escape must fail");
                assert!(error.contains("unsafe bound input path"));
                return;
            }
            other => panic!("unknown safety {other}"),
        }
        let reached = matches!(dependency, "root" | "normal" | "build");
        if reached && safety == "symlink" {
            assert!(fixture
                .digests()
                .expect_err("unsafe reachable file")
                .contains("symlink"));
        } else {
            let changed = fixture.digests().expect("changed closure digests");
            assert_eq!(
                baseline != changed,
                reached,
                "{dependency}/{operation}/{safety}"
            );
        }
    }

    #[test]
    fn helper_edits_additions_and_deletions_invalidate_only_reachable_packages() {
        for dependency in ["root", "normal", "build", "dev", "unrelated"] {
            for operation in ["edit", "add", "delete"] {
                exercise_row(dependency, operation, "regular");
            }
        }
    }

    #[test]
    #[ignore = "requires generated PICT rows via QUINT_SOURCE_CLOSURE_ROWS"]
    fn generated_source_closure_rows() {
        let path = std::env::var("QUINT_SOURCE_CLOSURE_ROWS").expect("PICT row path");
        let contents = fs::read_to_string(path).expect("generated PICT rows");
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some("Dependency\tOperation\tSafety"));
        let mut count = 0;
        for line in lines {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3, "PICT row {line}");
            exercise_row(fields[0], fields[1], fields[2]);
            count += 1;
            eprintln!("PICT row {count}: {line}");
        }
        assert!(count > 0, "empty PICT table");
    }
}
