//! Repository-local semantic source inventory derived from the Cargo authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use crate::cargo_authority::{AuthorityPackage, CargoAuthority};

pub(super) fn production_inputs(
    root: &Path,
    sources: &[&str],
    authority: &CargoAuthority,
) -> Result<(BTreeSet<String>, bool), String> {
    if authority.schema_version != 2
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
    let mut has_untrusted_proc_macro = false;
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = packages
            .get(id)
            .ok_or_else(|| format!("unresolved source closure package {id}"))?;
        pending.extend(package.dependencies.iter().map(String::as_str));
        has_untrusted_proc_macro |= package.proc_macro
            && (package.source.is_none()
                || !super::TOKEN_ONLY_PROC_MACROS.contains(&package.name.as_str()));
        if let Some(manifest) = &package.manifest {
            inventory_package(root, package, manifest, &mut inputs)?;
        }
    }
    Ok((inputs, has_untrusted_proc_macro))
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
                        proc_macro: false,
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
                    schema_version: 2,
                    root_package: "fireemu-verification-quint".to_owned(),
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    packages,
                },
            }
        }

        fn inputs(&self) -> Result<BTreeSet<String>, String> {
            production_inputs(self.directory.path(), &["root/src/lib.rs"], &self.authority)
                .map(|(inputs, _)| inputs)
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
                .map(|(inputs, _)| inputs)
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

    fn compile_time_guard_fixture() -> (Fixture, crate::model::ModelDescriptor) {
        let fixture = Fixture::new();
        let root = fixture.directory.path();
        let descriptor = crate::model::ModelDescriptor {
            production_sources: &["root/src/lib.rs"],
            driver: "root/src/lib.rs",
            connect_test: "root/src/lib.rs",
            additional_evidence_inputs: &[
                "normal/tests/input.txt",
                "normal/benches/input.txt",
                "normal/examples/input.txt",
                "root/tests/input.txt",
            ],
            ..*crate::model::model("EventDelivery").expect("registered model")
        };
        for path in super::super::COMMON_DIGEST_PATHS
            .iter()
            .chain(descriptor.additional_evidence_inputs)
        {
            let path = root.join(path);
            fs::create_dir_all(path.parent().expect("input parent")).expect("input directory");
            fs::write(path, "").expect("common or explicit input");
        }
        for package in ["root", "normal"] {
            fs::write(
                root.join(format!("{package}/src/lib.rs")),
                if package == "root" {
                    "#[cfg(test)]\nmod probe;\npub fn value() -> &'static str { normal::value() }\n"
                } else {
                    "#[cfg(test)]\nmod probe;\npub fn value() -> &'static str { env!(\"VALUE\") }\n"
                },
            )
            .expect("test-only declaration");
            fs::write(root.join(format!("{package}/src/probe.rs")), "// Probe.\n")
                .expect("test-only module");
        }
        // Unreachable compile-time code must not disable this model's exclusions.
        fs::write(root.join("unrelated/build.rs"), "fn main() {}\n")
            .expect("unreachable build script");
        fs::write(
            root.join("unrelated/Cargo.toml"),
            "[package]\n[lib]\nproc-macro = true\n",
        )
        .expect("unreachable proc-macro manifest");
        let authority_path = root.join(super::super::CARGO_AUTHORITY_INPUT);
        fs::write(
            &authority_path,
            serde_json::to_vec(&fixture.authority).expect("serialize authority"),
        )
        .expect("authority without build script");
        let baseline = super::super::expected_bound_inputs(root, &descriptor, None)
            .expect("inventory without build script");
        assert!(!baseline.iter().any(|input| input.ends_with("/probe.rs")));
        for path in descriptor.additional_evidence_inputs {
            assert!(baseline.iter().any(|input| input == path));
        }

        (fixture, descriptor)
    }

    #[test]
    fn external_proc_macros_guard_the_entire_model_unless_allow_listed() {
        for (name, reachable, proc_macro, retains) in [
            ("include_dir_macros", true, true, true),
            ("unknown-macro", true, true, true),
            ("serde_derive", true, true, false),
            ("include_dir_macros", false, true, false),
            ("ordinary-library", true, false, false),
        ] {
            let (mut fixture, descriptor) = compile_time_guard_fixture();
            let root = fixture.directory.path();
            fs::create_dir(root.join("root/src/fixtures")).expect("fixture directory");
            fs::write(
                root.join("root/src/fixtures/mod.rs"),
                "pub const VALUE: u8 = 1;\n",
            )
            .expect("test-only fixture");
            fs::write(
                root.join("root/src/lib.rs"),
                if name == "serde_derive" {
                    "#[cfg(test)] mod fixtures;\n#[derive(serde_derive::Serialize)] pub struct Value;\n"
                } else {
                    "#[cfg(test)] mod fixtures;\npub static FIXTURES: include_dir::Dir<'static> = include_dir::include_dir!(\"$CARGO_MANIFEST_DIR/src/fixtures\");\n"
                },
            )
            .expect("directory embedding invocation");
            // A reachable local build dependency reaches an external facade and its macro.
            if reachable {
                fixture.authority.packages[2]
                    .dependencies
                    .push("include_dir".to_owned());
            }
            fixture.authority.packages.push(AuthorityPackage {
                id: "include_dir".to_owned(),
                name: "include_dir".to_owned(),
                version: "0.7.4".to_owned(),
                source: Some("registry+fixture".to_owned()),
                manifest: None,
                build_script: None,
                proc_macro: false,
                features: vec![],
                dependencies: vec![name.to_owned()],
            });
            fixture.authority.packages.push(AuthorityPackage {
                id: name.to_owned(),
                name: name.to_owned(),
                version: "1".to_owned(),
                source: Some("registry+fixture".to_owned()),
                manifest: None,
                build_script: None,
                proc_macro,
                features: vec![],
                dependencies: vec![],
            });
            for source in ["registry+fixture", "git+https://example.invalid/macros"] {
                fixture
                    .authority
                    .packages
                    .last_mut()
                    .expect("macro package")
                    .source = Some(source.to_owned());
                fs::write(
                    root.join(super::super::CARGO_AUTHORITY_INPUT),
                    serde_json::to_vec(&fixture.authority).expect("serialize authority"),
                )
                .expect("authority with external macro");
                let bound = super::super::expected_bound_inputs(root, &descriptor, None)
                    .expect("inventory with external macro");
                for path in ["root/src/fixtures/mod.rs", "normal/src/probe.rs"] {
                    assert_eq!(
                        bound.iter().any(|input| input == path),
                        retains,
                        "{name}/{reachable}/{proc_macro}/{source}: {path}"
                    );
                }
                assert!(bound.iter().any(|input| input == "normal/tests/input.txt"));
            }
        }
    }

    #[test]
    fn local_proc_macro_with_an_allow_listed_name_still_disables_exclusions() {
        let (mut fixture, descriptor) = compile_time_guard_fixture();
        let root = fixture.directory.path();
        fixture.authority.packages[1].name = "serde_derive".to_owned();
        fixture.authority.packages[1].proc_macro = true;
        fs::write(
            root.join(super::super::CARGO_AUTHORITY_INPUT),
            serde_json::to_vec(&fixture.authority).expect("serialize authority"),
        )
        .expect("authority with local proc-macro target");
        let bound = super::super::expected_bound_inputs(root, &descriptor, None)
            .expect("inventory with local proc-macro target");
        assert!(bound.iter().any(|input| input == "root/src/probe.rs"));
        assert!(bound.iter().any(|input| input == "normal/tests/input.txt"));
    }

    #[test]
    fn reachable_compile_time_code_prevents_all_model_test_only_exclusions() {
        for script in ["tests/build.rs", "build.rs", "src/lib.rs"] {
            let (mut fixture, descriptor) = compile_time_guard_fixture();
            let root = fixture.directory.path();
            let authority_path = root.join(super::super::CARGO_AUTHORITY_INPUT);

            let script_path = format!("normal/{script}");
            let source = if script == "src/lib.rs" {
                fs::write(
                    root.join("normal/Cargo.toml"),
                    "[package]\n[lib]\nproc-macro = true\n",
                )
                .expect("reachable proc-macro manifest");
                fs::write(
                    root.join("root/src/lib.rs"),
                    "#[cfg(test)] mod probe; pub fn value() -> usize { normal::measured!() }\n",
                )
                .expect("production macro invocation");
                r#"extern crate proc_macro;
#[cfg(test)]
mod probe;
#[proc_macro]
pub fn measured(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src").join("probe").with_extension("rs");
    std::fs::read(path).unwrap().len().to_string().parse().unwrap()
}
"#
            } else if script == "tests/build.rs" {
                fs::write(
                    root.join("normal/Cargo.toml"),
                    "[package]\nbuild = \"tests/build.rs\"\n",
                )
                .expect("custom build manifest");
                fixture.authority.packages[1].build_script = Some(script_path.clone());
                "fn main() { println!(\"cargo:rustc-env=VALUE=one\"); }\n"
            } else {
                // Leave authority unchanged to cover discovery of a new default build script.
                r#"fn main() {
    let path = std::path::Path::new("../root").join("src").join("probe").with_extension("rs");
    let bytes = std::fs::read(&path).unwrap();
    println!("cargo:rerun-if-changed={}", path.display());
    println!("cargo:rustc-env=VALUE={}", bytes.len());
}
"#
            };
            fs::write(root.join(&script_path), source).expect("build script");
            fs::write(
                &authority_path,
                serde_json::to_vec(&fixture.authority).expect("serialize authority"),
            )
            .expect("authority with build script");
            let bound = super::super::expected_bound_inputs(root, &descriptor, None)
                .expect("inventory with build script");
            for path in fixture.inputs().expect("unfiltered inventory") {
                assert!(bound.contains(&path), "{script} must retain {path}");
            }
            for path in descriptor.additional_evidence_inputs {
                assert!(
                    bound.iter().any(|input| input == path),
                    "{script} must retain {path}"
                );
            }
            for path in [
                script_path.as_str(),
                "normal/src/probe.rs",
                "root/src/probe.rs",
            ] {
                let before = super::super::current_input_digest(root, path).expect("bound digest");
                let mut bytes = fs::read(root.join(path)).expect("bound bytes");
                bytes.extend_from_slice(b"// Changed build input.\n");
                fs::write(root.join(path), bytes).expect("change build input");
                assert_ne!(
                    before,
                    super::super::current_input_digest(root, path).expect("changed digest"),
                    "{script} must bind every byte of {path}"
                );
            }
        }
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
        fixture.authority.schema_version = 1;
        assert!(fixture
            .inputs()
            .expect_err("legacy authority")
            .contains("unsupported source closure Cargo authority"));
        fixture.authority.schema_version = 2;
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
