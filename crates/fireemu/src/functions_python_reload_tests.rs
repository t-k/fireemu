use std::path::Path;

#[test]
fn python_codebases_are_supervised_for_source_reload() {
    let root =
        std::env::temp_dir().join(format!("fireemu-python-reload-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("requirements.txt"), "firebase-functions\n").unwrap();
    let codebase = crate::config::FunctionsCodebase {
        codebase: "py".to_owned(),
        source: root.display().to_string(),
        runtime: None,
        ignore: Vec::new(),
    };
    assert!(super::super::reload_supervised(&codebase));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[tokio::test]
async fn python_reload_snapshot_links_the_venv_and_excludes_it_from_the_copy() {
    let root = std::env::temp_dir().join(format!(
        "fireemu-python-snapshot-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let source = root.join("source");
    std::fs::create_dir_all(source.join("venv/bin")).unwrap();
    std::fs::write(source.join("venv/bin/python"), "interpreter").unwrap();
    std::fs::write(source.join("main.py"), "def handler(): return 'old'\n").unwrap();
    std::fs::create_dir_all(source.join("__pycache__")).unwrap();
    std::fs::write(source.join("__pycache__/handler.pyc"), "cache").unwrap();
    std::fs::write(source.join("handler.pyo"), "cache").unwrap();
    std::fs::create_dir_all(source.join("my__pycache__")).unwrap();
    std::fs::write(source.join("my__pycache__/source.py"), "application asset").unwrap();

    let python = crate::config::FunctionsCodebase {
        codebase: "py".to_owned(),
        source: source.display().to_string(),
        runtime: Some("python312".to_owned()),
        ignore: Vec::new(),
    };
    let ignores = super::super::reload_ignore_patterns(&python);
    assert!(ignores.iter().any(|pattern| pattern == "venv"));
    std::fs::write(source.join(".env.local"), "SECRET=value\n").unwrap();
    let snapshot =
        super::super::snapshot_functions_source_with_linked_venv(&source, &ignores).unwrap();
    let snapshot_source = snapshot.to_path_buf();
    let venv = snapshot_source.join("venv");
    assert!(std::fs::symlink_metadata(&venv)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_link(&venv).unwrap(),
        std::fs::canonicalize(source.join("venv")).unwrap()
    );
    assert_eq!(
        std::fs::read(venv.join("bin/python")).unwrap(),
        b"interpreter"
    );
    assert!(snapshot_source.join("main.py").is_file());
    assert_eq!(
        std::fs::read(snapshot_source.join(".env.local")).unwrap(),
        b"SECRET=value\n"
    );
    assert!(!snapshot_source.join("__pycache__").exists());
    assert!(!snapshot_source.join("handler.pyo").exists());
    assert_eq!(
        std::fs::read(snapshot_source.join("my__pycache__/source.py")).unwrap(),
        b"application asset"
    );
    snapshot.remove().await.unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn python_reload_excludes_runtime_environment_and_cache_artifacts() {
    let codebase = crate::config::FunctionsCodebase {
        codebase: "py".to_owned(),
        source: "/tmp/functions".to_owned(),
        runtime: Some("python312".to_owned()),
        ignore: Vec::new(),
    };
    let ignores = super::super::reload_ignore_patterns(&codebase);
    assert!(super::super::ignored_reload_path(
        Path::new("venv/lib/python/site.py"),
        &ignores
    ));
    assert!(!super::super::ignored_reload_path(
        Path::new("src/main.py"),
        &ignores
    ));
    assert!(super::super::is_python_cache_path(Path::new(
        "src/__pycache__/module.cpython-312.pyc"
    )));
    assert!(super::super::is_python_cache_path(Path::new(
        "src/module.pyo"
    )));
    assert!(!super::super::ignored_reload_path(
        Path::new("src/__pycache__/module.cpython-312.pyc"),
        &ignores
    ));
    assert!(!super::super::ignored_reload_path(
        Path::new("src/module.pyo"),
        &ignores
    ));
}

#[cfg(unix)]
#[test]
fn node_reload_snapshot_keeps_python_named_runtime_assets() {
    let root = std::env::temp_dir().join(format!(
        "fireemu-node-cache-snapshot-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let source = root.join("source");
    std::fs::create_dir_all(source.join("__pycache__")).unwrap();
    std::fs::write(source.join("__pycache__/handler.pyc"), "node asset").unwrap();
    std::fs::write(source.join("helper.pyo"), "node helper").unwrap();
    std::fs::create_dir_all(source.join("my__pycache__")).unwrap();
    std::fs::write(
        source.join("my__pycache__/source.py"),
        "node application asset",
    )
    .unwrap();
    let codebase = crate::config::FunctionsCodebase {
        codebase: "node".to_owned(),
        source: source.display().to_string(),
        runtime: Some("nodejs20".to_owned()),
        ignore: Vec::new(),
    };
    let ignores = super::super::reload_ignore_patterns(&codebase);
    assert!(!super::super::ignored_reload_path(
        Path::new("__pycache__/handler.pyc"),
        &ignores
    ));
    let snapshot = super::super::snapshot_functions_source(&source, &ignores).unwrap();
    assert_eq!(
        std::fs::read(snapshot.join("__pycache__/handler.pyc")).unwrap(),
        b"node asset"
    );
    assert_eq!(
        std::fs::read(snapshot.join("helper.pyo")).unwrap(),
        b"node helper"
    );
    std::fs::remove_dir_all(snapshot.into_path()).unwrap();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn python_cache_exclusion_uses_exact_components_and_tracks_similarly_named_sources() {
    let root =
        std::env::temp_dir().join(format!("fireemu-python-cache-paths-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("my__pycache__")).unwrap();
    std::fs::create_dir_all(root.join("__pycache__")).unwrap();
    std::fs::write(root.join("my__pycache__/source.py"), "one").unwrap();
    std::fs::write(root.join("__pycache__/bytecode.pyc"), "cache").unwrap();
    std::fs::write(root.join("helper.pyo"), "cache").unwrap();
    let ignores = Vec::new();
    let mut charge = |_, _| Ok(());
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let first = super::super::functions_source_stamp_with_python_cache_excluded(
        &root,
        &ignores,
        &mut charge,
        &cancelled,
    )
    .unwrap();
    std::fs::write(root.join("my__pycache__/source.py"), "two").unwrap();
    let second = super::super::functions_source_stamp_with_python_cache_excluded(
        &root,
        &ignores,
        &mut charge,
        &cancelled,
    )
    .unwrap();
    assert_ne!(first.content_signature, second.content_signature);
    assert_eq!(first.tracked_files, 1);
    assert_eq!(second.tracked_files, 1);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exercise the complete generated PICT table in one test.
async fn pict_generated_reload_cases_exercise_snapshot_and_language_behaviors() {
    let cases = include_str!("../tests/fixtures/python_reload_pict.tsv");
    let mut lines = cases.lines();
    assert_eq!(
        lines.next(),
        Some("Language\tSourceEdit\tEnvironment\tSnapshot")
    );
    let rows: Vec<_> = lines.collect();
    assert_eq!(rows.len(), 8, "the checked-in PICT table changed");
    for (index, row) in rows.iter().enumerate() {
        let [language, source_edit, environment, snapshot_outcome]: [&str; 4] = row
            .split('\t')
            .collect::<Vec<_>>()
            .try_into()
            .expect("each PICT row has four factors");
        let root = std::env::temp_dir().join(format!(
            "fireemu-python-reload-pict-{}-{index}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        let python = language == "Python";
        let runtime = if python { "python312" } else { "nodejs20" };
        let codebase = crate::config::FunctionsCodebase {
            codebase: format!("pict-{index}"),
            source: source.display().to_string(),
            runtime: Some(runtime.to_owned()),
            ignore: Vec::new(),
        };
        let ignores = super::super::reload_ignore_patterns(&codebase);
        assert!(super::super::reload_supervised(&codebase), "{row}");
        if python {
            assert!(ignores.iter().any(|pattern| pattern == "venv"), "{row}");
        } else {
            assert!(!ignores.iter().any(|pattern| pattern == "venv"), "{row}");
        }
        if environment == "venv_with_cache" {
            std::fs::create_dir_all(source.join("venv/cache")).unwrap();
            std::fs::write(source.join("venv/cache/dependency.bin"), b"dependency").unwrap();
            std::fs::create_dir_all(source.join("__pycache__")).unwrap();
            std::fs::write(source.join("__pycache__/entry.pyc"), b"bytecode").unwrap();
        } else {
            assert_eq!(environment, "venv_only", "{row}");
            std::fs::create_dir_all(source.join("venv")).unwrap();
        }
        match source_edit {
            "valid" => std::fs::write(source.join("main.py"), "value = 'valid'\n").unwrap(),
            "invalid_then_recovery" => {
                std::fs::write(source.join("main.py"), "def handler(:\n").unwrap();
            }
            "none" => std::fs::write(source.join("main.py"), "value = 'initial'\n").unwrap(),
            other => panic!("unknown PICT source edit {other:?}"),
        }
        let python_runtime = python;
        let mut charge = |_, _| Ok(());
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let expected = if python_runtime {
            super::super::functions_source_stamp_with_python_cache_excluded(
                &source,
                &ignores,
                &mut charge,
                &cancelled,
            )
            .unwrap()
        } else {
            super::super::functions_source_stamp_with_charge(
                &source,
                &ignores,
                &mut charge,
                &cancelled,
            )
            .unwrap()
        }
        .content_signature;
        let stable = if snapshot_outcome == "consistent" {
            expected
        } else {
            assert_eq!(snapshot_outcome, "inconsistent", "{row}");
            expected ^ 1
        };
        let mut retry_delay = std::time::Duration::from_millis(750);
        let mut last_snapshot_error = false;
        let scan_budget = super::super::FunctionsSourceScanBudget::new();
        let snapshot = super::super::snapshot_consistent_reload_source(
            &source,
            &codebase,
            &scan_budget,
            stable,
            &mut retry_delay,
            &mut last_snapshot_error,
        )
        .await;
        if snapshot_outcome == "consistent" {
            let snapshot = snapshot.expect("consistent PICT source must be staged: {row}");
            let staged_venv = snapshot.join("venv");
            assert!(staged_venv.exists(), "venv missing for {row}");
            if python {
                assert!(
                    std::fs::symlink_metadata(&staged_venv)
                        .unwrap()
                        .file_type()
                        .is_symlink(),
                    "Python venv must stay linked for {row}"
                );
                assert!(!snapshot.join("__pycache__").exists(), "{row}");
            } else {
                assert!(
                    staged_venv.is_dir(),
                    "Node venv-named runtime input is copied for {row}"
                );
                assert!(!std::fs::symlink_metadata(&staged_venv)
                    .unwrap()
                    .file_type()
                    .is_symlink());
            }
            snapshot.remove().await.unwrap();
        } else {
            assert!(
                snapshot.is_none(),
                "inconsistent PICT source must be rejected: {row}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
