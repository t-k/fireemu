use std::os::unix::fs::symlink;

fn temp_tree(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "fireemu-python-link-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    root
}

#[tokio::test]
async fn python_source_signature_and_snapshot_include_external_sibling_directory_alias() {
    let workspace = temp_tree("sibling");
    let source = workspace.join("functions");
    let shared = workspace.join("shared");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(source.join("main.py"), "VALUE = 1\n").unwrap();
    std::fs::write(shared.join("module.py"), "VALUE = 'captured'\n").unwrap();
    symlink("../shared", source.join("shared")).unwrap();

    let before = super::super::functions_source_stamp_with_python_cache_excluded(
        &source,
        &[],
        &mut |_, _| Ok(()),
        &super::super::AtomicBool::new(false),
    )
    .expect("Python source traversal follows ordinary source aliases");
    let snapshot = super::super::snapshot_functions_source_with_linked_venv(&source, &[])
        .expect("Python snapshots materialize external source aliases");
    let snapshot_path = snapshot.to_path_buf();
    let after = super::super::functions_source_stamp_with_python_cache_excluded(
        &snapshot_path,
        &[],
        &mut |_, _| Ok(()),
        &super::super::AtomicBool::new(false),
    )
    .expect("materialized aliases are ordinary snapshot files");
    assert_eq!(before.content_signature, after.content_signature);
    assert_eq!(std::fs::read(snapshot_path.join("shared/module.py")).unwrap(), b"VALUE = 'captured'\n");
    assert!(!std::fs::symlink_metadata(snapshot_path.join("shared")).unwrap().file_type().is_symlink());

    snapshot.remove().await.unwrap();
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn python_aliases_are_separate_logical_inputs_and_snapshots_are_independent() {
    let workspace = temp_tree("aliases");
    let source = workspace.join("functions");
    let shared = workspace.join("shared");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(source.join("main.py"), "VALUE = 'main-before'\n").unwrap();
    std::fs::write(shared.join("module.py"), "VALUE = 'captured'\n").unwrap();
    symlink("../shared", source.join("shared")).unwrap();
    symlink("../shared", source.join("second_shared")).unwrap();
    let absolute_file = workspace.join("absolute.py");
    std::fs::write(&absolute_file, b"EXTERNAL = True\n").unwrap();
    symlink(&absolute_file, source.join("absolute.py")).unwrap();

    let before = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap();
    let snapshot = super::super::snapshot_functions_source_with_linked_venv(&source, &[]).unwrap();
    let captured = snapshot.to_path_buf();
    assert_eq!(
        std::fs::read(captured.join("shared/module.py")).unwrap(),
        b"VALUE = 'captured'\n"
    );
    assert_eq!(
        std::fs::read(captured.join("second_shared/module.py")).unwrap(),
        b"VALUE = 'captured'\n"
    );
    assert_eq!(
        std::fs::read(captured.join("absolute.py")).unwrap(),
        b"EXTERNAL = True\n"
    );
    for alias in ["shared", "second_shared", "absolute.py"] {
        assert!(!std::fs::symlink_metadata(captured.join(alias))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    std::fs::write(shared.join("module.py"), "VALUE = 'later'\n").unwrap();
    std::fs::write(source.join("main.py"), "VALUE = 'main-after'\n").unwrap();
    std::fs::write(&absolute_file, b"EXTERNAL = False\n").unwrap();
    let replacement = workspace.join("replacement");
    std::fs::create_dir_all(&replacement).unwrap();
    std::fs::write(replacement.join("module.py"), "VALUE = 'retargeted'\n").unwrap();
    std::fs::remove_file(source.join("shared")).unwrap();
    symlink("../replacement", source.join("shared")).unwrap();
    let after = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap();
    assert_ne!(before.content_signature, after.content_signature);
    std::fs::remove_dir_all(&shared).unwrap();
    assert_eq!(
        std::fs::read(captured.join("shared/module.py")).unwrap(),
        b"VALUE = 'captured'\n"
    );
    assert_eq!(
        std::fs::read(captured.join("second_shared/module.py")).unwrap(),
        b"VALUE = 'captured'\n"
    );
    assert_eq!(
        std::fs::read(captured.join("absolute.py")).unwrap(),
        b"EXTERNAL = True\n"
    );
    assert_eq!(
        std::fs::read(captured.join("main.py")).unwrap(),
        b"VALUE = 'main-before'\n"
    );
    snapshot.remove().await.unwrap();
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn python_links_reject_dangling_cycles_and_fifo_targets() {
    let workspace = temp_tree("invalid-links");
    let source = workspace.join("functions");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    symlink("missing.py", source.join("dangling.py")).unwrap();
    let error = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap_err();
    assert!(error.contains("cannot resolve source link"), "{error}");
    std::fs::remove_file(source.join("dangling.py")).unwrap();

    symlink(".", source.join("self")).unwrap();
    let error = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap_err();
    assert!(error.contains("cycle"), "{error}");
    std::fs::remove_file(source.join("self")).unwrap();

    symlink("..", source.join("nested/ancestor")).unwrap();
    let error = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap_err();
    assert!(error.contains("cycle"), "{error}");
    std::fs::remove_file(source.join("nested/ancestor")).unwrap();

    let fifo = workspace.join("target.fifo");
    create_fifo(&fifo);
    symlink("../target.fifo", source.join("fifo.py")).unwrap();
    let error = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap_err();
    assert!(error.contains("neither a regular file nor a directory"), "{error}");
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn python_nonblocking_file_open_rejects_fifo_replacement_within_deadline() {
    const CHILD: &str = "FIREEMU_PYTHON_FIFO_REPLACEMENT_CHILD";
    let exact_test = "functions::tests::python_reload_symlink_tests::python_nonblocking_file_open_rejects_fifo_replacement_within_deadline";
    if std::env::var_os(CHILD).is_some() {
        let root = std::path::PathBuf::from(std::env::var_os("FIREEMU_PYTHON_FIFO_REPLACEMENT_ROOT").unwrap());
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("candidate.py");
        std::fs::write(&path, b"regular").unwrap();
        assert!(std::fs::metadata(&path).unwrap().is_file());
        let error = super::super::open_source_regular_file_after(&path, "test", || {
            std::fs::remove_file(&path).map_err(|error| error.to_string())?;
            create_fifo(&path);
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        return;
    }

    let root = temp_tree("fifo-replacement");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", exact_test, "--nocapture"])
        .env(CHILD, "1")
        .env("FIREEMU_PYTHON_FIFO_REPLACEMENT_ROOT", &root)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "FIFO replacement child failed: {status}");
            std::fs::remove_dir_all(root).unwrap();
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(root);
            panic!("FIFO replacement test exceeded its 3-second deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn python_stamp(
    root: &std::path::Path,
    ignores: &[String],
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
) -> Result<super::super::FunctionsSourceStamp, String> {
    super::super::functions_source_stamp_with_charge_and_file_version_and_python_cache(
        root,
        ignores,
        true,
        charge,
        &super::super::AtomicBool::new(false),
        &super::super::functions_source_file_version,
    )
}

#[tokio::test]
async fn python_capture_rejects_link_content_edits_and_retargets_during_capture() {
    for retarget in [false, true] {
        let workspace = temp_tree(if retarget { "retarget" } else { "target-edit" });
        let source = workspace.join("functions");
        let external = workspace.join("shared");
        let replacement = workspace.join("replacement");
        let snapshot_root = workspace.join("snapshots");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        std::fs::create_dir_all(&replacement).unwrap();
        std::fs::create_dir_all(&snapshot_root).unwrap();
        std::fs::write(source.join("main.py"), "VALUE = 1\n").unwrap();
        std::fs::write(external.join("module.py"), b"VALUE = 'before'\n").unwrap();
        std::fs::write(replacement.join("module.py"), b"VALUE = 'retargeted'\n").unwrap();
        symlink("../shared", source.join("shared")).unwrap();
        let mut changed = false;
        let mut charge = |_: u64, _: u64| {
            if !changed && std::fs::read_dir(&snapshot_root).unwrap().next().is_some() {
                changed = true;
                if retarget {
                    std::fs::remove_file(source.join("shared")).unwrap();
                    symlink("../replacement", source.join("shared")).unwrap();
                } else {
                    std::fs::write(external.join("module.py"), b"VALUE = 'after'\n").unwrap();
                }
            }
            Ok(())
        };
        let ignores = vec!["shared".to_owned()];
        let result = super::super::snapshot_functions_source_with_charge_at_and_venv(
            &source,
            &ignores,
            true,
            &mut charge,
            &super::super::AtomicBool::new(false),
            &snapshot_root,
        );
        let error = result.expect_err("capture must reject a mixed linked-source snapshot");
        assert!(error.contains("changed while capturing"), "{error}");
        assert!(changed, "the capture mutation callback did not run");
        assert_eq!(std::fs::read_dir(&snapshot_root).unwrap().count(), 0);
        std::fs::remove_dir_all(workspace).unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep generated PICT cases and their assertions together.
async fn pict_generated_python_symlink_cases_exercise_scan_and_snapshot() {
    let table = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/python_reload_symlink_pict.tsv")).unwrap();
    let mut rows = table.lines();
    let header = rows.next().unwrap();
    assert_eq!(header, "LinkKind\tTargetLocation\tLinkSpelling\tOperation\tMutationPhase");
    let mut executed = 0;
    for row in rows {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 5, "invalid generated PICT row: {row}");
        let [kind, location, spelling, operation, phase] = fields.as_slice() else {
            unreachable!()
        };
        assert!(matches!(*phase, "Static" | "TargetEditDuringCapture" | "RetargetDuringCapture" | "AddEmptyDirectoryDuringCapture" | "ReplaceWithFifo"));
        let workspace = temp_tree(&format!("pict-{executed}"));
        let source = workspace.join("functions");
        let target = if *location == "External" {
            workspace.join("target")
        } else {
            source.join("target")
        };
        std::fs::create_dir_all(&source).unwrap();
        let link_path = if *kind == "File" {
            source.join("alias.py")
        } else {
            source.join("alias")
        };
        let target_file = target.join("module.py");
        let replacement = if *kind == "File" {
            if *location == "External" { workspace.join("replacement.py") } else { source.join("replacement.py") }
        } else if *location == "External" {
            workspace.join("replacement")
        } else {
            source.join("replacement")
        };
        match *kind {
            "File" => {
                std::fs::create_dir_all(&target).unwrap();
                std::fs::write(&target_file, b"VALUE = 1\n").unwrap();
                let link_target = if *spelling == "Absolute" {
                    std::fs::canonicalize(&target_file).unwrap()
                } else if *location == "External" {
                    std::path::PathBuf::from("../target/module.py")
                } else {
                    std::path::PathBuf::from("target/module.py")
                };
                symlink(link_target, &link_path).unwrap();
                std::fs::write(&replacement, b"VALUE = 2\n").unwrap();
            }
            "Directory" => {
                std::fs::create_dir_all(&target).unwrap();
                std::fs::write(&target_file, b"VALUE = 1\n").unwrap();
                let link_target = if *spelling == "Absolute" {
                    std::fs::canonicalize(&target).unwrap()
                } else if *location == "External" {
                    std::path::PathBuf::from("../target")
                } else {
                    std::path::PathBuf::from("target")
                };
                symlink(link_target, &link_path).unwrap();
                std::fs::create_dir_all(&replacement).unwrap();
                std::fs::write(replacement.join("module.py"), b"VALUE = 2\n").unwrap();
            }
            "Cycle" => symlink("alias", &link_path).unwrap(),
            "Dangling" => symlink("../missing-target", &link_path).unwrap(),
            "Fifo" => {
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                create_fifo(&target);
                let link_target = if *spelling == "Absolute" {
                    std::fs::canonicalize(&target).unwrap()
                } else if *location == "External" {
                    std::path::PathBuf::from("../target")
                } else {
                    std::path::PathBuf::from("target")
                };
                symlink(link_target, &link_path).unwrap();
            }
            _ => panic!("unknown generated PICT link kind: {kind}"),
        }

        let snapshot_root = workspace.join("snapshots");
        std::fs::create_dir_all(&snapshot_root).unwrap();
        let mut mutated = false;
        let mut charge = |_: u64, bytes: u64| {
            let capture_started = *operation == "Snapshot"
                && std::fs::read_dir(&snapshot_root).unwrap().next().is_some();
            let scan_read_started = *operation == "Scan" && bytes > 0;
            if !mutated
                && matches!(
                    *phase,
                    "TargetEditDuringCapture"
                        | "RetargetDuringCapture"
                        | "AddEmptyDirectoryDuringCapture"
                )
                && (capture_started || scan_read_started)
            {
                mutated = true;
                if *phase == "TargetEditDuringCapture" {
                    std::fs::write(&target_file, b"VALUE = 3\n").unwrap();
                } else if *phase == "RetargetDuringCapture" {
                    std::fs::remove_file(&link_path).unwrap();
                    let replacement_link = if *spelling == "Absolute" {
                        std::fs::canonicalize(&replacement).unwrap()
                    } else if *location == "External" {
                        std::path::PathBuf::from(if *kind == "File" { "../replacement.py" } else { "../replacement" })
                    } else {
                        std::path::PathBuf::from(if *kind == "File" { "replacement.py" } else { "replacement" })
                    };
                    symlink(replacement_link, &link_path).unwrap();
                } else {
                    std::fs::create_dir(target.join("feature")).unwrap();
                }
            }
            Ok(())
        };
        let result = if *operation == "Scan" {
            python_stamp(&source, &[], &mut charge).map(|_| ())
        } else {
            let snapshot = super::super::snapshot_functions_source_with_charge_at_and_venv(
                &source,
                &[],
                true,
                &mut charge,
                &super::super::AtomicBool::new(false),
                &snapshot_root,
            );
            if let Ok(snapshot) = snapshot {
                snapshot.remove().await.unwrap();
                Ok(())
            } else {
                snapshot.map(|_| ())
            }
        };
        if matches!(*kind, "Cycle" | "Dangling" | "Fifo")
            || (*operation == "Snapshot"
                && matches!(
                    *phase,
                    "TargetEditDuringCapture"
                        | "RetargetDuringCapture"
                        | "AddEmptyDirectoryDuringCapture"
                ))
        {
            assert!(result.is_err(), "expected failure for PICT row {row}: {result:?}");
        } else {
            assert!(result.is_ok(), "expected success for PICT row {row}: {result:?}");
        }
        if matches!(
            *phase,
            "TargetEditDuringCapture" | "RetargetDuringCapture" | "AddEmptyDirectoryDuringCapture"
        ) && matches!(*kind, "File" | "Directory")
        {
            assert!(mutated, "PICT mutation phase did not execute for row {row}");
        }
        assert_eq!(std::fs::read_dir(&snapshot_root).unwrap().count(), 0);
        std::fs::remove_dir_all(workspace).unwrap();
        executed += 1;
    }
    assert_eq!(executed, 16);
}

fn create_fifo(path: &std::path::Path) {
    let status = std::process::Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success(), "mkfifo failed for {}", path.display());
}

#[test]
fn python_aliases_share_byte_and_entry_budgets() {
    for (budget_kind, starting_value) in [
        ("byte", super::super::MAX_FUNCTIONS_SOURCE_BYTES - 3),
        ("entry", super::super::MAX_FUNCTIONS_SOURCE_ENTRIES - 3),
    ] {
        let workspace = temp_tree(&format!("{budget_kind}-budget"));
        let source = workspace.join("functions");
        let shared = workspace.join("shared");
        let destination = workspace.join("snapshot");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(shared.join("module.py"), b"xy").unwrap();
        symlink("../shared", source.join("first")).unwrap();
        symlink("../shared", source.join("second")).unwrap();
        let cancelled = super::super::AtomicBool::new(false);
        let mut charge = |_, _| Ok(());
        let mut traversal = super::super::FunctionsSourceTraversal {
            ignores: &[],
            entry_budget: super::super::FunctionsSourceEntryBudget {
                entries: if budget_kind == "entry" { starting_value } else { 0 },
            },
            byte_budget: super::super::FunctionsSourceByteBudget {
                bytes: if budget_kind == "byte" { starting_value } else { 0 },
                largest: None,
            },
            charge: &mut charge,
            cancelled: &cancelled,
            exclude_python_cache_artifacts: true,
            exclude_python_venv: false,
            follow_source_symlinks: true,
            active_directories: Vec::new(),
        };
        let error = traversal
            .copy_directory(&source, &destination, std::path::Path::new(""), 0)
            .unwrap_err();
        if budget_kind == "byte" {
            assert!(error.contains("256 MiB byte budget"), "{error}");
            assert!(destination.join("first/module.py").exists());
            assert!(!destination.join("second/module.py").exists());
        } else {
            assert!(error.contains("at most 100000 entries"), "{error}");
        }
        std::fs::remove_dir_all(workspace).unwrap();
    }
}

#[tokio::test]
async fn python_capture_cancellation_during_linked_file_io_cleans_snapshot() {
    let workspace = temp_tree("cancel-linked-capture");
    let source = workspace.join("functions");
    let shared = workspace.join("shared");
    let snapshot_root = workspace.join("snapshots");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::create_dir_all(&snapshot_root).unwrap();
    std::fs::write(shared.join("module.py"), vec![b'x'; 128 * 1024]).unwrap();
    symlink("../shared", source.join("shared")).unwrap();
    let cancelled = super::super::AtomicBool::new(false);
    let mut charge = |_, bytes: u64| {
        if bytes > 0 && std::fs::read_dir(&snapshot_root).unwrap().next().is_some() {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    };
    let result = super::super::snapshot_functions_source_with_charge_at_and_venv(
        &source,
        &[],
        true,
        &mut charge,
        &cancelled,
        &snapshot_root,
    );
    let error = result.expect_err("capture should notice cancellation during linked file IO");
    assert!(error.contains("cancelled"), "{error}");
    assert_eq!(std::fs::read_dir(&snapshot_root).unwrap().count(), 0);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn node_source_traversal_continues_to_skip_special_files() {
    let workspace = temp_tree("node-special");
    let source = workspace.join("functions");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("index.js"), "exports.handler = () => 1\n").unwrap();
    let fifo = source.join("ignored.fifo");
    create_fifo(&fifo);
    let stamp = super::super::functions_source_stamp(&source, &[]).unwrap();
    assert_eq!(stamp.tracked_files, 1);
    let snapshot = super::super::snapshot_functions_source(&source, &[]).unwrap();
    assert!(!snapshot.join("ignored.fifo").exists());
    drop(snapshot);
    std::fs::remove_dir_all(workspace).unwrap();
}


#[test]
fn python_linked_directory_depth_uses_the_shared_traversal_limit() {
    let workspace = temp_tree("linked-depth");
    let source = workspace.join("functions");
    let chain = workspace.join("chain");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&chain).unwrap();
    for index in 0..=super::super::MAX_FUNCTIONS_SOURCE_DEPTH {
        std::fs::create_dir_all(chain.join(format!("dir-{index}"))).unwrap();
        if index < super::super::MAX_FUNCTIONS_SOURCE_DEPTH {
            symlink(
                format!("../dir-{}", index + 1),
                chain.join(format!("dir-{index}/next")),
            )
            .unwrap();
        }
    }
    symlink("../chain/dir-0", source.join("alias")).unwrap();
    let error = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap_err();
    assert!(error.contains("at most 128 directories deep"), "{error}");
    std::fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn python_cache_alias_is_excluded_before_resolving_its_target() {
    let workspace = temp_tree("cache-alias");
    let source = workspace.join("functions");
    let cached = workspace.join("cache-target");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&cached).unwrap();
    std::fs::write(source.join("main.py"), b"VALUE = 1\n").unwrap();
    std::fs::write(cached.join("module.pyc"), b"cache bytes").unwrap();
    symlink("../cache-target", source.join("__pycache__")).unwrap();
    let signature = python_stamp(&source, &[], &mut |_, _| Ok(())).unwrap();
    assert_eq!(signature.tracked_files, 1);
    let snapshot = super::super::snapshot_functions_source_with_linked_venv(&source, &[]).unwrap();
    assert!(!snapshot.join("__pycache__").exists());
    drop(snapshot);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn python_signatures_include_logical_empty_directories_and_reject_capture_topology_changes() {
    let workspace = temp_tree("empty-linked-directory");
    let source = workspace.join("functions");
    let shared = workspace.join("shared");
    let snapshot_root = workspace.join("snapshots");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::create_dir_all(&snapshot_root).unwrap();
    symlink("../shared", source.join("shared")).unwrap();
    let baseline = python_stamp(&source, &[], &mut |_, _| Ok(()))
        .unwrap()
        .content_signature;
    std::fs::create_dir(shared.join("feature")).unwrap();
    let added = python_stamp(&source, &[], &mut |_, _| Ok(()))
        .unwrap()
        .content_signature;
    assert_ne!(added, baseline);
    std::fs::rename(shared.join("feature"), shared.join("renamed")).unwrap();
    let renamed = python_stamp(&source, &[], &mut |_, _| Ok(()))
        .unwrap()
        .content_signature;
    assert_ne!(renamed, added);
    std::fs::remove_dir(shared.join("renamed")).unwrap();
    let removed = python_stamp(&source, &[], &mut |_, _| Ok(()))
        .unwrap()
        .content_signature;
    assert_eq!(removed, baseline);

    let mut changed = false;
    let mut charge = |_, _| {
        if !changed && std::fs::read_dir(&snapshot_root).unwrap().next().is_some() {
            changed = true;
            std::fs::create_dir(shared.join("feature")).unwrap();
        }
        Ok(())
    };
    let result = super::super::snapshot_functions_source_with_charge_at_and_venv(
        &source,
        &[],
        true,
        &mut charge,
        &super::super::AtomicBool::new(false),
        &snapshot_root,
    );
    let error = result.expect_err("empty-directory topology mutation must reject capture");
    assert!(error.contains("changed while capturing"), "{error}");
    assert!(changed);
    assert_eq!(std::fs::read_dir(&snapshot_root).unwrap().count(), 0);
    std::fs::remove_dir_all(workspace).unwrap();
}
