"""Offline process test for the proposed O8 parent import closure."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert SPEC is not None and SPEC.loader is not None
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)

SOURCES = {
    "commit_o8": HERE / "commit_o8.py",
    "o8_bundle": HERE / "o8_bundle.py",
    "commit_acquisition": HERE / "commit_acquisition.py",
    "commit_baseline": HERE / "commit_baseline.py",
    "commit_reserved_adapter": HERE / "commit_reserved_adapter.py",
    "commit_remote_transport": HERE / "commit_remote_transport.py",
    "commit_production": HERE / "commit_production.py",
    "commit_production_bridge": HERE / "commit_production_bridge.py",
    "gate_adapter": HERE / "gate_adapter.py",
    "local_transport": HERE / "local_transport.py",
    "local_collector": HERE / "local_collector.py",
    "owned_transform_runner": HERE / "owned_transform_runner.py",
    "transform_comparator": HERE / "transform_comparator.py",
    "transform_compiler": HERE / "transform_compiler.py",
    "broad": ROOT / "tools/compat-broad/broad.py",
    "broad_cases": ROOT / "tools/compat-broad/broad_cases.py",
    "broad_contract": ROOT / "tools/compat-broad/broad_contract.py",
    "batch_adapter": ROOT / "tools/compat-broad/batch_adapter.py",
    "batch_contract": ROOT / "tools/compat-broad/batch_contract.py",
    "batch_pair": ROOT / "tools/compat-broad/batch_pair.py",
    "shared_cases": ROOT / "tools/compat-broad/shared_cases.py",
    "shared_gate": ROOT / "tools/compat-broad/shared_gate.py",
    "shared_production": ROOT / "tools/compat-broad/shared_production.py",
    "shared_production_pair": ROOT / "tools/compat-broad/shared_production_pair.py",
    "reservations": ROOT / "tools/compat-broad/production-admission/reservations.py",
    "o8_admission": ROOT / "tools/compat-broad/o8-core/o8_admission.py",
    "o8_campaign": ROOT / "tools/compat-broad/o8-core/o8_campaign.py",
    "evidence_common": ROOT / "tools/compat-inventory/evidence_common.py",
    "owned_runner": ROOT / "tools/compat-inventory/owned_runner.py",
    "production_plan": ROOT / "tools/compat-broad/fs-write-limits/production_plan.py",
    "remote_transport": ROOT / "tools/compat-broad/fs-write-limits/remote_transport.py",
    "shadow": ROOT / "tools/compat-broad/fs-write-limits/shadow.py",
    "compiler": ROOT / "tools/compat-broad/fs-write-limits/compiler.py",
    "transport": ROOT / "tools/compat-broad/fs-write-limits/transport.py",
    "production_bridge": ROOT / "tools/compat-broad/fs-write-limits/production_bridge.py",
    "credential_prep": ROOT / "tools/compat-broad/fs-write-txn/credential_prep.py",
}


def test_remote_transport_loads_exact_member_from_inherited_archive(tmp_path: Path) -> None:
    main = b"import commit_remote_transport\nprint(commit_remote_transport._transport.__file__)\n"
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(HERE / "o8_fd_bootstrap.py"), str(fd), sha],
            cwd=tmp_path,
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"/dev/fd/{fd}/transport.py"


def test_local_transport_loads_exact_member_from_inherited_archive(tmp_path: Path) -> None:
    main = b"import local_transport\nprint(local_transport._transport.__file__)\n"
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(HERE / "o8_fd_bootstrap.py"), str(fd), sha],
            cwd=tmp_path,
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"/dev/fd/{fd}/transport.py"


def test_gate_adapter_imports_first_from_exact_archive_member(tmp_path: Path) -> None:
    """The adapter must load its compiler before any parent imports it."""
    main = b"import gate_adapter, transform_compiler\nprint(gate_adapter.__file__)\n"
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(HERE / "o8_fd_bootstrap.py"),
                str(fd),
                sha,
            ],
            cwd=tmp_path,
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"/dev/fd/{fd}/gate_adapter.py"


def test_parent_imports_remain_inside_inherited_archive(tmp_path: Path) -> None:
    """A dirty checkout and PYTHONPATH must not supply executable modules."""
    main = b"""import importlib, json, sys
names = ('commit_o8', 'commit_acquisition', 'commit_reserved_adapter', 'gate_adapter', 'commit_remote_transport', 'local_transport', 'owned_transform_runner', 'o8_admission', 'o8_campaign')
for name in names:
    importlib.import_module(name)
print(json.dumps({name: sys.modules[name].__file__ for name in sys.modules if name in ('commit_o8', 'commit_acquisition', 'commit_reserved_adapter', 'gate_adapter', 'commit_remote_transport', 'local_transport', 'owned_transform_runner', 'o8_admission', 'o8_campaign', 'broad_contract', 'shared_gate', 'reservations', 'broad')}, sort_keys=True))
"""
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "argparse.py").write_text(
        "raise RuntimeError('dirty argparse imported')\n"
    )
    (dirty / "sitecustomize.py").write_text(
        "raise RuntimeError('sitecustomize imported')\n"
    )
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(HERE / "o8_fd_bootstrap.py"),
                str(fd),
                sha,
            ],
            cwd=dirty,
            env={**os.environ, "PYTHONPATH": str(dirty)},
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert all(
            origin.startswith(f"/dev/fd/{fd}/")
            for origin in json.loads(result.stdout).values()
        )


def test_archive_worker_does_not_derive_a_mutable_checkout_import_root(
    tmp_path: Path,
) -> None:
    main = b"""import json, sys, commit_remote_transport
print(json.dumps({'path': sys.path, 'base': sys.base_prefix}))
"""
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(HERE / "o8_fd_bootstrap.py"),
                str(fd),
                sha,
            ],
            cwd=tmp_path,
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout)
        archive_path = f"/dev/fd/{fd}"
        assert observed["path"][0] == archive_path
        assert not any(
            entry.endswith("/tools/compat-broad") for entry in observed["path"]
        )
        assert not any(
            entry == str(tmp_path) or entry.startswith(f"{tmp_path}/")
            for entry in observed["path"]
        )


def test_historical_source_map_is_independent_of_current_archive_map(
    tmp_path: Path,
) -> None:
    """A changed current source requires a new archive without rewriting O7 history."""
    source = tmp_path / "__main__.py"
    source.write_bytes(b"print('current')\n")
    historical = {"__main__.py": hashlib.sha256(b"print('historical')\n").hexdigest()}
    current = {"__main__.py": hashlib.sha256(source.read_bytes()).hexdigest()}
    first, first_sha = bundle.build_archive(tmp_path, current)
    source.write_bytes(b"print('changed')\n")
    changed = {"__main__.py": hashlib.sha256(source.read_bytes()).hexdigest()}
    second, second_sha = bundle.build_archive(tmp_path, changed)
    assert historical != current != changed
    assert first_sha != second_sha
    assert historical == {
        "__main__.py": hashlib.sha256(b"print('historical')\n").hexdigest()
    }
    bundle.verify_archive(first, current, first_sha)
    bundle.verify_archive(second, changed, second_sha)


def test_same_name_checkout_shadows_cannot_replace_archive_dependencies(
    tmp_path: Path,
) -> None:
    main = b"""import json, local_transport, gate_adapter, sys
print(json.dumps({name: sys.modules[name].__file__ for name in ('local_transport', 'gate_adapter', 'transform_compiler', 'transport', 'production_bridge') if name in sys.modules}, sort_keys=True))
"""
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    for name in ("transport", "production_bridge", "transform_compiler"):
        (dirty / f"{name}.py").write_text(
            f"raise RuntimeError('checkout shadow {name} imported')\n"
        )
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(HERE / "o8_fd_bootstrap.py"),
                str(fd),
                sha,
            ],
            cwd=dirty,
            env={**os.environ, "PYTHONPATH": str(dirty)},
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        origins = json.loads(result.stdout)
        assert all(origin.startswith(f"/dev/fd/{fd}/") for origin in origins.values())


def test_gate_adapter_accepts_preloaded_compiler_from_archive(
    tmp_path: Path,
) -> None:
    main = b"import json, transform_compiler, gate_adapter\nprint(json.dumps({'compiler': transform_compiler.__file__, 'adapter': gate_adapter.__file__}))\n"
    (tmp_path / "__main__.py").write_bytes(main)
    manifest = {"__main__.py": hashlib.sha256(main).hexdigest()}
    for name, source in SOURCES.items():
        data = source.read_bytes()
        (tmp_path / f"{name}.py").write_bytes(data)
        manifest[f"{name}.py"] = hashlib.sha256(data).hexdigest()
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(HERE / "o8_fd_bootstrap.py"), str(fd), sha],
            cwd=tmp_path,
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        origins = json.loads(result.stdout)
        assert origins == {
            "adapter": f"/dev/fd/{fd}/gate_adapter.py",
            "compiler": f"/dev/fd/{fd}/transform_compiler.py",
        }
