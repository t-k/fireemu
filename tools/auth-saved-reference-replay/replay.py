"""Replay immutable Auth production receipts against a fixed local artifact."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = ROOT / "spec/compatibility/broad-runs/auth-saved-reference-replay-v2.json"
CORPORA = {
    "auth-basic-v2": {
        "receipt": ROOT / "spec/compatibility/evidence/auth-basic-v2/receipt.json",
        "contract": ROOT / "tools/auth-basic-v2/auth_v2_contract.py",
        "validator": ROOT / "tools/publish-auth-v2.py",
        "probe": ROOT / "tools/auth-basic-v2/auth_v2_recorder.py",
    },
    "auth-profile": {
        "receipt": ROOT / "spec/compatibility/evidence/auth-profile/receipt.json",
        "contract": ROOT / "tools/auth-profile/profile_contract.py",
        "validator": ROOT / "tools/auth-profile/profile_contract.py",
        "probe": ROOT / "tools/auth-profile/profile_recorder.py",
    },
    "auth-display-name": {
        "receipt": ROOT / "spec/compatibility/evidence/auth-display-name/receipt.json",
        "contract": ROOT / "tools/auth-display-name/display_name_contract.py",
        "validator": ROOT / "tools/auth-display-name/display_name_contract.py",
        "probe": ROOT / "tools/auth-display-name/display_name_recorder.py",
    },
    "auth-password": {
        "receipt": ROOT / "spec/compatibility/evidence/auth-password/receipt.json",
        "contract": ROOT / "tools/auth-password/password_contract.py",
        "validator": ROOT / "tools/auth-password/password_contract.py",
        "probe": ROOT / "tools/auth-password/password_recorder.py",
    },
}
OWNED_RUNNERS = {
    "auth-basic-v2": ROOT / "tools/auth-basic-v2/auth_v2_owned.py",
    "auth-profile": ROOT / "tools/auth-profile/profile_owned.py",
    "auth-display-name": ROOT / "tools/auth-display-name/display_name_owned.py",
    "auth-password": ROOT / "tools/auth-password/password_owned.py",
}
OWNED_RUNNER_HELPER = ROOT / "tools/compat-inventory/owned_runner.py"
SOURCE_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BUILD_COMMAND = ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
EXPECTED_CLEANUP = {"uidAbsent": True, "emailAbsent": True}


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def typed_json(value: Any) -> Any:
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", value]
    if type(value) is float:
        return ["float", value]
    if type(value) is str:
        return ["string", value]
    if isinstance(value, list):
        return ["array", [typed_json(item) for item in value]]
    if isinstance(value, dict):
        return ["object", [[key, typed_json(value[key])] for key in sorted(value)]]
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def typed_equal(left: Any, right: Any) -> bool:
    return typed_json(left) == typed_json(right)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_bool(value: Any, message: str) -> None:
    require(type(value) is bool, message)


def exact_int(value: Any, message: str) -> None:
    require(type(value) is int, message)


def validate_cleanup(value: Any, message: str) -> None:
    require(typed_equal(value, EXPECTED_CLEANUP), message)


def load_module(path: Path, name: str | None = None) -> Any:
    module_name = name or f"auth_saved_module_{path.stem}_{file_digest(path)[:12]}"
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ValueError(f"cannot load module: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def load_contract(path: Path) -> Any:
    return load_module(path)


def relative_spec_path(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"path is outside replay root: {path}") from exc
    require(".." not in relative.parts, f"invalid path: {path}")
    return relative.as_posix()


def load_spec() -> dict[str, Any]:
    spec = json.loads(SPEC_PATH.read_bytes())
    require(spec.get("schemaVersion") == 2, "replay spec schema changed")
    require(spec.get("kind") == "auth-saved-reference-replay-v2", "replay spec kind changed")
    require(spec.get("runtimeSourceBinding") == "run-manifest.sourceCommit", "runtime source binding changed")
    comparison = spec.get("comparison")
    runner = spec.get("runner")
    require(isinstance(comparison, dict) and isinstance(runner, dict), "replay tool bindings missing")
    for section in (comparison, runner):
        path = ROOT / section["tool"]
        require(relative_spec_path(path) == section["tool"], "replay tool path escaped root")
        require(file_digest(path) == section["toolSha256"], f"replay tool hash mismatch: {path}")
    owned_runners = runner.get("ownedRunners")
    require(
        isinstance(owned_runners, list)
        and [entry.get("id") for entry in owned_runners] == list(OWNED_RUNNERS),
        "owned runner order changed",
    )
    for entry in owned_runners:
        path = OWNED_RUNNERS[entry["id"]]
        require(entry.get("tool") == relative_spec_path(path), f"{entry['id']}: owned runner path changed")
        require(file_digest(path) == entry.get("toolSha256"), f"{entry['id']}: owned runner hash mismatch")
    helper = runner.get("ownedRunnerHelper")
    require(isinstance(helper, dict), "owned runner helper binding missing")
    require(helper.get("tool") == relative_spec_path(OWNED_RUNNER_HELPER), "owned runner helper path changed")
    require(file_digest(OWNED_RUNNER_HELPER) == helper.get("toolSha256"), "owned runner helper hash mismatch")
    entries = spec.get("corpora")
    require(isinstance(entries, list) and [entry.get("id") for entry in entries] == list(CORPORA), "replay corpus order changed")
    for entry in entries:
        name = entry["id"]
        metadata = CORPORA[name]
        for key in ("receipt", "contract", "validator", "probe"):
            path = metadata[key]
            require(entry.get(key) == relative_spec_path(path), f"{name}: spec {key} binding changed")
            require(file_digest(path) == entry.get(f"{key}Sha256"), f"{name}: {key} hash mismatch")
        require(file_digest(metadata["receipt"]) == entry.get("receiptSha256"), f"{name}: receipt hash mismatch")
        contract = load_contract(metadata["contract"])
        require(len(contract.CASES) == entry.get("caseCount"), f"{name}: case count changed")
    return spec


def validate_rows(name: str, rows: list[dict[str, Any]]) -> None:
    metadata = CORPORA[name]
    validator = load_module(metadata["validator"])
    validate_case = getattr(validator, "validate_case", None)
    if validate_case is None:
        return
    contract = load_contract(metadata["contract"])
    for row, case in zip(rows, contract.CASES, strict=True):
        validate_case(row, case)


def expected_probe_inputs(name: str) -> dict[str, str]:
    return load_module(CORPORA[name]["probe"]).inputs()


def expected_runtime_inputs() -> dict[str, str]:
    sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
    try:
        from evidence_common import runtime_inputs

        return runtime_inputs(ROOT)
    finally:
        sys.path.pop(0)


def validate_saved_receipt(name: str, receipt: dict[str, Any], spec_entry: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = CORPORA[name]
    if spec_entry is not None:
        require(file_digest(metadata["receipt"]) == spec_entry["receiptSha256"], f"{name}: immutable receipt changed")
    contract = load_contract(metadata["contract"])
    production = receipt.get("production")
    require(isinstance(production, dict), f"{name}: missing production report")
    require(production.get("target") == "production", f"{name}: target changed")
    cases = production.get("cases")
    expected_cases = list(contract.CASES)
    require(isinstance(cases, list), f"{name}: production cases missing")
    require(all(isinstance(row, dict) for row in cases) and [row.get("id") for row in cases] == expected_cases, f"{name}: production case order changed")
    validate_rows(name, cases)
    validate_cleanup(production.get("cleanup"), f"{name}: production cleanup is incomplete")
    exact_bool(production.get("configurationUnchanged"), f"{name}: production configuration flag is not boolean")
    require(production["configurationUnchanged"] is True, f"{name}: production configuration was not preserved")
    production_probe = production.get("probeSourceCommit")
    require(SOURCE_RE.fullmatch(production_probe or "") is not None, f"{name}: historical probe source is malformed")
    return {"receiptSha256": file_digest(metadata["receipt"]), "productionProbeSourceCommit": production_probe, "productionRecordedAt": production.get("recordedAt"), "productionCases": cases, "productionCleanup": production["cleanup"], "productionConfigurationSha256": production.get("configuration", {}).get("sha256")}


def validate_local_report(name: str, report: dict[str, Any], source_commit: str, expected_inputs: dict[str, str] | None = None, expected_probe: dict[str, str] | None = None, expected_artifact: str | None = None, expected_configuration: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = load_contract(CORPORA[name]["contract"])
    require(report.get("target") == "local", f"{name}: local target missing")
    require(SOURCE_RE.fullmatch(source_commit or "") is not None, f"{name}: source commit is missing or malformed")
    require(contract.complete(report), f"{name}: local report is incomplete")
    validate_rows(name, report["cases"])
    require(report.get("runtimeSourceCommit") == source_commit, f"{name}: local source commit is not the replay source")
    if expected_probe is not None:
        require(typed_equal(report.get("probeInputs"), expected_probe), f"{name}: probe inputs do not match the current probe source")
    artifact = report.get("artifact")
    build = report.get("build")
    process = report.get("ownedProcess")
    require(isinstance(artifact, dict) and artifact.get("kind") == "local-build" and SHA256_RE.fullmatch(artifact.get("sha256", "")) is not None, f"{name}: artifact provenance missing")
    require(isinstance(build, dict), f"{name}: build provenance missing")
    exact_int(build.get("exitCode"), f"{name}: build exitCode is not an integer")
    require(build["artifactSha256"] == artifact["sha256"] and build["exitCode"] == 0, f"{name}: build provenance mismatch")
    if expected_artifact is not None:
        require(artifact["sha256"] == expected_artifact, f"{name}: mixed artifact detected")
    if expected_inputs is not None:
        require(typed_equal(build.get("inputs"), expected_inputs), f"{name}: build inputs do not match the fixed source tree")
    require(isinstance(process, dict), f"{name}: owned process evidence missing")
    exact_int(process.get("exitCode"), f"{name}: process exitCode is not an integer")
    exact_bool(process.get("stopped"), f"{name}: process stopped flag is not boolean")
    exact_bool(process.get("listenersClosed"), f"{name}: listenersClosed flag is not boolean")
    require(process["exitCode"] == 0 and process["stopped"] is True and process["listenersClosed"] is True, f"{name}: owned process was not closed")
    validate_cleanup(report.get("cleanup"), f"{name}: local cleanup is incomplete")
    configuration = report.get("configuration")
    require(isinstance(configuration, dict) and typed_equal(configuration.get("value"), {"profile": "strict", "schemaVersion": 1}), f"{name}: strict configuration evidence missing")
    if expected_configuration is not None:
        require(typed_equal(configuration, expected_configuration), f"{name}: configuration evidence differs between corpora")
    return {"localRecordedAt": report.get("recordedAt"), "localCases": report["cases"], "localCleanup": report["cleanup"], "localArtifactSha256": artifact["sha256"], "localBuildInputs": digest(build["inputs"]), "localProbeInputs": digest(report["probeInputs"]) if "probeInputs" in report else None, "localConfigurationSha256": configuration.get("sha256"), "localConfigurationFileSha256": configuration.get("fileSha256"), "runtimeSourceCommit": source_commit, "ownedProcess": {"exitCode": process["exitCode"], "stopped": process["stopped"], "listenersClosed": process["listenersClosed"]}}


def validate_artifact_binding(build: dict[str, Any], artifact: str, local_root: Path) -> dict[str, int]:
    """Validate evidence and return a caller-owned verified launch FD capability."""
    source_path = Path(build.get("sourcePath", ""))
    launch_path = Path(build.get("launchCopyPath", ""))
    os_module = __import__("os")
    stat_module = __import__("stat")

    def open_anchored(path: Path, role: str) -> tuple[Path, int]:
        require(path.is_absolute(), f"artifact binding {role} path is unavailable")
        require(".." not in path.parts, f"artifact binding {role} path contains '..'")
        absolute = path.absolute()
        try:
            canonical = absolute.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path is unavailable") from exc
        require(
            canonical == absolute,
            f"artifact binding {role} path must be canonical and must not use a symlink parent",
        )
        parts = absolute.parts
        require(len(parts) >= 2, f"artifact binding {role} path must name a file")
        directory_flags = (
            os_module.O_RDONLY
            | getattr(os_module, "O_DIRECTORY", 0)
            | getattr(os_module, "O_CLOEXEC", 0)
            | getattr(os_module, "O_NOFOLLOW", 0)
        )
        file_flags = os_module.O_RDONLY | getattr(os_module, "O_CLOEXEC", 0) | getattr(
            os_module, "O_NOFOLLOW", 0
        )

        def identity(metadata):
            return metadata.st_dev, metadata.st_ino, stat_module.S_IFMT(metadata.st_mode)

        expected_directories = []
        prefix = Path(absolute.anchor)
        try:
            root_metadata = os_module.stat(prefix, follow_symlinks=False)
            require(
                stat_module.S_ISDIR(root_metadata.st_mode),
                f"artifact binding {role} root is not a directory",
            )
            for component in parts[1:-1]:
                prefix /= component
                metadata = os_module.stat(prefix, follow_symlinks=False)
                require(
                    stat_module.S_ISDIR(metadata.st_mode),
                    f"artifact binding {role} path component is not a directory",
                )
                expected_directories.append(metadata)
            expected_file = os_module.stat(absolute, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path is unavailable") from exc
        require(
            stat_module.S_ISREG(expected_file.st_mode),
            f"artifact binding {role} path must be a regular file",
        )
        require(
            expected_file.st_nlink == 1,
            f"artifact binding {role} path must not be a hardlink",
        )
        try:
            directory_descriptor = os_module.open(absolute.anchor, directory_flags)
        except OSError as exc:
            raise ValueError(
                f"artifact binding {role} root is unavailable or is a symlink"
            ) from exc
        try:
            opened_root = os_module.fstat(directory_descriptor)
            require(
                stat_module.S_ISDIR(opened_root.st_mode)
                and identity(opened_root) == identity(root_metadata),
                f"artifact binding {role} root changed before opening",
            )
            for index, component in enumerate(parts[1:-1]):
                next_descriptor = os_module.open(
                    component, directory_flags, dir_fd=directory_descriptor
                )
                try:
                    opened = os_module.fstat(next_descriptor)
                    require(
                        stat_module.S_ISDIR(opened.st_mode)
                        and identity(opened) == identity(expected_directories[index]),
                        f"artifact binding {role} path component changed before opening",
                    )
                except BaseException:
                    os_module.close(next_descriptor)
                    raise
                os_module.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os_module.open(
                parts[-1], file_flags, dir_fd=directory_descriptor
            )
            try:
                opened = os_module.fstat(descriptor)
                require(
                    stat_module.S_ISREG(opened.st_mode)
                    and opened.st_nlink == 1
                    and identity(opened) == identity(expected_file),
                    f"artifact binding {role} path changed before opening",
                )
            except BaseException:
                os_module.close(descriptor)
                raise
        except OSError as exc:
            raise ValueError(
                f"artifact binding {role} path is unavailable or is a symlink"
            ) from exc
        finally:
            os_module.close(directory_descriptor)
        return absolute, descriptor

    def read_stable(path: Path, role: str) -> tuple[str, tuple[int, int], Path, int]:
        canonical, descriptor = open_anchored(path, role)
        try:
            before = os_module.fstat(descriptor)
            require(
                stat_module.S_ISREG(before.st_mode),
                f"artifact binding {role} path must be a regular file",
            )
            require(
                before.st_nlink == 1,
                f"artifact binding {role} path must not be a hardlink",
            )
            chunks = []
            while True:
                chunk = os_module.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os_module.fstat(descriptor)
        finally:
            os_module.close(descriptor)
        def identity(metadata):
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
        require(
            identity(before) == identity(after),
            f"artifact binding {role} changed while reading",
        )
        try:
            current = os_module.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path disappeared") from exc
        require(
            stat_module.S_ISREG(current.st_mode)
            and current.st_nlink == 1
            and identity(current) == identity(after),
            f"artifact binding {role} path changed while reading",
        )
        try:
            final = os_module.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path disappeared") from exc
        require(
            stat_module.S_ISREG(final.st_mode)
            and final.st_nlink == 1
            and identity(final) == identity(after),
            f"artifact binding {role} path changed after verification",
        )
        bound_canonical, bound_descriptor = open_anchored(path, role)
        try:
            bound = os_module.fstat(bound_descriptor)
            require(
                stat_module.S_ISREG(bound.st_mode)
                and bound.st_nlink == 1
                and identity(bound) == identity(after),
                f"artifact binding {role} path changed before use",
            )
            require(
                bound_canonical == canonical,
                f"artifact binding {role} path changed before use",
            )
        except BaseException:
            os_module.close(bound_descriptor)
            raise
        return (
            hashlib.sha256(b"".join(chunks)).hexdigest(),
            (after.st_dev, after.st_ino),
            canonical,
            bound_descriptor,
        )

    source_digest, source_identity, _source_canonical, source_descriptor = read_stable(
        source_path, "source"
    )
    try:
        launch_digest, launch_identity, launch_canonical, launch_descriptor = read_stable(
            launch_path, "launch"
        )
    except BaseException:
        os_module.close(source_descriptor)
        raise
    try:
        os_module.close(source_descriptor)
        require(source_path != launch_path, "artifact binding source and launch paths must differ")
        require(
            source_identity != launch_identity,
            "artifact binding source and launch paths must have independent inodes",
        )
        require(source_digest == build.get("sourceSha256") == artifact, "artifact binding source hash mismatch")
        require(launch_digest == build.get("launchCopySha256") == artifact, "artifact binding launch hash mismatch")
        try:
            launch_canonical.relative_to(local_root.resolve())
        except ValueError as exc:
            raise ValueError("artifact binding launch path escapes private output") from exc
    except BaseException:
        os_module.close(launch_descriptor)
        raise
    return {"_launchFd": launch_descriptor}


def compare(name: str, local: dict[str, Any], receipt: dict[str, Any], expected_source_commit: str | None = None, spec_entry: dict[str, Any] | None = None) -> dict[str, Any]:
    saved = validate_saved_receipt(name, receipt, spec_entry)
    source_commit = local.get("runtimeSourceCommit")
    if expected_source_commit is not None:
        require(source_commit == expected_source_commit, f"{name}: local source commit does not match replay source")
    current = validate_local_report(name, local, source_commit)
    local_cases = current["localCases"]
    production_cases = saved["productionCases"]
    row_results = [{"id": production.get("id"), "classification": "MATCH" if typed_equal(local_row, production) else "SEMANTIC_MISMATCH"} for local_row, production in zip(local_cases, production_cases, strict=True)]
    mismatches = [row["id"] for row in row_results if row["classification"] != "MATCH"]
    return {"corpus": name, "classification": "SEMANTIC_MISMATCH" if mismatches else "MATCH", "caseCount": len(row_results), "matchCount": len(row_results) - len(mismatches), "mismatchCases": mismatches, "rows": row_results, "savedProduction": saved, "currentLocal": current, "configurationComparison": {"classification": "SEPARATE_EVIDENCE", "localStrictProfileSha256": current["localConfigurationSha256"], "productionProjectionSha256": saved["productionConfigurationSha256"], "reason": "The local strict runner configuration and the production configuration projection are different contracts; they are retained separately rather than coerced into equality."}}


def validate_manifest(local_root: Path, source_commit: str, spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    path = local_root / "run-manifest.json"
    require(path.is_file(), "run manifest is missing")
    manifest = json.loads(path.read_bytes())
    require(manifest.get("schemaVersion") == 2 and manifest.get("kind") == "auth-saved-reference-replay-local-v2", "run manifest schema changed")
    require(manifest.get("sourceCommit") == source_commit, "run manifest source binding changed")
    build = manifest.get("build")
    require(isinstance(build, dict) and build.get("command") == BUILD_COMMAND, "run manifest build command changed")
    exact_int(build.get("exitCode"), "run manifest build exitCode is not an integer")
    require(build["exitCode"] == 0 and build.get("artifactSha256") == manifest.get("artifactSha256"), "run manifest build failed")
    artifact = manifest.get("artifactSha256")
    require(SHA256_RE.fullmatch(artifact or "") is not None, "run manifest artifact hash is malformed")
    binding = validate_artifact_binding(build, artifact, local_root)
    try:
        require(typed_equal(build.get("inputs"), expected_runtime_inputs()), "run manifest source inputs do not match the current tree")
    finally:
        os.close(binding["_launchFd"])
    entries = manifest.get("corpora")
    require(isinstance(entries, dict) and set(entries) == set(CORPORA), "run manifest corpus binding changed")
    expected_configuration = None
    reports: dict[str, dict[str, Any]] = {}
    for name in CORPORA:
        entry = entries[name]
        require(isinstance(entry, dict), f"{name}: run manifest entry missing")
        require(entry.get("runtimeSourceCommit") == source_commit, f"{name}: manifest source binding changed")
        require(entry.get("status") in {"passed", "failed"}, f"{name}: manifest status is invalid")
        require(entry.get("artifactSha256") == artifact, f"{name}: manifest artifact binding changed")
        report_path = Path(entry.get("localReport", ""))
        require(report_path.name == "local.json" and report_path.parent.name == name, f"{name}: report path is not corpus-bound")
        local_path = local_root / name / "local.json"
        require(local_path.is_file(), f"{name}: local report missing")
        require(entry.get("localReportSha256") == file_digest(local_path), f"{name}: local report bytes are not bound")
        require(type(entry.get("localReportBytes")) is int and entry["localReportBytes"] == local_path.stat().st_size, f"{name}: local report length is not bound")
        local = json.loads(local_path.read_bytes())
        require(local.get("status") == entry["status"], f"{name}: manifest status does not match local report")
        probe = expected_probe_inputs(name)
        if expected_configuration is None:
            expected_configuration = local.get("configuration")
        report = validate_local_report(name, local, source_commit, build["inputs"], probe, artifact, expected_configuration)
        require(entry.get("probeInputsSha256") == digest(local["probeInputs"]), f"{name}: probe input digest is not bound")
        require(entry.get("configurationSha256") == local["configuration"].get("sha256"), f"{name}: configuration is not bound")
        require(entry.get("configurationFileSha256") == local["configuration"].get("fileSha256"), f"{name}: configuration file is not bound")
        require(type(entry.get("processExitCode")) is int and entry["processExitCode"] == 0, f"{name}: process exit is not bound")
        require(type(entry.get("listenersClosed")) is bool and entry["listenersClosed"] is True, f"{name}: listener state is not bound")
        require(typed_equal(entry.get("cleanup"), EXPECTED_CLEANUP), f"{name}: cleanup is not bound")
        reports[name] = report
    return manifest, reports


def evaluate(local_root: Path, output: Path, source_commit: str) -> dict[str, Any]:
    spec = load_spec()
    _manifest, _ = validate_manifest(local_root, source_commit, spec)
    reports = {}
    spec_entries = {entry["id"]: entry for entry in spec["corpora"]}
    for name, metadata in CORPORA.items():
        local = json.loads((local_root / name / "local.json").read_bytes())
        receipt = json.loads(metadata["receipt"].read_bytes())
        reports[name] = compare(name, local, receipt, source_commit, spec_entries[name])
    stable = {name: {key: reports[name][key] for key in ("classification", "caseCount", "matchCount", "mismatchCases", "rows", "currentLocal", "configurationComparison")} for name in reports}
    result = {"schemaVersion": 2, "kind": "auth-saved-reference-replay-v2", "sourceCommit": source_commit, "runManifestSha256": file_digest(local_root / "run-manifest.json"), "corpora": reports, "allCasesMatch": all(report["classification"] == "MATCH" for report in reports.values()), "comparisonDigest": digest(stable)}
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("evaluation output already exists") from exc
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
    return result


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--local-root", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--source-commit", required=True)
    return cli


if __name__ == "__main__":
    args = parser().parse_args()
    result = evaluate(args.local_root, args.output, args.source_commit)
    print(json.dumps({"classification": "MATCH" if result["allCasesMatch"] else "SEMANTIC_MISMATCH", "corpora": {name: {"classification": report["classification"], "caseCount": report["caseCount"], "matchCount": report["matchCount"]} for name, report in result["corpora"].items()}, "comparisonDigest": result["comparisonDigest"]}, sort_keys=True))
    raise SystemExit(0 if result["allCasesMatch"] else 1)
