"""Execute the fixed O3 plan on one pinned retained artifact, on owned loopback."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))

import broad
import local_collector as local_collector_module
import local_transport as local_transport_module
from broad_contract import digest, local_origin
from evidence_common import runtime_inputs_at_commit
from local_collector import collect_local
from local_transport import TRANSPORT, local_executor, save_new, verify_wire_journal
from owned_runner import control_get, local_addresses
from transform_comparator import _exact, compare_rows
from transform_compiler import compile_plan

ARTIFACT_SHA = "be2771b9f2093cced55e8158d8d5a72ed35e6ac5e32edddb068daa45511e12ae"
RUNTIME_COMMIT = "cce4a4f9b7369938c89bd32a5106e8d3cab59f83"
BUILD_COMMAND = [
    "cargo",
    "build",
    "--locked",
    "-p",
    "fireemu",
    "--message-format=json",
]
DEFAULT_PROFILE = {
    "name": "historical-default",
    "artifactSha256": ARTIFACT_SHA,
    "runtimeCommit": RUNTIME_COMMIT,
    "manifestCommitField": "sourceCommit",
    "requireTopLevelArtifactSha": True,
}
REPAIRED_PROFILE = {
    "name": "repaired-567565bdd",
    "artifactSha256": "e792e0bc1947bbd227b3ee9778eca093cda94fbde767911dd6139a6cbfd90be4",
    "runtimeCommit": "567565bdd654cab00dbb84101edcc7bdc628e230",
    "manifestCommitField": "executionCommit",
    "requireTopLevelArtifactSha": False,
}
CURRENT_PROFILE = {
    "name": "current-4f11e691",
    "artifactSha256": "a34c865c2c87b16281080dba9327543a9d8f8876f172a74569b5291ef2a1219f",
    "runtimeCommit": "4f11e691a739b1659d2b95aaf3faeb081842b239",
    "manifestCommitField": "executionCommit",
    "requireTopLevelArtifactSha": False,
    "historicalCompilerSha256": "eab79d565e2ab28c2be0c46d2d3dfcef193aee808bf570a484e9121f3c7c7d53",
}
G0_CURRENT_PROFILE = {
    "name": "current-8f129b10",
    "artifactSha256": "bf713deb0952db610c840d6233b9c343496df5b69b9c4e934a4054c27f765897",
    "runtimeCommit": "8f129b10aac6cf9a875fbf67fd8775a746daec40",
    "manifestCommitField": "executionCommit",
    "requireTopLevelArtifactSha": False,
}
CURRENT_8245_PROFILE = {
    "name": "current-8245-e896132a",
    "artifactSha256": "8245b80ea941344e114fe8f61cd7721d2519739509779e7504c295c1bbb66849",
    "runtimeCommit": "e896132a2317a5f38b2780857301f7b0f88b2e68",
    "manifestCommitPath": ["runtimeSource", "commit"],
    "requireTopLevelArtifactSha": False,
}
G0_CURRENT_648_PROFILE = {
    "name": "current-648-7737",
    "artifactSha256": "7737f6c389aff0a0f280757591af3b81f11edfbc8438cb69268da0f4c2237026",
    "runtimeCommit": "648aabe56cf6147128ffadf565d93ca7a92013c1",
    "manifestCommitPath": ["runtimeSource", "commit"],
    "requireTopLevelArtifactSha": False,
}
PROFILES = {
    item["name"]: item
    for item in (
        DEFAULT_PROFILE,
        REPAIRED_PROFILE,
        CURRENT_PROFILE,
        G0_CURRENT_PROFILE,
        CURRENT_8245_PROFILE,
        G0_CURRENT_648_PROFILE,
    )
}
PROJECT = "demo-firestore-probe"
CONFIGURATION = {
    "schemaVersion": 1,
    "profile": "strict",
    "firestore": {"edition": "standard", "apiMode": "native"},
    "daemon": {"authProjectNumbers": {}},
}


def sha_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compiler_for_profile(path: Path | None, profile: dict) -> Path | None:
    expected = profile.get("historicalCompilerSha256")
    if expected is None:
        return None
    if path is None or path.is_symlink() or not path.is_file() or sha_file(path) != expected:
        raise ValueError("historical compiler source binding differs")
    return path


def compile_bound_plan(compiler_path: Path | None, project: str, database: str, nonce: str) -> dict:
    if compiler_path is None:
        return compile_plan(project, database, nonce)
    module_spec = importlib.util.spec_from_file_location("bound_transform_compiler", compiler_path)
    if module_spec is None or module_spec.loader is None:
        raise ValueError("historical compiler source binding differs")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module.compile_plan(project, database, nonce)


def validate_bound_plan(plan: dict, compiler_path: Path | None) -> None:
    expected = compile_bound_plan(compiler_path, plan["project"], plan["database"], plan["nonce"])
    if not _exact(plan, expected):
        raise ValueError("compiler plan drift")


def compare_bound_rows(
    compiler_path: Path | None,
    plan: dict,
    rows: list[dict],
    cleanup: list[dict],
) -> dict:
    if compiler_path is None:
        return compare_rows(plan, rows, plan, rows, left_recovery=cleanup, right_recovery=cleanup)
    compiler_spec = importlib.util.spec_from_file_location("bound_transform_compiler", compiler_path)
    if compiler_spec is None or compiler_spec.loader is None:
        raise ValueError("historical compiler source binding differs")
    compiler = importlib.util.module_from_spec(compiler_spec)
    compiler_spec.loader.exec_module(compiler)
    comparator_spec = importlib.util.spec_from_file_location("bound_transform_comparator", HERE / "transform_comparator.py")
    if comparator_spec is None or comparator_spec.loader is None:
        raise ValueError("comparator source binding differs")
    previous = sys.modules.get("transform_compiler")
    sys.modules["transform_compiler"] = compiler
    try:
        comparator = importlib.util.module_from_spec(comparator_spec)
        comparator_spec.loader.exec_module(comparator)
        return comparator.compare_rows(plan, rows, plan, rows, left_recovery=cleanup, right_recovery=cleanup)
    finally:
        if previous is None:
            sys.modules.pop("transform_compiler", None)
        else:
            sys.modules["transform_compiler"] = previous


def resolve_profile(profile: dict | str = DEFAULT_PROFILE) -> dict:
    if isinstance(profile, str):
        try:
            return PROFILES[profile]
        except KeyError:
            raise ValueError("unknown artifact profile") from None
    if not isinstance(profile, dict) or profile.get("name") not in PROFILES:
        raise ValueError("unregistered artifact profile")
    registered = PROFILES[profile["name"]]
    if profile != registered:
        raise ValueError("unregistered artifact profile")
    return registered


def manifest_commit(manifest: dict, profile: dict) -> str | None:
    path = profile.get("manifestCommitPath")
    if path is not None:
        if not isinstance(path, list) or not path or any(
            not isinstance(part, str) or not part for part in path
        ):
            raise ValueError("invalid manifest commit path")
        value: object = manifest
        for part in path:
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value if isinstance(value, str) else None
    field = profile.get("manifestCommitField")
    if not isinstance(field, str) or not field:
        raise ValueError("invalid manifest commit field")
    value = manifest.get(field)
    return value if isinstance(value, str) else None


def validate_runtime_provenance(
    manifest: dict, profile: dict | str = DEFAULT_PROFILE
) -> dict:
    """Compare the entire manifest input map to the fixed Git tree, not itself."""
    profile = resolve_profile(profile)
    runtime_commit = profile["runtimeCommit"]
    expected = runtime_inputs_at_commit(runtime_commit, ROOT)
    actual = manifest.get("build", {}).get("inputs")
    if manifest_commit(manifest, profile) != runtime_commit or not _exact(
        actual, expected
    ):
        raise ValueError("retained runtime input map differs from fixed Git tree")
    return {
        "runtimeInputsDigest": digest(actual),
        "expectedRuntimeInputsDigest": digest(expected),
        "runtimeInputCount": len(expected),
        "runtimeInputsVerifiedAgainst": "git-tree:" + runtime_commit,
    }


def validate_manifest_payload(
    manifest: dict, manifest_bytes: bytes, profile: dict | str
) -> dict:
    profile = resolve_profile(profile)
    artifact_sha = profile["artifactSha256"]
    build = manifest.get("build", {})
    if (
        manifest_commit(manifest, profile) != profile["runtimeCommit"]
        or (
            profile["requireTopLevelArtifactSha"]
            and manifest.get("artifactSha256") != artifact_sha
        )
        or build.get("artifactSha256") != artifact_sha
        or type(build.get("exitCode")) is not int
        or build["exitCode"] != 0
        or build.get("command") != BUILD_COMMAND
        or not isinstance(build.get("inputs"), dict)
        or not build["inputs"]
    ):
        raise ValueError("retained artifact/build/source binding differs")
    return {
        "artifactSha256": artifact_sha,
        "runtimeSourceCommit": profile["runtimeCommit"],
        "retainedManifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "artifactProfile": profile["name"],
        **validate_runtime_provenance(manifest, profile),
    }


@contextmanager
def owned_artifact(source: Path, expected_sha: str = ARTIFACT_SHA):
    """Launch scope for an exclusive verified copy, never the caller's pathname."""
    with tempfile.TemporaryDirectory(prefix="fireemu-o3-owned-") as directory:
        private = Path(directory)
        private.chmod(0o700)
        executable = private / "fireemu"
        broad.retain_artifact(source, executable, expected_sha)
        stat = executable.stat()
        identity = {
            "path": str(executable),
            "sha256": sha_file(executable),
            "device": stat.st_dev,
            "inode": stat.st_ino,
            "size": stat.st_size,
            "mode": stat.st_mode & 0o777,
        }
        yield executable, identity


def validate_retained_artifact(
    artifact: Path, manifest_path: Path, profile: dict | str = DEFAULT_PROFILE
) -> dict:
    """Validate the authorized saved artifact, never build or accept arbitrary code."""
    profile = resolve_profile(profile)
    artifact_sha = profile["artifactSha256"]
    if artifact.is_symlink() or manifest_path.is_symlink():
        raise ValueError("retained inputs must be regular files")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    runtime = validate_manifest_payload(manifest, manifest_bytes, profile)
    if sha_file(artifact) != artifact_sha:
        raise ValueError("retained artifact/build/source binding differs")
    return runtime


def validate_current_g0_artifact(
    artifact: Path,
    manifest_path: Path,
    *,
    profile: dict | str,
    repo: Path,
    max_manifest_bytes: int = 32 * 1024 * 1024,
    max_artifact_bytes: int = 1024 * 1024 * 1024,
) -> dict:
    """Validate a retained artifact against an ancestor source and current Rust inputs.

    This is a provenance-only extension for the G0 adapter. It reuses the registered profile,
    receipt schema, exact build command and artifact hashing above; it does not alter historical
    profile semantics or execute the artifact.
    """
    profile = resolve_profile(profile)
    repo = Path(repo).resolve()
    if repo != ROOT.resolve():
        raise ValueError("current source checkout differs from validator checkout")
    if artifact.is_symlink() or manifest_path.is_symlink():
        raise ValueError("retained inputs must be regular files")
    if not artifact.is_file() or not manifest_path.is_file():
        raise ValueError("retained inputs must be regular files")
    if manifest_path.stat().st_size > max_manifest_bytes:
        raise ValueError("retained manifest exceeds bound")
    if artifact.stat().st_size > max_artifact_bytes:
        raise ValueError("retained artifact exceeds bound")
    runtime = validate_retained_artifact(artifact, manifest_path, profile=profile)
    manifest = json.loads(manifest_path.read_bytes())
    source_commit = manifest_commit(manifest, profile)
    current_commit = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    try:
        subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", source_commit, current_commit],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, TypeError):
        raise ValueError("retained source is not an ancestor of current checkout") from None
    source_inputs = runtime_inputs_at_commit(source_commit, repo)
    current_inputs = runtime_inputs_at_commit(current_commit, repo)
    receipt_inputs = manifest.get("build", {}).get("inputs")
    if receipt_inputs != source_inputs or source_inputs != current_inputs:
        raise ValueError("retained runtime input map differs from current checkout")
    return {
        **runtime,
        "runtimeSourceCommit": source_commit,
        "currentSourceCommit": current_commit,
        "sourceInputsDigest": digest(source_inputs),
        "currentInputsDigest": digest(current_inputs),
        "sourceInputsEqualCurrent": True,
    }


def source_inputs() -> dict:
    inputs = broad.source_inputs()
    inputs.update(
        {
            str(path.relative_to(ROOT)): sha_file(path)
            for path in sorted(HERE.glob("*.py"))
        }
    )
    inputs[str(TRANSPORT.relative_to(ROOT))] = sha_file(TRANSPORT)
    return inputs


def copy_exclusive(source: Path, destination: Path) -> None:
    with destination.open("xb") as stream:
        stream.write(source.read_bytes())
    destination.chmod(0o400)


def validate_copied_manifest(output: Path, inputs: dict, profile: dict | str) -> dict:
    profile = resolve_profile(profile)
    expected_path = output / "retained-manifest.json"
    copied_path = Path(inputs.get("retainedManifestPath", ""))
    if (
        copied_path != expected_path
        or copied_path.is_symlink()
        or not copied_path.is_file()
    ):
        raise ValueError("retained manifest copy is not bound")
    manifest_bytes = copied_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != inputs.get(
        "retainedManifestSha256"
    ):
        raise ValueError("retained manifest digest differs")
    runtime = validate_manifest_payload(
        json.loads(manifest_bytes), manifest_bytes, profile
    )
    for key in (
        "artifactProfile",
        "artifactSha256",
        "runtimeSourceCommit",
        "retainedManifestSha256",
        "runtimeInputsDigest",
        "expectedRuntimeInputsDigest",
        "runtimeInputCount",
        "runtimeInputsVerifiedAgainst",
    ):
        if inputs.get(key) != runtime[key]:
            raise ValueError("retained manifest provenance differs")
    return runtime


def child(output: Path, nonce: str, profile_name: str, compiler_path: Path | None) -> None:
    inputs = json.loads((output / "run-inputs.json").read_bytes())
    profile = resolve_profile(profile_name)
    compiler_path = compiler_for_profile(compiler_path, profile)
    if compiler_path is not None:
        local_transport_module._validate_plan = lambda plan: validate_bound_plan(plan, compiler_path)
        local_collector_module._validate_plan = lambda plan: validate_bound_plan(plan, compiler_path)
    validate_copied_manifest(output, inputs, profile)
    plan = compile_bound_plan(compiler_path, PROJECT, "(default)", nonce)
    if (
        inputs["nonce"] != nonce
        or inputs["artifactProfile"] != profile["name"]
        or inputs["project"] != PROJECT
        or inputs["sourceInputs"] != source_inputs()
        or not _exact(json.loads((output / "plan.json").read_bytes()), plan)
        or inputs["planDigest"] != plan["planDigest"]
        or inputs["configurationDigest"] != sha_file(output / "config.json")
        or not _exact(json.loads((output / "config.json").read_bytes()), CONFIGURATION)
    ):
        raise ValueError("child source/plan/configuration binding differs")
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    local_origin(firestore)
    local_origin(control)
    save_new(
        output / "instance.json",
        {
            "parentPid": os.getppid(),
            "pid": os.getpid(),
            "argv": sys.argv,
            "nonce": nonce,
            "project": PROJECT,
            "authOrigin": auth,
            "firestoreOrigin": firestore,
            "controlOrigin": control,
        },
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or wrong != 403
        or resources.get("project") != PROJECT
        or os.environ.get("GOOGLE_CLOUD_PROJECT") != PROJECT
    ):
        raise ValueError("owned local instance identity differs")
    save_new(
        output / "identity.json",
        {
            "project": PROJECT,
            "status": status,
            "wrongTokenStatus": wrong,
            "controlRequests": 2,
        },
    )
    binding = digest(inputs)
    result = collect_local(
        plan, local_executor(plan, firestore, output / "wire", binding)
    )
    save_new(output / "result.json", result)
    count = verify_wire_journal(plan, result, output / "wire", binding)
    contract = compare_bound_rows(compiler_path, plan, result["rows"], result["cleanup"])
    save_new(
        output / "local-contract.json",
        {
            "basis": "Self-validation against the local contract; not an independent or production comparison.",
            "comparison": contract,
        },
    )
    complete = (
        result["recordingComplete"]
        and result["cleanupComplete"]
        and source_inputs() == inputs["sourceInputs"]
    )
    save_new(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": "o3-commit-transform-owned-local-v1",
            "target": "owned-retained-local-artifact",
            "project": PROJECT,
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "recordingComplete": complete,
            "stateValidation": complete,
            "manifest": {
                "binding": binding,
                "sourceInputs": inputs["sourceInputs"],
                "dataRequests": count,
            },
            "manifestDigest": binding,
            "cases": [
                {
                    "id": plan["campaignId"],
                    "family": "firestore",
                    "status": "fail"
                    if not complete
                    else "mismatch"
                    if contract["classification"] != "MATCH"
                    else "pass",
                    "basis": "Local contract self-validation, with independent acquisition and promotion still false.",
                }
            ],
        },
    )


def run(
    output: Path,
    artifact: Path,
    retained_manifest: Path,
    profile: dict | str = DEFAULT_PROFILE,
    historical_compiler: Path | None = None,
) -> dict:
    """Own the verified executable copy, child, and all OS-assigned listeners."""
    profile = resolve_profile(profile)
    compiler_path = compiler_for_profile(historical_compiler, profile)
    runtime = validate_retained_artifact(artifact, retained_manifest, profile)
    with owned_artifact(artifact, profile["artifactSha256"]) as (executable, identity):
        sealed = _run_pinned(
            output, executable, retained_manifest, runtime, identity, profile, compiler_path
        )
    sealed["ownedArtifactRemoved"] = not executable.exists()
    if not sealed["ownedArtifactRemoved"]:
        sealed["status"] = "incomplete"
    save_new(output / "evidence.json", sealed)
    return sealed


def _run_pinned(
    output: Path,
    artifact: Path,
    retained_manifest: Path,
    runtime: dict,
    identity: dict,
    profile: dict,
    compiler_path: Path | None,
) -> dict:
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze the collector checkout before execution")
    before = source_inputs()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    copied_manifest = output / "retained-manifest.json"
    copy_exclusive(retained_manifest, copied_manifest)
    if sha_file(copied_manifest) != runtime["retainedManifestSha256"]:
        raise ValueError("retained manifest copy changed")
    nonce = uuid.uuid4().hex
    plan = compile_bound_plan(compiler_path, PROJECT, "(default)", nonce)
    save_new(output / "plan.json", plan)
    save_new(output / "config.json", CONFIGURATION)
    inputs = {
        **runtime,
        "artifactProfile": profile["name"],
        "retainedManifestPath": str(copied_manifest),
        "ownedArtifact": identity,
        "collectorSourceCommit": commit,
        "sourceInputs": before,
        "nonce": nonce,
        "project": PROJECT,
        "planDigest": plan["planDigest"],
        "configurationDigest": sha_file(output / "config.json"),
        "dataRequestUpperBound": 17,
        "identityControlRequests": 2,
        "productionExecuted": False,
        "historicalCompilerSha256": profile.get("historicalCompilerSha256"),
    }
    save_new(output / "run-inputs.json", inputs)
    command = [
        str(artifact),
        "exec",
        "--config",
        str(output / "config.json"),
        "--project",
        PROJECT,
        "--only",
        "auth,firestore",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--hub-port",
        "0",
        "--ui-port",
        "0",
        "--logging-port",
        "0",
        "--log-verbosity",
        "silent",
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        str(output),
        "--nonce",
        nonce,
        "--profile",
        profile["name"],
    ]
    if compiler_path is not None:
        command.extend(["--historical-compiler", str(compiler_path)])
    save_new(output / "command.json", {"argv": command, "binding": digest(inputs)})
    report = {
        **runtime,
        "collectorSourceCommit": commit,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
    }
    broad.supervise(command, output, nonce, report, timeout=270, recovery_grace=30)
    save_new(output / "supervisor-final.json", report)
    manifest_stable = True
    try:
        validate_copied_manifest(output, inputs, profile)
    except ValueError:
        manifest_stable = False
    stable = (
        source_inputs() == before
        and sha_file(artifact) == profile["artifactSha256"]
        and artifact.stat().st_dev == identity["device"]
        and artifact.stat().st_ino == identity["inode"]
        and manifest_stable
    )
    files = {
        str(path.relative_to(output)): sha_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    sealed = {
        "kind": "o3-commit-transform-local-evidence-v1",
        "binding": digest(inputs),
        "files": files,
        "sourceStable": stable,
        "recordingComplete": report["recordingComplete"],
        "ownedProcess": report["ownedProcess"],
        "status": report["status"] if stable else "incomplete",
        "productionExecuted": False,
        "acquisitionValidated": False,
        "promotionReady": False,
    }
    return sealed


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--child", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--retained-manifest", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--historical-compiler", type=Path)
    parser.add_argument(
        "--profile", choices=sorted(PROFILES), default=DEFAULT_PROFILE["name"]
    )
    args = parser.parse_args()
    if args.child:
        if (
            not args.nonce
            or not args.profile
            or args.artifact
            or args.retained_manifest
        ):
            parser.error("child requires --nonce and --profile")
        child(args.child.resolve(), args.nonce, args.profile, args.historical_compiler)
        return 0
    if (
        not args.artifact
        or not args.retained_manifest
        or args.nonce
        or not args.profile
    ):
        parser.error("output requires --artifact, --retained-manifest and --profile")
    result = run(
        args.output.resolve(),
        args.artifact.absolute(),
        args.retained_manifest.absolute(),
        profile=args.profile,
        historical_compiler=args.historical_compiler.absolute() if args.historical_compiler else None,
    )
    print(
        json.dumps({"status": result["status"], "ownedProcess": result["ownedProcess"]})
    )
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
