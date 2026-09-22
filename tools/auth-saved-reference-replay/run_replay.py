"""Run the four existing Auth owned probes against one fixed local artifact."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

from replay import CORPORA, digest, file_digest, require

ROOT = Path(__file__).resolve().parents[2]
RUNNERS = {
    "auth-basic-v2": ROOT / "tools/auth-basic-v2/auth_v2_owned.py",
    "auth-profile": ROOT / "tools/auth-profile/profile_owned.py",
    "auth-display-name": ROOT / "tools/auth-display-name/display_name_owned.py",
    "auth-password": ROOT / "tools/auth-password/password_owned.py",
}


def load_runner(path: Path):
    sys.path.insert(0, str(path.parent))
    try:
        name = f"auth_saved_runner_{path.stem}"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ValueError(f"cannot load runner: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def run(output_root: Path) -> dict:
    require(not output_root.exists(), "output root must not already exist")
    output_root.mkdir(mode=0o700)
    # Import lazily so contract/evaluator tests do not build the Rust artifact.
    sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
    try:
        from owned_runner import artifact_binding, build_artifact

        binary, build = build_artifact()
    finally:
        sys.path.pop(0)

    source_path = binary.resolve(strict=True)
    launch_path = output_root / "artifact" / "fireemu"
    launch_path.parent.mkdir(mode=0o700)
    shutil.copyfile(source_path, launch_path)
    launch_path.chmod(0o500)
    build = {
        **build,
        **artifact_binding(source_path, launch_path, build, build["inputs"]),
    }

    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    reports = {}
    for name in CORPORA:
        runner = load_runner(RUNNERS[name])
        runner.build_artifact = lambda: (launch_path, build)
        report = runner.run(output_root / name)
        require(
            runner.complete(report),
            f"{name}: owned replay failed or is incomplete",
        )
        status = report.get("status")
        require(status in {"passed", "failed"}, f"{name}: invalid report status")
        reports[name] = {
            "status": status,
            "localReport": f"{name}/local.json",
            "localReportSha256": file_digest(output_root / name / "local.json"),
            "localReportBytes": (output_root / name / "local.json").stat().st_size,
            "artifactSha256": report["artifact"]["sha256"],
            "runtimeSourceCommit": report["runtimeSourceCommit"],
            "cleanup": report["cleanup"],
            "listenersClosed": report["ownedProcess"]["listenersClosed"],
            "processExitCode": report["ownedProcess"]["exitCode"],
            "probeInputsSha256": digest(report["probeInputs"]),
            "configurationSha256": report["configuration"]["sha256"],
            "configurationFileSha256": report["configuration"]["fileSha256"],
        }
        require(
            report["artifact"]["sha256"] == build["artifactSha256"]
            and report["runtimeSourceCommit"] == source_commit
            and report["ownedProcess"]["listenersClosed"] is True,
            f"{name}: fixed artifact or cleanup binding failed",
        )
    manifest = {
        "schemaVersion": 2,
        "kind": "auth-saved-reference-replay-local-v2",
        "sourceCommit": source_commit,
        "build": build,
        "artifactSha256": build["artifactSha256"],
        "corpora": reports,
    }
    (output_root / "run-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output-root", type=Path, required=True)
    args = cli.parse_args()
    result = run(args.output_root)
    print(
        json.dumps(
            {
                "sourceCommit": result["sourceCommit"],
                "artifactSha256": result["artifactSha256"],
                "corpora": sorted(result["corpora"]),
            },
            sort_keys=True,
        )
    )
