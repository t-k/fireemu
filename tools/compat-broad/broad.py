"""Thin offline-only entry over existing conformance sessions and a fixed owned artifact."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from broad_cases import PROJECT, SEED, auth_cases, check_generated, generated_programs
from broad_contract import (
    ROOT,
    SELECTED_FS,
    catalog,
    compare_program,
    digest,
    family_for,
    historical,
    local_origin,
    programs,
)

sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from evidence_common import runtime_inputs
from owned_runner import (
    build_artifact,
    control_get,
    local_addresses,
    sanitized_environment,
    socket_closed,
)

HERE = Path(__file__).resolve().parent
CONFIG = {
    "schemaVersion": 1,
    "profile": "strict",
    "firestore": {"edition": "standard", "apiMode": "native"},
}
CATALOG = ROOT / "spec/compatibility/broad-catalog.json"


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def source_inputs():
    paths = list(HERE.glob("*.py")) + list(HERE.glob("*.mjs"))
    paths += [
        ROOT / f"conformance/src/{s}-probe/{f}.mjs"
        for s in ("auth", "firestore")
        for f in ("programs", "session")
    ]
    paths += [ROOT / "conformance/src/firestore-probe/credentials.mjs", CATALOG]
    paths += [
        ROOT / "tools/compat-inventory/owned_runner.py",
        ROOT / "tools/compat-inventory/evidence_common.py",
    ]
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths
        if p.exists()
    }


def session(service, selected, origin, output):
    origin = local_origin(origin)
    inp, out = output / f"{service}-input.json", output / f"{service}-actual.json"
    save(inp, selected)
    env = sanitized_environment(dict(os.environ))
    env.update(BROAD_ORIGIN=origin, BROAD_STATS=str(output / f"{service}-stats.json"))
    if service == "auth":
        env.update(
            AUTH_PROBE_BASE=origin + "/identitytoolkit.googleapis.com",
            AUTH_PROBE_IN=str(inp),
            AUTH_PROBE_OUT=str(out),
            AUTH_PROBE_RUN=str(SEED),
            AUTH_PROBE_KEY="fake-api-key",
            AUTH_PROBE_TIMEOUT_MS="5000",
        )
    else:
        env.update(
            FIRESTORE_PROBE_HOST=origin.removeprefix("http://"),
            FIRESTORE_PROBE_PROJECT=PROJECT,
            FIRESTORE_PROBE_IN=str(inp),
            FIRESTORE_PROBE_OUT=str(out),
            FIRESTORE_PROBE_SCHEME="http",
            FIRESTORE_PROBE_TARGET="local",
            FIRESTORE_PROBE_TOKEN="owner",
            FIRESTORE_PROBE_TIMEOUT_MS="5000",
        )
    command = [
        "node",
        "--import",
        str(HERE / "local-guard.mjs"),
        str(ROOT / f"conformance/src/{service}-probe/session.mjs"),
    ]
    with (output / f"{service}-stderr.log").open("wb") as errors:
        process = subprocess.Popen(
            command, env=env, cwd=output, stdout=subprocess.DEVNULL, stderr=errors
        )
        save(output / f"{service}-process.json", {"pid": process.pid, "argv": command})
        try:
            code = process.wait(timeout=130)
            if code != 0 or not out.exists():
                raise ValueError(f"{service} session did not produce a complete run")
            return json.loads(out.read_bytes())
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def child(output, nonce):
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    local_origin(firestore)
    if os.environ["GOOGLE_CLOUD_PROJECT"] != PROJECT:
        raise ValueError("project mismatch")
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if status != 200 or wrong != 403 or resources.get("project") != PROJECT:
        raise ValueError("owned control identity mismatch")
    save(
        output / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": nonce,
            "authOrigin": auth,
            "firestoreOrigin": firestore,
            "controlOrigin": control,
            "wrongTokenStatus": wrong,
        },
    )
    definitions = {s: programs(s)[0] for s in ("auth", "firestore")}
    selected = {
        "auth": definitions["auth"],
        "firestore": [p for p in definitions["firestore"] if p["id"] in SELECTED_FS]
        + generated_programs(),
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        jobs = {
            s: executor.submit(
                session, s, selected[s], auth if s == "auth" else firestore, output
            )
            for s in selected
        }
        actual = {s: job.result() for s, job in jobs.items()}
    rows, sources = [], {}
    for service, service_programs in selected.items():
        old, matrix, reference = historical(service)
        sources[service] = reference
        old_by_id = {p["id"]: p for p in old}
        expected = {p["id"]: p for p in matrix["programs"]}
        for program in service_programs:
            recorded = actual[service].get(program["id"], {})
            if program["id"].startswith("broad/"):
                rows.extend(check_generated(program, recorded))
                continue
            compared = compare_program(
                program,
                old_by_id.get(program["id"]),
                recorded,
                expected.get(program["id"], {}).get("steps", {}),
            )
            rows.extend(
                {
                    **row,
                    "id": service + ":" + row["id"],
                    "family": family_for(service, program["id"]),
                    "basis": "historical-production-reference",
                    "currentOperationDigest": digest(program),
                }
                for row in compared
            )
    rows.extend(auth_cases(auth))
    report = {
        "schemaVersion": 1,
        "target": "owned-local-artifact",
        "project": PROJECT,
        "edition": "Standard Native",
        "profile": "strict",
        "seed": SEED,
        "configuration": CONFIG,
        "historicalSources": sources,
        "cases": rows,
        "selectedPrograms": selected,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
    }
    save(output / "cases.json", report)
    return report


def stop_registered(output, parent_pid, nonce):
    # PID-specific identity validation, never broad process-group/name killing.
    registrations = list(output.glob("*-process.json"))
    instance_path = output / "instance.json"
    if instance_path.exists():
        instance = json.loads(instance_path.read_bytes())
        if instance["parentPid"] != parent_pid or instance["nonce"] != nonce:
            raise ValueError("unexpected child ownership")
        registrations.append(instance_path)
    for path in registrations:
        info = json.loads(path.read_bytes())
        pid = info["pid"]
        if type(pid) is not int or pid <= 1:
            raise ValueError("invalid owned pid")
        expected = info["argv"]
        if path == instance_path:
            expected = [sys.executable, *expected]
        for sig in (signal.SIGTERM, signal.SIGKILL):
            state = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm=", "-o", "args="],
                capture_output=True,
                text=True,
                check=False,
            )
            if not state.stdout.strip():
                break
            fields = state.stdout.strip().split(maxsplit=1)
            if (
                len(fields) != 2
                or fields[1] != " ".join(expected)
                or Path(fields[0]).name != Path(expected[0]).name
            ):
                raise ValueError("owned pid reused; refusing signal")
            os.kill(pid, sig)
            time.sleep(0.2)


def summarize(report):
    from collections import Counter

    counts = dict(Counter(r["status"] for r in report["cases"]))
    families = {
        f: dict(Counter(r["status"] for r in report["cases"] if r["family"] == f))
        for f in sorted({r["family"] for r in report["cases"]})
    }
    # A program's first divergent operation is a triage candidate, not a distinct bug per row.
    candidates: dict[str, dict] = {}
    for row in report["cases"]:
        if row["status"] not in {"mismatch", "fail"}:
            continue
        key = row["id"].split("#")[0]
        if key not in candidates:
            candidates[key] = {
                "firstDivergentOperation": row["id"],
                "relatedRows": [],
                "causeStatus": "needs-minimization",
                "fixable": "undetermined",
                "basis": row["basis"],
            }
        candidates[key]["relatedRows"].append(row["id"])
    return {
        "counts": counts,
        "families": families,
        "triageCandidates": candidates,
        "independentGapCount": None,
        "note": "Triage groups are not independent confirmed causes. See reviewed triage for minimization and fixability.",
    }


def run(output):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze the checkout before artifact execution")
    before = source_inputs()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    binary, build = build_artifact()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    nonce = uuid.uuid4().hex
    report = {"status": "incomplete", "productionExecuted": False}
    with tempfile.TemporaryDirectory(prefix="fireemu-broad-") as temp:
        private = Path(temp).resolve()
        artifact = private / "fireemu"
        shutil.copyfile(binary, artifact)
        artifact.chmod(0o500)
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != build["artifactSha256"]:
            raise ValueError("artifact copy mismatch")
        config = private / "config.json"
        save(config, CONFIG)
        command = [
            str(artifact),
            "exec",
            "--config",
            str(config),
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
        ]
        with (output / "owned-stderr.log").open("wb") as errors:
            process = subprocess.Popen(
                command,
                cwd=private,
                env=sanitized_environment(dict(os.environ)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=errors,
            )
            try:
                code = process.wait(timeout=240)
                if code != 0:
                    raise ValueError(
                        "owned runner failed; inspect private sanitized logs"
                    )
                report = json.loads((output / "cases.json").read_bytes())
                instance = json.loads((output / "instance.json").read_bytes())
                if instance["parentPid"] != process.pid or instance["nonce"] != nonce:
                    raise ValueError("owned process mismatch")
                if not all(
                    socket_closed(instance[k])
                    for k in ("authOrigin", "firestoreOrigin", "controlOrigin")
                ):
                    raise ValueError("owned listeners remain open")
                if source_inputs() != before or runtime_inputs(ROOT) != build["inputs"]:
                    raise ValueError("execution inputs changed")
                report.update(
                    status="completed",
                    executionCommit=commit,
                    artifactSha256=build["artifactSha256"],
                    runtimeInputs=build["inputs"],
                    executionInputs=before,
                    configurationDigest=digest(CONFIG),
                    build=build,
                    ownedProcess={
                        "pid": process.pid,
                        "stopped": True,
                        "listenersClosed": True,
                    },
                )
                report["summary"] = summarize(report)
            finally:
                stop_registered(output, process.pid, nonce)
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                save(output / "manifest.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-catalog", action="store_true")
    parser.add_argument("--check-catalog", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    if args.write_catalog:
        save(CATALOG, catalog())
    elif args.check_catalog:
        if json.loads(CATALOG.read_bytes()) != catalog():
            raise ValueError("broad inventory is stale")
        for service in ("auth", "firestore"):
            historical(service)
        print("Broad inventory and historical corpus bindings checked")
    elif args.child:
        child(args.child.resolve(), args.nonce)
    elif args.run and args.output:
        report = run(args.output.resolve())
        print(json.dumps({"status": report["status"], "summary": report["summary"]}))
    else:
        parser.error("select a catalog command or --run --output")


if __name__ == "__main__":
    main()
