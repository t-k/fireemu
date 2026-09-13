"""Thin offline-only entry over existing conformance sessions and a fixed owned artifact."""

# ruff: noqa: BLE001 -- Continue independent cleanup; record only sanitized exception types.
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
    catalog,
    compare_program,
    digest,
    family_for,
    historical,
    local_origin,
    programs,
    replay_selection,
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
FIRESTORE_CONFIG = {"edition": "standard", "apiMode": "native"}
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


def session(service, selected, origin, output, *, current_wire=False):
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
    if current_wire:
        if service != "firestore":
            raise ValueError("current wire recorder only supports Firestore")
        env["FIRESTORE_PROBE_WIRE_DIR"] = str(output / "wire-private")
    command = [
        "node",
        "--import",
        str(HERE / "local-guard.mjs"),
        str(
            HERE / "current-session.mjs"
            if current_wire
            else ROOT / f"conformance/src/{service}-probe/session.mjs"
        ),
    ]
    with (output / f"{service}-stderr.log").open("wb") as errors:
        process = subprocess.Popen(
            command, env=env, cwd=output, stdout=subprocess.DEVNULL, stderr=errors
        )
        try:
            save(
                output / f"{service}-process.json",
                {"pid": process.pid, "argv": command},
            )
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
    current_fs, legacy = replay_selection()
    selected = {
        "auth": definitions["auth"],
        "firestore": current_fs + generated_programs(),
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
    # Execute the exact historical sequence in a separate session/output identity.
    legacy_output = output / "historical-transform"
    legacy_output.mkdir()
    legacy_actual = session("firestore", legacy, firestore, legacy_output)
    _, legacy_matrix, _ = historical("firestore")
    legacy_expected = {p["id"]: p for p in legacy_matrix["programs"]}
    for program in legacy:
        rows.extend(
            {
                **row,
                "id": "firestore:historical/" + row["id"],
                "family": "fs-writes",
                "basis": "historical-production-reference",
                "executionVariant": "exact-historical-operation-sequence",
                "currentOperationDigest": digest(program),
            }
            for row in compare_program(
                program,
                program,
                legacy_actual.get(program["id"], {}),
                legacy_expected[program["id"]]["steps"],
            )
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
        "historicalReplayPrograms": legacy,
        "historicalReplayObservations": legacy_actual,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "localObservations": actual,
        "requestStats": {
            service: json.loads((output / f"{service}-stats.json").read_bytes())
            for service in selected
        },
    }
    save(output / "cases.json", report)
    return report


def stop_registered(output, parent_pid, nonce, *, recovery_grace=0.2):
    """Attempt each owned child independently; aggregate failures without unsafe signals."""
    if not 0 <= recovery_grace <= 300:
        raise ValueError("invalid recovery grace")
    grace_deadline = time.monotonic() + recovery_grace
    registrations = sorted(output.rglob("*-process.json"))
    instance_path = output / "instance.json"
    if instance_path.exists():
        registrations.append(instance_path)
    failures = []
    for path in registrations:
        try:
            info = json.loads(path.read_bytes())
            if path == instance_path and (
                info["parentPid"] != parent_pid or info["nonce"] != nonce
            ):
                raise ValueError("unexpected child ownership")
            pid, expected = info["pid"], info["argv"]
            if type(pid) is not int or pid <= 1:
                raise ValueError("invalid owned pid")
            if path == instance_path:
                expected = [sys.executable, *expected]
            for sig in (signal.SIGTERM, signal.SIGKILL):
                state = subprocess.run(
                    [
                        "ps",
                        "-ww",
                        "-p",
                        str(pid),
                        "-o",
                        "stat=",
                        "-o",
                        "ucomm=" if sys.platform == "darwin" else "comm=",
                        "-o",
                        "args=",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if not state.stdout.strip():
                    break
                fields = state.stdout.strip().split(maxsplit=2)
                # A zombie cannot execute or receive useful termination signals. Its
                # Popen owner must still reap it; do not relax live-process argv checks.
                if fields[0].startswith("Z"):
                    break
                if len(fields) != 3:
                    raise ValueError("incomplete process identity")
                comm = Path(fields[1]).name.lower()
                same_binary = comm == Path(expected[0]).name.lower() or (
                    comm.startswith("python")
                    and Path(expected[0]).name.lower().startswith("python")
                )
                if fields[2] != " ".join(expected) or not same_binary:
                    raise ValueError("owned pid reused; refusing signal")
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    break
                if sig == signal.SIGTERM:
                    while time.monotonic() < grace_deadline:
                        state = subprocess.run(
                            ["ps", "-p", str(pid), "-o", "stat="],
                            capture_output=True,
                            text=True,
                            check=False,
                        ).stdout.strip()
                        if not state or state.startswith("Z"):
                            break
                        time.sleep(min(0.05, max(0, grace_deadline - time.monotonic())))
        except Exception as error:
            failures.append(type(error).__name__)
    if failures:
        raise ValueError("one or more owned registrations could not be confirmed")


def cleanup_run(process, output, nonce, report, *, recovery_grace=0.2):
    """Registration errors must never skip stopping the owned parent or recording failure."""
    try:
        stop_registered(output, process.pid, nonce, recovery_grace=recovery_grace)
    except Exception as error:
        report.update(status="incomplete", cleanupFailure=type(error).__name__)
    finally:
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except Exception as error:
            report.update(
                status="incomplete", parentCleanupFailure=type(error).__name__
            )
        finally:
            save(output / "manifest.json", report)


def supervise(command, output, nonce, report, *, timeout=240, recovery_grace=0.2):
    """Persist immutable parent inputs before launch; retain partial results on every exit."""
    report.update(status="incomplete", recordingComplete=False, cases=[])
    save(output / "manifest.json", report)
    process = None
    try:
        with (output / "owned-stderr.log").open("wb") as errors:
            process = subprocess.Popen(
                command,
                cwd=output,
                env=sanitized_environment(dict(os.environ)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=errors,
            )
            try:
                report["exitCode"] = process.wait(timeout=timeout)
                report["stopReason"] = (
                    "child-completed" if report["exitCode"] == 0 else "child-nonzero"
                )
            except subprocess.TimeoutExpired:
                report.update(exitCode=None, stopReason="child-timeout")
    except Exception as error:
        report.update(
            stopReason="process-start-failure"
            if process is None
            else "supervision-failure",
            failureType=type(error).__name__,
        )
    finally:
        if process is not None:
            # Stop owned processes even when the child result is absent or malformed.
            cleanup_run(process, output, nonce, report, recovery_grace=recovery_grace)
        try:
            partial_path = output / "cases.json"
            if partial_path.exists():
                partial = json.loads(partial_path.read_bytes())
                report["partialResultSha256"] = hashlib.sha256(
                    partial_path.read_bytes()
                ).hexdigest()
                if (
                    not isinstance(partial, dict)
                    or not isinstance(partial.get("cases"), list)
                    or not partial["cases"]
                    or not all(
                        isinstance(row, dict)
                        and all(
                            isinstance(row.get(key), str)
                            for key in ["id", "status", "family"]
                        )
                        for row in partial["cases"]
                    )
                    or any(
                        row["status"] in {"fail", "mismatch"}
                        and not isinstance(row.get("basis"), str)
                        for row in partial["cases"]
                    )
                ):
                    raise ValueError("invalid child report")
                # Child data cannot replace parent artifact/configuration/provenance.
                for key in [
                    "schemaVersion",
                    "kind",
                    "cases",
                    "manifest",
                    "manifestDigest",
                    "auth",
                    "selectedPrograms",
                    "historicalSources",
                    "localObservations",
                    "requestStats",
                    "historicalReplayPrograms",
                    "historicalReplayObservations",
                    "target",
                    "project",
                    "edition",
                    "profile",
                    "seed",
                    "formalCompatibilityClaim",
                ]:
                    if key in partial:
                        report[key] = partial[key]
                report["recordingComplete"] = (
                    partial.get("recordingComplete", report.get("exitCode") == 0)
                    is True
                )
                report["partialResultSha256"] = hashlib.sha256(
                    partial_path.read_bytes()
                ).hexdigest()
        except Exception as error:
            report.update(
                recordingComplete=False, partialResultFailure=type(error).__name__
            )
        stopped = process is None or process.poll() is not None
        closed = None
        try:
            instance = json.loads((output / "instance.json").read_bytes())
            if (
                process is None
                or instance["parentPid"] != process.pid
                or instance["nonce"] != nonce
            ):
                raise ValueError("owned process identity mismatch")
            closed = all(
                socket_closed(local_origin(instance[k]))
                for k in ("authOrigin", "firestoreOrigin", "controlOrigin")
            )
        except Exception as error:
            report["terminationVerificationFailure"] = type(error).__name__
        report["ownedProcess"] = {
            "pid": process.pid if process else None,
            "stopped": stopped,
            "listenersClosed": closed,
        }
        complete = (
            report.get("stopReason") == "child-completed"
            and report["recordingComplete"]
            and stopped
            and closed is True
            and not any(
                report.get(k)
                for k in [
                    "cleanupFailure",
                    "parentCleanupFailure",
                    "terminationVerificationFailure",
                    "partialResultFailure",
                ]
            )
        )
        report["status"] = "completed" if complete else "incomplete"
        try:
            report["summary"] = summarize(report)
        except Exception as error:
            report.update(
                status="incomplete", summaryFailure=type(error).__name__, summary={}
            )
        finally:
            save(output / "manifest.json", report)
    return report


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


def run(
    output,
    *,
    child_script=None,
    project=PROJECT,
    configuration=None,
    execution_timeout=240,
    recovery_grace=0.2,
):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze the checkout before artifact execution")
    base_config = {
        **CONFIG,
        "daemon": {"authProjectNumbers": {}},
        **(configuration or {}),
    }
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
        index_commit = "2526c61eda5fc53ac91250307786127ae3c601be"
        index_bytes = subprocess.check_output(
            ["git", "show", f"{index_commit}:conformance/firestore.indexes.json"],
            cwd=ROOT,
        )
        index_sha = hashlib.sha256(index_bytes).hexdigest()
        if (
            index_sha
            != "8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c"
        ):
            raise ValueError("historical index bytes do not match production evidence")
        index_file = private / "indexes.json"
        index_file.write_bytes(index_bytes)
        actual_config = {
            **base_config,
            "firestore": {**FIRESTORE_CONFIG, "indexFile": str(index_file)},
        }
        config = private / "config.json"
        save(config, actual_config)
        command = [
            str(artifact),
            "exec",
            "--config",
            str(config),
            "--project",
            project,
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
            str(child_script or Path(__file__).resolve()),
            "--child",
            str(output),
            "--nonce",
            nonce,
        ]
        report.update(
            executionCommit=commit,
            artifactSha256=build["artifactSha256"],
            runtimeInputs=build["inputs"],
            executionInputs=before,
            configurationDigest=digest(actual_config),
            configuration={
                **base_config,
                "firestore": {
                    **FIRESTORE_CONFIG,
                    "indexFile": "<owned-private-index-file>",
                },
            },
            indexConfiguration={
                "sha256": index_sha,
                "sourceCommit": index_commit,
                "value": json.loads(index_bytes),
            },
            build=build,
        )
        report["supervision"] = {
            "timeoutSeconds": execution_timeout,
            "recoveryGraceSeconds": recovery_grace,
        }
        supervise(
            command,
            output,
            nonce,
            report,
            timeout=execution_timeout,
            recovery_grace=recovery_grace,
        )
        if source_inputs() != before or runtime_inputs(ROOT) != build["inputs"]:
            report.update(status="incomplete", stopReason="execution-inputs-changed")
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
        return 0 if report["status"] == "completed" else 2
    else:
        parser.error("select a catalog command or --run --output")


if __name__ == "__main__":

    def interrupted(signum, frame):
        raise InterruptedError("owned run interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    sys.exit(main())
