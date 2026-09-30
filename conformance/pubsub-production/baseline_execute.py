"""Coordinator-only three-call read-only fixture baseline; never invoked by a lane."""
import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from urllib.parse import quote


def source_module(name, path, *, source=None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes() if source is None else source, str(path), "exec"), module.__dict__)
    return module


def verified_module(name, path, expected_sha, *, source=None):
    snapshot = path.read_bytes() if source is None else source
    if hashlib.sha256(snapshot).hexdigest() != expected_sha:
        raise Rejected("reviewed executable snapshot mismatch")
    return source_module(name, path, source=snapshot)


_common = source_module("lane7_baseline_common", Path(__file__).with_name("execute.py"))
_process = source_module("lane7_baseline_process", Path(__file__).with_name("baseline_process.py"))
Rejected, append_ledger, check_ledger, sha = _common.Rejected, _common.append_ledger, _common.check_ledger, _common.sha
ProcessStopped, run_owned = _process.ProcessStopped, _process.run_owned
PROJECT, LOCK_HELPER = _common.PROJECT, _common.LOCK_HELPER
TASK, ENVELOPE, SUBJECT = "PUBSUB-EVENTARC-FIXTURE-BASELINE", "PUBSUB-EVENTARC-fixture-baseline-002", "PUBSUB-EVENTARC fixture-baseline-002"
RESERVE, CAP = 0.01, 3


def baseline_requests(project_number):
    if not isinstance(project_number, str) or not re.fullmatch(r"[0-9]{12,13}", project_number):
        raise Rejected("explicit project number required")
    principal = quote(f"service-{project_number}@gcp-sa-pubsub.iam.gserviceaccount.com", safe="")
    return [dict(id="identity", method="GET", url=f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJECT}", readOnly=True),
            dict(id="project-iam", method="POST", url=f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getIamPolicy",
                 requestBody='{"options":{"requestedPolicyVersion":3}}', readOnly=True),
            dict(id="pubsub-service-identity", method="GET",
                 url=f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts/{principal}", readOnly=True)]


def safe_environment():
    env = dict(os.environ)
    for key in ("NODE_OPTIONS", "NODE_PATH", "CLOUDSDK_CONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME",
                "GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN", "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
                "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"):
        if env.get(key):
            raise Rejected("credential or runtime override forbidden")
    env.update(CLOUDSDK_CORE_DISABLE_PROMPTS="true", CLOUDSDK_CORE_DISABLE_USAGE_REPORTING="true")
    return env


def receipts(directory, requests):
    path = directory / "requests.jsonl"
    if not path.exists():
        return dict(attempted=0, completed=0, unknown=0)
    if path.is_symlink() or path.stat().st_size > 100000:
        raise Rejected("bounded regular receipt journal required")
    before, headers, after = [], {}, set()
    expected = {request["id"]: request for request in requests}
    for line in path.read_text().splitlines():
        row = json.loads(line)
        key = row["id"]
        if key not in expected:
            raise Rejected("unexpected receipt")
        state = row["state"]
        if state == "before-send":
            if len(before) >= CAP or key != requests[len(before)]["id"] or any(row.get(k) != v for k, v in expected[key].items()):
                raise Rejected("duplicate, out-of-order or changed request")
            before.append(key)
        elif state == "response-headers":
            if key not in before or key in headers or key in after or type(row.get("status")) is not int:
                raise Rejected("invalid header receipt")
            header_pairs = row.get("headers")
            if not isinstance(header_pairs, list) or any(not isinstance(pair, list) or len(pair) != 2 or any(not isinstance(value, str) for value in pair) for pair in header_pairs):
                raise Rejected("invalid raw header pairs")
            if sum(len(value.encode()) for pair in header_pairs for value in pair) > 16384:
                raise Rejected("raw header bound exceeded")
            headers[key] = dict(status=row["status"], headers=header_pairs)
        elif state == "response-persisted":
            if key not in headers or key in after or row.get("status") != headers[key]["status"]:
                raise Rejected("invalid response sequence")
            raw_path = directory / (key + ".json")
            if raw_path.is_symlink() or raw_path.stat().st_size > 3000000:
                raise Rejected("bounded regular raw receipt required")
            raw = json.loads(raw_path.read_text())
            payload = base64.b64decode(raw["bodyBase64"], validate=True)
            digest = hashlib.sha256(payload).hexdigest()
            if (len(payload) > 1048576 or base64.b64encode(payload).decode() != raw["bodyBase64"]
                or raw["body"] != payload.decode("utf8", errors="replace")
                or any(raw.get(k) != v for k, v in expected[key].items())
                or raw.get("state") != state or raw.get("status") != headers[key]["status"]
                or raw.get("headers") != headers[key]["headers"]
                or raw.get("bodySha256") != digest or row.get("bodySha256") != digest
                or raw.get("bodyBytes") != len(payload) or row.get("bodyBytes") != len(payload)):
                raise Rejected("raw response integrity mismatch")
            after.add(key)
        else:
            raise Rejected("unknown receipt state")
    return dict(attempted=len(before), completed=len(after), unknown=len(before) - len(after))


def execute(*, root, worktree, manifest, packet_sha, manifest_sha, locks, authority_input,
            check_authority, command=run_owned, append=append_ledger,
            now=lambda: dt.datetime.now(dt.timezone.utc), monotonic=time.monotonic):
    requests = baseline_requests(manifest["projectNumber"])
    if manifest["requests"] != requests or not re.fullmatch(r"[a-f0-9]{32}", manifest["runId"]):
        raise Rejected("fixed read-only requests and fresh run required")
    started = monotonic()
    ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
    directory = root / "docs.local/runs/codex-lane7" / ("fixture-baseline-002-" + manifest["runId"])
    reserved, terminal, retain = False, False, False
    credential_attempts, child_started, quiescent = 0, False, True
    def admit():
        remaining = 600 - (monotonic() - started)
        if remaining <= 10:
            raise Rejected("wall budget exhausted before live authority")
        check_authority(timeout=min(10, remaining - 5))
    common = dict(taskId=TASK, project=PROJECT, runDir=str(directory), runId=manifest["runId"],
        packetId="fixture-baseline-002", envelopeId=ENVELOPE, packetSha256=packet_sha,
        corpusDigest=manifest_sha, sourceCommit=manifest["sourceCommit"], estimatedUsd=RESERVE)
    locks.acquire()
    try:
        if directory.exists() or directory.is_symlink():
            raise Rejected("fresh run directory required")
        admit()
        check_ledger([json.loads(line) for line in ledger.read_text().splitlines() if line.strip()],
                     now(), packet_sha, task=TASK, reserve=RESERVE)
        append(ledger, {**common, "ts": now().isoformat(), "event": "reserved", "maxRequests": CAP,
                       "maxCredentialCliAttempts": 1, "writes": "none"})
        reserved = True
        result = dict(outcome="exploration-incomplete-read-only-baseline", attempted=0, completed=0, unknown=0, mutationAttempts=0)
        try:
            env = safe_environment()
            remaining = 600 - (monotonic() - started)
            if remaining <= 10:
                raise Rejected("wall budget exhausted before credential")
            admit()
            remaining = 600 - (monotonic() - started)
            if remaining <= 10:
                raise Rejected("wall budget exhausted after credential authority")
            credential_attempts = 1
            locks.mark_sent(mutation=False)
            quiescent = False
            token_result = command(["gcloud", "auth", "application-default", "print-access-token"],
                timeout=min(60, remaining - 5), env=env, policy="credential-wrapper")
            quiescent = token_result.processQuiescent is True and token_result.directChildReaped is True
            token = token_result.stdout.strip()
            if not quiescent or token_result.returncode != 0 or not token or len(token) > 16384 or any(ch.isspace() for ch in token):
                raise Rejected("credential command did not finish safely")
            admit()
            remaining = 600 - (monotonic() - started)
            if remaining <= 10:
                raise Rejected("wall budget exhausted before collector")
            child_started, quiescent = True, False
            child = command([manifest["nodeExecutable"], str(worktree / "conformance/pubsub-production/baseline-capture.mjs")],
                input=json.dumps(dict(root=str(root), projectNumber=manifest["projectNumber"],
                    runId=manifest["runId"], accessToken=token, authority=authority_input)),
                timeout=remaining - 5, env=env)
            quiescent = child.processQuiescent is True and child.directChildReaped is True
            if not quiescent:
                raise Rejected("collector quiescence not verified")
            counts = receipts(directory, requests)
            result.update(counts)
            summary = json.loads((directory / "summary.json").read_text())
            if any(summary.get(k) != v for k, v in counts.items()):
                raise Rejected("summary disagrees with durable raw receipts")
            if child.returncode == 0 and counts == dict(attempted=3, completed=3, unknown=0) and summary.get("outcome") == "captured-read-only-baseline" and not summary.get("terminationRequired"):
                result["outcome"] = "exploration-recorded-read-only-baseline"
        except (Exception, KeyboardInterrupt) as error:
            if isinstance(error, ProcessStopped):
                quiescent = error.quiescent and error.reaped
                retain = not quiescent or error.unexpected_descendant
                result["stopReason"] = error.reason
            if child_started:
                if quiescent:
                    try:
                        result.update(receipts(directory, requests))
                    except Exception:
                        result.update(attempted=CAP, completed=0, unknown=CAP)
                else:
                    result.update(attempted=CAP, completed=0, unknown=CAP)
        retain = retain or not quiescent
        result.update(processQuiescent=quiescent, sandboxAtBaseline=quiescent and not retain,
            credentialCliAttempts=credential_attempts,
            credentialHttpRequests="opaque-cli-managed" if credential_attempts else 0)
        if retain:
            result["outcome"] = "needs-recovery"
        append(ledger, {**common, "ts": now().isoformat(), "event": "finished", **result})
        terminal = True
        return result
    except ProcessStopped as error:
        retain = not (error.quiescent and error.reaped) or error.unexpected_descendant
        if retain and not reserved:
            append(ledger, {**common, "ts": now().isoformat(), "event": "finished",
                "outcome": "needs-recovery", "phase": "pre-reservation-authority", "localOnly": True,
                "attempted": 0, "completed": 0, "unknown": 0, "mutationAttempts": 0,
                "credentialCliAttempts": 0, "processQuiescent": error.quiescent,
                "directChildReaped": error.reaped, "sandboxAtBaseline": False})
            terminal = True
        raise
    finally:
        locks.close(success=terminal and not retain, retain=retain or reserved and not terminal)


def private_file(root, path):
    if path.is_symlink() or not path.resolve().is_relative_to(root / "docs.local") or not path.is_file():
        raise Rejected("private regular file required")
    return path


def pinned_node(manifest):
    path = Path(manifest["nodeExecutable"])
    if (not path.is_absolute() or path.is_symlink() or path.resolve() != path
        or not path.is_file() or not os.access(path, os.X_OK)
        or sha(path) != manifest["nodeExecutableSha256"]):
        raise Rejected("canonical reviewed real Node binary required")
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approval-line", type=int, default=0)
    parser.add_argument("--go", default="")
    args = parser.parse_args()
    worktree = Path(__file__).resolve().parents[2]
    env = safe_environment()
    common = Path(subprocess.check_output(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=worktree, text=True, timeout=10).strip())
    root = common.parent
    private_file(root, args.manifest)
    private_file(root, args.packet)
    manifest = json.loads(args.manifest.read_text())
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=worktree, text=True, timeout=10).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=worktree, text=True, timeout=10)
    if head != manifest["sourceCommit"] or dirty or manifest["sender"] != "coordinator" or manifest["project"] != PROJECT:
        raise Rejected("clean reviewed source and fixed project required")
    source_paths = {"conformance/pubsub-production/" + name for name in
        ("baseline_execute.py", "baseline_process.py", "baseline-capture.mjs", "fixture-baseline.mjs",
         "baseline-authority.mjs", "execute.py", "capture.mjs", "preflight.mjs", "ledger-revocation.mjs")}
    if {entry["path"] for entry in manifest["sources"]} != source_paths or len(manifest["sources"]) != len(source_paths):
        raise Rejected("all executable dependencies must be bound")
    for entry in manifest["sources"]:
        path = worktree / entry["path"]
        if path.is_symlink() or sha(path) != entry["sha256"]:
            raise Rejected("reviewed source hash mismatch")
    node = pinned_node(manifest)
    requests = baseline_requests(manifest["projectNumber"])
    node_requests = json.loads(subprocess.check_output([node, "--input-type=module", "-e",
        "import {baselineRequests} from './conformance/pubsub-production/fixture-baseline.mjs'; process.stdout.write(JSON.stringify(baselineRequests(process.argv[1])))",
        manifest["projectNumber"]], cwd=worktree, text=True, timeout=10, env=env))
    if requests != node_requests or manifest["requests"] != requests or manifest["bounds"] != dict(maxResourceRequests=3, maxCredentialCliInvocations=1, maxWallSeconds=600, reserveUsd=RESERVE, taskCapUsd=10):
        raise Rejected("fixed read-only request plan or bounds differ")
    manifest_sha, packet_sha = sha(args.manifest), sha(args.packet)
    packet = args.packet.read_text()
    if manifest_sha not in packet or head not in packet:
        raise Rejected("packet must bind manifest and source")
    helper = private_file(root, root / LOCK_HELPER)
    helper_source = helper.read_bytes()
    if hashlib.sha256(helper_source).hexdigest() != manifest["lockHelperSha256"]:
        raise Rejected("reviewed lock helper mismatch")
    if not args.execute:
        print(json.dumps(dict(outcome="offline-source-check", productionRequests=0, credentialCliAttempts=0)))
        return
    if args.go != packet_sha:
        raise Rejected("exact coordinator go required")
    authority_input = dict(decisionLine=args.approval_line, envelopeId=ENVELOPE, subject=SUBJECT,
        maxRequests=CAP, reserveUsd=RESERVE, pins=dict(packetSha256=packet_sha, manifestSha256=manifest_sha,
            runnerSha256=sha(Path(__file__)), sourceCommit=head))
    def authority(*, timeout):
        if (root / "docs.local/runs/QUIET-WINDOW").exists():
            raise Rejected("quiet window active")
        checked = run_owned([node, str(worktree / "conformance/pubsub-production/baseline-authority.mjs")],
            input=json.dumps({**authority_input, "ledgerText": (root / "docs.local/instructions/owner-decisions.md").read_text()}),
            timeout=timeout, env=env)
        if checked.returncode != 0:
            raise Rejected("read-only baseline authority refused")
    module = verified_module("lane7_baseline_sandbox_lock", helper, manifest["lockHelperSha256"], source=helper_source)
    locks = module.ProjectLocks(root, [PROJECT], TASK, ENVELOPE, head)
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = execute(root=root, worktree=worktree, manifest=manifest, packet_sha=packet_sha,
            manifest_sha=manifest_sha, locks=locks, authority_input=authority_input, check_authority=authority)
        print(json.dumps(result))
        if result["outcome"] != "exploration-recorded-read-only-baseline":
            raise SystemExit(1)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print("Coordinator read-only baseline stopped; inspect only private receipts and ledger.", file=sys.stderr)
        raise SystemExit(1)
