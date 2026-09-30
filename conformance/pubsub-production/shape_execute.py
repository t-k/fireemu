"""Coordinator-only bounded Pub/Sub shape capture; never invoked by a lane."""
import argparse
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

# Reuse the reviewed ledger, durability and project-lock contracts without accepting stale pyc.
_COMMON = Path(__file__).with_name("execute.py")
_spec = importlib.util.spec_from_file_location("lane7_reviewed_common", _COMMON)
_common = importlib.util.module_from_spec(_spec)
exec(compile(_COMMON.read_bytes(), str(_COMMON), "exec"), _common.__dict__)
Rejected, check_ledger, append_ledger, sha = _common.Rejected, _common.check_ledger, _common.append_ledger, _common.sha
PROJECT, LOCK_HELPER = _common.PROJECT, _common.LOCK_HELPER
TASK = "PUBSUB-EVENTARC-SHAPE"
ENVELOPE = "PUBSUB-EVENTARC-shape-001"
SUBJECT = "PUBSUB-EVENTARC shape-001"
RESERVE = 0.02
CAP = 16


def safe_environment():
    env = dict(os.environ)
    for key in ("NODE_OPTIONS", "NODE_PATH", "CLOUDSDK_CONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME",
                "GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN", "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
                "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"):
        if env.get(key):
            raise Rejected("credential or runtime override forbidden")
    env.update(CLOUDSDK_CORE_DISABLE_PROMPTS="true", CLOUDSDK_CORE_DISABLE_USAGE_REPORTING="true")
    return env


def run_child(argv, *, input=None, timeout, env, **_):
    child = subprocess.Popen(argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        stdout, stderr = child.communicate(input=input, timeout=timeout)
        return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
    except BaseException:
        # Kill this exact child and reap it; do not leave credential or capture processes behind.
        child.kill()
        child.wait()
        raise


def receipts(directory, requests):
    before, headers, after = set(), {}, set()
    expected = {request["id"]: request for request in requests}
    mutation = set()
    path = directory / "requests.jsonl"
    if path.exists():
        for line in path.read_text().splitlines():
            row = json.loads(line)
            key = row["id"]
            if key not in expected:
                raise Rejected("unexpected request receipt")
            state = row["state"]
            if state == "before-send":
                request = expected[key]
                if key in before or any(row.get(field) != value for field, value in request.items()):
                    raise Rejected("duplicate or changed request")
                before.add(key)
                if request["method"] != "GET":
                    mutation.add(key)
                if request["method"] == "PUT" and row.get("ownership") != "fresh-absent-before-create":
                    raise Rejected("create lacks ownership intent")
            elif state == "response-headers":
                if key not in before or key in headers or key in after or not isinstance(row.get("status"), int):
                    raise Rejected("invalid response header sequence")
                headers[key] = row["status"]
            elif state == "response-persisted":
                if key not in headers or key in after:
                    raise Rejected("invalid response persistence sequence")
                after.add(key)
            else:
                raise Rejected("unknown receipt state")
    if len(before) > CAP:
        raise Rejected("resource request cap exceeded")
    collision = any(status == 409 and expected[key]["method"] == "PUT" for key, status in headers.items())
    return dict(attempted=len(before), completed=len(after), unknown=len(before - after),
                mutationAttempts=len(mutation)), collision


def execute(*, root, worktree, manifest, baseline, packet_sha, manifest_sha, locks,
            authority_input, check_authority, command=run_child, append=append_ledger,
            now=lambda: dt.datetime.now(dt.timezone.utc), monotonic=time.monotonic):
    ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
    directory = root / "docs.local/runs/codex-lane7" / ("shape-001-" + manifest["runId"])
    started = monotonic()
    locks.acquire()
    reserved, terminal, retain = False, False, False
    credential_attempts, child_started = 0, False
    try:
        if directory.exists():
            raise Rejected("fresh run directory required")
        check_authority()
        check_ledger([json.loads(line) for line in ledger.read_text().splitlines() if line.strip()],
            now(), packet_sha, task=TASK, reserve=RESERVE)
        common = dict(taskId=TASK, project=PROJECT, runDir=str(directory), runId=manifest["runId"],
            packetId="shape-001", envelopeId=ENVELOPE, packetSha256=packet_sha, corpusDigest=manifest_sha,
            sourceCommit=manifest["sourceCommit"], estimatedUsd=RESERVE)
        append(ledger, {**common, "ts": now().isoformat(), "event": "reserved", "maxRequests": CAP,
                       "maxCredentialCliAttempts": 1})
        reserved = True
        result = dict(outcome="exploration-inconclusive", sandboxAtBaseline=True,
            attempted=0, completed=0, unknown=0, mutationAttempts=0)
        try:
            env = safe_environment()
            remaining = 600 - (monotonic() - started)
            if remaining <= 0:
                raise Rejected("wall budget expired")
            credential_attempts = 1
            locks.mark_sent(mutation=False)
            token_result = command(["gcloud", "auth", "application-default", "print-access-token"],
                capture_output=True, text=True, timeout=min(60, remaining), check=False, env=env)
            token = token_result.stdout.strip()
            if token_result.returncode != 0 or not token or len(token) > 16384 or any(ch.isspace() for ch in token):
                raise Rejected("credential command failed")
            check_authority()
            remaining = 600 - (monotonic() - started)
            if remaining <= 0:
                raise Rejected("wall budget expired")
            # A crashed child may have mutated: retain until a durable clean terminal proves otherwise.
            child_started = True
            locks.mark_sent(mutation=True)
            child = command(["node", str(worktree / "conformance/pubsub-production/shape-capture.mjs"), str(directory)],
                input=json.dumps(dict(accessToken=token, runId=manifest["runId"], baseline=baseline,
                    authority=authority_input, ownerLedgerPath=str(root / "docs.local/instructions/owner-decisions.md"),
                    quietPath=str(root / "docs.local/runs/QUIET-WINDOW"))),
                capture_output=True, text=True, timeout=remaining, check=False, env=env)
            counts, collision = receipts(directory, manifest["requests"])
            result.update(counts)
            summary = json.loads((directory / "summary.json").read_text())
            if collision or summary.get("runId") != manifest["runId"] or any(summary.get(k) != v for k, v in counts.items()):
                raise Rejected("capture summary disagrees with durable receipts")
            if summary.get("sandboxAtBaseline") is not True or summary.get("outcome") not in ("exploration-recorded", "exploration-inconclusive"):
                raise Rejected("baseline not proved")
            if summary["outcome"] == "exploration-recorded" and (child.returncode != 0 or counts != dict(attempted=16, completed=16, unknown=0, mutationAttempts=4)):
                raise Rejected("complete shape recording not proved")
            result.update(outcome=summary["outcome"], sandboxAtBaseline=True)
        except (Exception, KeyboardInterrupt):
            if child_started:
                result.update(outcome="needs-recovery", sandboxAtBaseline=False)
                try:
                    counts, _ = receipts(directory, manifest["requests"])
                    result.update(counts)
                except Exception:
                    result.update(attempted=CAP, completed=0, unknown=CAP, mutationAttempts=4)
        result.update(credentialCliAttempts=credential_attempts,
            credentialHttpRequests="opaque-cli-managed" if credential_attempts else 0)
        retain = not result["sandboxAtBaseline"]
        append(ledger, {**common, "ts": now().isoformat(), "event": "finished", **result})
        terminal = True
        return result
    finally:
        locks.close(success=terminal and not retain, retain=retain or reserved and not terminal)


def private_file(root, path):
    if path.is_symlink() or not path.resolve().is_relative_to(root / "docs.local") or not path.is_file():
        raise Rejected("private regular file required")
    return path


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
    common = Path(subprocess.check_output(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=worktree, text=True).strip())
    root = common.parent
    private_file(root, args.manifest)
    private_file(root, args.packet)
    manifest = json.loads(args.manifest.read_text())
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=worktree, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=worktree, text=True)
    if head != manifest["sourceCommit"] or dirty or manifest["sender"] != "coordinator" or manifest["project"] != PROJECT:
        raise Rejected("clean reviewed source and fixed project required")
    if not re.fullmatch(r"[a-f0-9]{32}", manifest["runId"]):
        raise Rejected("fresh run id required")
    source_paths = {"conformance/pubsub-production/" + name for name in
        ("shape_execute.py", "execute.py", "shape-capture.mjs", "capture.mjs", "preflight.mjs", "authority-check.mjs", "ledger-revocation.mjs")}
    if {entry["path"] for entry in manifest["sources"]} != source_paths or len(manifest["sources"]) != len(source_paths):
        raise Rejected("all executable source dependencies must be bound")
    for entry in manifest["sources"]:
        path = worktree / entry["path"]
        if path.is_symlink() or sha(path) != entry["sha256"]:
            raise Rejected("reviewed source hash mismatch")
    requests = json.loads(subprocess.check_output(["node", "--input-type=module", "-e",
        "import {shapeRequests} from './conformance/pubsub-production/shape-capture.mjs'; process.stdout.write(JSON.stringify(shapeRequests(process.argv[1])))",
        manifest["runId"]], cwd=worktree, text=True, timeout=10, env=env))
    if requests != manifest["requests"] or manifest["bounds"] != dict(maxResourceRequests=16, maxCredentialCliInvocations=1, maxWallSeconds=600, reserveUsd=RESERVE, taskCapUsd=10):
        raise Rejected("fixed request plan or bounds differ")
    baseline = {}
    for kind, entry in manifest["baseline"].items():
        if kind not in ("topics", "subscriptions"):
            raise Rejected("unexpected baseline")
        path = private_file(root, root / entry["path"])
        if sha(path) != entry["sha256"]:
            raise Rejected("recorded baseline hash mismatch")
        row = json.loads(path.read_text())
        if row["status"] != 200 or json.loads(row["body"]) != {}:
            raise Rejected("recorded empty baseline required")
        baseline[kind] = dict(status=row["status"], body=row["body"])
    if set(baseline) != {"topics", "subscriptions"}:
        raise Rejected("both recorded lists required")
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
        maxRequests=CAP, reserveUsd=RESERVE,
        pins=dict(packetSha256=packet_sha, manifestSha256=manifest_sha,
                  runnerSha256=sha(Path(__file__)), sourceCommit=head))
    def authority():
        if (root / "docs.local/runs/QUIET-WINDOW").exists():
            raise Rejected("quiet window active")
        checked = run_child(["node", str(worktree / "conformance/pubsub-production/authority-check.mjs")],
            input=json.dumps({**authority_input, "ledgerText": (root / "docs.local/instructions/owner-decisions.md").read_text()}),
            timeout=10, env=env)
        if checked.returncode != 0:
            raise Rejected("writer authority refused")
    spec = importlib.util.spec_from_file_location("reviewed_sandbox_lock", helper)
    module = importlib.util.module_from_spec(spec)
    exec(compile(helper_source, str(helper), "exec"), module.__dict__)
    locks = module.ProjectLocks(root, [PROJECT], TASK, ENVELOPE, head)
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = execute(root=root, worktree=worktree, manifest=manifest, baseline=baseline,
            packet_sha=packet_sha, manifest_sha=manifest_sha, locks=locks,
            authority_input=authority_input, check_authority=authority)
        print(json.dumps(result))
        if result["outcome"] != "exploration-recorded":
            raise SystemExit(1)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print("Coordinator shape capture stopped; inspect only private receipts and ledger.", file=sys.stderr)
        raise SystemExit(1)
