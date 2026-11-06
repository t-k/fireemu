#!/usr/bin/env python3
"""Run finite Apple SDK cases against endpoints supplied by emulator exec."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CASES = [
    "firestore.write-read", "firestore.transforms", "firestore.query", "firestore.listener",
    "firestore.transaction", "firestore.offline-resume", "firestore.batch-delete",
    "firestore.rules-anonymous-denied", "firestore.rules-owner", "firestore.rules-signout",
    "auth.signup", "auth.signin", "auth.refresh", "storage.upload-download", "storage.metadata",
    "storage.resumable", "storage.download-url", "storage.list-delete", "storage.rules-denied",
    "database.set-read", "database.listener", "database.transaction", "database.on-disconnect",
]

def complete(results):
    return [r.get("case") for r in results] == CASES and all(r.get("status") == "passed" for r in results)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not already exist")
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True)
    results = []
    started = time.monotonic()
    stopping = 0

    def handle_signal(signum, frame):
        nonlocal stopping
        stopping = signum

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    for case in CASES:
        if stopping:
            return 128 + stopping
        before = time.monotonic()
        result = {"case": case, "status": "failed", "reason": "harness-no-result"}
        try:
            child = subprocess.Popen([str(binary), case], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=os.environ, start_new_session=True)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if stopping:
                        raise SystemExit(128 + stopping)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(child.args, 30)
                    try:
                        stdout, _ = child.communicate(timeout=min(0.1, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        continue
                if stopping:
                    raise SystemExit(128 + stopping)
            except BaseException:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    # Sweep the group even if its leader has already exited.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                raise
            finally:
                child.stdout.close()
                child.stderr.close()
            for line in stdout.splitlines():
                try:
                    candidate = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if isinstance(candidate, dict) and candidate.get("case") == case:
                    result = candidate
            if child.returncode != 0 and result.get("status") == "passed":
                result = {"case": case, "status": "failed", "reason": "harness-exit-mismatch"}
            result["exitCode"] = child.returncode
            # SDK logs may contain generated identities or paths. Persist fixed result fields only.
        except subprocess.TimeoutExpired:
            result = {"case": case, "status": "failed", "reason": "case-deadline"}
        result["wallSeconds"] = round(time.monotonic() - before, 3)
        results.append(result)
        with (args.output / "cases.jsonl").open("a") as output:
            output.write(json.dumps(result, sort_keys=True) + "\n")
        print(json.dumps(result, sort_keys=True), flush=True)
    summary = {"cases": results, "seconds": round(time.monotonic() - started, 3), "passed": complete(results)}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return (128 + stopping) if stopping else (0 if summary["passed"] else 1)

if __name__ == "__main__":
    sys.exit(main())
