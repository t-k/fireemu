#!/usr/bin/env python3
"""Run finite Apple SDK cases against endpoints supplied by emulator exec."""
import argparse
import json
import os
from pathlib import Path
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
    for case in CASES:
        before = time.monotonic()
        result = {"case": case, "status": "failed", "reason": "harness-no-result"}
        try:
            child = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=30, env=os.environ)
            for line in child.stdout.splitlines():
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
    return 0 if summary["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
