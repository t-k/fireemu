#!/usr/bin/env python3
"""Run every required Kani proof and reject incomplete or unsuccessful execution."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
KANI_VERSION = "0.67.0"
PROOF_TIMEOUT = 3600
EXPECTED_HARNESSES = tuple("harnesses::" + name for name in (
    "limit_boundary_classification",
    "severity_is_monotone",
    "epoch_guard_rejects_every_other_epoch",
    "virtual_clock_never_moves_backwards",
    "idle_predicate_never_ignores_active_work",
    "terminal_event_rejects_every_transition",
    "boundary_reject_precedes_warning",
    "totp_window_boundary",
    "production_index_never_false_accepts",
))

EXPECTED_COVERS = {
    "harnesses::limit_boundary_classification": 1,
    "harnesses::totp_window_boundary": 3,
    "harnesses::production_index_never_false_accepts": 3,
}

def discover_harnesses():
    """Reject proof inventory changes until the execution contract is updated."""
    source = (ROOT / "verification/kani/src/lib.rs").read_text()
    return tuple("harnesses::" + name for name in re.findall(
        r"#\[kani::proof\]\s*(?:#\[[^\]]+\]\s*)*fn\s+(\w+)\s*\(", source
    ))


def validate_output(output):
    """Validate the pinned Kani0.67 terse format, including each actual proof."""
    summary = re.findall(r"^Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.$", output, re.M)
    count = len(EXPECTED_HARNESSES)
    if summary != [(str(count), "0", str(count))] or output.count("Manual Harness Summary:") != 1:
        raise ValueError("incomplete or unsuccessful proof summary")
    proof_output, trailer = output.split("Manual Harness Summary:", 1)
    blocks = re.split(r"^Checking harness ([^\n]+)\.\.\.\s*$", proof_output, flags=re.M)
    names = blocks[1::2]
    if len(names) != count or set(names) != set(EXPECTED_HARNESSES):
        raise ValueError("actual proof identities differ from the execution contract")
    if "cover properties" in blocks[0] or "cover properties" in trailer:
        raise ValueError("cover summary outside a proof result")
    for name, block in zip(names, blocks[2::2]):
        if re.findall(r"^VERIFICATION:- (\S+)$", block, re.M) != ["SUCCESSFUL"]:
            raise ValueError("a proof did not succeed")
        checks = re.findall(r"^ \*\* (\d+) of (\d+) failed(?: \([^\n]*\))?$", block, re.M)
        if len(checks) != 1 or checks[0][0] != "0" or int(checks[0][1]) < 1:
            raise ValueError("missing or failed verification checks")
        count = EXPECTED_COVERS.get(name, 0)
        expected = [f" ** {count} of {count} cover properties satisfied"] if count else []
        covers = [line for line in block.splitlines() if "cover properties" in line]
        if covers != expected:
            raise ValueError(f"missing, incomplete or unexpected cover summary: {name}")


def run_command(command, timeout, capture_output=False):
    """Bound execution and clean only the process group created for this command."""
    process = subprocess.Popen(command, cwd=ROOT, start_new_session=True, text=True,
                               stdout=subprocess.PIPE if capture_output else None,
                               stderr=subprocess.PIPE if capture_output else None)
    stdout = stderr = None
    primary_error = None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = []
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                deadline = time.monotonic() + 0.3
                while time.monotonic() < deadline:
                    process.poll()
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                cleanup_errors.append(error)
            try:
                process.communicate(timeout=2)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(error)
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(error)
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError as error:
                        cleanup_errors.append(error)
            if cleanup_errors:
                for error in cleanup_errors:
                    print(f"Kani cleanup UNCONFIRMED: {error}", file=sys.stderr)
                failure = primary_error if primary_error is not None else cleanup_errors[0]
                failure.cleanup_errors = tuple(cleanup_errors)
                if primary_error is None:
                    failure.stdout, failure.stderr = stdout, stderr
                    raise failure
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except KeyboardInterrupt:
                if primary_error is None:
                    raise


def execute(receipt_path=None):
    """Run every proof without filters and publish provenance only after success."""
    if receipt_path is not None and receipt_path.exists():
        raise FileExistsError("refusing to overwrite an existing receipt")
    discovered = discover_harnesses()
    if set(discovered) != set(EXPECTED_HARNESSES) or len(discovered) != len(EXPECTED_HARNESSES):
        raise ValueError("source proof inventory differs from the execution contract")
    source_digest = hashlib.sha256((ROOT / "verification/kani/src/lib.rs").read_bytes()).hexdigest()
    version = run_command(["cargo", "kani", "--version"], capture_output=True, timeout=30)
    if version.stdout.strip() != f"cargo-kani {KANI_VERSION}":
        raise ValueError(f"required Kani version is {KANI_VERSION}")
    result = run_command([
        "cargo", "kani", "-p", "fireemu-verification-kani", "--output-format", "terse",
        "-Z", "unstable-options", "--harness-timeout", "300s",
    ], capture_output=True, timeout=PROOF_TIMEOUT)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    validate_output(result.stdout)
    if source_digest != hashlib.sha256((ROOT / "verification/kani/src/lib.rs").read_bytes()).hexdigest():
        raise ValueError("proof source changed during verification")
    if receipt_path is not None:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with receipt_path.open("x") as stream:
            json.dump({"producer": "fireemu-kani-runner", "kani_version": KANI_VERSION,
                       "harnesses": list(EXPECTED_HARNESSES), "source_sha256": source_digest,
                       "output_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}, stream, indent=2)
            stream.write("\n")


def interrupt(_signal, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, help="new runner provenance JSON path; must not exist")
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        execute(args.receipt.resolve() if args.receipt else None)
    except KeyboardInterrupt:
        print("Kani verification interrupted", file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        for stream, output in ((sys.stdout, getattr(error, "stdout", None)),
                               (sys.stderr, getattr(error, "stderr", None))):
            if output:
                print(output.decode(errors="replace") if isinstance(output, bytes) else output,
                      end="", file=stream)
        print(f"Kani verification failed: {error}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(f"Kani verified all {len(EXPECTED_HARNESSES)} required proofs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
