"""Replay the Txn-04 campaign on a binary built from this checkout, in both profiles, and judge it against the committed production projection.

The committed record (`fs-transaction-expiry-retry-04-recorded-comparison-v1.json`) binds both production recordings (sha256), their projection and post states
(projectionDigest, postStateDigest) and the comparison rules (the three strict cases superseded by P10-C). Its `artifact` and `profiles` blocks name the binary
of the last local regeneration; they are history. Whether the binary of the current commit still answers as production recorded is decided here, on every
commit in CI, by the same projection functions and the same rules publish.py applied:

- emulator: every case and every post state equals production;
- strict: every case and post state outside the superseded cases equals production, and `idle-expiry/commit-after-idle` still differs.

    python txn04_current_replay.py --binary target/debug/fireemu --dep-info target/debug/fireemu.d --out <new directory>

Local only: the shadow runs the binary on loopback with the control clock, and no production request is made.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(HERE), str(HERE.parent), str(ROOT / "tools/compat-inventory")]
import txn_expiry_comparison as comparison  # noqa: E402
from broad_contract import digest  # noqa: E402
from evidence_common import binary_inputs, dependency_info_in_test_only_trees, dependency_info_paths, ui_bundled  # noqa: E402

RECORD = ROOT / "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json"
RELEASE_INPUTS = ROOT / "spec/compatibility/broad-runs/fs-transaction-release-replay-inputs-v1.json"
PROFILES = ("strict", "emulator")
#: The superseded difference publish.py required of strict: production aborted the commit after a 120.3 s idle, while the case table's 90 s wait stays
#: under strict's 120 s limit, so strict commits.
REQUIRED_STRICT_DIFFERENCE = "idle-expiry/commit-after-idle"
PYTHON = "3.12.13"
CASE_COUNT = 13
OWNED_DOCUMENTS = 5


def expectations(record, release_inputs):
    """The production projection, post states and superseded cases, after checking them against the record's own digests and the release replay inputs."""
    projection = {row["caseId"]: {key: value for key, value in row.items() if key != "caseId"} for row in record["cases"]}
    post_states = record["postStates"]
    if len(projection) != len(record["cases"]) or len(projection) != CASE_COUNT:
        raise ValueError("the record's case inventory differs")
    recordings = record["recordings"]
    if len(recordings) != 2:
        raise ValueError("the record must bind two recordings")
    for row in recordings:
        if row["projectionDigest"] != digest(projection):
            raise ValueError("the record's projection digest differs from its cases")
        if row["postStateDigest"] != digest(post_states):
            raise ValueError("the record's post-state digest differs from its post states")
    shas = [row["reference"]["sha256"] for row in recordings]
    released = release_inputs["special"]["e04"]["recordings"]
    if [entry["originSha256"] for entry in released] != shas or any(
        entry["projection"]["projection"] != projection or entry["projection"]["postStates"] != post_states for entry in released
    ):
        raise ValueError("the release replay inputs disagree with the record")
    superseded = set(record["supersededForStrict"]["cases"])
    if not superseded <= set(projection) or REQUIRED_STRICT_DIFFERENCE not in superseded:
        raise ValueError("the superseded strict cases differ")
    return {"projection": projection, "postStates": post_states, "superseded": superseded, "recordingSha256": shas}


def _differences(expected, local):
    keys = {}
    for case in sorted(set(expected["projection"]) | set(local["projection"])):
        if expected["projection"].get(case) != local["projection"].get(case):
            keys[case] = case
    for case in sorted(set(expected["postStates"]) | set(local["postStates"])):
        if expected["postStates"].get(case) != local["postStates"].get(case):
            keys[case + comparison.POST_STATE] = case
    return keys


def judge_profile(profile, expected, local):
    """Problems of one profile's local answers against production; empty means the profile answers as recorded."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    problems = []
    if sorted(local["projection"]) != sorted(expected["projection"]):
        problems.append(f"{profile}: the case inventory differs from production")
    differences = _differences(expected, local)
    if profile == "emulator":
        problems += [f"emulator: {key} differs from production" for key in differences]
        return problems
    problems += [f"strict: {key} differs from production" for key, case in differences.items() if case not in expected["superseded"]]
    if REQUIRED_STRICT_DIFFERENCE not in differences:
        problems.append(f"strict: {REQUIRED_STRICT_DIFFERENCE} no longer differs from production; the superseded declaration needs review")
    return problems


def receipt_problems(acquired, *, record, binary_sha, head, inputs_digest):
    """Every obligation recorded_local.py put on a shadow run, bound to this binary and this commit instead of a stored build receipt."""
    problems = []

    def need(condition, message):
        if not condition:
            problems.append(message)

    # The shadow's own `complete` also requires its frozen preproduction self-contract to MATCH; that table is history, and recorded_local.py and publish.py
    # required it to stay SEMANTIC_MISMATCH while production decides the comparison. The other conditions of `complete` are checked one by one here.
    need((acquired.get("selfContract") or {}).get("classification") == comparison.SEMANTIC_MISMATCH, "the historical self-contract is not the recorded SEMANTIC_MISMATCH")
    need((acquired.get("publication") or {}).get("failures") == [], "the shadow reported publication failures")
    need(acquired.get("child") == {"exitCode": 0, "signal": None, "stopped": True}, "the emulator child did not stop cleanly")
    need(acquired.get("sourceDigestBefore") == acquired.get("sourceDigestAfter") == record["sourceDigest"], "the campaign source differs from the record")
    need(acquired.get("casesDigest") == record["casesDigest"], "the case table differs from the record")
    runtime = acquired.get("runtime") or {}
    need(runtime.get("artifactSha256") == runtime.get("childObservedArtifactSha256") == binary_sha, "the replayed binary is not the built one")
    need(runtime.get("sourceCommit") == head, "the replay is not bound to this commit")
    need(runtime.get("runtimeInputsDigest") == inputs_digest and runtime.get("runtimeInputsClean") is True, "the binary inputs are not this checkout's clean inputs")
    need(runtime.get("wrongControlTokenStatus") == 403, "the control endpoint accepted a wrong token")
    need((runtime.get("pythonRuntime") or {}).get("pythonVersion") == PYTHON == (runtime.get("childPythonRuntime") or {}).get("pythonVersion"), "the Python runtime differs")
    receipt = acquired.get("receipt")
    if not isinstance(receipt, dict):
        problems.append("the shadow produced no receipt")
        return problems
    need(receipt.get("complete") is True, "the receipt is not complete")
    need(receipt.get("sourceDigest") == record["sourceDigest"], "the receipt's source digest differs from the record")
    need(receipt.get("target") == "local" and receipt.get("timing") == "control-clock", "the receipt is not a local control-clock run")
    case_ids = [row["caseId"] for row in receipt.get("rows", []) if row.get("caseId")]
    need(len(case_ids) == len(set(case_ids)) == CASE_COUNT and set(case_ids) == {row["caseId"] for row in record["cases"]}, "the receipt's cases differ")
    for key in ("unrecovered", "openTransactions", "unconfirmedTransactionStarts", "responsibility"):
        need(receipt.get(key) == [], f"the receipt leaves {key}")
    need(all(item.get("released") is True for item in receipt.get("transactionReleases", [])), "a transaction was not released")
    cleanup = receipt.get("cleanup", [])
    need(len(cleanup) == OWNED_DOCUMENTS and all(item.get("complete") is True and item.get("absent") is True for item in cleanup), "the owned documents were not cleaned up")
    return problems


def dependency_info_problems(info, root):
    """The build must have read this checkout's sources (more than 100 files) and nothing in a test-only tree, so `binary_inputs` describes it."""
    problems = []
    if len(dependency_info_paths(info, root)) <= 100:
        problems.append("the dependency info lists too few files of this checkout")
    excluded = dependency_info_in_test_only_trees(info, root)
    if excluded:
        problems.append(f"the build read test-only files: {excluded}")
    return problems


def _replay(profile, binary, out):
    import txn_expiry_shadow as shadow

    shadow.runtime_inputs = binary_inputs   # as recorded_local.py: the shadow binds the binary-v1 input set
    shadow.CONFIG = {**shadow.CONFIG, "profile": profile}
    acquired = shadow.run_shadow(binary, out / profile)
    receipt = acquired.get("receipt")
    reasons = []
    if isinstance(receipt, dict):
        reasons = comparison._reasons(receipt, "local", expect_target="local") or comparison._elapsed_reasons(receipt, "local")
    local = {"projection": comparison._projection(receipt), "postStates": comparison._post_states(receipt)} if isinstance(receipt, dict) else None
    return acquired, reasons, local


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--dep-info", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="a new directory")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True)
    record = json.loads(RECORD.read_bytes())
    expected = expectations(record, json.loads(RELEASE_INPUTS.read_bytes()))
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    binary_sha = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    inputs = binary_inputs(ROOT)
    problems = dependency_info_problems(args.dep_info.read_text(), ROOT)
    if ui_bundled(ROOT):
        problems.append("ui/dist exists, so the binary embeds files outside binary_inputs")
    summary = {"kind": "fs-transaction-expiry-retry-04-current-replay-v1", "sourceCommit": head, "binarySha256": binary_sha,
               "runtimeInputsDigest": digest(inputs), "runtimeInputCount": len(inputs), "recordings": expected["recordingSha256"], "productionRequests": 0, "profiles": {}}
    for profile in PROFILES:
        acquired, reasons, local = _replay(profile, args.binary, args.out)
        found = [f"{profile}: {problem}" for problem in receipt_problems(acquired, record=record, binary_sha=binary_sha, head=head, inputs_digest=digest(inputs))]
        found += [f"{profile}: local receipt reason {reason}" for reason in reasons]
        if local is not None:
            found += judge_profile(profile, expected, local)   # already named by profile
        summary["profiles"][profile] = {"problems": found, "cases": len(local["projection"]) if local else 0}
        problems += found
    summary["problems"] = problems
    summary["ok"] = not problems
    (args.out / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
