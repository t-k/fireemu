"""Replay the 13 cases of the E04 campaign on a strict binary with the three REST idle waits at 121 s, and publish the comparison.

The campaign's table waits 90 s for its three idle observations (commit, rollback and lock release after an idle expiry); strict's idle limit is 120 s, so
that replay was superseded (see `supersededForStrict` in the 04 record). Here the same shadow and projections run from a sibling copy of this directory
(`fs-write-txn-overlay-idle`, untracked, built by this tool) whose three waits are `IDLE_SECONDS` (121 s): inside the interval production narrowed for the idle
threshold ([110.70, 122.96) s, ledger 809 (5)). Production's own idles were 120.35 to 121.15 s for the commit, 120.60 to 121.06 s for the rollback and 124.68 to
125.22 s for the lock release: 121 s is inside the first two; for the lock release it is a lower idle with the same outcome (strict refuses every idle above 120 s), a
valid sample and not the recorded idle. The local idle of each is 121 s on the emulator's control clock. Every case and post state of the replay is compared with both
production recordings by the campaign's own projections.

    python fs_txn_expiry_idle_replay.py --binary <fireemu> --commit <sha of its source> --recordings <E04 run dir> --out <record.json> [--keep <receipt dir>]
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OVERLAY = HERE.parent / "fs-write-txn-overlay-idle"
IDLE_SECONDS = 121
DECLARED_WAIT = "        elapsed=90,"
REPLAY_WAIT = f"        elapsed={IDLE_SECONDS},"
IDLE_CASES = ("idle-expiry/commit-after-idle", "idle-expiry/rollback-after-idle", "idle-expiry/lock-released-after-idle")


def replay_cases_text(text):
    """The case table with its three observation waits at the measured idle; any other shape of the table is refused."""
    if text.count(DECLARED_WAIT) != 3 or REPLAY_WAIT in text:
        raise ValueError("the case table does not have exactly three 90 s waits")
    return text.replace(DECLARED_WAIT, REPLAY_WAIT)


def tracked_overlay_paths(root):
    """The runner-built overlay copies that are tracked by git under `root` (there must be none): asked from the repository root, where the pathspec means something."""
    listed = subprocess.check_output(["git", "ls-files", "tools/compat-broad"], cwd=root, text=True).split()
    return [path for path in listed if "fs-write-txn-overlay-" in path]


def _tool_files(directory):
    return {path.name: path for path in Path(directory).iterdir() if path.is_file()}


def ensure_replay_tools(source=HERE, destination=OVERLAY):
    """The sibling copy of the tool directory with the replay table. An existing copy must be exactly what this would build: every file
    equal to the tool directory's, except the case table, which has the replay waits (bytecode caches are not compared)."""
    source, destination = Path(source), Path(destination)
    expected = replay_cases_text((source / "txn_expiry_cases.py").read_text())
    if destination.exists() and _tool_files(destination):
        have, want = _tool_files(destination), _tool_files(source)
        if sorted(have) != sorted(want):
            raise ValueError("the replay copy differs from the tool directory: its files are not the same")
        for name, path in want.items():
            current = have[name].read_text()
            if current != (expected if name == "txn_expiry_cases.py" else path.read_text()):
                raise ValueError(f"the replay copy differs from the tool directory in {name}")
        return destination
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)   # an existing directory with no files (only caches) is filled
    (destination / "txn_expiry_cases.py").write_text(expected)
    return destination


#: What the replay ran: the campaign's shadow, comparison and collector, its case table (with the replay waits) and this tool.
REPLAYED_FILES = ("txn_expiry_shadow.py", "txn_expiry_comparison.py", "txn_expiry_collector.py", "txn_expiry_cases.py", "fs_txn_expiry_idle_replay.py")


def replayed_file_digests(directory):
    files = _tool_files(directory)
    missing = [name for name in REPLAYED_FILES if name not in files]
    if missing:
        raise ValueError(f"replayed files are missing: {missing}")
    return {name: hashlib.sha256(files[name].read_bytes()).hexdigest() for name in REPLAYED_FILES}


def compare_rows(production, local):
    """Per case, its projection (code, status, message, rpc, role) and its post state, side by side; a row matches when both sides are equal."""
    if sorted(production["projection"]) != sorted(local["projection"]) or sorted(production["postStates"]) != sorted(local["postStates"]):
        raise ValueError("the case inventories differ")
    rows = []
    for case in sorted(production["projection"]):
        rows.append({"caseId": case, "production": production["projection"][case], "local": local["projection"][case], "match": production["projection"][case] == local["projection"][case]})
        if case in production["postStates"]:   # only some cases read a document back
            rows.append({"caseId": case + "#postState", "production": production["postStates"][case], "local": local["postStates"][case], "match": production["postStates"][case] == local["postStates"][case]})
    return rows


def local_idles(receipt):
    """The idle each idle-expiry step was made after, as the campaign measured it on the control clock."""
    return {row["slot"]: row["idleSeconds"] for row in receipt["rows"] if row.get("idleOfTransaction") and row.get("idleSeconds") is not None}


def build_record(*, commit, binary_sha256, recording_digests, rows_by_recording, idles, cases_blob, file_digests):
    mismatches = sum(not row["match"] for rows in rows_by_recording for row in rows)
    return {
        "schemaVersion": 1, "kind": "fs-transaction-expiry-retry-04-release-replay-v1", "parent": "FS-TRANSACTION", "campaign": "FS-TRANSACTION-EXPIRY-RETRY-04",
        "profile": "strict", "productionRequests": 0, "authorizesProduction": False,
        "artifact": {"sourceCommit": commit, "binarySha256": binary_sha256},
        "replay": {
            "tool": "tools/compat-broad/fs-write-txn/fs_txn_expiry_idle_replay.py", "idleWaitSeconds": IDLE_SECONDS, "idleCases": list(IDLE_CASES), "localIdleSeconds": idles,
            "casesFileBlob": cases_blob, "fileSha256": file_digests,
            "note": ("The campaign's case table with its three idle waits changed from 90 s to 121 s and nothing else. Each idle observation was made after the idle in localIdleSeconds on the control clock, "
                     "inside the interval [110.70, 122.96) s production narrowed for the idle threshold (ledger 809 (5)); the lock-release case idled 124.7 to 125.2 s in production, so 121 s is a lower idle there with the same outcome (strict refuses every idle above its 120 s limit): "
                     "a valid sample, not the recorded idle. The other cases are replayed unchanged."),
        },
        "recordings": [{"recording": index + 1, "productionFileSha256": digest, "rows": rows, "mismatches": sum(not row["match"] for row in rows)}
                       for index, (digest, rows) in enumerate(zip(recording_digests, rows_by_recording, strict=True))],
        "summary": {"recordings": len(recording_digests), "rows": sum(len(rows) for rows in rows_by_recording), "mismatches": mismatches},
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--recordings", type=Path, required=True, help="the E04 run directory holding recording-1.json and recording-2.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--keep", type=Path, help="where the replay's receipt directory goes (it must not exist)")
    args = parser.parse_args(argv)
    overlay = ensure_replay_tools()
    sys.path.insert(0, str(overlay))
    sys.path.insert(1, str(overlay.parent))
    import txn_expiry_comparison as comparison
    import txn_expiry_shadow as shadow

    shadow.CONFIG = {**shadow.CONFIG, "profile": "strict"}
    keep = args.keep or args.out.with_suffix(".replay")
    acquired = shadow.run_shadow(args.binary, keep)
    receipt = acquired.get("receipt")
    if not receipt or receipt["complete"] is not True or acquired["publication"]["failures"] or acquired["child"] != {"exitCode": 0, "signal": None, "stopped": True}:
        raise SystemExit("the replay did not complete")
    local = {"projection": comparison._projection(receipt), "postStates": comparison._post_states(receipt)}
    recordings = [args.recordings / f"recording-{n}.json" for n in (1, 2)]
    rows = []
    for path in recordings:
        value = json.loads(path.read_text())
        rows.append(compare_rows({"projection": comparison._projection(value), "postStates": comparison._post_states(value)}, local))
    blob = subprocess.check_output(["git", "-C", str(HERE), "rev-parse", "HEAD:tools/compat-broad/fs-write-txn/txn_expiry_cases.py"], text=True).strip()
    record = build_record(commit=args.commit, binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), recording_digests=[hashlib.sha256(path.read_bytes()).hexdigest() for path in recordings],
                          rows_by_recording=rows, idles=local_idles(receipt), cases_blob=blob, file_digests=replayed_file_digests(overlay))
    args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(record["summary"]), json.dumps(record["replay"]["localIdleSeconds"]))


if __name__ == "__main__":
    main()
