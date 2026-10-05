"""Publish a program's two saved production recordings and their local replays as the two records the closure cites.

For each program, `fs-transaction-<key>-recorded-observations-v1.json` holds what the two recordings agree on (the program's own projection: case codes and
diagnostics, read states, token ends, cleanup) and `fs-transaction-<key>-recorded-comparison-v1.json` holds the replays: one fixed strict artifact, each
recording replayed once, every row of the replay beside the recorded one.

Inputs are private (the run directories and the replay outputs of `fs_txn_compare_local.py` or `fs_txn_compare_local_grpc.py`); the published files carry
no run identity: no nonce, no owner marker, no issued token and no run directory name. The publisher refuses what it cannot vouch for: a replay that is
incomplete or mismatches, replays on different artifacts, tools, profiles or clocks, a replay of a file other than the recording named, recordings whose
projections differ, and any output that carries an identity of the run.

    python publish_recorded_comparison.py --key p01 --program FS-TRANSACTION-P01-LIFECYCLE --condition FS-TRANSACTION/read-write-lifecycle \\
        --recording rec-1.json --recording rec-2.json --result out-1.json --result out-2.json --family framework --table fs_txn_table_p01 --out-dir spec/compatibility/broad-runs
"""

import argparse
import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("SMOKE_TOOLS", str(HERE)))

SAME = ("commit", "binary_sha256", "profile", "compareToolSha256", "clock")
ROW_SECTIONS = ("cases", "reads", "commitTimes", "skipped", "idleCandidates")
OBSERVATION_LIMITS = [
    "Raw REST bodyBytes, content-length and member-order layout were not retained; the record proves decoded response semantics, not wire layout.",
    "The closure review and the final-artifact regression are separate conditions and stay open.",
]


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _rows(result):
    return sum(len(result.get(section) or []) for section in ROW_SECTIONS)


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def as_recorded_entry(repo, path, commit, used):
    """A file replayed as it was when the recording was made: its commit, git blob and digest. The file replayed must be the committed one and the commit must be in
    the history of the checkout, so the record can be reproduced with `git show <commit>:<path>`."""
    try:
        committed = _git(repo, "show", f"{commit}:{path}")
        blob = _git(repo, "rev-parse", f"{commit}:{path}").decode().strip()
        _git(repo, "merge-base", "--is-ancestor", commit, "HEAD")
    except subprocess.CalledProcessError as error:
        raise ValueError("the as-recorded commit or file is not in the history") from error
    if committed != Path(used).read_bytes():
        raise ValueError("the file replayed is not the committed one")
    return {"path": path, "commit": commit, "blob": blob, "sha256": hashlib.sha256(committed).hexdigest()}


def build(*, program, key, conditions, recordings, results, projections, identities, table=None, limits=(), as_recorded=()):
    """The observations and comparison records, or ValueError when the inputs cannot be vouched for."""
    if len(recordings) != 2 or len(results) != 2 or len(projections) != 2:
        raise ValueError("two recordings, two replays and two projections are required")
    first = results[0]["metadata"]
    for result, recording in zip(results, recordings, strict=True):
        meta = result["metadata"]
        if result.get("complete") is not True or result.get("failure") is not None or result.get("mismatches") != 0:
            raise ValueError("a replay is incomplete or mismatches")
        if meta.get("productionFileSha256") != _digest(recording):
            raise ValueError("a replay is not of the recording named")
        if any(meta.get(name) != first.get(name) for name in SAME):
            raise ValueError("the replays differ in artifact, tool, profile or clock")
        if meta.get("planCorpusDigest") != meta.get("productionCorpusDigest"):
            raise ValueError("a replay's plan is not the recording's corpus")
    if projections[0] != projections[1]:
        raise ValueError("the two recordings do not agree")
    observations = {
        "schemaVersion": 1, "kind": "fs-transaction-recorded-observations-v1", "parent": "FS-TRANSACTION", "condition": list(conditions),
        "coverage": "PARTIAL", "authorizesProduction": False, "decodedSemanticsValidated": True, "rawRestWireLayoutValidated": False,
        "normalization": "Only the declared run identities (nonce, owner marker, issued token values, project number) are replaced by roles; codes, diagnostics, read states, token ends and cleanup are the program's own projection.",
        "remainingBoundaries": [*OBSERVATION_LIMITS, *limits],
        "corpora": [{"program": program, "packetName": projections[0].get("packetName"), "corpusDigest": projections[0]["corpusDigest"], "recordings": 2, "agree": True,
                     "productionFileSha256": [_digest(path) for path in recordings], "projection": projections[0]}],
    }
    comparison = {
        "schemaVersion": 1, "kind": "fs-transaction-recorded-comparison-v1", "parent": "FS-TRANSACTION", "program": program, "condition": list(conditions),
        "coverage": "PARTIAL", "authorizesProduction": False, "productionRequests": 0, "profile": first["profile"],
        "artifact": {"sourceCommit": first["commit"], "binarySha256": first["binary_sha256"]},
        "comparer": {"sha256": first["compareToolSha256"], "replayClock": first["clock"]},
        # a table file replayed as it was when recorded is named by its asRecorded entry (commit, blob, digest); naming today's file beside it would pair a path with a digest it does not have
        **({"table": table} if table and not any(entry["path"] == table["path"] for entry in as_recorded) else {}),
        **({"asRecorded": list(as_recorded)} if as_recorded else {}),
        "recordings": [{"recording": index + 1, "productionFileSha256": result["metadata"]["productionFileSha256"], "mismatches": 0,
                        **{section: result[section] for section in ROW_SECTIONS if result.get(section) is not None},
                        **({"achievedAges": result["achievedAges"]} if result.get("achievedAges") else {}),
                        **({"tokenAges": result["tokenAges"]} if result.get("tokenAges") else {})} for index, result in enumerate(results)],
        "summary": {"recordings": 2, "rows": sum(_rows(result) for result in results), "mismatches": 0},
        "remainingBoundaries": [*OBSERVATION_LIMITS, "The artifact is the strict profile of the commit named; a later source change needs a new replay.", *limits],
    }
    text = json.dumps([observations, comparison])
    if any(identity and identity in text for identity in identities):
        raise ValueError("a published record carries an identity of the run")
    return observations, comparison


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--condition", action="append", required=True)
    parser.add_argument("--recording", action="append", required=True, type=Path)
    parser.add_argument("--result", action="append", required=True, type=Path)
    parser.add_argument("--family", required=True, help="framework, or a gRPC family module such as txn_idle_grpc")
    parser.add_argument("--table", help="the framework table module")
    parser.add_argument("--as-recorded", action="append", default=[], metavar="NAME=COMMIT", help="a tool file replayed as it was when the recording was made, from that commit")
    parser.add_argument("--limit", action="append", default=[])
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    recordings = [json.loads(path.read_text()) for path in args.recording]
    if args.family == "framework":
        from txn_program_collector import projection

        module = importlib.import_module(args.table)
        projections = [projection(recording, module.TABLE) for recording in recordings]
        table_path = Path(module.__file__)
        table = {"path": f"tools/compat-broad/fs-write-txn/{table_path.name}", "sha256": _digest(table_path)}
    else:
        collector = importlib.import_module(f"{args.family}_collector")
        projections = [collector.projection(recording) for recording in recordings]
        table = None
    identities = []
    for recording in recordings:
        identities += [recording.get("nonce"), recording.get("ownerId")] + [entry.get("value") for entry in (recording.get("tokens") or {}).values()]
    results = [json.loads(path.read_text()) for path in args.result]
    replayed = Path(os.environ.get("SMOKE_TOOLS", str(HERE)))
    as_recorded = [as_recorded_entry(HERE, f"tools/compat-broad/fs-write-txn/{name}", commit, replayed / name) for name, _, commit in (item.partition("=") for item in args.as_recorded)]
    observations, comparison = build(program=args.program, key=args.key, conditions=args.condition, recordings=args.recording, results=results,
                                     projections=projections, identities=identities, table=table, limits=args.limit, as_recorded=as_recorded)
    for kind, value in (("observations", observations), ("comparison", comparison)):
        (args.out_dir / f"fs-transaction-{args.key}-recorded-{kind}-v1.json").write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(comparison["summary"]))


if __name__ == "__main__":
    main()
