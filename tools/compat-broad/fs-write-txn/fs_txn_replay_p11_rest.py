"""Replay the REST part of P11 (a read-write transaction kept alive by reads past its 270 s total lifetime) against a
local fireemu with its virtual clock, and compare the answers with the P11 production recording.

Run it as the child of `fireemu exec` (it needs FIRESTORE_EMULATOR_HOST, FIREEMU_CONTROL_URL and FIREEMU_CONTROL_TOKEN):

    COMPARE_COMMIT=<full sha> COMPARE_PROFILE=strict COMPARE_BINARY_SHA256=<sha256> \\
      fireemu exec --config <config> --project demo-program --only firestore ... -- \\
      python fs_txn_replay_p11_rest.py <production recording-N.json> <out.json>

The table is P11's REST chain up to the expiry Commit, then a release Rollback and a plain read; every wait advances the
emulator's virtual clock (`clock:advance`) instead of sleeping. Compared: the live read, the expiry read, the expiry
Commit and the release Rollback, by code and first line of the diagnostic. Only the recorded order (read, Commit,
Rollback) is compared; the other orders and gRPC are unobserved (P12 records them)."""

import datetime
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("SMOKE_TOOLS", str(HERE)))

from txn_program_collector import Collector  # noqa: E402
from txn_program_program import RequestBudget, compile_plan  # noqa: E402

COMPARED = (("rest/live-read", "rest/live-read"), ("rest/expiry-read", "rest/expiry-read"),
            ("rest/expiry-commit", "rest/expiry-commit"), ("cleanup/token/rest-k", "rest/release"))


def normalize(text):
    return text.replace("demo-program", "fireemu-oracle-sbx")


def recorded_rows(recording):
    """The compared production rows, by local site name."""
    rows = {row["site"]: row for row in recording["steps"] + recording.get("cleanupSteps", [])}
    return {local: {"code": rows[site]["result"]["code"], "details": rows[site]["result"]["details"]}
            for site, local in COMPARED if site in rows}


def compare_rows(production, local):
    rows = []
    for site in (local_name for _site, local_name in COMPARED):
        expected, actual = production.get(site), local.get(site)
        same = expected is not None and actual is not None and expected["code"] == actual["code"] \
            and normalize(actual["details"]).split("\n")[0] == expected["details"].split("\n")[0]
        rows.append({"site": site, "production": expected, "local": actual, "match": same})
    return rows


class VirtualClock:
    """Real time plus every second the waits advanced the emulator's virtual clock."""

    def __init__(self, control, token):
        self.control, self.token, self.skew = control.rstrip("/"), token, 0.0

    def now(self):
        return time.monotonic() + self.skew

    def utc(self):
        moment = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.skew)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def sleep(self, seconds):
        seconds = max(1, int(round(seconds)))
        request = urllib.request.Request(self.control + "/sessions/default/clock:advance", data=json.dumps({"seconds": seconds}).encode(),
                                         method="POST", headers={"content-type": "application/json", "authorization": "Bearer " + self.token})
        urllib.request.urlopen(request, timeout=10).read()
        self.skew += seconds


def table():
    import fs_txn_table_p11 as p11

    steps = []
    for step in p11.STEPS:
        steps.append(step)
        if step["id"] == "rest/expiry-commit":
            break
    steps.append({"id": "rest/release", "transport": "rest", "rpc": "Rollback", "document": None, "tokenInput": "rest-k", "tokenOutput": None,
                  "writes": (), "caseId": "rest/release", "role": "observation", "allow": (0, 3, 5, 9, 10)})
    steps.append({"id": "rest/post-read-a", "transport": "rest", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None,
                  "writes": (), "caseId": None, "role": "post-state", "allow": (0,)})
    return {**p11.TABLE, "steps": tuple(steps), "caps": {**p11.TABLE["caps"], "observation": len(steps)}, "maxTokens": 1}


def main():
    from txn_program_runner import wire_scope
    from txn_program_wire import NodeWire, discover_runtime

    replay = table()
    host, port = os.environ["FIRESTORE_EMULATOR_HOST"].rsplit(":", 1)
    runtime = discover_runtime(Path(os.environ.get("NODE_BINARY") or shutil.which("node")))
    plan = compile_plan(replay, os.urandom(16).hex(), os.urandom(16).hex())
    wire = NodeWire(runtime, wire_scope(replay), target={"kind": "local", "host": host, "port": int(port)})
    clock = VirtualClock(os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"])
    receipt = Collector(plan, replay, RequestBudget(plan, replay), wire, "owner", save=lambda _state: None,
                        monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    source = Path(sys.argv[1])
    recording = json.loads(source.read_text())
    local = {row["site"]: {"code": row["result"]["code"], "details": row["result"]["details"]} for row in receipt["steps"]}
    metadata = {key[8:].lower(): value for key, value in os.environ.items() if key.startswith("COMPARE_")}
    metadata.update({"productionFile": str(source), "productionFileSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                     "replayToolSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "localProject": "demo-program"})
    rows = compare_rows(recorded_rows(recording), local)
    Path(sys.argv[2]).write_text(json.dumps({"metadata": metadata, "complete": receipt["complete"], "failure": receipt["failureType"],
                                             "rows": rows, "mismatches": sum(not row["match"] for row in rows)}, indent=1))
    print("complete", receipt["complete"], receipt["failureType"], "mismatches", sum(not row["match"] for row in rows))
    for row in rows:
        if not row["match"]:
            print("DIVERGE", json.dumps(row)[:300])


if __name__ == "__main__":
    main()
