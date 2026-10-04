"""Run a program table against a local fireemu and keep every answer: a rehearsal of what a packet would record, with no production request.

Run it as the child of `fireemu exec` (it reads FIRESTORE_EMULATOR_HOST). With COMPARE_CLOCK=virtual the waits advance the emulator's virtual clock instead of sleeping (it then
also reads FIREEMU_CONTROL_URL and FIREEMU_CONTROL_TOKEN), and RUN_LOCAL_ADVANCE_SECONDS moves that clock just after the step named by RUN_LOCAL_ADVANCE_AFTER: a read at a time ago needs a database older than the time asked
for, and a database created at the process start is not.

    SMOKE_TABLE=fs_txn_table_p14 COMPARE_CLOCK=virtual RUN_LOCAL_CLOCK_START=2026-10-04T00:00:00Z RUN_LOCAL_ADVANCE_SECONDS=3700 RUN_LOCAL_ADVANCE_AFTER=grpc/tv/rollback-unknown fireemu exec --config <config> --project demo-program --only firestore --firestore-port 0 ... -- \\
      python fs_txn_run_local.py <out.json>

The receipt is saved beside the summary: one line per step with its site, transport, rpc and code, and the cleanup that followed."""

import importlib
import ipaddress
import json
import os
import datetime
import shutil
import sys
import time
import traceback
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("SMOKE_TOOLS", str(HERE)))

from txn_program_collector import Collector  # noqa: E402
from txn_program_program import RequestBudget, compile_plan  # noqa: E402


class VirtualClock:
    """The emulator's virtual clock as the recording sees it. A fireemu started with `daemon.clockStart` has a clock that only moves when it is advanced, so with a start given
    (`RUN_LOCAL_CLOCK_START`) the recording's clocks do too: UTC is the start plus what was advanced, monotonic is what the waits advanced. Without one the clocks are real time plus
    what was advanced."""

    def __init__(self, control, token, start=None):
        self.control, self.token, self.skew, self.utc_skew, self.start = control.rstrip("/"), token, 0.0, 0.0, start

    def now(self):
        return (0.0 if self.start else time.monotonic()) + self.skew + 1000.0

    def utc(self):
        base = self.start or datetime.datetime.now(datetime.timezone.utc)
        return (base + datetime.timedelta(seconds=self.utc_skew)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def advance(self, seconds, *, hidden=False):
        """Move the emulator's clock. A hidden advance moves what the recording writes as the time now but not its monotonic clock, so the recording's own deadline does not see it."""
        request = urllib.request.Request(self.control + "/sessions/default/clock:advance", data=json.dumps({"seconds": seconds}).encode(), method="POST",
                                         headers={"content-type": "application/json", "authorization": "Bearer " + self.token})
        urllib.request.urlopen(request, timeout=10).read()
        self.utc_skew += seconds
        if not hidden:
            self.skew += seconds

    def sleep(self, seconds):
        self.advance(max(1, int(round(seconds))))


def summarize(receipt):
    """One row per observation step, in order, and the cleanup rows apart."""
    row = lambda value: {"site": value["site"], "transport": value["transport"], "rpc": value["rpc"], "code": value["result"]["code"], "details": value["result"]["details"][:100]}  # noqa: E731
    return {"complete": receipt["complete"], "failure": receipt["failureType"], "steps": [row(value) for value in receipt["steps"]], "cleanup": [row(value) for value in receipt["cleanupSteps"]],
            "waits": receipt.get("waits", []), "unknownStarts": receipt["unknownStarts"], "unknownRollbacks": receipt["unknownRollbacks"], "unknownCommits": receipt["unknownCommits"]}


def main():
    from txn_program_runner import wire_scope
    from txn_program_wire import NodeWire, discover_runtime

    table = importlib.import_module(os.environ["SMOKE_TABLE"]).TABLE
    host, port = os.environ["FIRESTORE_EMULATOR_HOST"].rsplit(":", 1)
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("loopback local target required")
    runtime = discover_runtime(Path(os.environ.get("NODE_BINARY") or shutil.which("node")))
    plan = compile_plan(table, os.urandom(16).hex(), os.urandom(16).hex())
    project = table.get("project", "fireemu-oracle-sbx")
    wire = NodeWire(runtime, wire_scope(table), target={"kind": "local", "host": host, "port": int(port)}, **({} if project == "fireemu-oracle-sbx" else {"project": project}))
    # The collector keeps only the type of the error that stopped it; a rehearsal prints the whole of it (never used against production).
    original = Collector._observe

    def traced(self):
        try:
            return original(self)
        except BaseException:
            traceback.print_exc()
            raise

    Collector._observe = traced
    extra, runner = {}, Collector
    if os.environ.get("COMPARE_CLOCK") == "virtual":
        start = os.environ.get("RUN_LOCAL_CLOCK_START")
        clock = VirtualClock(os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"], datetime.datetime.fromisoformat(start.replace("Z", "+00:00")) if start else None)
        extra = {"monotonic": clock.now, "utc": clock.utc, "sleep": clock.sleep}
        advance, after = int(os.environ.get("RUN_LOCAL_ADVANCE_SECONDS", "0")), os.environ.get("RUN_LOCAL_ADVANCE_AFTER")
        if advance and after:
            moved = []

            class Advancing(Collector):
                def _rpc(self, site, *args, **kwargs):
                    result = super()._rpc(site, *args, **kwargs)
                    if site == after and not moved:
                        moved.append(site)
                        clock.advance(advance, hidden=True)
                    return result

            runner = Advancing
    receipt = runner(plan, table, RequestBudget(plan, table), wire, "owner", save=lambda _state: None, **extra).run()
    out = Path(sys.argv[1])
    out.with_suffix(".receipt.json").write_text(json.dumps(receipt, indent=1))
    summary = summarize(receipt)
    out.write_text(json.dumps(summary, indent=1))
    print("complete", summary["complete"], summary["failure"], "steps", len(summary["steps"]), "cleanup", len(summary["cleanup"]))
    for entry in summary["steps"]:
        print(f"{entry['site']:42} {entry['rpc']:18} {entry['code']:3} {entry['details'][:60]}")


if __name__ == "__main__":
    main()
