"""Offline read-only baseline executor tests: fake credentials and capture only."""
import base64
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("baseline_execute.py")
NOW = dt.datetime(2026, 9, 30, 16, tzinfo=dt.timezone.utc)


def load():
    spec = importlib.util.spec_from_file_location("lane7_baseline_execute", SOURCE)
    module = importlib.util.module_from_spec(spec)
    exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), module.__dict__)
    return module


class BaselineExecutorTests(unittest.TestCase):
    def scenario(self, mode="complete"):
        m = load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(json.dumps({"ts": "2026-09-30T13:00:00Z", "event": "finished",
                "project": m.PROJECT, "taskId": "OTHER", "outcome": "cleanup-verified"}) + "\n")
            locks, calls, guards = Mock(), [], []
            clock = [0]
            manifest = dict(sourceCommit="b" * 40, runId="a" * 32, projectNumber="123456789012", nodeExecutable="/synthetic/pinned/node")
            manifest["requests"] = m.baseline_requests(manifest["projectNumber"])

            def authority(*, timeout=10):
                self.assertLessEqual(timeout, 10)
                guards.append(len(calls))
                if mode == "stale-budget":
                    clock[0] = 575 if len(guards) == 1 else clock[0] + 9
                if mode == "revoked" and len(calls) == 1:
                    raise m.Rejected("authority stopped")

            def command(argv, **kwargs):
                if argv[0] != "gcloud":
                    self.assertEqual(argv[0], manifest["nodeExecutable"], "collector must bypass a PATH shim")
                else:
                    self.assertEqual(kwargs.get("policy"), "credential-wrapper")
                self.assertTrue(locks.acquire.called)
                self.assertEqual(json.loads(ledger.read_text().splitlines()[-1])["event"], "reserved")
                calls.append(argv)
                if mode.startswith("process-state-"):
                    q, r, u = (flag == "1" for flag in mode.removeprefix("process-state-"))
                    raise m.ProcessStopped(quiescent=q, reaped=r, unexpected_descendant=u)
                if mode == "unreaped":
                    raise m.ProcessStopped(quiescent=False, reaped=False)
                if mode == "unexpected-child":
                    raise m.ProcessStopped(quiescent=True, reaped=True, unexpected_descendant=True)
                if mode == "cancelled":
                    raise m.ProcessStopped(quiescent=True, reaped=True, reason="cancelled")
                if argv[0] == "gcloud":
                    if mode == "stale-budget":
                        self.assertLessEqual(kwargs["timeout"], 600 - clock[0] - 5,
                            "credential budget must be recomputed after live authority")
                    if mode == "late-authority":
                        clock[0] = 595
                    return Mock(returncode=0, stdout="synthetic-secret", processQuiescent=True, directChildReaped=True)
                data = json.loads(kwargs["input"])
                self.assertEqual(data["accessToken"], "synthetic-secret")
                directory = root / "docs.local/runs/codex-lane7" / ("fixture-baseline-002-" + manifest["runId"])
                directory.mkdir(parents=True)
                rows = []
                for index, request in enumerate(manifest["requests"]):
                    rows.append({**request, "state": "before-send"})
                    if mode == "partial" and index == 1:
                        break
                    raw = {**request, "state": "response-persisted", "status": 403, "headers": [],
                        "body": "{}", "bodyBase64": base64.b64encode(b"{}").decode(), "bodyBytes": 2,
                        "bodySha256": hashlib.sha256(b"{}").hexdigest()}
                    if mode == "bad-body" and index == 0:
                        raw["bodySha256"] = "e" * 64
                    if mode == "bad-header" and index == 0:
                        raw["headers"] = [["x-evidence", "altered"]]
                    (directory / (request["id"] + ".json")).write_text(json.dumps(raw))
                    rows.extend([{"id": request["id"], "state": "response-headers", "status": 403, "headers": []},
                                 {"id": request["id"], "state": "response-persisted", "status": 403,
                                  "bodyBytes": raw["bodyBytes"], "bodySha256": raw["bodySha256"]}])
                wal = "".join(json.dumps(row) + "\n" for row in rows)
                if mode == "corrupt-wal":
                    wal += '{"id":'
                (directory / "requests.jsonl").write_text(wal)
                summary = dict(outcome="captured-read-only-baseline", attempted=3, completed=3, unknown=0)
                if mode == "partial":
                    summary = dict(outcome="incomplete-read-only-baseline", attempted=2, completed=1, unknown=1)
                (directory / "summary.json").write_text(json.dumps(summary))
                return Mock(returncode=0 if mode != "partial" else 1, processQuiescent=True, directChildReaped=True)

            def append(path, row):
                if mode == "terminal-failure" and row["event"] == "finished":
                    raise OSError("synthetic-secret")
                m.append_ledger(path, row)

            def close(**kwargs):
                if kwargs["success"]:
                    self.assertEqual(json.loads(ledger.read_text().splitlines()[-1])["event"], "finished")
                    self.assertTrue(json.loads(ledger.read_text().splitlines()[-1])["processQuiescent"])
            locks.close.side_effect = close
            options = dict(root=root, worktree=root, manifest=manifest, packet_sha="c" * 64,
                manifest_sha="d" * 64, locks=locks, authority_input={}, check_authority=authority,
                command=command, append=append, now=lambda: NOW, monotonic=lambda: clock[0])
            with patch.dict(m.os.environ, {}, clear=True):
                if mode == "terminal-failure":
                    with self.assertRaises(OSError):
                        m.execute(**options)
                    self.assertTrue(locks.close.call_args.kwargs["retain"])
                    return
                result = m.execute(**options)
            self.assertNotIn("synthetic-secret", ledger.read_text())
            terminal = json.loads(ledger.read_text().splitlines()[-1])
            self.assertEqual(terminal["event"], "finished")
            self.assertEqual(result["mutationAttempts"], 0)
            if mode == "complete":
                self.assertEqual(result["outcome"], "exploration-recorded-read-only-baseline")
                self.assertEqual((result["attempted"], result["completed"], result["unknown"]), (3, 3, 0))
                self.assertGreaterEqual(len(guards), 2)
            if mode == "partial":
                self.assertEqual(result["outcome"], "exploration-incomplete-read-only-baseline")
                self.assertEqual((result["attempted"], result["completed"], result["unknown"]), (2, 1, 1))
            if mode in ("corrupt-wal", "bad-body", "bad-header"):
                self.assertEqual(result["unknown"], 3)
            if mode in ("revoked", "late-authority"):
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["attempted"], 0)
            if mode == "late-authority":
                self.assertTrue(all(count == 0 for count in guards), "exhausted budget must not start another authority child")
            if mode == "cancelled":
                self.assertEqual(len(calls), 1, "operator cancellation must not start the collector")
                self.assertEqual(result["stopReason"], "cancelled")
            expected_retain = mode in ("unreaped", "unexpected-child")
            if mode.startswith("process-state-"):
                # Independent contract truth table: only proved exit+reap without an
                # unexpected descendant permits release after a read-only failure.
                expected_retain = mode != "process-state-110"
                self.assertEqual(result["processQuiescent"], mode[-3:-1] == "11")
                self.assertEqual(result["sandboxAtBaseline"], not expected_retain)
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["attempted"], 0)
            self.assertEqual(locks.close.call_args.kwargs["retain"], expected_retain)

    def test_complete_capture_including_read_only_post_and403_is_not_baseline_usability(self): self.scenario()
    def test_partial_raw_capture_preserves_unknown_without_retry(self): self.scenario("partial")
    def test_corrupt_wal_counts_all_three_slots_conservatively(self): self.scenario("corrupt-wal")
    def test_raw_body_digest_mismatch_cannot_count_as_captured(self): self.scenario("bad-body")
    def test_revocation_after_credentials_prevents_resource_child(self): self.scenario("revoked")
    def test_unreaped_process_retains_lock(self): self.scenario("unreaped")
    def test_even_cleaned_unexpected_descendant_retains_lock(self): self.scenario("unexpected-child")
    def test_terminal_fsync_failure_retains_lock(self): self.scenario("terminal-failure")
    def test_changed_headers_cannot_count_as_captured(self): self.scenario("bad-header")
    def test_late_authority_cannot_exceed_remaining_whole_run_budget(self): self.scenario("late-authority")
    def test_credential_deadline_recomputed_after_slow_live_authority(self): self.scenario("stale-budget")
    def test_operator_cancellation_stops_before_any_resource_stage(self): self.scenario("cancelled")

    def test_finite_process_admission_table_covers_all_exit_reap_descendant_states(self):
        for flags in ("000", "001", "010", "011", "100", "101", "110", "111"):
            with self.subTest(flags=flags):
                self.scenario("process-state-" + flags)

    def test_local_only_prereservation_authority_stop_cannot_leave_an_unexplained_lock(self):
        m = load()
        for q in (True, False):
            with self.subTest(quiescent=q), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
                ledger.parent.mkdir(parents=True)
                ledger.write_text("")
                manifest = dict(sourceCommit="b"*40, runId="a"*32, projectNumber="123456789012")
                manifest["requests"] = m.baseline_requests(manifest["projectNumber"])
                locks, command = Mock(), Mock()
                def stopped(**_):
                    raise m.ProcessStopped(quiescent=q, reaped=q)
                with self.assertRaises(m.ProcessStopped):
                    m.execute(root=root, worktree=root, manifest=manifest, packet_sha="c"*64,
                              manifest_sha="d"*64, locks=locks, authority_input={},
                              check_authority=stopped, command=command)
                command.assert_not_called()
                if q:
                    self.assertFalse(locks.close.call_args.kwargs["retain"])
                else:
                    terminal = json.loads(ledger.read_text().splitlines()[-1])
                    self.assertEqual(terminal["event"], "finished")
                    self.assertEqual(terminal["outcome"], "needs-recovery")
                    self.assertTrue(terminal["localOnly"])
                    self.assertEqual(terminal["attempted"], 0)
                    self.assertEqual(terminal["credentialCliAttempts"], 0)
                    self.assertTrue(locks.close.call_args.kwargs["retain"])

    def test_real_node_pin_is_canonical_executable_and_integrity_bound(self):
        m = load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            node = root / "node"
            node.write_bytes(b"synthetic installed runtime")
            node.chmod(0o700)
            manifest = dict(nodeExecutable=str(node), nodeExecutableSha256=m.sha(node))
            self.assertEqual(m.pinned_node(manifest), str(node))
            for bad in (dict(manifest, nodeExecutable="node"),
                        dict(manifest, nodeExecutableSha256="0"*64),
                        dict(manifest, nodeExecutable=str(root/"missing"))):
                with self.subTest(bad=bad), self.assertRaises(m.Rejected):
                    m.pinned_node(bad)
            linked = root / "linked"
            linked.symlink_to(node)
            with self.assertRaises(m.Rejected):
                m.pinned_node(dict(manifest, nodeExecutable=str(linked)))

    def test_private_helper_executes_the_single_hash_verified_byte_snapshot(self):
        m = load()
        approved = b"marker = 'reviewed'\n"
        replaced = b"marker = 'unreviewed'\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "helper.py"
            with patch.object(Path, "read_bytes", side_effect=[approved, replaced]) as reads:
                module = m.verified_module("test_verified_helper", path, hashlib.sha256(approved).hexdigest())
            self.assertEqual(module.marker, "reviewed")
            self.assertEqual(reads.call_count, 1)


if __name__ == "__main__":
    unittest.main()
