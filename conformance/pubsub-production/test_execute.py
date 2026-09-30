"""Offline coordinator executor contracts; credentials and transports are fake."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).with_name("execute.py")
NOW = dt.datetime(2026, 9, 30, 12, tzinfo=dt.timezone.utc)
PROJECT = "fireemu-oracle-idp"


def load():
    if not SOURCE.exists():
        raise AssertionError("concrete coordinator executor is missing")
    spec = importlib.util.spec_from_file_location("lane7_execute", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def baseline():
    return [{"ts": "2026-09-30T10:00:00Z", "event": "finished", "project": PROJECT,
             "taskId": "OTHER", "outcome": "recorded", "estimatedUsd": 0}]


class ExecutorTests(unittest.TestCase):
    def test_project_spacing_open_runs_and_unrelated_projects(self):
        m = load()
        m.check_ledger(baseline(), NOW, "a" * 64)
        for row in (
            {"ts": "2026-09-30T11:45:00Z", "event": "finished", "outcome": "recorded"},
            {"ts": "2026-09-30T10:30:00Z", "event": "reserved", "runDir": "unclosed"},
            {"ts": "2026-09-30T10:30:00Z", "event": "started", "runDir": "unclosed"},
            {"ts": "2026-09-30T10:30:00Z", "event": "finished", "outcome": "needs-recovery"},
        ):
            with self.subTest(row=row), self.assertRaises(m.Rejected):
                m.check_ledger(baseline() + [{**row, "project": PROJECT, "taskId": "OTHER"}], NOW, "a" * 64)
        m.check_ledger(baseline() + [{"event": "started", "project": "fireemu-oracle-query"}], NOW, "a" * 64)

    def test_only_finished_rows_close_a_run_and_old_exploration_stays_open(self):
        m = load()
        start = {"ts": "2026-09-30T10:05:00Z", "event": "started", "project": PROJECT,
                 "taskId": "OLD", "runDir": "legacy"}
        terminal = {"ts": "2026-09-30T10:10:00Z", "project": PROJECT,
                    "taskId": "OLD", "runDir": "legacy", "outcome": "recorded"}
        with self.assertRaises(m.Rejected):
            m.check_ledger(baseline() + [start, terminal], NOW, "a" * 64)
        m.check_ledger(baseline() + [start, {**terminal, "event": "finished"}], NOW, "a" * 64)

    def test_combined_project_spacing_and_exact_project_side_recovery(self):
        m = load()
        recent = {"ts": "2026-09-30T11:59:00Z", "project": "fireemu-oracle-query, fireemu-oracle-idp",
                  "event": "finished", "taskId": "OTHER", "outcome": "recorded"}
        with self.assertRaises(m.Rejected):
            m.check_ledger(baseline() + [recent], NOW, "a" * 64)
        start = {"ts": "2026-09-30T09:00:00Z", "project": "fireemu-oracle-query,fireemu-oracle-idp",
                 "event": "reserved", "taskId": "OTHER", "runId": "combined"}
        failed = {**start, "ts": "2026-09-30T09:10:00Z", "event": "finished", "outcome": "needs-recovery"}
        closed = {"ts": "2026-09-30T10:00:00Z", "project": PROJECT, "event": "finished",
                  "taskId": "OTHER", "runId": "combined", "outcome": "cleanup-verified",
                  "sandboxAtBaseline": True, "closesStartedAt": start["ts"]}
        with self.assertRaises(m.Rejected):
            m.check_ledger(baseline() + [start, failed], NOW, "a" * 64)
        m.check_ledger(baseline() + [start, failed, closed], NOW, "a" * 64)
        for changed in ({"runId": "foreign"}, {"taskId": "foreign"}, {"closesStartedAt": "wrong"},
                        {"sandboxAtBaseline": False}, {"project": "fireemu-oracle-query"}):
            with self.subTest(changed=changed), self.assertRaises(m.Rejected):
                m.check_ledger(baseline() + [start, failed, {**closed, **changed}], NOW, "a" * 64)

    def test_budget_does_not_double_count_reservation_and_terminal(self):
        m = load()
        rows = baseline() + [{"ts": "2026-09-30T10:00:00Z", "project": PROJECT,
            "taskId": m.TASK, "runDir": "old", "event": "reserved", "estimatedUsd": 5},
            {"ts": "2026-09-30T10:01:00Z", "project": PROJECT, "taskId": m.TASK,
             "runDir": "old", "event": "finished", "outcome": "recorded-preflight", "estimatedUsd": 5}]
        m.check_ledger(rows, NOW, "a" * 64)
        with self.assertRaises(m.Rejected):
            m.check_ledger(rows + [{"ts": "2026-09-30T10:02:00Z", "project": PROJECT,
                "taskId": m.TASK, "event": "finished", "runDir": "another",
                "outcome": "recorded-preflight", "estimatedUsd": 5}], NOW, "a" * 64)
        with self.assertRaises(m.Rejected):
            m.check_ledger(rows + [{"packetSha256": "a" * 64}], NOW, "a" * 64)

    def scenario(self, credential_error=False, capture_error=False, terminal_error=False, expired=False):
        m = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text("".join(json.dumps(row) + "\n" for row in baseline()))
            lock = Mock()
            def release(**kwargs):
                if not kwargs["retain"]:
                    rows = [json.loads(s) for s in ledger.read_text().splitlines()]
                    self.assertEqual(rows[-1]["event"], "finished")
            lock.close.side_effect = release
            calls = []
            def command(argv, **kwargs):
                rows = [json.loads(s) for s in ledger.read_text().splitlines()]
                self.assertEqual(rows[-1]["event"], "reserved")
                self.assertTrue(lock.acquire.called)
                calls.append(argv)
                if argv[0] == "gcloud":
                    self.assertEqual(argv, ["gcloud", "auth", "application-default", "print-access-token"])
                    self.assertLessEqual(kwargs["timeout"], 60)
                    if credential_error:
                        raise RuntimeError("fake-secret-token")
                    return Mock(returncode=0, stdout="fake-secret-token\n")
                self.assertEqual(argv[0], "node")
                self.assertEqual(json.loads(kwargs["input"])["accessToken"], "fake-secret-token")
                output = Path(argv[-1])
                output.mkdir()
                if capture_error:
                    (output / "requests.jsonl").write_text(json.dumps({"id": "identity", "state": "before-send"}) + "\n")
                    raise RuntimeError("fake-secret-token")
                summary = {"outcome": "recorded-preflight", "attempted": 13, "completed": 13, "unknown": 0}
                (output / "summary.json").write_text(json.dumps(summary))
                (output / "requests.jsonl").write_text("".join(json.dumps({"id": str(i), "state": state}) + "\n" for i in range(13) for state in ("before-send", "response-persisted")))
                return Mock(returncode=0, stdout=json.dumps(summary))
            append = m.append_ledger
            def save(path, row):
                if terminal_error and row["event"] == "finished":
                    raise OSError("fake-secret-token")
                append(path, row)
            manifest = {"project": {"id": PROJECT, "number": "123456789012"},
                        "sourceCommit": "a" * 40}
            opts = dict(root=root, worktree=root, manifest=manifest, packet_sha="b" * 64,
                manifest_sha="c" * 64, locks=lock, command=command, append=save,
                now=lambda: NOW, monotonic=iter([0, 0, 601]).__next__ if expired else lambda: 0)
            if terminal_error:
                with self.assertRaises(OSError):
                    m.execute(**opts)
                self.assertTrue(lock.close.call_args.kwargs["retain"])
            else:
                result = m.execute(**opts)
                rows = [json.loads(s) for s in ledger.read_text().splitlines()]
                self.assertEqual([row["event"] for row in rows[-2:]], ["reserved", "finished"])
                self.assertNotIn("fake-secret-token", ledger.read_text())
                self.assertEqual(result["credentialCliAttempts"], 1)
                self.assertEqual(lock.close.call_args.kwargs["retain"], False)
                if credential_error or expired:
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(result["attempted"], 0)
                    self.assertEqual(result["outcome"], "incomplete-read-only")
                elif capture_error:
                    self.assertEqual(result["attempted"], 1)
                    self.assertEqual(result["unknown"], 1)
                else:
                    self.assertEqual(result["outcome"], "recorded-preflight")
                    self.assertEqual(result["attempted"], 13)

    def test_reserve_before_credentials_and_finish_before_release(self):
        self.scenario()

    def test_credential_failure_consumes_cli_attempt_and_sends_no_resource(self):
        self.scenario(credential_error=True)

    def test_wall_budget_includes_credential_time_and_prevents_capture(self):
        self.scenario(expired=True)

    def test_child_failure_recovers_durable_unknown_slots(self):
        self.scenario(capture_error=True)

    def test_terminal_persistence_failure_retains_owned_lock(self):
        self.scenario(terminal_error=True)

    def test_authorization_requires_exact_hash_envelope_and_unrevoked_row(self):
        m = load()
        sha = "a" * 64
        row = f"- 2026-09-30 | preflight | decision=APPROVE; packetSha256={sha}; envelopeId={m.ENVELOPE}; | coordinator"
        m.check_authority([row], 1, sha, sha)
        for lines, number, go in (([row], 0, sha), ([row], 1, "b" * 64),
                                  ([row.replace("decision=APPROVE", "decision=PROPOSE")], 1, sha),
                                  ([row.replace("decision=APPROVE", "NOT decision=APPROVE")], 1, sha),
                                  ([row.replace("decision=APPROVE", "REVOKED; previously decision=APPROVE")], 1, sha),
                                  ([row, f"REVOKED packetSha256={sha}"], 1, sha)):
            with self.subTest(lines=lines, number=number), self.assertRaises(m.Rejected):
                m.check_authority(lines, number, sha, go)

    def test_invalid_receipts_cannot_be_claimed_complete(self):
        m = load()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "requests.jsonl").write_text(json.dumps({"id": "x", "state": "response-persisted"}) + "\n")
            with self.assertRaises(m.Rejected):
                m.receipt_counts(p)


if __name__ == "__main__":
    unittest.main()
