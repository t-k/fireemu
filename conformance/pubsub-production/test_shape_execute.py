"""Offline writer lifecycle tests: fake credential CLI and fake capture child only."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("shape_execute.py")
NOW = dt.datetime(2026, 9, 30, 12, tzinfo=dt.timezone.utc)


def load():
    if not SOURCE.exists():
        raise AssertionError("bounded writer executor is missing")
    spec = importlib.util.spec_from_file_location("lane7_shape_execute", SOURCE)
    module = importlib.util.module_from_spec(spec)
    exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), module.__dict__)
    return module


class ShapeExecutorTests(unittest.TestCase):
    def scenario(self, mode="complete"):
        m = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(json.dumps({"ts": "2026-09-30T10:00:00Z", "event": "finished",
                "project": m.PROJECT, "taskId": "OTHER", "outcome": "cleanup-verified"}) + "\n")
            locks = Mock()
            requests = [{"id": str(i), "method": "PUT" if i in (6, 8) else "DELETE" if i in (10, 12) else "GET",
                         "url": f"https://example.invalid/{i}"} for i in range(16)]
            run_id = "a" * 32
            manifest = {"sourceCommit": "b" * 40, "runId": run_id, "requests": requests}
            calls, guards = [], []
            def authority():
                guards.append(len(calls))
                if mode == "revoked" and len(guards) > 1:
                    raise m.Rejected("revoked")
            def command(argv, **kwargs):
                calls.append(argv)
                self.assertTrue(locks.acquire.called)
                self.assertEqual(json.loads(ledger.read_text().splitlines()[-1])["event"], "reserved")
                if argv[0] == "gcloud":
                    if mode == "credential-failure":
                        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output="fake-secret")
                    return Mock(returncode=0, stdout="fake-secret\n")
                self.assertEqual(argv[0], "node")
                self.assertEqual(json.loads(kwargs["input"])["accessToken"], "fake-secret")
                output = Path(argv[-1])
                output.mkdir(parents=True)
                count = 7 if mode in ("child-failure", "mismatch") else 16
                receipts = []
                for i, request in enumerate(requests[:count]):
                    receipts.append({**request, "state": "before-send",
                        **({"ownership": "fresh-absent-before-create"} if request["method"] == "PUT" else {})})
                    if mode != "child-failure" or i != 6:
                        receipts.append({"id": request["id"], "state": "response-headers", "status": 409 if mode == "collision" and i == 6 else 200})
                        receipts.append({"id": request["id"], "state": "response-persisted", "status": 200})
                (output / "requests.jsonl").write_text("".join(json.dumps(r) + "\n" for r in receipts))
                if mode == "child-failure":
                    raise RuntimeError("fake-secret")
                summary = {"runId": run_id, "attempted": count, "completed": count,
                    "unknown": 0, "mutationAttempts": sum(r["method"] != "GET" for r in requests[:count]),
                    "outcome": "exploration-recorded", "sandboxAtBaseline": True}
                if mode == "mismatch":
                    summary["attempted"] = 0
                    summary["outcome"] = "exploration-inconclusive"
                (output / "summary.json").write_text(json.dumps(summary))
                return Mock(returncode=0)
            def append(path, row):
                if mode == "terminal-failure" and row["event"] == "finished":
                    raise OSError("fake-secret")
                m.append_ledger(path, row)
            kwargs = dict(root=root, worktree=root, manifest=manifest, baseline={},
                packet_sha="c" * 64, manifest_sha="d" * 64, authority_input={}, check_authority=authority,
                locks=locks, command=command, append=append, now=lambda: NOW, monotonic=lambda: 0)
            if mode == "terminal-failure":
                with self.assertRaises(OSError):
                    m.execute(**kwargs)
                self.assertTrue(locks.close.call_args.kwargs["retain"])
                return
            with patch.dict(m.os.environ, {}, clear=True):
                result = m.execute(**kwargs)
            self.assertNotIn("fake-secret", ledger.read_text())
            self.assertEqual(json.loads(ledger.read_text().splitlines()[-1])["event"], "finished")
            if mode in ("child-failure", "mismatch", "collision"):
                self.assertEqual(result["outcome"], "needs-recovery")
                self.assertFalse(result["sandboxAtBaseline"])
                self.assertTrue(locks.close.call_args.kwargs["retain"])
                self.assertEqual(result["attempted"], 16 if mode == "collision" else 7)
            else:
                self.assertFalse(locks.close.call_args.kwargs["retain"])
            if mode == "complete":
                self.assertEqual(result["outcome"], "exploration-recorded")
                self.assertEqual(result["attempted"], 16)
                self.assertGreaterEqual(len(guards), 2)
            if mode == "revoked":
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["attempted"], 0)
            if mode == "child-failure":
                self.assertEqual(result["unknown"], 1)

    def test_complete_reserved_locked_and_terminal_before_release(self):
        self.scenario()

    def test_unknown_mutation_retains_lock(self):
        self.scenario("child-failure")

    def test_summary_count_mismatch_retains_lock(self):
        self.scenario("mismatch")

    def test_collision_header_overrides_claimed_clean_summary(self):
        self.scenario("collision")

    def test_credential_failure_is_terminal_without_resource_requests(self):
        self.scenario("credential-failure")

    def test_revocation_after_credential_prevents_capture(self):
        self.scenario("revoked")

    def test_failed_terminal_append_retains_lock(self):
        self.scenario("terminal-failure")

    def test_child_timeout_and_interrupt_kill_and_reap_only_owned_child(self):
        m = load()
        for error in (subprocess.TimeoutExpired(["fake"], 1), KeyboardInterrupt()):
            child = Mock()
            child.communicate.side_effect = [error, ("", "")]
            with patch.object(m.subprocess, "Popen", return_value=child):
                with self.assertRaises(type(error)):
                    m.run_child(["fake"], input="secret", timeout=1, env={})
            child.kill.assert_called_once()
            child.wait.assert_called_once()

    def test_credential_and_node_environment_overrides_are_rejected(self):
        m = load()
        for key in ("NODE_OPTIONS", "CLOUDSDK_CONFIG", "CLOUDSDK_AUTH_ACCESS_TOKEN",
                    "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_ACTIVE_CONFIG_NAME"):
            with self.subTest(key=key), patch.dict(m.os.environ, {key: "foreign"}, clear=True):
                with self.assertRaises(m.Rejected):
                    m.safe_environment()


if __name__ == "__main__":
    unittest.main()
