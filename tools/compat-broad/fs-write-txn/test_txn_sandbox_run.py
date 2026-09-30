"""Two recordings use one project lock and never repeat an incomplete pass."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_sandbox_run as runner
import txn_sandbox_runtime as runtime
from test_txn_sandbox_admission import DECISION, LAST, NOW, PINS
from test_txn_sandbox_contract import receipt


@pytest.mark.parametrize("other_project_finishes", [False, True])
def test_exception_request_count_is_saved_without_exception_text_before_the_stop_row(tmp_path, other_project_finishes):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)

    def stopped(*args):
        if other_project_finishes:
            runner.admission.append_ledger(ledger, {
                "ts": "2026-09-27T15:30:00Z", "project": "fireemu-oracle-idp",
                "taskId": "OTHER", "outcome": "recorded", "attemptId": "another-project",
            })
        error = ValueError("private-token-must-not-be-saved")
        error.sandbox_requests = 4
        raise error

    with pytest.raises(ValueError):
        runner.record_twice(ledger_path=ledger, private_dir=tmp_path, pins=PINS,
                            decisions=DECISION, now=NOW, record_once=stopped)
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["requests"] == 4
    assert rows[-1]["requestCountBasis"] == "precharged-upper-bound"
    failure = Path(rows[-1]["runDir"]) / "failure-1.json"
    assert json.loads(failure.read_text()) == {
        **runtime.evidence(),
        "failureType": "ValueError", "sandboxRequests": 4,
        "requestCountBasis": "precharged-upper-bound",
    }
    assert "private-token" not in failure.read_text() + ledger.read_text()
    assert (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()


def test_two_complete_recordings_freeze_under_one_lock(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)
    calls = []
    checked = []

    def recheck():
        checked.append((tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists())

    def record(index, nonce, owner, directory):
        calls.append((index, nonce, owner, directory))
        assert (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
        answer = receipt(nonce)
        answer["requestCount"] = 70 + index
        answer["sandboxRequests"] = 70 + index
        return answer

    result = runner.record_twice(
        ledger_path=ledger,
        private_dir=tmp_path,
        pins=PINS,
        decisions=DECISION,
        now=lambda: NOW,
        record_once=record,
        admission_check=recheck,
    )
    assert checked == [True]
    assert len(calls) == 2
    assert calls[0][1] != calls[1][1]
    assert calls[0][2] != calls[1][2]
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
    assert Path(result["freezePath"]).exists()
    assert len(json.loads(Path(result["freezePath"]).read_text())["cases"]) == 13
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["outcome"] for row in rows[1:]] == [
        "reserved", "recorded", "reserved", "recorded"
    ]
    assert rows[2]["requests"] == 70 and rows[4]["requests"] == 71
    assert all(row["envelopeId"] == PINS["envelopeId"] for row in rows[1:])
    assert all(all(row[key] == value for key, value in runtime.evidence().items()) for row in rows[1:])


def test_incomplete_first_pass_keeps_lock_and_skips_second(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)
    calls = []

    def record(index, nonce, owner, directory):
        calls.append(index)
        answer = receipt(nonce)
        answer["complete"] = False
        answer["unrecovered"] = ["control"]
        answer["sandboxRequests"] = 70
        return answer

    with pytest.raises(ValueError, match="incomplete"):
        runner.record_twice(
            ledger_path=ledger,
            private_dir=tmp_path,
            pins=PINS,
            decisions=DECISION,
            now=NOW,
            record_once=record,
        )
    assert calls == [0]
    assert (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["outcome"] == "needs-recovery"


def test_freeze_mismatch_records_a_stopped_row_and_private_differences(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)

    def record(index, nonce, owner, directory):
        answer = receipt(nonce)
        answer["sandboxRequests"] = 70
        if index == 1:
            answer["rows"][0]["observed"]["code"] = 13
        return answer

    with pytest.raises(ValueError, match="recordings differ"):
        runner.record_twice(
            ledger_path=ledger, private_dir=tmp_path, pins=PINS,
            decisions=DECISION, now=NOW, record_once=record,
        )
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["outcome"] == "stopped-needs-review"
    assert rows[-1]["reason"] == "freeze-mismatch"
    assert (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
    differences = json.loads((Path(rows[-1]["runDir"]) / "freeze-differences.json").read_text())
    assert differences["differences"]


def test_keyboard_interrupt_still_records_a_stop_and_keeps_the_lock(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)

    def interrupted(*_args):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        runner.record_twice(
            ledger_path=ledger, private_dir=tmp_path, pins=PINS,
            decisions=DECISION, now=NOW, record_once=interrupted,
        )
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["outcome"] == "stopped-needs-review"
    assert (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()


def test_missing_owner_approval_does_not_take_lock_or_send(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)
    calls = []
    with pytest.raises(ValueError, match="owner"):
        runner.record_twice(
            ledger_path=ledger,
            private_dir=tmp_path,
            pins=PINS,
            decisions="",
            now=datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc),
            record_once=lambda *_args: calls.append(1),
        )
    assert calls == []
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
    assert len(ledger.read_text().splitlines()) == 1


def test_legacy_shared_lock_prevents_any_recording(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)
    (tmp_path / "sandbox-ledger.jsonl.lock").write_text("legacy")
    calls = []
    with pytest.raises(FileExistsError, match="legacy"):
        runner.record_twice(
            ledger_path=ledger,
            private_dir=tmp_path,
            pins=PINS,
            decisions=DECISION,
            now=NOW,
            record_once=lambda *_args: calls.append(1),
        )
    assert calls == [] and len(ledger.read_text().splitlines()) == 1
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
