"""Two recordings use one shared lock and never repeat an incomplete pass."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_sandbox_run as runner
from test_txn_sandbox_admission import DECISION, LAST, NOW, PINS
from test_txn_sandbox_contract import receipt


def test_two_complete_recordings_freeze_under_one_lock(tmp_path):
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n")
    ledger.chmod(0o600)
    calls = []
    checked = []

    def recheck():
        checked.append((tmp_path / "sandbox-ledger.jsonl.lock").exists())

    def record(index, nonce, owner, directory):
        calls.append((index, nonce, owner, directory))
        assert (tmp_path / "sandbox-ledger.jsonl.lock").exists()
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
    assert not (tmp_path / "sandbox-ledger.jsonl.lock").exists()
    assert Path(result["freezePath"]).exists()
    assert len(json.loads(Path(result["freezePath"]).read_text())["cases"]) == 13
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["outcome"] for row in rows[1:]] == [
        "reserved", "recorded", "reserved", "recorded"
    ]
    assert rows[2]["requests"] == 70 and rows[4]["requests"] == 71


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
    assert (tmp_path / "sandbox-ledger.jsonl.lock").exists()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["outcome"] == "needs-recovery"


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
    assert not (tmp_path / "sandbox-ledger.jsonl.lock").exists()
    assert len(ledger.read_text().splitlines()) == 1
