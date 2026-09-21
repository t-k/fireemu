"""Read-only evidence and recovery-allocation contract tests."""

from pathlib import Path
import os
import sys
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reservations


def test_bounded_evidence_reader_rejects_symlink_and_fifo(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="canonical evidence"):
        reservations.Ledger._read_bounded_json(link)

    fifo = tmp_path / "evidence.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular evidence"):
        reservations.Ledger._read_bounded_json(fifo)


def test_bounded_evidence_reader_rejects_changed_file_after_read(tmp_path, monkeypatch):
    path = tmp_path / "evidence.json"
    path.write_text("{}")
    original_fstat = reservations.os.fstat
    calls = 0

    def changed_fstat(descriptor):
        nonlocal calls
        calls += 1
        value = original_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_mode=value.st_mode,
                st_ino=value.st_ino,
                st_dev=value.st_dev,
                st_size=value.st_size + 1,
                st_mtime_ns=value.st_mtime_ns,
                st_ctime_ns=value.st_ctime_ns,
            )
        return value

    monkeypatch.setattr(reservations.os, "fstat", changed_fstat)
    with pytest.raises(ValueError, match="stable evidence"):
        reservations.Ledger._read_bounded_json(path)
