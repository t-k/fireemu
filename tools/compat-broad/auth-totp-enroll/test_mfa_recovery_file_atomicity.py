"""Owner review 95c5b994a item 1: the private recovery files never observe a
partial write.

`config-lock.json` (`mfa_config_lock._private_write`), `run-state.json`
(`mfa_production._write_private`) and the Gate's bindings file
(`mfa_gate.MfaGate._save_bindings`) were each rewritten with a truncate-then-write
in place. A stop between the truncate and the write left a zero-byte file, and
`--resume` / `--abandon` read each of these whole before anything else, so
recovery failed before it started. All three now write a freshly created,
uniquely named temporary file in the same directory, fsync it, and rename it onto
the target with `os.replace`; a reader of the target only ever sees the previous
complete record or the new one, never neither. `_save_bindings` was not one of
the review's cited lines, but it is the same private run directory and the same
defect class, so it is fixed the same way here.

These are unit-level fault injections against the three write helpers directly,
matching the idiom `test_mfa_durable_responsibility.py` already uses for the
local-shadow checkpoint. No network, no credential, no production access.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import mfa_config_lock
import mfa_gate
import mfa_production

BEFORE = {"synthetic": True, "changeAttempted": True, "ticket": "local-fixture"}
AFTER = {"synthetic": True, "next": 2}

WRITERS = {
    "config-lock": (mfa_config_lock._private_write, mfa_config_lock._private_read),
    "run-state": (mfa_production._write_private, mfa_production._read_private),
}


@pytest.mark.parametrize("target", ["config-lock", "run-state"])
@pytest.mark.parametrize("fault", ["file-fsync", "replace"])
def test_a_fault_at_any_point_before_replace_preserves_the_previous_complete_record(
    tmp_path, monkeypatch, target, fault
):
    # `stream.write()` on the `os.fdopen`-wrapped temp file (same shape as the
    # already-reviewed `mfa_production._write_immutable`) goes through CPython's
    # buffered-IO layer, not the `os.write` symbol, so a short/zero write is not
    # injectable at this layer; `fsync` and `replace` are the two calls this code
    # makes directly and are exactly where a real stop's outcome is decided. The
    # subprocess tests below cover an actual process death at both sides of the
    # rename, which is the fault the review is about.
    write, read = WRITERS[target]
    path = tmp_path / f"{target}.json"
    write(path, BEFORE)
    old = path.read_bytes()

    if fault == "file-fsync":
        real_fsync = os.fsync

        def broken(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("sync failed")
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", broken)
    else:  # replace
        monkeypatch.setattr(
            os,
            "replace",
            lambda *a, **k: (_ for _ in ()).throw(OSError("rename failed")),
        )

    with pytest.raises(OSError):
        write(path, AFTER)
    # The target is exactly the previous complete record: never truncated, never
    # partially overwritten, and no leftover temp file masquerades as it.
    assert path.read_bytes() == old
    assert read(path) == BEFORE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("target", ["config-lock", "run-state"])
@pytest.mark.parametrize("where", ["before-replace", "after-replace"])
def test_process_death_around_the_atomic_replace_keeps_old_or_new_complete(
    tmp_path, target, where
):
    """A real crash (not a raised exception) either side of `os.replace`."""
    module = "mfa_config_lock" if target == "config-lock" else "mfa_production"
    function = "_private_write" if target == "config-lock" else "_write_private"
    path = tmp_path / f"{target}.json"
    write, read = WRITERS[target]
    write(path, BEFORE)
    old = path.read_bytes()

    script = f"""
import os, sys
sys.path.insert(0, {str(HERE)!r})
sys.path.insert(0, {str(ROOT / "tools/compat-broad")!r})
sys.path.insert(0, {str(ROOT / "tools/compat-broad/production-admission")!r})
sys.path.insert(0, {str(ROOT / "tools/compat-broad/o8-core")!r})
import {module} as m
original = os.replace
def die(*args, **kwargs):
    if {where!r} == "after-replace":
        original(*args, **kwargs)
    os._exit(17)
os.replace = die
m.{function}(__import__("pathlib").Path(sys.argv[1]), {AFTER!r})
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", script, str(path)],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 17, result.stderr
    data = path.read_bytes()
    # Readable either way, and exactly the previous or the new record: never a
    # truncated or partially written file.
    parsed = json.loads(data)
    if where == "before-replace":
        assert data == old
        assert parsed == BEFORE
    else:
        assert parsed == AFTER
    assert read(path) == parsed


@pytest.mark.parametrize("target", ["config-lock", "run-state"])
def test_a_leftover_temp_file_from_an_interrupted_write_is_ignored_on_resume(
    tmp_path, target
):
    write, read = WRITERS[target]
    path = tmp_path / f"{target}.json"
    write(path, BEFORE)
    # A stop between temp creation and the rename leaves an unreferenced,
    # uniquely named sibling file; simulate it directly rather than via a fault.
    stray = tmp_path / f".{path.name}.leftover-from-a-dead-process"
    stray.write_bytes(b"{}")
    stray.chmod(0o600)
    # Resume reads the target by its exact name; the stray file is invisible to it.
    assert read(path) == BEFORE
    # And a later, real write is unaffected: it picks its own fresh unique name
    # and still replaces the target atomically.
    write(path, AFTER)
    assert read(path) == AFTER
    assert stray.read_bytes() == b"{}"
    assert stray.exists()


def test_the_gate_bindings_file_is_written_the_same_atomic_way(tmp_path, monkeypatch):
    """`MfaGate._save_bindings` shares the shape; exercise its own write path."""
    path = tmp_path / mfa_gate.BINDINGS_FILE

    class Bindings:
        def __init__(self):
            self._bindings_path = path
            self.bindings = {"password": "seed"}
            self._observed = {"pendingControlUid": "uid-one"}

        _save_bindings = mfa_gate.MfaGate._save_bindings

    record = Bindings()
    record._save_bindings()
    old = path.read_bytes()
    assert json.loads(old) == {
        "bindings": {"password": "seed"},
        "observed": {"pendingControlUid": "uid-one"},
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    monkeypatch.setattr(
        os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("rename failed"))
    )
    record.bindings["password"] = "changed"
    with pytest.raises(OSError):
        record._save_bindings()
    assert path.read_bytes() == old
