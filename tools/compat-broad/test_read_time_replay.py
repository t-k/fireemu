from pathlib import Path

import pytest


def test_saved_read_time_record_is_pinned_and_current_program_matches():
    import broad
    from broad import digest
    from read_time_replay import PROGRAM_DIGEST, load_saved_program

    saved = load_saved_program(Path("spec/compatibility/broad-runs/a12183a0-second-current.json"))
    program = next(p for p in broad.programs("firestore")[0] if p["id"] == "reads/read-time")
    assert saved["status"] == "completed"
    assert digest(program) == PROGRAM_DIGEST


def test_saved_read_time_record_rejects_byte_mutation(tmp_path):
    from read_time_replay import load_saved_program

    source = Path("spec/compatibility/broad-runs/a12183a0-second-current.json")
    mutated = tmp_path / "saved.json"
    mutated.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_saved_program(mutated)
