import json
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
COMPARISON = (
    REPOSITORY
    / "spec/compatibility/broad-runs/fs-stream-half-close-1cb475837-current-comparison.json"
)


def test_published_fs_stream_comparison_uses_a_relative_local_run_path():
    comparison = json.loads(COMPARISON.read_text(encoding="utf-8"))

    local_run_path = Path(comparison["localRunPath"])

    assert not local_run_path.is_absolute()
