import json
import re
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
try:
    from public_evidence import public_json, public_json_bytes
except ImportError:
    public_json = None
    public_json_bytes = None


def test_public_json_validates_and_returns_the_existing_serialization():
    assert callable(public_json)
    assert public_json({"b": 2, "a": 1}, indent=2, sort_keys=True) == (
        json.dumps({"b": 2, "a": 1}, indent=2, sort_keys=True) + "\n"
    )


def test_public_json_refuses_before_a_sink_can_truncate_existing_bytes(tmp_path):
    assert callable(public_json)
    output = tmp_path / "receipt.json"
    output.write_text("keep existing bytes", encoding="utf-8")
    with pytest.raises(ValueError) as raised:
        output.write_text(public_json({"path": "../../outside.json"}), encoding="utf-8")
    assert str(raised.value) == "public evidence path validation failed"
    assert output.read_text(encoding="utf-8") == "keep existing bytes"


def test_public_json_fails_closed_without_node(tmp_path, monkeypatch):
    assert callable(public_json)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ValueError, match="^public evidence validation unavailable$"):
        public_json({"safe": True})


def test_public_json_bytes_returns_the_exact_validated_snapshot():
    assert callable(public_json_bytes)
    data = b'{"path":"target/release/fireemu"}\r\n'
    assert public_json_bytes(data) is data


def test_public_json_bytes_rejects_before_any_public_copy():
    assert callable(public_json_bytes)
    data = b'{"path":"../../outside.json"}\n'
    with pytest.raises(ValueError, match="^public evidence path validation failed$"):
        public_json_bytes(data)


def test_every_auth_publisher_and_compat_index_use_the_shared_bridge():
    publishers = sorted(TOOLS.glob("publish-auth-*.py"))
    assert len(publishers) == 39
    for path in publishers:
        source = path.read_text(encoding="utf-8")
        assert "from public_evidence import public_json" in source, path.name
        assert re.search(
            r"(?:BUNDLE|bundle(?:_path)?\(trigger\))\.write_text\(\s*public_json\(value",
            source,
        ), path.name
    compatibility_publisher = TOOLS / "compat-inventory/publish.py"
    source = compatibility_publisher.read_text(encoding="utf-8")
    assert "write_index(value, serialized=index_text)" in source
