"""Part selection must survive the local supervisor's fixed child arguments.

The supervisor and daemon workload are test doubles. The selected entrypoint,
argparse boundary, and subprocess lifecycle are real. No production access.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import broad
import shadow_03 as shadow

NONCE = "1" * 32
PINS = {"test-only-source": "a" * 64}

CHILD_PROBE = r"""
import json
import os
from pathlib import Path
import runpy
import sys
entry = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(entry.parent))
import shadow_03

def capture(output, nonce, part="ALL", index_profile="historical"):
    print(json.dumps({"part": part, "indexProfile": index_profile,
                      "nonce": nonce, "output": str(output), "pid": os.getpid()}))

shadow_03._real_child = capture
arguments = sys.argv[2:]
if entry.name == "shadow_03.py":
    raise SystemExit(shadow_03.main(arguments))
sys.argv = [str(entry), *arguments]
runpy.run_path(str(entry), run_name="__main__")
"""


def probe_child(entry, output, index_profile):
    arguments = ["--child", str(output), "--nonce", NONCE]
    if index_profile != "historical":
        arguments.extend(["--index-profile", index_profile])
    environment = {k: os.environ[k] for k in ("PATH", "PYTHONPATH") if k in os.environ}
    with subprocess.Popen(
        [sys.executable, "-B", "-c", CHILD_PROBE, str(entry), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        code, pid = process.returncode, process.pid
    assert code == 0, stderr
    assert process.poll() is not None
    assert process.stdout.closed and process.stderr.closed
    result = json.loads(stdout)
    assert result["pid"] == pid
    return result


def install_supervisor(
    monkeypatch, *, status="completed", child_pins=None, child_result=None, launch=True
):
    observed = {}
    monkeypatch.setattr(shadow, "source_inputs", lambda: copy.deepcopy(PINS))
    monkeypatch.setattr(
        shadow, "save", lambda path, value: path.write_text(json.dumps(value))
    )

    def supervise(output, **options):
        observed.update(options)
        output.mkdir()
        (output / "manifest.json").write_text('{"fixture":"supervisor"}')
        dispatch = (
            probe_child(options["child_script"], output, options["index_profile"])
            if launch
            else None
        )
        if child_result is not None:
            child_receipt = child_result
        elif dispatch is not None:
            child_part = dispatch["part"]
            child_receipt = {
                "part": child_part,
                "campaignId": "FS-WRITE-LIMITS-03"
                + ("" if child_part == "ALL" else child_part),
            }
        else:
            child_receipt = None
        if child_receipt is not None:
            (output / "result.json").write_text(json.dumps(child_receipt))
        return {
            "status": status,
            "manifest": {
                "sourceInputs": copy.deepcopy(
                    PINS if child_pins is None else child_pins
                )
            },
            "childDispatch": dispatch,
        }

    monkeypatch.setattr(broad, "run", supervise)
    return observed


@pytest.mark.parametrize("part", ["A", "B", "ALL"])
@pytest.mark.parametrize("profile", ["historical", "nx-local"])
def test_parent_selection_reaches_child_and_matches_binding(
    monkeypatch, tmp_path, part, profile
):
    observed = install_supervisor(monkeypatch)
    output = tmp_path / "run"
    result = shadow.run(output, part, profile)
    binding = json.loads((output / "shadow-binding.json").read_text())
    assert result["childDispatch"]["part"] == binding["part"] == part
    assert result["childDispatch"]["indexProfile"] == profile
    assert result["childDispatch"]["nonce"] == NONCE
    assert result["childDispatch"]["output"] == str(output.resolve())
    assert binding["campaignId"] == "FS-WRITE-LIMITS-03" + (
        "" if part == "ALL" else part
    )
    assert binding["bound"] is True
    assert (
        binding["supervisorManifestSha256"]
        == hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest()
    )
    assert result["status"] == "completed"
    assert observed["project"] == "demo-firestore-probe"
    from compiler_03 import compile_limits_plan

    gate_plan = compile_limits_plan(
        "demo-firestore-probe", "(default)", "0" * 32, part
    )["localGatePlan"]
    assert observed["execution_timeout"] == (
        math.ceil(gate_plan["wallSeconds"]) + shadow.SHADOW_STARTUP_HEADROOM_SECONDS
    )
    assert observed["recovery_grace"] == 1
    assert observed["retain_executed_artifact"] is True
    assert observed["configuration"] == {"daemon": {"authProjectNumbers": {}}}


def test_default_selection_remains_all(monkeypatch, tmp_path):
    install_supervisor(monkeypatch)
    result = shadow.run(tmp_path / "run")
    assert result["childDispatch"]["part"] == "ALL"
    assert result["childDispatch"]["indexProfile"] == "historical"


@pytest.mark.parametrize("part", ["A", "B", "ALL"])
@pytest.mark.parametrize("profile", ["historical", "nx-local"])
def test_direct_child_cli_preserves_explicit_arguments(
    monkeypatch, tmp_path, part, profile
):
    captured = []
    monkeypatch.setattr(shadow, "_real_child", lambda *args: captured.append(args))
    assert (
        shadow.main(
            [
                "--child",
                str(tmp_path),
                "--nonce",
                NONCE,
                "--part",
                part,
                "--index-profile",
                profile,
            ]
        )
        == 0
    )
    assert captured == [(tmp_path.resolve(), NONCE, part, profile)]


@pytest.mark.parametrize("part", ["C", "a", ""])
def test_invalid_cli_part_never_starts_supervisor(monkeypatch, tmp_path, part):
    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid selection must not launch a supervisor")

    monkeypatch.setattr(shadow, "run", forbidden)
    with pytest.raises(SystemExit) as error:
        shadow.main(["--output", str(tmp_path), "--part", part])
    assert error.value.code == 2


def test_failed_supervisor_result_is_not_promoted(monkeypatch, tmp_path):
    install_supervisor(monkeypatch, status="incomplete", launch=False)
    assert shadow.run(tmp_path / "run", "A")["status"] == "incomplete"


def test_source_binding_failure_is_not_promoted(monkeypatch, tmp_path):
    install_supervisor(monkeypatch, child_pins={"different": "b" * 64}, launch=False)
    result = shadow.run(tmp_path / "run", "A")
    assert result["status"] == "incomplete"
    assert result["shadowBindingFailure"] is True


def test_missing_child_identity_breaks_binding(monkeypatch, tmp_path):
    install_supervisor(monkeypatch, launch=False)
    result = shadow.run(tmp_path / "run", "A")
    binding = json.loads((tmp_path / "run" / "shadow-binding.json").read_text())
    assert binding["childPart"] is None
    assert binding["childCampaignId"] is None
    assert binding["bound"] is False
    assert result["status"] == "incomplete"
    assert result["shadowBindingFailure"] is True


@pytest.mark.parametrize(
    ("child_part", "child_campaign_id"),
    [
        ("ALL", "FS-WRITE-LIMITS-03"),
        ("A", "FS-WRITE-LIMITS-03"),
        ("ALL", "FS-WRITE-LIMITS-03A"),
    ],
)
def test_child_identity_mismatch_breaks_binding_even_when_source_pins_match(
    monkeypatch, tmp_path, child_part, child_campaign_id
):
    install_supervisor(
        monkeypatch,
        child_result={"part": child_part, "campaignId": child_campaign_id},
    )
    result = shadow.run(tmp_path / "run", "A")
    binding = json.loads((tmp_path / "run" / "shadow-binding.json").read_text())
    assert binding["sourceInputsBefore"] == binding["sourceInputsAfter"]
    assert binding["childPart"] == child_part
    assert binding["childCampaignId"] == child_campaign_id
    assert binding["bound"] is False
    assert result["status"] == "incomplete"
    assert result["shadowBindingFailure"] is True


def test_new_entrypoint_is_in_source_digest_map(monkeypatch, tmp_path):
    lane = tmp_path / "tools/compat-broad/fs-write-limits"
    lane.mkdir(parents=True)
    for name in ("shadow_03.py", "shadow_03a.py", "shadow_03b.py"):
        source = HERE / name
        assert source.is_file(), f"missing entrypoint: {name}"
        (lane / name).write_bytes(source.read_bytes())
    catalog = tmp_path / "catalog.json"
    catalog.write_text("{}")
    monkeypatch.setattr(shadow, "HERE", lane)
    monkeypatch.setattr(shadow, "ROOT", tmp_path)
    monkeypatch.setattr(shadow, "_CATALOG", catalog)
    actual = shadow.source_inputs()
    for name in ("shadow_03.py", "shadow_03a.py", "shadow_03b.py"):
        relative = f"tools/compat-broad/fs-write-limits/{name}"
        assert (
            actual[relative] == hashlib.sha256((lane / name).read_bytes()).hexdigest()
        )


@pytest.mark.parametrize("conflicting", ["B", "ALL"])
def test_a_entrypoint_stays_pinned_to_a(monkeypatch, tmp_path, conflicting):
    entry = HERE / "shadow_03a.py"
    assert entry.is_file()
    captured = []
    monkeypatch.setattr(shadow, "_real_child", lambda *args: captured.append(args))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(entry), "--child", str(tmp_path), "--nonce", NONCE, "--part", conflicting],
    )
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(entry), run_name="__main__")
    assert error.value.code == 0
    assert captured == [(tmp_path.resolve(), NONCE, "A", "historical")]
