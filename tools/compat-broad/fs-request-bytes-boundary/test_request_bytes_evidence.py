"""The published request-byte shadow record stays bound to what produced it.

If this fails after editing a lane module, rerun the shadow. A stale published
record is a broken binding, not a cosmetic difference:

    uv run --offline --project tools/compat-inventory --locked python \\
        tools/compat-broad/fs-request-bytes-boundary/request_bytes_shadow.py \\
        --output <fresh-directory>

then copy its `local-shadow.json` over the published record.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (str(HERE), str(HERE.parent), str(ROOT / "tools/compat-inventory")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import request_bytes_shadow as shadow_module
from request_bytes_campaign import LOCAL_EXPECTATION
from request_bytes_compiler import DOCUMENT_COUNT, REQUEST_LIMIT, REQUEST_TARGETS

RECORD = ROOT / "spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json"

REGENERATE = (
    "rerun request_bytes_shadow.py and republish its local-shadow.json; the "
    "published record was produced by different modules"
)


def record() -> dict:
    return json.loads(RECORD.read_bytes())


def test_the_published_record_is_exactly_what_the_generator_emits():
    """A hand-augmented or hand-redacted evidence file must fail here."""
    value = record()
    generated = shadow_module.build_shadow_document(
        before=value["sourceDigestBefore"],
        after=value["sourceDigestAfter"],
        runtime=value["runtime"],
        plan_digest=value["planDigest"],
        campaign_digest_value=value["campaignDigest"],
        probes=value["probeOutcomes"],
        collector=value["observation"],
        shadow=value["shadow"],
        gates={
            "recordingComplete": value["recordingComplete"],
            "stateValidation": value["stateValidation"],
        },
        cases=value["cases"],
    )
    assert set(generated) == set(value), set(generated) ^ set(value)
    assert generated == value, "the published record is not the generator's output"


def test_the_published_record_was_produced_by_the_current_modules():
    value = record()
    assert value["sourceDigestBefore"] == shadow_module.observation_source_digest(), (
        REGENERATE
    )
    assert value["sourceDigestAfter"] == value["sourceDigestBefore"]


def test_the_published_record_describes_this_worktree_rust_source():
    from broad_contract import digest
    from evidence_common import runtime_inputs

    value = record()
    assert value["runtime"]["runtimeInputsDigest"] == digest(runtime_inputs(ROOT)), (
        "rerun the shadow: the recorded artifact no longer describes the Rust "
        "source in this worktree"
    )
    assert value["runtime"]["runtimeInputsClean"] is True
    assert value["runtime"]["artifactSha256"] == value["artifactSha256"]
    assert len(value["runtime"]["sourceCommit"]) == 40
    assert value["runtime"]["sourceRoot"] == shadow_module.REPOSITORY_ROOT_MARKER


def test_the_published_record_holds_the_three_boundary_probes():
    value = record()
    outcomes = {row["probe"]: row for row in value["probeOutcomes"]}
    assert [row["requestBytes"] for row in value["probeOutcomes"]] == list(
        REQUEST_TARGETS
    )
    assert outcomes["under"]["httpStatus"] == 200
    assert outcomes["exact"]["httpStatus"] == 200
    assert outcomes["exact"]["requestBytes"] == REQUEST_LIMIT
    assert outcomes["over"]["requestBytes"] == REQUEST_LIMIT + 1
    assert all(row["complete"] is True for row in value["probeOutcomes"])


def test_the_published_record_carries_the_observed_local_refusal():
    """This row is the input the limits-layer lane is told to depend on."""
    value = record()
    over = next(row for row in value["probeOutcomes"] if row["probe"] == "over")
    observed = LOCAL_EXPECTATION["observedRefusal"]
    assert over["httpStatus"] == observed["httpStatus"]
    assert over["errorCode"] == observed["errorCode"]
    assert over["errorStatus"] == observed["errorStatus"]
    assert over["errorMessage"] == observed["message"]
    assert value["shadow"]["classification"] == LOCAL_EXPECTATION["classification"]


def test_the_published_record_proved_every_owned_resource_absent():
    value = record()
    observation = value["observation"]
    assert observation["resourceAbsence"] is True
    assert observation["rowCount"] == len(REQUEST_TARGETS) * (2 * DOCUMENT_COUNT + 1)
    assert observation["recoveryRowCount"] == len(REQUEST_TARGETS) * 3 * DOCUMENT_COUNT
    assert observation["failures"] == []
    assert observation["completed"] is True


def test_the_published_record_stayed_inside_the_campaign_request_budget():
    import json as _json

    budget = _json.loads(
        (ROOT / "spec/compatibility/fs-request-bytes-budget.json").read_bytes()
    )["budget"]
    value = record()
    assert value["observation"]["requestCount"] <= budget["maxHttpRequests"]


def test_the_published_record_is_complete_and_claims_nothing():
    value = record()
    assert value["complete"] is True
    assert value["recordingComplete"] is True
    assert value["stateValidation"] is True
    assert value["productionExecuted"] is False
    assert value["formalCompatibilityClaim"] is False
    assert value["rawHttpMetricStatus"] == "observation hypothesis"
    assert value["target"] == "owned-local-artifact"
    assert value["project"] == shadow_module.PROJECT


def test_published_evidence_contains_no_absolute_filesystem_path():
    """This repository is published; a personal path must never be committed."""
    text = RECORD.read_text()
    for needle in ('"/Users/', '"/home/', '"/private/', '"/tmp/', '"/var/'):
        assert needle not in text, f"the record contains {needle}"


def test_published_evidence_contains_no_credential_material():
    text = RECORD.read_text().lower()
    for marker in ("bearer ", "authorization", "refresh_token", "private_key"):
        assert marker not in text, f"the record contains {marker}"


def test_the_published_record_is_small_enough_to_review():
    assert RECORD.stat().st_size < 64 * 1024
