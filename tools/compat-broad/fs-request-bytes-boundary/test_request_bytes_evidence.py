"""The published request-byte shadow record stays bound to what produced it.

If this fails after editing a lane module, rerun the shadow. A stale published
record is a broken binding, not a cosmetic difference:

    uv run --offline --project tools/compat-inventory --locked python \\
        tools/compat-broad/fs-request-bytes-boundary/request_bytes_shadow.py \\
        --output <fresh-directory> --publish

which writes a new 11 MiB-specific receipt and updates the preparation citation;
the old 10 MiB receipt remains historical.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (str(HERE), str(HERE.parent), str(ROOT / "tools/compat-inventory")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pytest
import request_bytes_shadow as shadow_module
from request_bytes_campaign import (
    LOCAL_EXPECTATION,
    campaign_digest,
    compile_request_bytes_campaign,
)
from request_bytes_compiler import (
    DOCUMENT_COUNT,
    REQUEST_LIMIT,
    REQUEST_TARGETS,
    compact_utf8,
    compile_request_bytes_plan,
)

RECORD = ROOT / "spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json"

REGENERATE = (
    "rerun request_bytes_shadow.py and republish the 11 MiB local-shadow; the "
    "published record was produced by different modules"
)


def record() -> dict:
    return json.loads(RECORD.read_bytes())


def test_the_published_record_is_assembled_the_way_the_generator_assembles_it():
    """Check the record's assembly, which is all this particular check can do.

    The generator is fed the record's own blocks, so this catches a changed,
    added or dropped top-level key, a `complete` flag that does not follow from
    the parts, and any constant the generator fills in itself. It does **not**
    validate the contents of `shadow`, `observation`, `runtime`, `probeOutcomes`
    or `cases`, because those are the inputs. The two checks below recompute
    `shadow` and the gates from `observation`, which is what closes that gap;
    `runtime`, `probeOutcomes` and `slotTimings` are pinned by the binding,
    boundary and timing checks further down.
    """
    value = record()
    generated = shadow_module.build_shadow_document(
        before=value["sourceDigestBefore"],
        after=value["sourceDigestAfter"],
        runtime=value["runtime"],
        nonce=value["nonce"],
        plan_digest=value["planDigest"],
        campaign_digest_value=value["campaignDigest"],
        probes=value["probeOutcomes"],
        timings=value["slotTimings"],
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


def test_published_journal_is_compact_but_bound_to_the_private_capture():
    observation = record()["observation"]
    journal = observation["localJournal"]
    assert journal["captureComplete"] is True
    assert journal["rowCount"] == 258
    assert journal["sidecarCount"] == observation["requestCount"]
    assert journal["skippedCount"] == 17
    assert journal["skippedSummary"] == [
        {
            "probe": "over",
            "kind": "cleanup-version-bound-delete",
            "reason": "creation-and-current-version-not-proven",
            "count": 17,
        }
    ]
    assert "rowEntries" not in journal
    assert "sidecarEntries" not in journal


def test_the_published_classification_recomputes_from_the_published_observation():
    """A hand-edited `shadow` block must fail here."""
    value = record()
    assert value["shadow"] == shadow_module.classify_local_result(
        value["observation"]
    ), "the recorded classification does not follow from the recorded observation"


def test_the_published_gates_recompute_from_the_published_observation():
    """A hand-edited `recordingComplete` or `stateValidation` must fail here."""
    value = record()
    gates = shadow_module.shadow_gates(
        value["observation"],
        value["shadow"],
        source_bound=value["sourceDigestBefore"] == value["sourceDigestAfter"],
    )
    assert gates == {
        "recordingComplete": value["recordingComplete"],
        "stateValidation": value["stateValidation"],
    }, "the recorded gates do not follow from the recorded observation"


def test_the_published_cases_recompute_from_the_compiled_campaign():
    """A hand-edited status, localObserved or requestBytes must fail here."""
    value = record()
    campaign = compile_request_bytes_campaign(
        value["project"], value["database"], value["nonce"]
    )
    assert value["cases"] == shadow_module.shadow_cases(
        campaign["cases"], value["shadow"]
    ), "the recorded case table does not follow from the compiled campaign"


@pytest.mark.parametrize(
    "field",
    ["status", "localObserved", "requestBytes", "productionExpectation", "basis"],
)
def test_a_tampered_case_row_is_rejected(field):
    """The case block used to be an unbound input fed straight back in."""
    value = record()
    campaign = compile_request_bytes_campaign(
        value["project"], value["database"], value["nonce"]
    )
    tampered = json.loads(json.dumps(value["cases"]))
    tampered[-1][field] = "tampered"
    assert tampered != shadow_module.shadow_cases(campaign["cases"], value["shadow"])


def test_the_published_digests_recompute_from_the_published_nonce():
    """The nonce is published so a reader need not take the digests on trust."""
    value = record()
    plan = compile_request_bytes_plan(
        value["project"], value["database"], value["nonce"]
    )
    campaign = compile_request_bytes_campaign(
        value["project"], value["database"], value["nonce"]
    )
    assert value["planDigest"] == hashlib.sha256(compact_utf8(plan)).hexdigest()
    assert value["campaignDigest"] == campaign_digest(campaign)


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
    assert value["runtime"]["sourceRoot"] == shadow_module.REPOSITORY_ROOT_MARKER


def test_the_recorded_source_commit_is_a_real_commit_in_this_repository():
    """A length check accepted any 40 characters, including invented ones.

    The recorded commit has to exist here and be an ancestor of, or equal to,
    what the evidence test is running against. A fabricated value fails the
    existence check; a commit borrowed from an unrelated branch fails ancestry.
    A shallow clone cannot answer either question, so it is skipped explicitly
    rather than passed silently.

    Ancestry holds because this lane is integrated with a no-ff merge commit and
    never squashed, which keeps the recorded commit reachable from the
    integrated tip. If that policy ever changes, this check will fail and the
    failure will mean the merge policy changed, not that the record was
    tampered with.
    """
    commit = record()["runtime"]["sourceCommit"]
    assert re.fullmatch(r"[0-9a-f]{40}", commit), "source commit is not a SHA-1"

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
        )

    if git("rev-parse", "--git-dir").returncode != 0:
        pytest.skip("not a git checkout, so the commit cannot be resolved")
    if git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        pytest.skip("shallow clone: earlier commits are absent by construction")
    kind = git("cat-file", "-t", commit)
    assert kind.returncode == 0 and kind.stdout.strip() == "commit", (
        f"the recorded source commit {commit} is not a commit in this repository"
    )
    assert git("merge-base", "--is-ancestor", commit, "HEAD").returncode == 0, (
        f"the recorded source commit {commit} is not an ancestor of HEAD"
    )


def test_an_invented_source_commit_would_not_resolve():
    """The control for the check above: a well-formed SHA that is not here."""
    invented = "0" * 40
    result = subprocess.run(
        ["git", "cat-file", "-t", invented],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0 or result.stdout.strip() != "commit"


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
    # The verbatim bytes, so a reader never has to trust the parsed summary.
    assert json.loads(over["responseBody"]) == {
        "error": {
            "code": observed["errorCode"],
            "message": observed["message"],
            "status": observed["errorStatus"],
        }
    }


def test_the_accepted_probes_publish_a_digest_rather_than_their_body():
    value = record()
    for probe in ("under", "exact"):
        row = next(r for r in value["probeOutcomes"] if r["probe"] == probe)
        assert row["responseBody"] is None
        assert len(row["responseSha256"]) == 64


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
    # Spelled without the literal prefixes so the publication hygiene guard,
    # which scans this file too, does not trip on the needles themselves.
    for root in ("Users", "home", "private", "tmp", "var"):
        needle = '"/' + root + "/"
        assert needle not in text, f"the record contains {needle}"


def test_published_evidence_contains_no_credential_material():
    text = RECORD.read_text().lower()
    for marker in ("bearer ", "authorization", "refresh_token", "private_key"):
        assert marker not in text, f"the record contains {marker}"


def test_the_published_record_is_small_enough_to_review():
    assert RECORD.stat().st_size < 64 * 1024


# --- The published timings are a floor, and say so ---------------------------


def test_the_published_timings_are_internally_consistent():
    value = record()
    shadow_module.validate_slot_timings(
        value["slotTimings"], value["observation"]["requestCount"]
    )


def test_the_published_timings_are_labelled_a_floor_not_an_estimate():
    """Anyone citing these must be told what they exclude."""
    timings = record()["slotTimings"]
    assert timings["measurement"] == "loopback-floor"
    assert timings["isProductionEstimate"] is False
    for phrase in ("round trip", "TLS", "floor", "never an estimate"):
        assert phrase in timings["disclaimer"]


def test_the_published_timings_separate_the_two_slot_classes():
    timings = record()["slotTimings"]["classes"]
    assert set(timings) == {"boundaryCommit", "smallRequest"}
    assert timings["boundaryCommit"]["count"] == len(REQUEST_TARGETS)
    # The 255 non-Commit slots minus the over probe's zero-wire delete skips.
    assert timings["smallRequest"]["count"] > 200
    assert (
        timings["boundaryCommit"]["count"] + timings["smallRequest"]["count"]
        == record()["observation"]["requestCount"]
    )


def test_the_published_timings_cover_only_slots_that_sent_something():
    """A zero-wire skip costs no time and must not enter a percentile."""
    value = record()
    assert (
        value["slotTimings"]["dispatchedCount"] == value["observation"]["requestCount"]
    )
    assert value["slotTimings"]["dispatchedCount"] < 258


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda t: t["classes"]["smallRequest"].update(medianSeconds=9.0),
            id="median-above-p99",
        ),
        pytest.param(
            lambda t: t["classes"]["smallRequest"].update(p99Seconds=0.0),
            id="p99-below-median",
        ),
        pytest.param(
            lambda t: t["classes"]["smallRequest"].update(count=1),
            id="count-does-not-sum",
        ),
        pytest.param(
            lambda t: t.update(isProductionEstimate=True), id="claimed-as-an-estimate"
        ),
        pytest.param(lambda t: t.update(disclaimer=""), id="disclaimer-stripped"),
        pytest.param(
            lambda t: t.update(measurement="production"), id="mislabelled-measurement"
        ),
        pytest.param(lambda t: t["classes"].pop("boundaryCommit"), id="classes-merged"),
        pytest.param(
            lambda t: t["classes"]["boundaryCommit"].update(totalSeconds=0.0),
            id="total-below-maximum",
        ),
    ],
)
def test_a_tampered_timing_block_is_rejected(mutate):
    value = record()
    timings = json.loads(json.dumps(value["slotTimings"]))
    mutate(timings)
    with pytest.raises((ValueError, TypeError, KeyError)):
        shadow_module.validate_slot_timings(
            timings, value["observation"]["requestCount"]
        )


def test_the_preparation_doc_citation_is_generated_from_the_published_record():
    """The prose and the record must name the same run.

    They drifted once: a rebind updated the record and left the document citing
    an earlier run's commit and artifact, so the published narrative described
    evidence that was no longer published. The citation block is now generated,
    so the two cannot disagree; this compares it against what the generator
    emits for the record as published.
    """
    value = record()
    doc = (ROOT / shadow_module.PREPARATION_DOC).read_text()
    assert shadow_module.CITATION_BEGIN in doc
    assert shadow_module.CITATION_END in doc
    expected = shadow_module.citation_block(value)
    begin = doc.index(shadow_module.CITATION_BEGIN)
    end = doc.index(shadow_module.CITATION_END) + len(shadow_module.CITATION_END)
    assert doc[begin:end] == expected, (
        "the preparation document's evidence citation does not match the "
        "published record. Rebind both with one command:\n\n    "
        + shadow_module.REBIND_COMMAND
    )


def test_the_citation_rewrite_leaves_the_hand_written_document_alone():
    """Only the delimited block is generated."""
    value = record()
    doc = (ROOT / shadow_module.PREPARATION_DOC).read_text()
    rewritten = shadow_module.rewrite_citation(doc, value)
    assert rewritten == doc
    head = doc.split(shadow_module.CITATION_BEGIN)[0]
    tail = doc.split(shadow_module.CITATION_END)[1]
    assert head == rewritten.split(shadow_module.CITATION_BEGIN)[0]
    assert tail == rewritten.split(shadow_module.CITATION_END)[1]
    assert "## Artifacts" in tail or "## Artifacts" in head


def test_a_document_without_markers_is_refused_rather_than_guessed_at():
    value = record()
    with pytest.raises(ValueError, match="citation markers"):
        shadow_module.rewrite_citation("# A document with no markers\n", value)


def test_the_rebind_command_is_documented_where_it_is_needed():
    """A failure message naming a command nobody wrote down is not a fix."""
    readme = (
        ROOT / "tools/compat-broad/fs-request-bytes-boundary/README.md"
    ).read_text()
    assert shadow_module.REBIND_COMMAND in readme
    assert "--publish" in shadow_module.REBIND_COMMAND
