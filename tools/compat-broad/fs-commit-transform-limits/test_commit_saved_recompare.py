"""Offline recompare of a saved receipt under a repaired comparator."""

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commit_acquisition as acquisition
import commit_saved_recompare as recompare
from commit_reserved_adapter import ROOT
from test_commit_acquisition import fixture
from test_transform_comparator import _recovery_rows, _rows

LANE = ROOT / "tools/compat-broad/fs-commit-transform-limits"


def _saved(tmp_path, monkeypatch):
    inputs, _, _, kwargs = fixture(tmp_path, monkeypatch)
    output = tmp_path / "output"
    released = acquisition.run_acquisition(output, inputs, **kwargs)
    assert released["reservationReleased"] is True
    plan = inputs["plan"]
    reference = tmp_path / "reference.json"
    reference.write_text(
        json.dumps({"plan": plan, "rows": _rows(plan), "cleanup": _recovery_rows(plan)})
    )
    return inputs, output, reference


def test_saved_recompare_binds_both_comparators_without_production(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    record = recompare.recompare_saved(
        output,
        reference,
        expected_inputs_digest=inputs["inputsDigest"],
        comparator_root=LANE,
        expected_execution_kind="injected-transport",
    )
    assert record["newProductionRequests"] == 0
    assert record["productionExecuted"] is False
    assert record["frozen"]["classification"] == "MATCH"
    assert record["repaired"]["classification"] == "MATCH"
    assert sum(record["repaired"]["rowClassificationCounts"].values()) == 17
    binding = record["binding"]
    assert binding["expectedInputsDigest"] == inputs["inputsDigest"]
    assert set(binding["comparatorSourceSha256"]) == {
        "transform_comparator.py",
        "transform_compiler.py",
    }
    assert (
        binding["comparatorSourceSha256"]["transform_comparator.py"]
        == binding["frozenComparatorSourceSha256"]["transform_comparator.py"]
    )


def test_saved_recompare_still_validates_the_immutable_saved_records(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    (output / "collection/observation-00.json").write_text("{}")
    with pytest.raises(ValueError, match="saved row journal differs"):
        recompare.recompare_saved(
            output,
            reference,
            expected_inputs_digest=inputs["inputsDigest"],
            comparator_root=LANE,
            expected_execution_kind="injected-transport",
        )


def test_saved_recompare_refuses_a_comparator_root_without_sources(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    empty = tmp_path / "empty-comparator-root"
    empty.mkdir()
    with pytest.raises(ValueError, match="regular non-empty file required"):
        recompare.recompare_saved(
            output,
            reference,
            expected_inputs_digest=inputs["inputsDigest"],
            comparator_root=empty,
            expected_execution_kind="injected-transport",
        )


SLEEP_SECONDS = 2.0
SWAP_AFTER_SECONDS = 0.5

_FORCE_MISMATCH = """

_UNREPAIRED_COMPARE_ROWS = compare_rows


def compare_rows(*args, **kwargs):  # noqa: F811
    value = _UNREPAIRED_COMPARE_ROWS(*args, **kwargs)
    value["classification"] = "SEMANTIC_MISMATCH"
    for row in value["rows"]:
        row["classification"] = "SEMANTIC_MISMATCH"
    return value
"""


def _comparator_root(directory, *, slow):
    """A real, runnable comparator root the test owns and may rewrite."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("transform_comparator.py", "transform_compiler.py"):
        (directory / name).write_bytes((LANE / name).read_bytes())
    if slow:
        path = directory / "transform_comparator.py"
        path.write_text(
            path.read_text()
            + f"\n\nimport time  # noqa: E402\n\ntime.sleep({SLEEP_SECONDS})\n"
        )
    return directory


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _replace_during_run(path, data):
    """Atomically swap one file from another thread while the recompare runs."""
    path = Path(path)
    failures = []

    def swap():
        try:
            time.sleep(SWAP_AFTER_SECONDS)
            staging = path.with_name(path.name + ".incoming")
            staging.write_bytes(data)
            os.replace(staging, path)
        except OSError as error:  # pragma: no cover - reported by the test
            failures.append(error)

    thread = threading.Thread(target=swap)
    thread.start()
    return thread, failures


def _recompare(inputs, output, reference, root, historical_compiler_path=None):
    return recompare.recompare_saved(
        output,
        reference,
        expected_inputs_digest=inputs["inputsDigest"],
        comparator_root=root,
        historical_compiler_path=historical_compiler_path,
        expected_execution_kind="injected-transport",
    )


def test_historical_compiler_path_is_source_bound_and_recorded(tmp_path, monkeypatch):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=False)
    record = _recompare(inputs, output, reference, root, root / "transform_compiler.py")
    assert record["repaired"]["classification"] == "MATCH"
    assert record["binding"]["historicalCompilerSourceSha256"] == _sha256(
        root / "transform_compiler.py"
    )


def test_historical_compiler_symlink_is_refused(tmp_path, monkeypatch):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=False)
    link = tmp_path / "compiler-link.py"
    link.symlink_to(root / "transform_compiler.py")
    with pytest.raises(ValueError, match="regular non-empty file required"):
        _recompare(inputs, output, reference, root, link)


def test_historical_compiler_byte_mutation_is_refused(tmp_path, monkeypatch):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=False)
    mutated = tmp_path / "mutated-compiler.py"
    mutated.write_bytes((root / "transform_compiler.py").read_bytes() + b"\n# mutation\n")
    with pytest.raises(ValueError, match="historical compiler source binding differs"):
        _recompare(inputs, output, reference, root, mutated)


def test_a_quiet_run_records_the_hashes_of_the_sources_it_executed(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=True)
    record = _recompare(inputs, output, reference, root)
    assert record["repaired"]["classification"] == "MATCH"
    assert record["binding"]["comparatorSourceSha256"] == {
        name: _sha256(root / name)
        for name in ("transform_comparator.py", "transform_compiler.py")
    }
    assert record["binding"]["referenceSha256"] == _sha256(reference)


def test_a_comparator_swapped_mid_run_cannot_be_recorded_as_the_one_that_ran(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=True)
    original = (root / "transform_comparator.py").read_bytes()
    other = original + _FORCE_MISMATCH.encode()
    assert other != original
    thread, failures = _replace_during_run(root / "transform_comparator.py", other)
    try:
        with pytest.raises(ValueError, match="changed while the recompare ran"):
            _recompare(inputs, output, reference, root)
    finally:
        thread.join()
    assert failures == []
    # The swapped-in comparator really does classify differently, so recording
    # its hash beside the original's result would have been a false binding.
    assert (
        _recompare(inputs, output, reference, root)["repaired"]["classification"]
        == "SEMANTIC_MISMATCH"
    )


def test_a_compiler_swapped_mid_run_cannot_be_recorded_as_the_one_that_ran(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=True)
    compiler = root / "transform_compiler.py"
    original = compiler.read_bytes()
    other = original + b"\n# a byte-different compiler with the same behavior\n"
    assert other != original
    thread, failures = _replace_during_run(compiler, other)
    try:
        with pytest.raises(ValueError, match="changed while the recompare ran"):
            _recompare(inputs, output, reference, root)
    finally:
        thread.join()
    assert failures == []
    assert compiler.read_bytes() == other


def test_a_reference_swapped_mid_run_cannot_be_recorded_as_the_one_that_ran(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=True)
    original = reference.read_bytes()
    value = json.loads(original)
    value["rows"][2]["status"] = 201
    other = json.dumps(value).encode()
    assert other != original
    thread, failures = _replace_during_run(reference, other)
    try:
        with pytest.raises(ValueError, match="changed while the recompare ran"):
            _recompare(inputs, output, reference, root)
    finally:
        thread.join()
    assert failures == []
    # The swapped-in reference really does compare differently.
    assert (
        _recompare(inputs, output, reference, root)["repaired"]["classification"]
        == "SEMANTIC_MISMATCH"
    )


def test_a_refused_saved_acquisition_is_not_masked_by_our_own_reads(
    tmp_path, monkeypatch
):
    """The validator owns the refusal for an invalid saved directory.

    Reading the saved records before it runs would replace its diagnosis with
    a complaint about a missing file, so the pre-image is only ever a probe.
    """
    calls = []

    def refuse(output, reference_path, **kwargs):
        calls.append(str(output))
        raise ValueError("saved acquisition invalid")

    monkeypatch.setattr(recompare, "compare_saved", refuse)
    empty = tmp_path / "nothing-here"
    empty.mkdir()
    with pytest.raises(ValueError, match="^saved acquisition invalid$"):
        recompare.recompare_saved(
            empty,
            empty / "missing-reference.json",
            expected_inputs_digest="unused",
            comparator_root=empty / "missing-root",
            expected_execution_kind="injected-transport",
        )
    assert calls == [str(empty)]


def test_an_input_swapped_while_the_validator_runs_is_still_caught(
    tmp_path, monkeypatch
):
    """Close the window around the validator, which opens these paths itself."""
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=False)
    original = recompare.compare_saved
    replacement = json.dumps({"plan": {}, "rows": [], "cleanup": []}).encode()

    def swap_then_validate(*args, **kwargs):
        value = original(*args, **kwargs)
        staging = reference.with_name("incoming.json")
        staging.write_bytes(replacement)
        os.replace(staging, reference)
        return value

    monkeypatch.setattr(recompare, "compare_saved", swap_then_validate)
    with pytest.raises(ValueError, match="changed while the recompare ran"):
        _recompare(inputs, output, reference, root)


_SITE_PROBE = """import sys


def compare_rows(plan, rows, ref_plan, ref_rows, **kwargs):
    try:
        import pytest  # noqa: F401

        reachable = "yes"
    except ImportError:
        reachable = "no"
    return {
        "classification": "MATCH",
        "errors": [],
        "kind": f"no_site={sys.flags.no_site};site_packages_import={reachable}",
        "rows": [{"index": index, "classification": "MATCH"} for index in range(17)],
    }
"""


def test_the_child_interpreter_cannot_reach_site_packages(tmp_path, monkeypatch):
    """The snapshot is the only place a lane module can come from.

    pytest is installed for this run and lives only in site-packages, so the
    child failing to import it is the observable form of that claim.
    """
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-site", slow=False)
    (root / "transform_comparator.py").write_text(_SITE_PROBE)
    record = _recompare(inputs, output, reference, root)
    assert record["repaired"]["kind"] == "no_site=1;site_packages_import=no"


def test_the_witness_covers_what_the_validator_reads_too(tmp_path, monkeypatch):
    """The release record, the OAuth journals and every row journal.

    `compare_saved` reads these in the same run and the frozen classification
    depends on them, so a replacement after it read them must still refuse even
    though the published record carries no digest for them.
    """
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=False)
    original = recompare.compare_saved
    targets = [
        output / "release.json",
        output / "coordinator/oauth-refresh-charge.json",
        output / "coordinator/oauth-refresh-receipt.json",
        output / "coordinator/oauth-tokeninfo-charge.json",
        output / "coordinator/oauth-tokeninfo-receipt.json",
        output / "collection/observation-00.json",
        output / "collection/recovery-05.json",
    ]
    for target in targets:
        assert target.is_file(), target

        def swap_then_validate(*args, _target=target, **kwargs):
            value = original(*args, **kwargs)
            body = json.loads(_target.read_text())
            body["reviewMarker"] = "replaced after the validator read it"
            staging = _target.with_name(_target.name + ".incoming")
            staging.write_text(json.dumps(body))
            os.replace(staging, _target)
            return value

        keep = target.read_bytes()
        monkeypatch.setattr(recompare, "compare_saved", swap_then_validate)
        with pytest.raises(ValueError, match=f"{target.name} changed"):
            _recompare(inputs, output, reference, root)
        monkeypatch.setattr(recompare, "compare_saved", original)
        target.write_bytes(keep)


def test_a_refused_saved_acquisition_propagates_from_a_complete_saved_set(
    tmp_path, monkeypatch
):
    """The reviewer's fifth condition, with every saved file present."""
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    root = _comparator_root(tmp_path / "comparator-a", slow=False)
    reached = []

    def refuse(saved, reference_path, **kwargs):
        reached.append(str(saved))
        raise ValueError("fixture: saved acquisition invalid")

    monkeypatch.setattr(recompare, "compare_saved", refuse)
    with pytest.raises(ValueError, match="^fixture: saved acquisition invalid$"):
        _recompare(inputs, output, reference, root)
    assert reached == [str(output)]
