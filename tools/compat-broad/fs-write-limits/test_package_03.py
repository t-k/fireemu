"""Validate the FS-WRITE-LIMITS-03 preparation package against its sources.

The digests in the package are checked against the commit the package declares,
not against the mutable working tree, so a later edit cannot make a frozen
record appear to still describe today's files.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from compiler_03 import (
    CAMPAIGN,
    DOCUMENT_NAME_MAX,
    catalog_status,
    compile_limits_plan,
    name_charge_floor,
)

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "spec/compatibility/broad-runs"
MANIFEST = PACKAGE / "fs-write-limits-03.json"
BINDING = PACKAGE / "fs-write-limits-03-binding.json"
SHADOW = PACKAGE / "fs-write-limits-03-local-shadow.json"
PARTS = ("A", "B")

# Split so this file does not itself carry the prefixes it forbids: the
# publication-hygiene check greps published sources for these literals.
PERSONAL_PREFIXES = ("/Us" + "ers/", "/ho" + "me/", "/priv" + "ate/tmp", "/tm" + "p/")


def load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def at_commit(commit: str, relative: str) -> str:
    content = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return hashlib.sha256(content).hexdigest()


def test_package_is_owner_and_technically_blocked() -> None:
    manifest, binding, shadow = map(load, (MANIFEST, BINDING, SHADOW))
    identifiers = {manifest["campaignId"], binding["campaignId"], shadow["campaignId"]}
    assert identifiers == {CAMPAIGN}
    assert manifest["parentFeatureGroups"] == ["FS-DATA-WRITE"]
    assert manifest["status"] == binding["status"] == "BLOCKED_OWNER"
    assert (
        manifest["technicalStatus"] == binding["technicalStatus"] == "BLOCKED_TECHNICAL"
    )
    assert manifest["gate"]["productionAuthorization"] is False
    assert manifest["gate"]["owner"] is None
    assert manifest["target"]["projectId"] is None
    assert binding["source"]["productionArtifactSha256"] is None
    for document in (manifest, binding, shadow):
        assert document["productionExecuted"] is False
    assert manifest["evidenceBoundary"]["production"] == "unobserved"
    assert manifest["evidenceBoundary"]["savedProductionReference"] == "none"
    assert shadow["formalCompatibilityClaim"] is False


def test_the_package_never_publishes_a_nonce_or_an_absolute_path() -> None:
    for path in (MANIFEST, BINDING, SHADOW):
        text = path.read_text()
        for prefix in PERSONAL_PREFIXES:
            assert prefix not in text, (path.name, prefix)
        # The executed nonce is a 32-character hexadecimal string. The only
        # nonce the package may name is the manifest's lock placeholder.
        for token in text.replace('"', " ").replace("/", " ").split():
            assert not (
                len(token) == 32 and all(c in "0123456789abcdef" for c in token)
            )


def test_both_parts_are_declared_and_carry_the_whole_scope() -> None:
    manifest = load(MANIFEST)
    assert set(manifest["parts"]) == set(PARTS)
    assert manifest["partitionReason"]
    limits, residues = set(), set()
    for part in PARTS:
        declared = manifest["parts"][part]
        assert declared["campaignId"] == f"{CAMPAIGN}{part}"
        assert declared["scope"]
        for case in declared["cases"]:
            residues.add(case["residue"])
            if "limitId" in case:
                limits.add(case["limitId"])
            assert case["semantics"]
            assert case["expected"]
            assert case["localBasis"].startswith("artifact shadow at")
    assert residues == {"R3", "R4"}
    assert limits == {
        "FS-LIMIT-COLLECTION-ID",
        "FS-LIMIT-SUBCOLLECTION-DEPTH",
        "FS-LIMIT-DOCUMENT-NAME-BYTES",
        "FS-LIMIT-INDEX-ENTRY-BYTES",
        "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
        "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
        "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES",
        "FS-LIMIT-FIELD-PATH-BYTES",
        "FS-LIMIT-FIELD-VALUE-BYTES",
    }
    excluded = set(manifest["excludedSurfaces"])
    # The request-byte limit is the only write-path surface this campaign
    # leaves out, and it is assigned elsewhere rather than dropped.
    assert excluded == {"FS-LIMIT-API-REQUEST-BYTES"}
    assert not limits & excluded
    assert limits == set(manifest["requirementSurfaces"][1:])


def test_the_only_index_configuration_change_is_the_declared_exemption() -> None:
    manifest = load(MANIFEST)
    configuration = manifest["indexConfiguration"]
    assert configuration["compositeIndexes"] == 0
    assert configuration["additionsRequired"] == [
        {"collectionGroup": "nx", "fieldPath": "*", "indexes": []}
    ]
    assert configuration["singleFieldExemptions"] == 1
    assert configuration["appliedBy"]
    assert configuration["derivation"]
    assert (
        configuration["conformanceIndexesSha256Before"]
        == hashlib.sha256(
            (ROOT / "conformance/firestore.indexes.json").read_bytes()
        ).hexdigest()
    )
    assert (
        configuration["conformanceIndexesSha256After"]
        != configuration["conformanceIndexesSha256Before"]
    )
    # The campaign itself never mutates configuration.
    assert manifest["configuration"]["writes"] == 0
    exemption = next(
        case
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case.get("indexExemption")
    )
    assert exemption["limitId"] == "FS-LIMIT-DOCUMENT-NAME-BYTES"
    assert exemption["indexExemptionReason"]


def test_a_truncating_maximum_is_not_recorded_as_a_refusal() -> None:
    manifest = load(MANIFEST)
    case = next(
        case
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case.get("limitId") == "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES"
    )
    assert case["kind"] == "truncating-maximum"
    assert case["chargedInFullWouldBe"] > 7680
    assert "created" in case["expected"][0]


def test_the_aggregate_metric_is_probed_in_both_readings() -> None:
    manifest = load(MANIFEST)
    cases = [
        case
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case.get("aggregateShape")
    ]
    assert {case["aggregateShape"] for case in cases} == {"string", "nested-map"}
    for case in cases:
        assert case["kind"] == "metric-discriminator"
        assert case["metricEvidence"]["namesTheProperty"]
        assert case["metricEvidence"]["namesTheDocumentSize"]
        # Neither member can be accepted, and the package says why.
        assert "FS-LIMIT-DOCUMENT-BYTES" in case["entanglementReason"]


def test_the_field_path_boundary_is_probed_in_every_shape() -> None:
    manifest = load(MANIFEST)
    cases = [
        case
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case.get("limitId") == "FS-LIMIT-FIELD-PATH-BYTES"
    ]
    assert len(cases) == 3
    assert {case.get("pathShape") for case in cases} == {"map", "array", None}
    for case in cases:
        assert case["boundary"] == [1500, 1501]


def test_budgets_match_the_compiled_plans_and_stay_inside_the_cap() -> None:
    manifest = load(MANIFEST)
    for part in PARTS:
        budgets = manifest["parts"][part]["budgets"]
        plan = compile_limits_plan("fireemu-35fe6", "(default)", "0" * 32, part)
        accounting, gate = plan["budgetAccounting"], plan["localGatePlan"]
        assert budgets["observationRequests"] == accounting["observationRequests"]
        assert budgets["recoveryRequests"] == accounting["recoveryRequests"]
        assert budgets["maxOwnedDocuments"] == accounting["ownedDocuments"]
        assert budgets["maxWallSeconds"] == gate["wallSeconds"]
        assert budgets["recoveryReserveSeconds"] == gate["recoverySeconds"]
        management = (
            budgets["managementObservationRequests"]
            + budgets["managementRecoveryRequests"]
        )
        assert (
            budgets["requestUpperBound"] == accounting["requestUpperBound"] + management
        )
        assert budgets["envelopeCostMicrousd"] == budgets["fixedCostMicrousd"] + (
            budgets["requestUpperBound"] * budgets["requestCostMicrousd"]
        )
        assert budgets["envelopeCostMicrousd"] < budgets["costCapUsd"] * 1_000_000
        assert budgets["tariffsConfirmed"] is False
        # Each part must fit the shared Gate's own ceiling, which is why the
        # campaign is partitioned at all.
        assert gate["recoverySeconds"] >= accounting["recoveryRequests"] * 13.25
        assert gate["wallSeconds"] <= 1200


def test_binding_and_source_digests_resolve_at_the_declared_commit() -> None:
    manifest, binding, shadow = map(load, (MANIFEST, BINDING, SHADOW))
    assert (
        binding["manifest"]["sha256"]
        == hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    )
    assert (
        binding["localShadow"]["sha256"]
        == hashlib.sha256(SHADOW.read_bytes()).hexdigest()
    )
    commit = manifest["sourceBinding"]["codeSourceHead"]
    assert commit == binding["source"]["commit"] == shadow["sourceCommit"]
    declared = {
        **manifest["sourceBinding"]["campaignSourceDigests"],
        **manifest["sourceBinding"]["runtimeSourceDigests"],
        **shadow["campaignSources"],
    }
    for relative, digest in declared.items():
        assert at_commit(commit, relative) == digest, relative
    assert (
        manifest["sourceBinding"]["shadowArtifactSha256"]
        == binding["source"]["shadowArtifactSha256"]
        == {part: shadow["parts"][part]["artifact"]["sha256"] for part in PARTS}
    )


def test_both_recorded_shadows_are_complete_and_reclaimed_everything() -> None:
    shadow = load(SHADOW)
    for part in PARTS:
        execution = shadow["parts"][part]["execution"]
        assert execution["semanticMismatches"] == []
        assert execution["infrastructureFailures"] == []
        for key in (
            "recordingComplete",
            "stateValidation",
            "cleanupComplete",
            "cleanupValidated",
            "receiptValidated",
            "allOwnedResourcesAbsentAfterRecovery",
        ):
            assert execution[key] is True, (part, key)
        assert execution["ownedProcess"]["stopped"] is True
        assert execution["ownedProcess"]["listenersClosed"] is True
        plan = compile_limits_plan("demo-firestore-probe", "(default)", "0" * 32, part)
        accounting = plan["budgetAccounting"]
        assert execution["observationRequests"] == accounting["observationRequests"]
        assert execution["recoveryRequests"] == accounting["recoveryRequests"]
        assert execution["ownedDocuments"] == accounting["ownedDocuments"]
        assert shadow["parts"][part]["digests"]["sourceInputsBound"] is True


def test_pending_rows_are_recorded_with_their_reasons() -> None:
    manifest, shadow = load(MANIFEST), load(SHADOW)
    pending = manifest["pendingLocalImplementation"]
    assert pending["meaning"]
    for part in PARTS:
        assert (
            pending["parts"][part]["differences"]
            == shadow["parts"][part]["execution"]["pendingDifferences"]
        )
        for difference in pending["parts"][part]["differences"]:
            assert difference["pending"] is True
            assert difference["reason"]
    # Every pending row must trace to a case that says why it is pending, and
    # the only reason left is one the local shadow cannot remove.
    reasons = {
        case["pendingReason"]
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case.get("pendingReason")
    }
    assert len(reasons) == 1
    assert "index configuration" in next(iter(reasons))


def test_the_document_name_figures_are_computed_not_written_by_hand() -> None:
    """M1: a published figure a closure will cite must come from the compiler."""
    manifest = load(MANIFEST)
    case = next(
        case
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case.get("limitId") == "FS-LIMIT-DOCUMENT-NAME-BYTES"
    )
    prefix = len("projects/fireemu-35fe6/databases/(default)/documents/")
    figures = case["derivedFigures"]
    assert figures | name_charge_floor(prefix, DOCUMENT_NAME_MAX) == figures
    # The compiled document's own entry is published beside the two floors, so a
    # reader can see that this plan sits above both.
    assert figures["compiledDocumentEntry"] > figures["smallestMarkerBearingEntry"]
    # The floor for any indexed field, and the floor for a marker-bearing
    # document, are different numbers and the text must use both correctly.
    assert figures["smallestIndexedFieldEntry"] < figures["smallestMarkerBearingEntry"]
    for value in (
        figures["smallestNameSum"],
        figures["smallestIndexedFieldEntry"],
        figures["smallestMarkerBearingEntry"],
    ):
        assert str(value) in case["derivation"], value
    # No superseded figure may survive anywhere in the published package.
    assert "11040" not in MANIFEST.read_text()
    # The claim is scoped to documents that carry the ownership marker, because
    # a document with no fields generates no entries at all.
    assert "marker-bearing" in case["derivation"]
    assert "no fields" in case["derivation"]


def test_the_shadow_index_configuration_is_cross_checked() -> None:
    """S1: the shadow did not run under the digest the manifest declares."""
    manifest, shadow = load(MANIFEST), load(SHADOW)
    configuration = manifest["indexConfiguration"]
    assert configuration["shadowDifference"]
    for part in PARTS:
        declared = configuration["shadowRanUnder"][part]
        recorded = shadow["parts"][part]["execution"]["indexConfiguration"]
        assert declared == recorded, part
        assert declared["sha256"] != configuration["conformanceIndexesSha256Before"]


def test_the_declared_data_cost_is_accounted_for_in_the_envelope() -> None:
    """S2: a ceiling that omits a cost the same object declares is not a ceiling."""
    manifest = load(MANIFEST)
    for part in PARTS:
        budgets = manifest["parts"][part]["budgets"]
        assert budgets["dataCostIsIncludedInEnvelope"] is True
        assert budgets["costNote"]
        charged = budgets["requestUpperBound"] * budgets["requestCostMicrousd"]
        assert budgets["dataCostMicrousd"] <= charged
        assert budgets["envelopeCostMicrousd"] == budgets["fixedCostMicrousd"] + charged


def test_every_boundary_says_which_unit_it_is_expressed_in() -> None:
    """S3: the catalog's unit field and its notes disagree for the field value."""
    for part in PARTS:
        for case in load(MANIFEST)["parts"][part]["cases"]:
            if "limitId" not in case:
                continue
            assert case["boundaryUnit"], case["id"]
            assert case["catalogUnit"] == catalog_status(case["limitId"])["catalogUnit"]
            assert case["catalogImplemented"] == "implemented"
    # The field-value cases must between them cover both readings.
    units = {
        case["boundaryUnit"]
        for part in PARTS
        for case in load(MANIFEST)["parts"][part]["cases"]
        if case.get("limitId") == "FS-LIMIT-FIELD-VALUE-BYTES"
    }
    assert any("raw payload" in unit for unit in units)
    assert any("logical" in unit for unit in units)


def test_the_duplicate_control_cites_the_receipt_it_rests_on() -> None:
    """S4: the control's own basis must be checkable."""
    manifest = load(MANIFEST)
    case = next(
        case
        for part in PARTS
        for case in manifest["parts"][part]["cases"]
        if case["id"].endswith("/batch-duplicate-document")
    )
    assert "firestore-production-matrix.json" in case["derivation"]
    assert "non-atomic-batch" in case["derivation"]


def test_collector_and_comparator_bindings_name_the_new_modules() -> None:
    manifest = load(MANIFEST)
    for section in ("collectorBinding", "comparatorBinding"):
        binding = manifest[section]
        assert binding["path"].endswith("_03.py")
        assert (ROOT / binding["path"]).exists()
        assert (
            binding["digest"]
            == hashlib.sha256((ROOT / binding["path"]).read_bytes()).hexdigest()
        )
    assert manifest["collectorBinding"]["productionCollector"] is None
    assert manifest["comparatorBinding"]["productionComparator"] is None
    # The limits-02 sources must stay byte-for-byte as they were when that
    # campaign was frozen, or its receipt's collector source digest stops
    # resolving.
    frozen = "40dfc0da3a03968928fa1906cdee409b703a0bb1"
    for name in ("collector.py", "comparator.py", "compiler.py"):
        relative = f"tools/compat-broad/fs-write-limits/{name}"
        current = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        assert current == at_commit(frozen, relative), relative
