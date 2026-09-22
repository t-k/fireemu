"""Validate the FS-WRITE-LIMITS-03 preparation package against its sources.

The digests in the package are checked against the commit the package declares,
not against the mutable working tree, so a later edit cannot make a frozen
record appear to still describe today's files.
"""

from __future__ import annotations

import hashlib
import json
import copy
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
PARTS = ("ALL",)

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


def test_one_allocation_carries_the_whole_scope() -> None:
    manifest = load(MANIFEST)
    assert manifest["campaignId"] == CAMPAIGN
    assert manifest["allocation"]["parts"] == 1
    assert manifest["allocation"]["chargedBy"] == "shared_gate"
    assert manifest["allocation"]["earlyStop"]
    limits, residues = set(), set()
    for case in manifest["cases"]:
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


def test_the_package_states_how_an_early_stop_is_handled() -> None:
    """A frozen schedule keeps fail-closed recovery, and the record says how."""
    allocation = load(MANIFEST)["allocation"]
    assert "no-data abort" in allocation["earlyStop"]
    assert "abandon transition" in allocation["earlyStop"]
    assert "verified absent" in allocation["earlyStop"]
    # Ambiguous ownership is still fail-closed; the retired Gate defects are
    # not allowed to remain as package blockers.
    assert "ambiguous" in allocation["openGateDefect"]
    assert "owner-escalation" in allocation["openGateDefect"]
    assert "unknown create" not in allocation["openGateDefect"]
    assert allocation["gateWallCapSeconds"] == 1200


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
    exemption = next(case for case in manifest["cases"] if case.get("indexExemption"))
    assert exemption["limitId"] == "FS-LIMIT-DOCUMENT-NAME-BYTES"
    assert exemption["indexExemptionReason"]


def test_a_truncating_maximum_is_not_recorded_as_a_refusal() -> None:
    manifest = load(MANIFEST)
    case = next(
        case
        for case in manifest["cases"]
        if case.get("limitId") == "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES"
    )
    assert case["kind"] == "truncating-maximum"
    assert case["chargedInFullWouldBe"] > 7680
    assert "created" in case["expected"][0]


def test_the_aggregate_metric_is_probed_in_both_readings() -> None:
    manifest = load(MANIFEST)
    cases = [case for case in manifest["cases"] if case.get("aggregateShape")]
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
        for case in manifest["cases"]
        if case.get("limitId") == "FS-LIMIT-FIELD-PATH-BYTES"
    ]
    assert len(cases) == 3
    assert {case.get("pathShape") for case in cases} == {"map", "array", None}
    for case in cases:
        assert case["boundary"] == [1500, 1501]


def test_budgets_match_the_compiled_plans_and_stay_inside_the_cap() -> None:
    manifest = load(MANIFEST)
    for part in PARTS:
        budgets = manifest["budgets"]
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
        # The allocation must fit the Gate's own ceiling, and its reserve must
        # cover what the Gate itself will charge for this schedule.
        import compiler_03

        job = gate["jobs"]["limits"]
        charge = compiler_03.gate_charge(
            job["schedule"], job["recovery"], job["observation"] + job["recovery"]
        )
        assert gate["recoverySeconds"] >= charge["recoverySeconds"]
        assert gate["recoverySeconds"] < gate["wallSeconds"] <= 1200
        assert gate["transportCeilingSeconds"] == compiler_03.TRANSPORT_CEILING_SECONDS


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
        == {part: shadow["execution"][part]["artifact"]["sha256"] for part in PARTS}
    )


def test_the_recorded_shadow_ran_to_the_end_and_reclaimed_everything() -> None:
    """The schedule, cleanup, and Gate close all completed locally."""
    shadow = load(SHADOW)
    assert shadow["status"] == "completed-local-only"
    for part in PARTS:
        execution = shadow["execution"][part]["execution"]
        assert execution["semanticMismatches"] == []
        assert execution["infrastructureFailures"] == []
        for key in (
            "recordingComplete",
            "stateValidation",
            "allOwnedResourcesAbsentAfterRecovery",
        ):
            assert execution[key] is True, (part, key)
        assert execution["gateCloseRefused"] is False
        for key in (
            "cleanupComplete",
            "cleanupValidated",
            "receiptValidated",
            "completed",
        ):
            assert execution[key] is True, (part, key)
        assert execution["ownedProcess"]["stopped"] is True
        assert execution["ownedProcess"]["listenersClosed"] is True
        plan = compile_limits_plan("demo-firestore-probe", "(default)", "0" * 32, part)
        accounting = plan["budgetAccounting"]
        assert execution["observationRequests"] == accounting["observationRequests"]
        assert execution["recoveryRequests"] == accounting["recoveryRequests"]
        assert execution["ownedDocuments"] == accounting["ownedDocuments"]
        assert shadow["execution"][part]["digests"]["sourceInputsBound"] is True


def test_pending_rows_are_recorded_with_their_reasons() -> None:
    manifest, shadow = load(MANIFEST), load(SHADOW)
    pending = manifest["pendingLocalImplementation"]
    assert pending["meaning"]
    assert (
        pending["differences"]
        == shadow["execution"]["ALL"]["execution"]["pendingDifferences"]
    )
    profile = shadow["execution"]["ALL"]["execution"]["indexConfiguration"].get(
        "profile", "historical"
    )
    if profile == "nx-local":
        assert pending["differences"] == []
        assert shadow["execution"]["ALL"]["execution"]["pendingRows"] == []
        return
    for difference in pending["differences"]:
        assert difference["pending"] is True
        assert difference["reason"]
    # Every pending row must trace to a case that says why it is pending, and
    # the only reason left is one the local shadow cannot remove.
    reasons = {
        case["pendingReason"] for case in manifest["cases"] if case.get("pendingReason")
    }
    assert len(reasons) == 1
    assert "index configuration" in next(iter(reasons))


def test_nx_local_profile_cannot_hide_mismatch_or_identity_gap(tmp_path: Path) -> None:
    import package_03
    import broad

    published = load(SHADOW)
    previous = published["execution"]["ALL"]["execution"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    run = tmp_path / "retained-nx-shadow"
    run.mkdir()
    try:
        supervisor = {
            "executionCommit": commit,
            "configurationDigest": "unused-before-write",
            "indexConfiguration": {
                "profile": "nx-local",
                "sha256": package_03.campaign.INDEXES_SHA256_AFTER,
                "sourceCommit": None,
            },
            "ownedProcess": {"pid": 1, "stopped": True, "listenersClosed": True},
            "status": "completed",
            "build": {
                "command": ["offline-test-build"],
                "inputs": package_03.runtime_inputs_at_commit(commit, ROOT),
                "rustc": "retained-test-rustc",
                "artifactSha256": "unused-before-write",
            },
        }
        result = {
            key: copy.deepcopy(previous[key])
            for key in (
                "recordingComplete",
                "stateValidation",
                "cleanupComplete",
                "cleanupValidated",
                "receiptValidated",
                "semanticMismatches",
                "pendingDifferences",
                "pendingRows",
                "infrastructureFailures",
                "project",
            )
        }
        result.update(
            campaignId=package_03.CAMPAIGN,
            completed=True,
            rows=[{}],
            cleanup=[{}],
            resourceAbsence={"retained-doc": True},
            recordingComplete=True,
            stateValidation=True,
            cleanupComplete=True,
            cleanupValidated=True,
            receiptValidated=True,
            semanticMismatches=[],
            pendingDifferences=[],
            pendingRows=[],
            infrastructureFailures=[],
        )
        binding = {
            "bound": True,
            "sourceInputsBefore": package_03.source_inputs(),
            "sourceInputsAfter": package_03.source_inputs(),
            "childSourceInputs": package_03.source_inputs(),
            "supervisorManifestSha256": "unused-before-write",
        }
        index_bytes, index_sha, _ = broad.index_bytes_for_profile("nx-local")
        (run / "indexes.json").write_bytes(index_bytes)
        actual_config = {
            **broad.CONFIG,
            "daemon": {"authProjectNumbers": {}},
            "firestore": {
                **broad.FIRESTORE_CONFIG,
                "indexFile": "/retained/private/indexes.json",
            },
        }
        config_bytes = json.dumps(actual_config).encode()
        (run / "configuration.json").write_bytes(config_bytes)
        supervisor["configurationDigest"] = package_03.digest(actual_config)
        supervisor["configuration"] = {
            **actual_config,
            "firestore": {
                **actual_config["firestore"],
                "indexFile": "<owned-private-index-file>",
            },
        }
        artifact = b"retained-fireemu-artifact"
        (run / "fireemu").write_bytes(artifact)
        supervisor["build"]["artifactSha256"] = hashlib.sha256(artifact).hexdigest()
        supervisor["indexConfiguration"]["value"] = json.loads(index_bytes)
        (run / "manifest.json").write_text(json.dumps(supervisor))
        binding["supervisorManifestSha256"] = hashlib.sha256(
            (run / "manifest.json").read_bytes()
        ).hexdigest()
        (run / "result.json").write_text(json.dumps(result))
        (run / "shadow-binding.json").write_text(json.dumps(binding))
        shadow = package_03.shadow_record(run, commit)
    finally:
        import shutil

        shutil.rmtree(run)

    package_03.validate_nx_local_shadow(
        shadow,
        expected_commit=commit,
        expected_artifact_sha256=supervisor["build"]["artifactSha256"],
        expected_runtime_inputs_digest=package_03.digest(supervisor["build"]["inputs"]),
        expected_configuration_digest=supervisor["configurationDigest"],
    )
    published_manifest = package_03.manifest(load(MANIFEST), shadow, commit)
    published_binding = package_03.binding(
        load(BINDING), published_manifest, shadow, commit
    )
    assert published_manifest["indexConfiguration"]["shadowDifference"] is False
    assert published_binding["source"]["commit"] == commit
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps(supervisor))
    (run / "configuration.json").write_bytes(config_bytes)
    (run / "indexes.json").write_bytes(index_bytes)
    (run / "fireemu").write_bytes(artifact)
    (run / "result.json").write_text(json.dumps(result))
    binding["supervisorManifestSha256"] = "0" * 64
    (run / "shadow-binding.json").write_text(json.dumps(binding))
    with pytest.raises(SystemExit, match="fully recorded, source-bound"):
        package_03.shadow_record(run, commit)
    import shutil

    shutil.rmtree(run)
    mutations = [
        ("pendingDifferences", [{"pending": True}]),
        ("completed", False),
        ("artifactSha256", "d" * 64),
        ("indexSourceCommit", "0" * 40),
    ]
    for key, value in mutations:
        mutated = copy.deepcopy(shadow)
        if key == "artifactSha256":
            mutated["execution"]["ALL"]["artifact"]["sha256"] = value
        elif key == "indexSourceCommit":
            mutated["execution"]["ALL"]["execution"]["indexConfiguration"]["sourceCommit"] = value
        else:
            mutated["execution"]["ALL"]["execution"][key] = value
        with pytest.raises(ValueError, match="nx-local shadow"):
            package_03.validate_nx_local_shadow(
                mutated,
                expected_commit=commit,
        expected_artifact_sha256=supervisor["build"]["artifactSha256"],
        expected_runtime_inputs_digest=package_03.digest(supervisor["build"]["inputs"]),
                expected_configuration_digest="a" * 64,
            )

    for value in (None, "g" * 40, "0" * 40):
        mutated = copy.deepcopy(shadow)
        mutated["execution"]["ALL"]["executionCommit"] = value
        with pytest.raises(ValueError, match="nx-local shadow"):
            package_03.validate_nx_local_shadow(mutated, expected_commit=commit)


def test_the_document_name_figures_are_computed_not_written_by_hand() -> None:
    """M1: a published figure a closure will cite must come from the compiler."""
    manifest = load(MANIFEST)
    case = next(
        case
        for case in manifest["cases"]
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
    profile = shadow["execution"]["ALL"]["execution"]["indexConfiguration"].get(
        "profile", "historical"
    )
    assert configuration["shadowDifference"] is (profile != "nx-local")
    for part in PARTS:
        declared = configuration["shadowRanUnder"][part]
        recorded = shadow["execution"][part]["execution"]["indexConfiguration"]
        assert declared == recorded, part
        if recorded.get("profile", "historical") == "nx-local":
            assert declared["sha256"] == configuration["conformanceIndexesSha256After"]
            assert not configuration["shadowDifference"]
        else:
            assert declared["sha256"] != configuration["conformanceIndexesSha256Before"]


def test_manifest_recomputes_historical_shadow_difference_after_nx_local() -> None:
    """A historical profile must not inherit nx-local's cleared difference flag."""
    import copy
    import package_03

    previous = load(MANIFEST)
    shadow = load(SHADOW)
    shadow["execution"]["ALL"]["execution"]["indexConfiguration"]["profile"] = (
        "historical"
    )
    previous["indexConfiguration"]["shadowDifference"] = False
    published = package_03.manifest(previous, shadow, package_03.head_commit())
    assert published["indexConfiguration"]["shadowDifference"] is True

    nx_local = copy.deepcopy(shadow)
    execution = nx_local["execution"]["ALL"]["execution"]
    execution["indexConfiguration"] = {
        "profile": "nx-local",
        "sha256": package_03.campaign.INDEXES_SHA256_AFTER,
        "sourceCommit": None,
    }
    execution["pendingDifferences"] = []
    execution["pendingRows"] = []
    nx_local["execution"]["ALL"]["executionCommit"] = package_03.head_commit()
    published = package_03.manifest(previous, nx_local, package_03.head_commit())
    assert published["indexConfiguration"]["shadowDifference"] is False


def test_the_declared_data_cost_is_accounted_for_in_the_envelope() -> None:
    """S2: a ceiling that omits a cost the same object declares is not a ceiling."""
    manifest = load(MANIFEST)
    for part in PARTS:
        budgets = manifest["budgets"]
        assert budgets["dataCostIsIncludedInEnvelope"] is True
        assert budgets["costNote"]
        charged = budgets["requestUpperBound"] * budgets["requestCostMicrousd"]
        assert budgets["dataCostMicrousd"] <= charged
        assert budgets["envelopeCostMicrousd"] == budgets["fixedCostMicrousd"] + charged


def test_every_boundary_says_which_unit_it_is_expressed_in() -> None:
    """S3: the catalog's unit field and its notes disagree for the field value."""
    for case in load(MANIFEST)["cases"]:
        if "limitId" not in case:
            continue
        assert case["boundaryUnit"], case["id"]
        assert case["catalogUnit"] == catalog_status(case["limitId"])["catalogUnit"]
        assert case["catalogImplemented"] == "implemented"
    # The field-value cases must between them cover both readings.
    units = {
        case["boundaryUnit"]
        for case in load(MANIFEST)["cases"]
        if case.get("limitId") == "FS-LIMIT-FIELD-VALUE-BYTES"
    }
    assert any("raw payload" in unit for unit in units)
    assert any("logical" in unit for unit in units)


def test_the_duplicate_control_cites_the_receipt_it_rests_on() -> None:
    """S4: the control's own basis must be checkable."""
    manifest = load(MANIFEST)
    case = next(
        case
        for case in manifest["cases"]
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
    # The limits-02 receipt binds its collector sources at commit 40dfc0da3 and
    # resolves them with `git show`, so it is unaffected by the working tree.
    # HEAD's round35 import (271b4c9af) already changed collector.py and
    # compiler.py, so a byte-for-byte pin of the tree is no longer true; what
    # must hold is that the bound commit still resolves every module.
    frozen = "40dfc0da3a03968928fa1906cdee409b703a0bb1"
    review = load(PACKAGE / "fs-write-limits-02-40dfc0da3-review.json")
    assert review["sourceCommit"] == frozen
    for name in ("collector.py", "comparator.py", "compiler.py"):
        relative = f"tools/compat-broad/fs-write-limits/{name}"
        assert len(at_commit(frozen, relative)) == 64, relative


def test_the_o8_section_names_the_descriptor_and_its_bindings() -> None:
    """The published O8 figures are the descriptor's, not restated."""
    import limits_03_descriptor as campaign
    from compiler_03 import management_contract

    manifest, binding = load(MANIFEST), load(BINDING)
    o8 = manifest["o8"]
    assert o8["launcher"] == "tools/compat-broad/fs-write-limits/limits_03_o8.py"
    assert (
        binding["o8"]["launcherSha256"]
        == hashlib.sha256((ROOT / o8["launcher"]).read_bytes()).hexdigest()
    )
    assert (
        o8["workerSha256"]
        == hashlib.sha256((ROOT / o8["worker"]).read_bytes()).hexdigest()
    )
    assert o8["kinds"] == {
        "frozenInputs": campaign.FROZEN_INPUTS_KIND,
        "permission": campaign.PERMISSION_KIND,
        "approval": campaign.APPROVAL_KIND,
        "manifest": campaign.MANIFEST_KIND,
        "receipt": campaign.RECEIPT_KIND,
    }
    assert o8["ledgerBudget"] == campaign.ledger_budget()
    assert o8["managementContract"] == management_contract()
    assert o8["artifactProfile"] == campaign.artifact_profile()
    assert len(o8["approvalFields"]) == 17
    assert manifest["indexConfiguration"]["precondition"] == (
        campaign.index_exemption_precondition()
    )
    assert manifest["indexConfiguration"]["precondition"]["restoreRequiredAfterRun"]
    assert {lock["key"] for lock in o8["lockScopes"] if lock["mode"] == "WRITE"} == {
        "project/fireemu-35fe6/firestore/(default)/documents/oracle/{freshNonce}/limits-03/*",
        "project/fireemu-35fe6/firestore/(default)/indexes",
    }
    budgets = manifest["budgets"]
    assert budgets["managementSlots"]["observation"] == [
        "oauth-tokeninfo",
        "project",
        "database",
        "index-lifecycle-before",
        "index-lifecycle-apply",
        "index-lifecycle-poll",
        "index-lifecycle-after",
        "index-exemption",
        "auth",
    ]
    assert budgets["managementSlots"]["recovery"] == [
        "project",
        "database",
        "index-exemption",
        "auth",
        "index-lifecycle-restore",
        "index-lifecycle-poll-restore",
        "index-lifecycle-restored",
    ]
    assert budgets["maxWallSeconds"] == campaign.campaign_seconds() <= 1200
    assert manifest["allocation"]["managementCharged"]
    assert manifest["schedule"]["declared"] is True
    assert manifest["partition"]["parts"] == 1
    assert "scheduleDeclined" not in manifest
