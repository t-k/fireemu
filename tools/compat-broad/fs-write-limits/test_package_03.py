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

from compiler_03 import CAMPAIGN, compile_limits_plan

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "spec/compatibility/broad-runs"
MANIFEST = PACKAGE / "fs-write-limits-03.json"
BINDING = PACKAGE / "fs-write-limits-03-binding.json"
SHADOW = PACKAGE / "fs-write-limits-03-local-shadow.json"


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
        assert "/Users/" not in text
        assert "/private/tmp" not in text
        assert "/home/" not in text
        # The executed nonce is a 32-character hexadecimal string. The only
        # nonce the package may name is the manifest's lock placeholder.
        for token in text.replace('"', " ").replace("/", " ").split():
            assert not (
                len(token) == 32 and all(c in "0123456789abcdef" for c in token)
            )


def test_cases_are_the_two_declared_residues_and_nothing_else() -> None:
    manifest = load(MANIFEST)
    cases = manifest["cases"]
    assert len(cases) == 6
    assert [case["residue"] for case in cases] == ["R3"] * 3 + ["R4"] * 3
    limits = {case["limitId"] for case in cases if "limitId" in case}
    assert limits == {
        "FS-LIMIT-COLLECTION-ID",
        "FS-LIMIT-SUBCOLLECTION-DEPTH",
        "FS-LIMIT-DOCUMENT-NAME-BYTES",
    }
    excluded = set(manifest["excludedSurfaces"])
    assert "FS-LIMIT-INDEX-ENTRY-BYTES" in excluded
    assert not limits & excluded
    for identifier in excluded:
        assert manifest["excludedSurfaces"][identifier]
    assert manifest["locks"] == [
        {
            "key": "firestore/(default)/documents/oracle/{freshNonce}/limits-03/*",
            "mode": "WRITE",
        },
        {"key": "firestore/(default)/indexes", "mode": "READ"},
        {"key": "firestore/(default)/ruleset", "mode": "READ"},
    ]
    assert manifest["configuration"]["writes"] == 0


def test_budgets_match_the_compiled_plan_and_stay_inside_the_cap() -> None:
    manifest = load(MANIFEST)
    budgets = manifest["budgets"]
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "0" * 32)
    accounting, gate = plan["budgetAccounting"], plan["localGatePlan"]
    assert budgets["observationRequests"] == accounting["observationRequests"]
    assert budgets["recoveryRequests"] == accounting["recoveryRequests"]
    assert budgets["maxOwnedDocuments"] == accounting["ownedDocuments"]
    assert budgets["maxProbedNames"] == accounting["probedNames"]
    assert budgets["maxWallSeconds"] == gate["wallSeconds"]
    assert budgets["recoveryReserveSeconds"] == gate["recoverySeconds"]
    management = (
        budgets["managementObservationRequests"] + budgets["managementRecoveryRequests"]
    )
    assert budgets["requestUpperBound"] == accounting["requestUpperBound"] + management
    assert budgets["envelopeCostMicrousd"] == budgets["fixedCostMicrousd"] + (
        budgets["requestUpperBound"] * budgets["requestCostMicrousd"]
    )
    assert budgets["envelopeCostUsd"] < budgets["costCapUsd"]
    assert budgets["tariffsConfirmed"] is False


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
        **shadow["digests"]["campaignSources"],
    }
    for relative, digest in declared.items():
        assert at_commit(commit, relative) == digest, relative
    assert (
        manifest["sourceBinding"]["artifactSha256"]
        == shadow["artifact"]["sha256"]
        == binding["source"]["shadowArtifactSha256"]
    )


def test_the_recorded_shadow_is_complete_and_reclaimed_everything() -> None:
    shadow = load(SHADOW)
    execution = shadow["execution"]
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
        assert execution[key] is True, key
    assert execution["ownedProcess"]["stopped"] is True
    assert execution["ownedProcess"]["listenersClosed"] is True
    plan = compile_limits_plan("demo-firestore-probe", "(default)", "0" * 32)
    accounting = plan["budgetAccounting"]
    assert execution["observationRequests"] == accounting["observationRequests"]
    assert execution["recoveryRequests"] == accounting["recoveryRequests"]
    assert execution["ownedDocuments"] == accounting["ownedDocuments"]
    assert shadow["digests"]["sourceInputsBound"] is True


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
