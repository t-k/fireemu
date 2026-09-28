"""The executable local inventory preserves the previously proposed 45 inputs."""

import json

from broad_contract import ROOT, digest
from second_admission import manifest


def test_checked_in_second45_manifest_preserves_proposal_without_permission():
    stored = json.loads(
        (ROOT / "spec/compatibility/broad-second45-local-admission.json").read_text()
    )
    proposal = json.loads(
        (
            ROOT / "spec/compatibility/broad-second-production-subset-proposal.json"
        ).read_text()
    )
    assert digest(stored) == digest(manifest())
    assert stored["authCases"] == proposal["authCases"]
    assert stored["firestorePrograms"] == proposal["firestorePrograms"]
    assert stored["diagnosticRows"] == proposal["diagnosticRows"] == 45
    assert stored["productionExecutable"] is False
    assert stored["productionApproval"] is None
    assert stored["limits"] == proposal["proposedCaps"]["requests"]
