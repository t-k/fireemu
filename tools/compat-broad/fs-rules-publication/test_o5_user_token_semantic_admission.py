"""Installed-lane tests: actual collector + full acquisition comparator,
adopted from the external RULES-SEMANTIC-REPAIR-006 deliverable and renamed
to this lane's error vocabulary.

All transport replies are scripted fixtures, NOT production observations.
The transport returns a distinct raw uid per side, so the pre-redaction
principal binding is exercised end to end: collected, redacted, admitted and
projected.
"""

from __future__ import annotations

import copy

from o5_user_token_collector import ROLE_LOCAL_SHADOW, ROLE_PRODUCTION, collect
from o5_user_token_comparator_v2 import INDETERMINATE, MATCH, SEMANTIC_MISMATCH, compare
from test_o5_user_token_collector import Transport
from test_o5_user_token_collector_bound import (
    LOCAL_ENDPOINT,
    PRODUCTION_ENDPOINT,
    acquisition_for,
    fingerprints_for,
    plan_for,
)


class PrincipalTransport(Transport):
    def __init__(self, plan, role, *, wrong_owner=False, raw_literal=None):
        endpoint = PRODUCTION_ENDPOINT if role == ROLE_PRODUCTION else LOCAL_ENDPOINT
        super().__init__(
            plan, endpoint=endpoint, fingerprints=fingerprints_for(plan, role)
        )
        self.salt = "production" if role == ROLE_PRODUCTION else "local"
        self.wrong_owner = wrong_owner
        self.raw_literal = raw_literal

    def uid(self, ref):
        return f"{self.salt}-uid-{ref}"

    def _answer(self, request):
        reply = super()._answer(request)
        if (
            request.get("kind") == "account-readback"
            and reply.get("accountPresent") is True
        ):
            reply["uid"] = self.uid(request["accountRef"])
        if request.get("index") == 0:
            ref = "other-b" if self.wrong_owner else "owner-a"
            reply["fields"] = {"ownerUid": self.uid(ref), "value": 1}
            if self.raw_literal is not None:
                reply["fields"]["ownerUid"] = self.raw_literal
        return reply


def pair(**local_options):
    production_plan = plan_for(ROLE_PRODUCTION)
    production = collect(
        production_plan,
        PrincipalTransport(production_plan, ROLE_PRODUCTION),
        role=ROLE_PRODUCTION,
        run_id="semantic-prod",
        acquisition=acquisition_for(production_plan, ROLE_PRODUCTION),
    )
    local_plan = plan_for(ROLE_LOCAL_SHADOW)
    local = collect(
        local_plan,
        PrincipalTransport(local_plan, ROLE_LOCAL_SHADOW, **local_options),
        role=ROLE_LOCAL_SHADOW,
        run_id="semantic-local",
        acquisition=acquisition_for(local_plan, ROLE_LOCAL_SHADOW),
    )
    assert production["recordingComplete"] and local["recordingComplete"]
    return production, local, production_plan


def test_valid_distinct_uid_pair_passes_full_admission():
    production, local, plan = pair()
    result = compare(production, local, plan)
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert len(result["rows"]) == 33


def test_a_uid_in_a_non_principal_field_binds_without_failing_admission():
    """Capture is field-agnostic: a readback uid that shows up in a field the
    plan does not treat as a principal slot is bound too (and redacted, so the
    binding and the label still agree). Such a binding must never turn into a
    `principal-binding` admission failure, and the field is still compared
    literally, label against label."""
    production, local, plan = pair()
    row = local["rows"][0]
    assert "note" not in plan["observation"][0]["expect"].get("fields", {})
    assert row["principalFieldBindings"] == {
        "ownerUid": {"ref": "owner-a", "readbackIndex": 0}
    }
    for bundle in (production, local):
        bundle["rows"][0]["observed"]["fields"]["note"] = "principal:owner-a"
        bundle["rows"][0]["principalFieldBindings"]["note"] = {
            "ref": "owner-a",
            "readbackIndex": 0,
        }
    result = compare(production, local, plan)
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert result["rows"][0]["local"]["fields"]["note"] == "principal:owner-a"


def test_raw_wrong_owner_is_not_erased_by_the_collector_or_comparator():
    production, local, plan = pair(wrong_owner=True)
    assert local["rows"][0]["principalFieldBindings"]["ownerUid"]["ref"] == "other-b"
    result = compare(production, local, plan)
    assert result["errors"] == []
    assert result["classification"] == SEMANTIC_MISMATCH
    assert result["promotionReady"] is False
    assert result["rows"][0]["reasons"] == ["fields"]


def test_label_shaped_literal_does_not_create_a_principal_binding():
    production, local, plan = pair(raw_literal="principal:owner-a")
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert (
        "local:principal-unmapped:a-owner-reads-own-document:ownerUid"
        in result["errors"]
    )
    assert result["promotionReady"] is False


def test_arbitrary_nonempty_uid_does_not_pass():
    production, local, plan = pair(raw_literal="unknown-account")
    assert compare(production, local, plan)["classification"] == INDETERMINATE


def test_missing_binding_cannot_be_reconstructed_from_a_redacted_label():
    production, local, plan = pair()
    local["rows"][0]["principalFieldBindings"] = {}
    assert compare(production, local, plan)["classification"] == INDETERMINATE


def test_wrong_readback_index_does_not_pass():
    production, local, plan = pair()
    local["rows"][0]["principalFieldBindings"]["ownerUid"]["readbackIndex"] = 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert (
        "local:principal-binding:a-owner-reads-own-document:ownerUid:readback-mismatch"
        in result["errors"]
    )


def test_boolean_field_is_not_the_integer_field():
    production, local, plan = pair()
    local["rows"][0]["observed"]["fields"]["value"] = True
    result = compare(production, local, plan)
    assert result["classification"] == SEMANTIC_MISMATCH
    assert result["rows"][0]["reasons"] == ["fields"]


def test_numeric_presence_is_indeterminate_not_a_match():
    production, local, plan = pair()
    local["rows"][0]["observed"]["documentPresent"] = 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert (
        "local:row-schema:a-owner-reads-own-document:documentPresent"
        in result["errors"]
    )


def test_nonfinite_nested_value_is_indeterminate():
    production, local, plan = pair()
    local["rows"][0]["observed"]["fields"]["nested"] = {"bad": float("nan")}
    assert compare(production, local, plan)["classification"] == INDETERMINATE


def test_literal_projection_tag_cannot_impersonate_principal():
    """A mapping in a principal slot is not a principal; this lane reports
    it as unmapped (indeterminate) rather than as a typed mismatch."""
    production, local, plan = pair()
    local["rows"][0]["principalFieldBindings"] = {}
    local["rows"][0]["observed"]["fields"]["ownerUid"] = {"$principal": "owner-a"}
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert (
        "local:principal-unmapped:a-owner-reads-own-document:ownerUid"
        in result["errors"]
    )


def test_unmodified_production_hypotheses_stay_diagnostic():
    production, local, plan = pair()
    before = copy.deepcopy((production, local))
    result = compare(production, local, plan)
    assert result["classification"] == MATCH
    assert (production, local) == before
    assert result["hypotheses"]["credential-revocation"]["rows"] == 7
