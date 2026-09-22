"""Creation-outcome regressions for the AUTH-CREDENTIAL response boundary.

No network, credentials, canonical Ledger, or cleanup requests are used here.
A custom-token REST success may omit localId when the ID token proves the
expected identity and isNewUser is true; malformed legacy responses remain
UNKNOWN, never REFUSED.
"""
from __future__ import annotations

import copy
import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from credential_gate import CredentialGate, account_identifier, account_resource

NONCE = "0123456789abcdef0123456789abcdef"
PROJECT = "demo-ack-contract"
JOB = "auth-credential"
UID = account_identifier(NONCE, "custom")


def formal_id_token(uid: str = UID, project: str = PROJECT) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = json.dumps(
        {
            "sub": uid,
            "aud": project,
            "iss": f"https://securetoken.google.com/{project}",
            "firebase": {"sign_in_provider": "custom"},
        },
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"{header}.{encoded}."
MISSING = object()


def scenario():
    gate = object.__new__(CredentialGate)
    gate.job = JOB
    gate.bindings = {}
    gate._observed = {}
    resource = account_resource(PROJECT, NONCE, "custom")
    state = {
        "plan": {
            "project": PROJECT, "nonce": NONCE,
            "jobs": {JOB: {"recovery": [
                {"kind": "delete", "account": "custom"},
                {"kind": "uid-absence", "account": "custom"},
            ]}},
        },
        "events": [],
        "jobs": {JOB: {"authAccounts": {}, "resources": [resource], "absent": []}},
    }
    operation = {"kind": "custom-sign-in", "account": "custom", "resource": resource,
                 "binds": {"customUid": "idToken.sub", "customIdToken": "idToken",
                           "customRefresh": "refreshToken"}}
    return gate, state, operation


def success(*, new=True):
    # The envelope is synthetic and unsigned; the projection still requires the
    # production identity claims before it can grant ownership.
    return {"localId": UID, "idToken": formal_id_token(), "refreshToken": "test-refresh",
            "expiresIn": "3600", "isNewUser": new}


def apply_response(gate, state, operation, body, status=200, recovery=False):
    event = {"job": JOB, "phase": "recovery" if recovery else "observation",
             "completed": True, "failure": None, "responseDigest": "fixture-digest",
             "creationOutcome": "pending"}
    state["events"].append(event)
    gate._record_response(state, operation, recovery, event, status, body)
    return event


class CustomAckOutcomes(unittest.TestCase):
    def assert_unknown(self, body, status=200):
        gate, state, operation = scenario()
        original_body = copy.deepcopy(body)
        original_operation = copy.deepcopy(operation)
        event = apply_response(gate, state, operation, body, status)
        self.assertEqual(event["creationOutcome"], "unknown")
        self.assertEqual(event["authEvidence"]["creationOutcome"], "unknown")
        self.assertNotIn("uid", event["authEvidence"])
        self.assertNotIn("resource", event["authEvidence"])
        self.assertNotIn("body", event["authEvidence"])
        self.assertNotIn("idToken", event["authEvidence"])
        self.assertNotIn("refreshToken", event["authEvidence"])
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})
        self.assertEqual(state["jobs"][JOB]["absent"], [])
        self.assertFalse(gate._all_accounts_absent(state))
        self.assertEqual(body, original_body, "do not synthesize a localId in the response")
        self.assertEqual(operation, original_operation, "do not rewrite the frozen slot")
        return gate, state, operation, event

    def test_documented_success_without_local_id_is_accepted_when_identity_is_proven(self):
        gate, state, operation = scenario()
        body = success()
        del body["localId"]
        event = apply_response(gate, state, operation, body)
        self.assertEqual(event["creationOutcome"], "created")
        self.assertEqual(state["jobs"][JOB]["authAccounts"]["custom"]["uid"], UID)

    def test_missing_new_user_flag_does_not_prove_reuse(self):
        body = success()
        del body["isNewUser"]
        self.assert_unknown(body)

    def test_identified_new_user_keeps_existing_creation_path(self):
        gate, state, operation = scenario()
        body = success()
        event = apply_response(gate, state, operation, body)
        self.assertEqual(event["creationOutcome"], "created")
        self.assertEqual(state["jobs"][JOB]["authAccounts"]["custom"],
                         {"uid": UID, "resource": operation["resource"], "createEvent": 0})
        self.assertEqual(event["authEvidence"]["uid"], UID)
        self.assertEqual(gate._observed["customUid"], UID)
        self.assertNotIn("idToken", event["authEvidence"])
        self.assertFalse(gate._all_accounts_absent(state))

    def test_identified_existing_user_is_refused_but_not_owned(self):
        gate, state, operation = scenario()
        event = apply_response(gate, state, operation, success(new=False))
        self.assertEqual(event["creationOutcome"], "refused")
        self.assertEqual(event["authEvidence"]["creationOutcome"], "refused")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})
        self.assertFalse(gate._all_accounts_absent(state))

    def test_existing_user_without_local_id_is_refused_when_identity_is_proven(self):
        gate, state, operation = scenario()
        body = success(new=False)
        del body["localId"]
        event = apply_response(gate, state, operation, body)
        self.assertEqual(event["creationOutcome"], "refused")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_existing_user_for_another_identity_stays_unknown(self):
        body = success(new=False)
        body["localId"] = "another-account"
        self.assert_unknown(body)

    def test_new_user_for_another_identity_stays_unknown(self):
        gate, state, operation = scenario()
        body = success()
        body["localId"] = "another-account"
        body["idToken"] = formal_id_token("another-account")
        event = apply_response(gate, state, operation, body)
        self.assertEqual(event["creationOutcome"], "unknown")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_unknown_ack_does_not_allow_recording_a_cleanup_delete(self):
        body = success()
        del body["localId"]
        body["idToken"] = formal_id_token(project=PROJECT + "-other")
        gate, state, operation, first = self.assert_unknown(body)
        recovery = {**operation, "kind": "delete", "binds": {}}
        with self.assertRaisesRegex(ValueError, "never created"):
            apply_response(gate, state, recovery, {}, recovery=True)
        self.assertEqual(first["creationOutcome"], "unknown")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_unknown_ack_is_not_cleared_by_a_later_absence(self):
        body = success()
        del body["localId"]
        body["idToken"] = "legacy-id-token"
        gate, state, operation, first = self.assert_unknown(body)
        recovery = {**operation, "kind": "uid-absence", "binds": {}}
        with self.assertRaisesRegex(ValueError, "never created"):
            apply_response(gate, state, recovery, {"users": []}, recovery=True)
        self.assertEqual(first["creationOutcome"], "unknown")
        self.assertEqual(state["jobs"][JOB]["absent"], [])

    def test_existing_ack_is_not_cleanup_ownership(self):
        gate, state, operation = scenario()
        first = apply_response(gate, state, operation, success(new=False))
        with self.assertRaisesRegex(ValueError, "never created"):
            apply_response(gate, state, {**operation, "kind": "delete", "binds": {}},
                           {}, recovery=True)
        self.assertEqual(first["creationOutcome"], "refused")

    def test_known_creation_cleanup_still_requires_delete_then_absence(self):
        gate, state, operation = scenario()
        first = apply_response(gate, state, operation, success())
        apply_response(gate, state, {**operation, "kind": "delete", "binds": {}},
                       {}, recovery=True)
        self.assertFalse(gate._all_accounts_absent(state))
        apply_response(gate, state, {**operation, "kind": "uid-absence", "binds": {}},
                       {"users": []}, recovery=True)
        self.assertTrue(gate._all_accounts_absent(state))
        self.assertEqual(state["jobs"][JOB]["absent"], [operation["resource"]])
        self.assertEqual(first["creationOutcome"], "created")

    def test_duplicate_creation_still_refuses(self):
        gate, state, operation = scenario()
        apply_response(gate, state, operation, success())
        with self.assertRaisesRegex(ValueError, "created twice"):
            apply_response(gate, state, operation, success())
        self.assertEqual(len(state["jobs"][JOB]["authAccounts"]), 1)
        self.assertTrue(state["jobs"][JOB]["stopped"])

    def test_resource_substitution_still_refuses(self):
        gate, state, operation = scenario()
        operation["resource"] = "projects/foreign/auth/accounts/not-owned"
        with self.assertRaisesRegex(ValueError, "resource differs"):
            apply_response(gate, state, operation, success())
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_other_known_accounts_are_not_rewritten_by_unknown_custom_ack(self):
        gate, state, operation = scenario()
        prior = {"uid": "prior-user", "resource": "fixture-resource", "createEvent": 0}
        state["jobs"][JOB]["authAccounts"]["acct0"] = copy.deepcopy(prior)
        body = success()
        del body["localId"]
        body["idToken"] = formal_id_token(project=PROJECT + "-other")
        event = apply_response(gate, state, operation, body)
        self.assertEqual(event["creationOutcome"], "unknown")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {"acct0": prior})

    def test_sign_up_success_does_not_require_custom_new_user_flag(self):
        gate, state, operation = scenario()
        operation["kind"] = "sign-up"
        body = success()
        del body["isNewUser"]
        event = apply_response(gate, state, operation, body)
        self.assertEqual(event["creationOutcome"], "created")

    def test_refresh_success_is_still_noncreating(self):
        gate, state, operation = scenario()
        operation["kind"] = "refresh"
        event = apply_response(gate, state, operation, {"id_token": "test"})
        self.assertEqual(event["creationOutcome"], "refused")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})


def register_unknown_test(name, patch=None, status=200, body=MISSING):
    def check(self):
        value = success() if body is MISSING else copy.deepcopy(body)
        if patch is not None:
            for key, replacement in patch.items():
                if replacement is MISSING:
                    value.pop(key, None)
                else:
                    value[key] = replacement
        self.assert_unknown(value, status)
    check.__name__ = "test_" + name
    setattr(CustomAckOutcomes, check.__name__, check)


for name, patch in [
    ("new_user_null", {"isNewUser": None}),
    ("new_user_zero_is_not_false", {"isNewUser": 0}),
    ("new_user_one_is_not_true", {"isNewUser": 1}),
    ("new_user_string_false", {"isNewUser": "false"}),
    ("new_user_string_true", {"isNewUser": "true"}),
    ("missing_id_token", {"idToken": MISSING}),
    ("missing_refresh_token", {"refreshToken": MISSING}),
    ("empty_id_token", {"idToken": ""}),
    ("empty_refresh_token", {"refreshToken": ""}),
    ("null_identity", {"localId": None}),
    ("boolean_identity", {"localId": True}),
    ("overlong_identity", {"localId": "a" * 129}),
    ("unresolved_identity_binding", {"localId": "$binding:customUid"}),
    ("unresolved_token_binding", {"idToken": "$binding:customIdToken"}),
    ("success_containing_error", {"error": {"message": "fixture"}}),
    ("reuse_with_missing_token", {"isNewUser": False, "idToken": MISSING}),
    ("reuse_with_error", {"isNewUser": False, "error": {"message": "fixture"}}),
]:
    register_unknown_test(name, patch=patch)

for name, body in [
    ("empty_success", {}),
    ("null_success", None),
    ("array_success", []),
    ("string_success", "not-an-object"),
]:
    register_unknown_test(name, body=body)

for name, status in [
    ("float_status_is_not_typed_success", 200.0),
    ("boolean_status_is_not_typed_success", True),
    ("missing_status", None),
    ("server_error_does_not_prove_refusal", 500),
    ("gateway_error_does_not_prove_refusal", 502),
    ("gateway_timeout_does_not_prove_refusal", 504),
    ("redirect_does_not_prove_refusal", 302),
]:
    register_unknown_test(name, status=status)

for status in [400, 401, 403]:
    def check_refusal(self, status=status):
        gate, state, operation = scenario()
        event = apply_response(gate, state, operation,
                               {"error": {"message": "INVALID_CUSTOM_TOKEN"}}, status)
        self.assertEqual(event["creationOutcome"], "refused")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})
    setattr(CustomAckOutcomes, f"test_typed_refusal_{status}_is_preserved", check_refusal)

if __name__ == "__main__":
    unittest.main()
