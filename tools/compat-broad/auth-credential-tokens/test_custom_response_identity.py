"""AUTH-CUSTOM-IDENTITY-026: response projection, not JWT authentication.

The Gate unit tests call response methods on explicit in-memory state; they do
not exercise shared Gate admission, Ledger, HTTPS or production. Tokens here are
synthetic envelopes; an RS256-labelled fixture is NOT a verified signature.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential_collector as collector
import credential_gate as gate_module
import credential_responsibility as responsibility
import credential_shadow as shadow

PROJECT = "demo-custom-identity"
NONCE = "12" * 16
UID = f"custom-{NONCE}"
JOB = "auth-credential"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def token(claims: dict | None = None, *, alg: str = "none", raw: bytes | None = None) -> str:
    payload = {
        "sub": UID, "user_id": UID, "aud": PROJECT,
        "iss": f"https://securetoken.google.com/{PROJECT}",
        "firebase": {"sign_in_provider": "custom"},
        "iat": 100, "exp": 3700, "auth_time": 100,
    }
    if claims:
        payload.update(claims)
    header = b64(json.dumps({"alg": alg, "typ": "JWT", "kid": "fixture-only"}).encode())
    encoded = b64(raw if raw is not None else json.dumps(payload).encode())
    signature = "" if alg == "none" else b64(b"not-a-cryptographic-signature")
    return f"{header}.{encoded}.{signature}"


def response(*, new: bool = True, local_id: bool = False, claims: dict | None = None,
             alg: str = "none") -> dict:
    result = {"idToken": token(claims, alg=alg), "refreshToken": "fixture-refresh",
              "expiresIn": "3600", "isNewUser": new}
    if local_id:
        result["localId"] = UID
    return result


def identity(body: object, status: object = 200) -> str | None:
    return collector.custom_signin_response_uid(status, body, project=PROJECT, requested_uid=UID)


def make_gate() -> tuple:
    gate = gate_module.CredentialGate.__new__(gate_module.CredentialGate)
    gate.job, gate.bindings, gate._observed = JOB, {}, {}
    resource = gate_module.account_resource(PROJECT, NONCE, "custom")
    recovery = [{"kind": kind, "account": "custom"} for kind in ("delete", "uid-absence")]
    state = {"plan": {"nonce": NONCE, "project": PROJECT,
                      "jobs": {JOB: {"recovery": recovery}}}, "events": [],
             "jobs": {JOB: {"resources": [resource], "absent": []}}}
    operation = {"kind": "custom-sign-in", "account": "custom", "resource": resource,
                 "binds": {"customUid": "idToken.sub", "customIdToken": "idToken",
                           "customRefresh": "refreshToken"}}
    return gate, state, operation


def record(gate, state, operation, body, *, status=200, recovery=False):
    event = {"creationOutcome": "pending", "completed": True, "failure": None,
             "responseDigest": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()}
    state["events"].append(event)
    gate._record_response(state, operation, recovery, event, status, body)
    return event


def track(body, *, status=200):
    tracker = collector.new_tracker(NONCE)
    intent = responsibility.begin(tracker, "custom-signin", requested_uid=UID)
    outcome = None
    try:
        shadow._track_custom_signin(tracker, intent, status, body,
                                   project=PROJECT, requested_uid=UID)
    except shadow.ShadowError as error:
        outcome = str(error)
    return tracker, intent, outcome


class ExistingEntryPointRegressionTests(unittest.TestCase):
    """These same five scenarios are also run against the original entrypoint bodies."""
    def test_gate_accepts_formal_response_without_local_id(self):
        gate, state, op = make_gate()
        event = record(gate, state, op, response(alg="RS256"))
        self.assertEqual(event["creationOutcome"], "created")
        self.assertEqual(gate._observed.get("customUid"), UID)

    def test_gate_keeps_incomplete_success_unknown(self):
        gate, state, op = make_gate()
        body = response()
        body.pop("isNewUser")
        event = record(gate, state, op, body)
        self.assertEqual(event["creationOutcome"], "unknown")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_gate_does_not_bind_credentials_from_unconfirmed_identity(self):
        gate, state, op = make_gate()
        event = record(gate, state, op, response(claims={"sub": "another-user"}))
        self.assertEqual(gate._observed, {})
        self.assertEqual(event["creationOutcome"], "unknown")

    def test_runner_tracks_formal_response_without_local_id(self):
        tracker, intent, failure = track(response(alg="RS256"))
        self.assertIsNone(failure)
        self.assertIn(UID, tracker["accounts"])
        self.assertEqual(tracker["creationIntents"][intent]["state"], "confirmed")

    def test_runner_does_not_prefer_local_id_over_conflicting_subject(self):
        tracker, intent, failure = track(response(local_id=True, claims={"sub": "someone-else"}))
        self.assertEqual(failure, "custom sign-in creation status unconfirmed")
        self.assertEqual(tracker["accounts"], {})
        self.assertEqual(tracker["creationIntents"][intent]["state"], "unknown")


class IdentityProjectionTests(unittest.TestCase):
    def test_local_unsigned_and_signed_envelopes_are_data_not_signature_proof(self):
        for alg in ("none", "RS256"):
            with self.subTest(alg=alg):
                self.assertEqual(identity(response(alg=alg)), UID)

    def test_consistent_optional_local_id_is_supported_but_not_added(self):
        for local in (False, True):
            body = response(local_id=local)
            before = copy.deepcopy(body)
            self.assertEqual(identity(body), UID)
            self.assertEqual(body, before)
            self.assertEqual("localId" in body, local)

    def test_reuse_is_an_identity_result_not_creation(self):
        body = response(new=False)
        self.assertEqual(identity(body), UID)
        self.assertIs(body["isNewUser"], False)

    def test_unknown_new_user_flag_stays_unknown(self):
        for value in (None, 0, 1, "false", "true", [], {}):
            with self.subTest(value=value):
                self.assertIsNone(identity({**response(), "isNewUser": value}))
        body = response()
        del body["isNewUser"]
        self.assertIsNone(identity(body))

    def test_status_and_response_types(self):
        for status in (None, True, False, 200.0, "200", 201, 400, 500):
            with self.subTest(status=status):
                self.assertIsNone(identity(response(), status))
        for body in (None, [], "response", True, {}, {**response(), "error": None}):
            with self.subTest(body_type=type(body).__name__):
                self.assertIsNone(identity(body))

    def test_token_fields_are_required_and_bounded(self):
        for key in ("idToken", "refreshToken"):
            for value in (None, True, 1, [], {}, "", "x" * 8193):
                with self.subTest(key=key, kind=type(value).__name__):
                    self.assertIsNone(identity({**response(), key: value}))
            body = response()
            del body[key]
            self.assertIsNone(identity(body))

    def test_conflicting_optional_identity_is_not_ignored(self):
        for value in (None, True, 0, "", "other"):
            with self.subTest(value=value):
                self.assertIsNone(identity({**response(), "localId": value}))

    def test_subject_project_and_issuer_must_be_exact(self):
        cases = [{"sub": "elsewhere"}, {"sub": None}, {"sub": True}, {"sub": [UID]},
                 {"aud": PROJECT + "-other"}, {"aud": [PROJECT]}, {"aud": None},
                 {"iss": "https://session.firebase.google.com/" + PROJECT},
                 {"iss": f"https://securetoken.google.com/{PROJECT}/"},
                 {"user_id": "other"}, {"user_id": None}]
        for claims in cases:
            with self.subTest(claims=claims):
                self.assertIsNone(identity(response(claims=claims)))

    def test_subject_audience_and_issuer_cannot_be_missing(self):
        base = json.loads(base64.urlsafe_b64decode(token().split(".")[1] + "=="))
        for key in ("sub", "iss", "aud", "firebase"):
            claims = {k: v for k, v in base.items() if k != key}
            with self.subTest(key=key):
                self.assertIsNone(identity({**response(), "idToken": token(raw=json.dumps(claims).encode())}))

    def test_optional_user_id_need_not_exist(self):
        claims = json.loads(base64.urlsafe_b64decode(token().split(".")[1] + "=="))
        del claims["user_id"]
        self.assertEqual(identity({**response(), "idToken": token(raw=json.dumps(claims).encode())}), UID)

    def test_project_campaign_refuses_tenant_subjects(self):
        for tenant in ("tenant-a", None, "", False):
            with self.subTest(tenant=tenant):
                claims = {"firebase": {"sign_in_provider": "custom", "tenant": tenant}}
                self.assertIsNone(identity(response(claims=claims)))

    def test_provider_and_firebase_shape_are_checked(self):
        for firebase in (None, [], {}, "custom", {"sign_in_provider": "password"},
                         {"sign_in_provider": True}):
            with self.subTest(firebase=firebase):
                self.assertIsNone(identity(response(claims={"firebase": firebase})))

    def test_local_session_marker_does_not_change_subject(self):
        claims = {"firebase": {"sign_in_provider": "custom", "fireemu_session_epoch": "local-only"}}
        self.assertEqual(identity(response(claims=claims)), UID)

    def test_malformed_tokens_do_not_raise_or_reveal_input(self):
        for value in ("a.b.c", "a.b", "a.b.c.d", "日本語", token() + "x", "." + token()):
            with self.subTest(value_length=len(value)):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    self.assertIsNone(identity({**response(), "idToken": value}))
                self.assertEqual(output.getvalue(), "")

    def test_duplicate_payload_or_header_members_are_rejected(self):
        raw = ('{"sub":"'+UID+'","sub":"'+UID+'"}').encode()
        self.assertIsNone(identity({**response(), "idToken": token(raw=raw)}))
        parts = token().split(".")
        parts[0] = b64(b'{"alg":"none","alg":"none"}')
        self.assertIsNone(identity({**response(), "idToken": ".".join(parts)}))

    def test_non_json_and_nonfinite_payloads_are_rejected(self):
        for raw in (b"[]", b"null", b"\xff", b"{\"n\":NaN}", b"{\"n\":1e999}", b"{} trailing"):
            with self.subTest(raw=raw):
                self.assertIsNone(identity({**response(), "idToken": token(raw=raw)}))

    def test_configuration_arguments_are_not_coerced(self):
        for project, uid in ((None, UID), ("", UID), (PROJECT, None), (PROJECT, ""),
                             (PROJECT, "x" * 129), (PROJECT, True)):
            with self.subTest(project=project, uid=uid):
                self.assertIsNone(collector.custom_signin_response_uid(
                    200, response(), project=project, requested_uid=uid))

    def test_clock_claims_are_not_rewritten_or_used_as_observation_gate(self):
        body = response(claims={"iat": 3701, "exp": 3700, "auth_time": -123})
        original = copy.deepcopy(body)
        self.assertEqual(identity(body), UID)
        self.assertEqual(body, original)


class GateProjectionTests(unittest.TestCase):
    def test_explicit_reuse_never_grants_ownership(self):
        gate, state, op = make_gate()
        event = record(gate, state, op, response(new=False))
        self.assertEqual(event["creationOutcome"], "refused")
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})
        self.assertNotIn("uid", event["authEvidence"])
        self.assertNotIn("resource", event["authEvidence"])

    def test_response_is_not_mutated_and_token_not_copied_to_evidence(self):
        gate, state, op = make_gate()
        body = response()
        original = copy.deepcopy(body)
        event = record(gate, state, op, body)
        self.assertEqual(body, original)
        serialized = json.dumps(event)
        self.assertNotIn(body["idToken"], serialized)
        self.assertNotIn(body["refreshToken"], serialized)

    def test_legacy_local_id_binding_requires_refreezing_not_silent_reinterpretation(self):
        gate, state, op = make_gate()
        op["binds"]["customUid"] = "localId"
        with self.assertRaisesRegex(ValueError, "custom identity binding contract differs"):
            record(gate, state, op, response(local_id=True))
        self.assertEqual(gate._observed, {})
        self.assertTrue(state["jobs"][JOB]["stopped"])

    def test_legacy_or_empty_bindings_cannot_fallback_to_untrusted_local_id(self):
        for binds in ({"customUid": "localId"}, {}):
            gate, state, op = make_gate()
            op["binds"] = binds
            body = response(local_id=True, claims={"aud": "wrong-project"})
            if binds:
                with self.assertRaisesRegex(ValueError, "custom identity binding contract differs"):
                    record(gate, state, op, body)
            else:
                event = record(gate, state, op, body)
                self.assertEqual(event["creationOutcome"], "unknown")
            self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_duplicate_creation_is_still_refused(self):
        gate, state, op = make_gate()
        record(gate, state, op, response())
        with self.assertRaisesRegex(ValueError, "created twice"):
            record(gate, state, op, response())

    def test_foreign_resource_is_still_refused(self):
        gate, state, op = make_gate()
        op["resource"] += "-different"
        with self.assertRaisesRegex(ValueError, "resource differs"):
            record(gate, state, op, response())
        self.assertEqual(state["jobs"][JOB]["authAccounts"], {})

    def test_typed_failure_and_server_uncertainty_remain_distinct(self):
        for status, expected in ((400, "refused"), (403, "refused"), (500, "unknown"), (None, "unknown")):
            with self.subTest(status=status):
                gate, state, op = make_gate()
                event = record(gate, state, op, {"error": {"message": "FIXTURE"}}, status=status)
                self.assertEqual(event["creationOutcome"], expected)
                self.assertEqual(gate._observed, {})

    def test_reuse_without_proven_subject_stays_unknown(self):
        gate, state, op = make_gate()
        event = record(gate, state, op, response(new=False, claims={"aud": "other"}))
        self.assertEqual(event["creationOutcome"], "unknown")
        self.assertEqual(gate._observed, {})

    def test_signup_contract_still_uses_local_id(self):
        gate, state, op = make_gate()
        op.update(kind="sign-up", account="acct0",
                  resource=gate_module.account_resource(PROJECT, NONCE, "acct0"),
                  binds={"acct0Uid": "localId"})
        event = record(gate, state, op, {"localId": "signup-uid", "idToken": "fixture", "refreshToken": "fixture"})
        self.assertEqual(event["creationOutcome"], "created")
        self.assertEqual(gate._observed["acct0Uid"], "signup-uid")

    def test_custom_cleanup_still_requires_delete_before_absence(self):
        gate, state, op = make_gate()
        record(gate, state, op, response())
        recovery = {**op, "binds": {}, "kind": "uid-absence"}
        with self.assertRaisesRegex(ValueError, "typed post-delete"):
            record(gate, state, recovery, {"users": []}, recovery=True)

    def test_custom_cleanup_after_creation_can_reach_absence(self):
        gate, state, op = make_gate()
        record(gate, state, op, response())
        record(gate, state, {**op, "kind": "delete", "binds": {}}, {}, recovery=True)
        record(gate, state, {**op, "kind": "uid-absence", "binds": {}}, {"users": []}, recovery=True)
        self.assertEqual(state["jobs"][JOB]["absent"], [op["resource"]])


class RunnerTrackingTests(unittest.TestCase):
    def test_verified_uid_is_returned_for_later_admin_payloads(self):
        tracker = collector.new_tracker(NONCE)
        intent = responsibility.begin(tracker, "custom-signin", requested_uid=UID)
        body = response(alg="RS256")
        uid = shadow._track_custom_signin(tracker, intent, 200, body,
                                         project=PROJECT, requested_uid=UID)
        self.assertEqual(uid, UID)
        self.assertNotIn("localId", body)

    def test_reuse_stops_without_adding_account(self):
        tracker, intent, failure = track(response(new=False))
        self.assertEqual(failure, "custom sign-in reused an account not owned by this run")
        self.assertEqual(tracker["accounts"], {})
        self.assertEqual(tracker["creationIntents"][intent]["state"], "existing")

    def test_unknown_response_keeps_write_ahead_responsibility(self):
        body = response()
        del body["isNewUser"]
        tracker, intent, failure = track(body)
        self.assertEqual(failure, "custom sign-in creation status unconfirmed")
        self.assertEqual(responsibility.summary(tracker)["unknownCreates"], 1)
        self.assertEqual(tracker["accounts"], {})

    def test_refusal_does_not_invent_creation(self):
        tracker, intent, failure = track({"error": {"message": "INVALID_CUSTOM_TOKEN"}}, status=400)
        self.assertIn("INVALID_CUSTOM_TOKEN", failure)
        self.assertEqual(tracker["accounts"], {})
        self.assertEqual(tracker["creationIntents"][intent]["state"], "unknown")

    def test_bound_gate_and_runner_use_same_uid_without_altering_response(self):
        gate, state, op = make_gate()
        body = response(alg="RS256")
        original = copy.deepcopy(body)
        record(gate, state, op, body)
        tracker, intent, failure = track(body)
        self.assertIsNone(failure)
        self.assertEqual(gate._observed["customUid"], tracker["creationIntents"][intent]["uid"])
        self.assertEqual(body, original)

    def test_actual_journal_records_subject_but_never_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = collector.new_tracker(NONCE)
            responsibility.attach(tracker, Path(directory) / "journal", {"testOnly": True})
            try:
                intent = responsibility.begin(tracker, "custom-signin", requested_uid=UID)
                body = response(alg="RS256")
                shadow._track_custom_signin(tracker, intent, 200, body, project=PROJECT, requested_uid=UID)
                records = [p.read_text() for p in sorted((Path(directory)/"journal").glob("*.json"))]
                self.assertEqual(len(records), 3)
                self.assertEqual(json.loads(records[-1])["event"]["uid"], UID)
                for credential in (body["idToken"], body["refreshToken"]):
                    self.assertNotIn(credential, "".join(records))
                self.assertFalse(responsibility.summary(tracker)["authorizesCleanup"])
            finally:
                responsibility.close(tracker)

    def test_journal_failure_is_not_successful_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = collector.new_tracker(NONCE)
            responsibility.attach(tracker, Path(directory) / "journal", {"testOnly": True})
            try:
                intent = responsibility.begin(tracker, "custom-signin", requested_uid=UID)
                journal = tracker["_responsibilityJournal"]
                with mock.patch.object(journal, "append", side_effect=responsibility.JournalFailure("fixture")):
                    with self.assertRaises(responsibility.JournalFailure):
                        shadow._track_custom_signin(tracker, intent, 200, response(), project=PROJECT, requested_uid=UID)
                self.assertFalse(responsibility.summary(tracker)["recordingComplete"])
            finally:
                responsibility.close(tracker)


if __name__ == "__main__":
    unittest.main()
