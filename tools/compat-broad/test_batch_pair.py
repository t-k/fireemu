"""Synthetic input fixtures validate comparison, never claim live oracle behavior."""

import copy
import importlib.util


def module():
    assert importlib.util.find_spec("batch_pair"), (
        "separate production/local comparison contract required"
    )
    import batch_pair

    return batch_pair


def fixture_pair():
    p = module()
    from batch_contract import candidate, database_evidence
    from test_readiness import database

    manifest = candidate()
    operations = p.expected_operations(manifest)
    reports = []
    for production, label in [(True, "prod"), (False, "local")]:
        nonce = ("a" if production else "b") * 32
        names = p.namespace(
            manifest,
            nonce,
            {
                f"broad-{nonce}-a@example.invalid": label + "-a",
                f"broad-{nonce}-b@example.invalid": label + "-b",
            },
        )
        rows = []
        for item in p.row_table(manifest):
            body = (
                {
                    "value": True,
                    "list": [1, 2],
                    "localId": label + "-a",
                    "idToken": label + "-token",
                    "expiresIn": "3600",
                }
                if item["id"].startswith("auth:")
                else {"value": 1, "array": [True, 1, None]}
            )
            rows.append(
                {
                    "id": item["id"],
                    "principal": item["principal"],
                    "operation": operations[item["id"]],
                    "observation": {
                        "httpStatus": 200,
                        "mediaType": "application/json",
                        "body": p.normalize(
                            body,
                            names,
                            service="auth"
                            if item["id"].startswith("auth:")
                            else "firestore",
                        ),
                    },
                }
            )
        reports.append(
            {
                "schemaVersion": 2,
                "fixtureOnly": True,
                "completed": True,
                "failure": None,
                "unrecovered": [],
                "rows": rows,
                "productionExecuted": production,
                "manifestDigest": p.digest(manifest),
                "observerDigest": "fixture-observer",
                "comparisonBinding": p.binding(manifest),
                "namespace": names,
                "configurationUnchanged": True if production else None,
                "databaseObservations": [
                    database_evidence(database()),
                    database_evidence(database()),
                ]
                if production
                else [],
            }
        )
    return reports


def test_pair_fixtures_match_mismatch_missing_and_incomplete_cleanup():
    p = module()
    production, local = fixture_pair()
    result = p.compare_pair(production, local)
    assert result["compatibility"] == "match" and result["recordingComplete"]
    assert result["evidenceKind"] == "input-fixture"
    changed = copy.deepcopy(production)
    changed["rows"][0]["observation"]["body"]["value"] = True
    result = p.compare_pair(changed, local)
    assert result["compatibility"] == "mismatch" and result["recordingComplete"]
    assert p.exit_code(result, check=False) == 0
    assert p.exit_code(result, check=True) != 0
    for changes in [
        {"rows": production["rows"][:-1]},
        {"completed": False},
        {"unrecovered": [{"kind": "account"}]},
    ]:
        result = p.compare_pair({**production, **changes}, local)
        assert not result["recordingComplete"]
        assert result["compatibility"] == "indeterminate"
        assert p.exit_code(result, check=False) != 0


def test_principal_namespace_and_normalizer_bindings_cannot_be_forged():
    p = module()
    production, local = fixture_pair()
    for mutation in ["principal", "namespace", "normalizer", "operation"]:
        changed = copy.deepcopy(production)
        if mutation == "principal":
            changed["rows"][0]["principal"] = "anonymous"
        if mutation == "namespace":
            changed["namespace"]["firestoreParents"]["writes/transforms"] = (
                "projects/foreign/documents"
            )
        if mutation == "normalizer":
            changed["comparisonBinding"]["normalizerVersion"] = "unknown"
        if mutation == "operation":
            changed["rows"][0]["operation"]["extra"] = True
        result = p.compare_pair(changed, local)
        assert not result["bindingsValid"]
        assert result["compatibility"] == "indeterminate"


def test_auth_normalization_preserves_wrong_owner_relative_expiry_and_shape():
    p = module()
    _, local = fixture_pair()
    names = local["namespace"]
    a = p.normalize(
        {"localId": "local-a", "idToken": "secret", "expiresIn": "3600"},
        names,
        service="auth",
    )
    assert a == p.normalize(
        {"localId": "local-a", "idToken": "another-secret", "expiresIn": "3600"},
        names,
        service="auth",
    )
    for body in [
        {"localId": "local-b", "idToken": "secret", "expiresIn": "3600"},
        {"localId": "local-a", "idToken": "secret", "expiresIn": "3599"},
        {"localId": "local-a", "expiresIn": "3600"},
    ]:
        assert a != p.normalize(body, names, service="auth")
    assert (
        p.normalize({"applicationDate": "2030-01-01T00:00:00Z"}, names, service="auth")[
            "applicationDate"
        ]
        == "2030-01-01T00:00:00Z"
    )


def test_auth_emit_retains_completed_rows_before_later_failure():
    import pytest
    from broad_cases import auth_scenario

    emitted = []

    def fixture_call(path, body, **kwargs):
        if len(emitted) == 1:
            raise ValueError("fixture transport failure")
        return 200, {"localId": "a", "idToken": "token", "refreshToken": "refresh"}

    with pytest.raises(ValueError, match="fixture transport"):
        auth_scenario(fixture_call, on_row=lambda row, body: emitted.append(row))
    assert [row["id"] for row in emitted] == ["auth:broad/create-a"]


def test_malformed_database_and_rows_cannot_be_complete():
    p = module()
    production, local = fixture_pair()
    for records in [None, [None, None], [{}, {}]]:
        result = p.compare_pair({**production, "databaseObservations": records}, local)
        assert not result["recordingComplete"]
    bad = copy.deepcopy(local)
    bad["rows"][0]["id"] = []
    assert not p.compare_pair(production, bad)["recordingComplete"]


def test_projection_settings_mutations_and_response_changes_remain_visible():
    p = module()
    production, local = fixture_pair()
    mutations = [
        lambda row: row["observation"].update(httpStatus=400),
        lambda row: row["observation"].update(mediaType="text/plain"),
        lambda row: row["observation"]["body"].pop("value"),
        lambda row: row["observation"]["body"].update(array=[1, True, None]),
    ]
    for mutate in mutations:
        changed = copy.deepcopy(local)
        mutate(changed["rows"][0])
        result = p.compare_pair(production, changed)
        assert result["recordingComplete"] and result["compatibility"] == "mismatch"


def test_both_sides_cannot_substitute_a_different_or_missing_operation():
    p = module()
    for value in [None, {}, {"method": "DELETE"}]:
        production, local = fixture_pair()
        production["rows"][0]["operation"] = value
        local["rows"][0]["operation"] = value
        assert not p.compare_pair(production, local)["recordingComplete"]


def test_request_query_preconditions_are_bound():
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from batch_adapter import Adapter
    from batch_contract import candidate

    with TemporaryDirectory() as tmp:
        a = Adapter(
            candidate(),
            "a" * 32,
            Path(tmp) / "output",
            local_origins={
                "auth": "http://127.0.0.1:11001",
                "firestore": "http://127.0.0.1:11002",
            },
        )
        operations = [
            a.normal_operation("/v1/doc" + query, "PATCH", {}, "firestore")
            for query in [
                "?currentDocument.exists=false",
                "?currentDocument.exists=true",
                "",
            ]
        ]
        assert len({module().digest(o) for o in operations}) == 3


def test_owned_provider_email_and_access_token_normalization_is_bounded():
    p = module()
    production, local = fixture_pair()
    normalized = []
    for report in (production, local):
        names = report["namespace"]
        normalized.append(
            p.normalize(
                {
                    "providerUserInfo": [
                        {
                            "providerId": "password",
                            "federatedId": names["authEmails"]["a"],
                            "rawId": names["authEmails"]["a"],
                        }
                    ],
                    "access_token": names["nonce"],
                },
                names,
                service="auth",
            )
        )
        unknown = p.normalize(
            {"federatedId": "foreign@example.invalid", "access_token": False},
            names,
            service="auth",
        )
        assert unknown == {
            "federatedId": "foreign@example.invalid",
            "access_token": False,
        }
    assert normalized[0] == normalized[1]


def test_finite_recording_and_check_outcomes():
    import itertools

    from batch_contract import recording_exit_code

    p = module()
    checked = 0
    for completed, failure, recovered, matching, check in itertools.product(
        [False, True], repeat=5
    ):
        recording = {
            "completed": completed,
            "failure": "fixture" if failure else None,
            "unrecovered": [] if recovered else ["owned"],
        }
        is_complete = completed and not failure and recovered
        assert (recording_exit_code(recording) == 0) is is_complete
        result = {
            "recordingComplete": is_complete,
            "compatibility": "match" if matching else "mismatch",
        }
        assert (p.exit_code(result, check) == 0) is (
            is_complete and (matching or not check)
        )
        checked += 1
    assert checked == 32


def test_raw_id_mapping_requires_password_provider_path_and_observed_owner():
    p = module()
    production, _ = fixture_pair()
    names = production["namespace"]
    email = names["authEmails"]["a"]
    for body in [
        {"rawId": email},
        {"providerUserInfo": [{"providerId": "other", "rawId": email}]},
        {
            "providerUserInfo": [
                {"providerId": "password", "rawId": "foreign@example.invalid"}
            ]
        },
        {"providerUserInfo": [{"providerId": "password", "rawId": False}]},
    ]:
        assert p.normalize(body, names, service="auth") == body
    body = {
        "users": [
            {
                "providerUserInfo": [
                    {"providerId": "password", "rawId": names["authEmails"]["b"]}
                ]
            }
        ]
    }
    result = p.normalize(body, names, service="auth")
    assert result["users"][0]["providerUserInfo"][0]["rawId"] == {"$email": "b"}


def test_last_refresh_normalization_is_rfc3339_and_path_specific():
    p = module()
    _, local = fixture_pair()
    names = local["namespace"]

    def normalized(value):
        return p.normalize({"users": [{"lastRefreshAt": value}]}, names, service="auth")

    first = normalized("2026-09-12T13:02:03.123456789Z")
    assert first == normalized("2026-09-13T14:03:04Z")
    assert first == normalized("2026-09-13T14:03:04+09:00")
    assert first == normalized("2026-09-13T14:03:04-05:30")
    for invalid in [
        None,
        True,
        123,
        "123",
        "2026-02-30T13:02:03Z",
        "2026-09-12",
        "",
        "2026-09-12T13:02:03+00:60",
        "2026-09-12T13:02:03+01:99",
        "2026-09-12T13:02:03+24:00",
    ]:
        assert normalized(invalid)["users"][0]["lastRefreshAt"] == invalid
        assert normalized(invalid) != first
    for body in [
        {"lastRefreshAt": "2026-09-12T13:02:03Z"},
        {"nested": {"users": [{"lastRefreshAt": "2026-09-12T13:02:03Z"}]}},
    ]:
        assert p.normalize(body, names, service="auth") == body
    assert (
        p.normalize(
            {"users": [{"lastRefreshAt": "2026-09-12T13:02:03Z"}]},
            names,
            service="firestore",
        )
        != first
    )


def saved_local_fixture():
    import json

    from batch_adapter import observer_digest
    from broad_contract import ROOT

    p = module()
    _, local = fixture_pair()
    saved = json.loads(
        (
            ROOT / "spec/compatibility/broad-runs/bc38f392-paired-observations.json"
        ).read_bytes()
    )
    local["observerDigest"] = observer_digest()
    local["rows"] = [
        {
            "id": r["id"],
            "principal": r["principal"],
            "operation": r["operation"],
            "observation": {
                **r["production"],
                "body": p.normalize(
                    r["production"]["body"],
                    local["namespace"],
                    service=r["operation"]["service"],
                ),
            },
        }
        for r in saved["rows"]
    ]
    return local


def test_saved_reference_reevaluation_binds_operations_and_completeness():
    p = module()
    local = saved_local_fixture()
    result = p.compare_saved(local)
    assert result["recordingComplete"] and result["compatibility"] == "match"
    assert result["mode"] == "saved-production-versus-local"
    assert result["evidenceKind"] == "input-fixture"
    assert result["source"]["originalComparisonCounts"] == {"match": 35, "mismatch": 11}
    assert result["source"]["observerDigest"] != result["localObserverDigest"]
    changed = copy.deepcopy(local)
    changed["rows"][0]["observation"]["body"]["extra"] = True
    result = p.compare_saved(changed)
    assert result["recordingComplete"] and result["compatibility"] == "mismatch"
    for field, value in [
        ("completed", False),
        ("unrecovered", ["owned"]),
        ("observerDigest", "unknown"),
    ]:
        assert not p.compare_saved({**local, field: value})["recordingComplete"]
    for change in ["missing", "order", "principal", "operation", "namespace"]:
        changed = copy.deepcopy(local)
        if change == "missing":
            changed["rows"].pop()
        if change == "order":
            changed["rows"].reverse()
        if change == "principal":
            changed["rows"][0]["principal"] = "anonymous"
        if change == "operation":
            changed["rows"][0]["operation"]["body"] = {"different": True}
        if change == "namespace":
            changed["namespace"]["authEmails"]["a"] = "foreign@example.invalid"
        assert not p.compare_saved(changed)["recordingComplete"]


def test_saved_reference_files_are_pinned(tmp_path):
    import shutil

    import pytest
    from broad_contract import ROOT

    p = module()
    source = ROOT / "spec/compatibility/broad-runs"
    for name in ["bc38f392-paired-observations.json", "bc38f392-execution-result.json"]:
        shutil.copyfile(source / name, tmp_path / name)
    p.load_saved_reference(tmp_path)
    path = tmp_path / "bc38f392-paired-observations.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="saved reference hash"):
        p.load_saved_reference(tmp_path)
