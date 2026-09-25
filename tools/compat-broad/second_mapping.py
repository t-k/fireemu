"""Independent admission checks precede second45 mapping comparisons."""

from __future__ import annotations

from batch_pair import normalize
from broad_contract import digest
from second_admission import (
    BASE,
    FS_IDS,
    auth_recipe,
    equal,
    fs_recipe,
    manifest,
    require_operation,
)


def names(users, document=None):
    return {
        "authEmails": {r: u["email"] for r, u in users.items()},
        "authUids": {r: u["uid"] for r, u in users.items()},
        "firestoreParents": {} if document is None else {"second-document": document},
    }


def canonical(value, users, document=None):
    def visit(item):
        if isinstance(item, dict):
            return {k: visit(v) for k, v in item.items()}
        if isinstance(item, list):
            return [visit(v) for v in item]
        if isinstance(item, str):
            for role, user in users.items():
                for field in ("uid", "email", "token"):
                    if item == user[field]:
                        return {"$" + field: role}
            if document and document in item:
                return item.replace(document, "documents/SECOND")
        return item

    return visit(value)


def expected_ids():
    result = [f"second/auth/{i:02d}" for i in range(1, 33)]
    for p in FS_IDS:
        result += [
            p + "/" + s
            for s in (
                ("original", "normal", "before", "diagnostic", "after")
                if p == FS_IDS[1]
                else ("normal", "before", "diagnostic", "after")
            )
        ]
    return result


def validate_rows(result, *, observed_outcomes=False):
    if [r["id"] for r in result["rows"]] != expected_ids():
        raise ValueError("missing, duplicate, or reordered rows")
    if (
        result.get("admissionDigest")
        if observed_outcomes
        else result.get("manifestDigest")
    ) != digest(manifest()):
        raise ValueError("manifest not bound")
    if result.get("mode") not in {"direct", "mapped"}:
        raise ValueError("unknown mapping mode")
    for i, program in enumerate(FS_IDS):
        expected_name = BASE + (
            "/cur/c"
            if result["mode"] == "direct"
            else f"/_fireemuBroad/{result['nonce']}-{i}/cur/c"
        )
        if result["documents"].get(program) != expected_name:
            raise ValueError("foreign namespace")
    phases = ["setup"] * 4
    for i in range(32):
        phases += (
            ["baseline"] * 4
            + ["before"] * (3 if i in (26, 27) else 2)
            + ["diagnostic"]
            + ["after"] * 2
        )
    phases += ["recovery"] * 8
    for i in range(3):
        phases += (
            ["absence", "seed"]
            + (["original"] if i == 1 else [])
            + ["normal", "before", "diagnostic", "after"]
            + ["recovery"] * 3
        )
    trace = result.get("trace", [])
    if not observed_outcomes and (
        [t.get("phase") for t in trace] != phases
        or [t.get("ordinal") for t in trace] != list(range(len(phases)))
    ):
        raise ValueError("missing, duplicate, or reordered phase operations")
    for index, row in enumerate(result["rows"]):
        if index < 32:
            expected = auth_recipe(index, result["bindings"])
            relation = None
        else:
            program, step = row["id"].rsplit("/", 1)
            expected, relation = fs_recipe(
                program, step, row["document"], row["versions"]
            )
            if row["document"] != result["documents"][program]:
                raise ValueError("unowned document binding")
        require_operation(row["sent"], expected)
        if row.get("relation") != relation:
            raise ValueError("version relation mismatch")


def comparable(row, bindings):
    document = row.get("document")
    sent = canonical(row["sent"], bindings, document)
    if row.get("relation"):
        sent["query"] = [["currentDocument.updateTime", row["relation"]]]
    observation = {
        "httpStatus": row["observation"]["httpStatus"],
        "mediaType": row["observation"]["mediaType"],
        "wire": {
            key: row["observation"]["http"][key]
            for key in ("bodyKind", "complete", "contentType")
        },
        "body": normalize(
            row["observation"]["body"],
            names(bindings, document),
            service=row["sent"]["service"],
        ),
    }
    value = {
        "id": row["id"],
        "sent": sent,
        "relation": row.get("relation"),
        "observation": canonical(observation, bindings, document),
    }
    for key in ("before", "after"):
        if key in row:
            value[key] = canonical(
                normalize(
                    {"users": list(row[key].values())}, names(bindings), service="auth"
                ),
                bindings,
            )
    return value


def compare_second(direct, mapped):
    complete = all(
        r.get("recordingComplete") is True and r.get("cleanupComplete") is True
        for r in (direct, mapped)
    )
    errors = []
    observed_safety = []
    for label, result in (("direct", direct), ("mapped", mapped)):
        try:
            validate_rows(result)
            observed_safety.append(validate_trace(result))
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            errors.append({"side": label, "reason": str(error)})
    if (
        direct.get("nonce") == mapped.get("nonce")
        or direct.get("mode") != "direct"
        or mapped.get("mode") != "mapped"
    ):
        errors.append({"reason": "distinct direct/mapped bindings required"})
    identity = direct.get("runtimeIdentity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"artifactSha256", "executionCommit", "configurationDigest"}
        or not all(isinstance(v, str) and v for v in identity.values())
        or not equal(identity, mapped.get("runtimeIdentity"))
        or not direct.get("observerDigest")
        or direct.get("observerDigest") != mapped.get("observerDigest")
    ):
        errors.append({"reason": "runtime or observer not identically bound"})
    rows = []
    if not errors:
        for left, right in zip(direct["rows"], mapped["rows"], strict=True):
            rows.append(
                {
                    "id": left["id"],
                    "mapping": "match"
                    if equal(
                        comparable(left, direct["bindings"]),
                        comparable(right, mapped["bindings"]),
                    )
                    else "mismatch",
                }
            )
    return {
        "kind": "second45-mapping-comparison-v1",
        "semanticContract": "second45-received-json-semantics-v1",
        "manifestDigest": direct.get("manifestDigest"),
        "recordingComplete": complete,
        "safety": False
        if False in observed_safety
        or any(r.get("safety") is False for r in (direct, mapped))
        else (True if len(observed_safety) == 2 and all(observed_safety) else None),
        "mapping": "invalid"
        if errors or not complete
        else ("match" if all(r["mapping"] == "match" for r in rows) else "mismatch"),
        "rows": rows,
        "errors": errors,
        "productionCompatibility": "unobserved",
        "inputDigests": [digest(v) for v in (direct, mapped)],
    }


def validate_trace(result, *, observed_outcomes=False):
    """Bind independent recipes and version provenance to actual transport entries."""
    from urllib.parse import urlencode

    from current_contract import received
    from second_admission import PROJECT, operation
    from second_cases import auth_cases, auth_invariants

    safe = True
    entries = iter(result["trace"])
    users = result["bindings"]
    admin = f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"

    phase = "setup"
    ordinal = 0

    def take(expected):
        nonlocal ordinal
        entry = next(entries)
        if (
            entry.get("ordinal") != ordinal
            or entry.get("phase") != phase
            or entry.get("recovery") is not (phase == "recovery")
        ):
            raise ValueError("missing, duplicate, or reordered phase operations")
        ordinal += 1
        require_operation(entry["sent"], expected)
        observation = entry.get("observation")
        flexible_body = observed_outcomes and (
            phase == "diagnostic"
            or (
                expected["service"] == "firestore"
                and expected["method"] == "GET"
                and isinstance(observation, dict)
                and observation.get("httpStatus") == 404
                and phase in {"absence", "after", "recovery"}
            )
        )
        if (
            entry.get("failure")
            or not isinstance(observation, dict)
            or type(observation.get("httpStatus")) is not int
            or (not flexible_body and not isinstance(observation.get("body"), dict))
        ):
            raise ValueError("incomplete trace response")
        if (
            not received(
                {"status": observation["httpStatus"], "http": observation.get("http")}
            )
            or (not flexible_body and observation["http"]["bodyKind"] != "json")
            or observation.get("mediaType")
            != observation["http"]["contentType"].split(";", 1)[0].strip().lower()
        ):
            raise ValueError("incomplete or detached HTTP receipt")
        return observation

    def lookup(role):
        return take(
            operation(
                "auth",
                admin + "lookup",
                {"email": [users[role]["email"]]},
                privileged=True,
            )
        )

    def state(role):
        observation = lookup(role)
        records = observation["body"].get("users")
        if (
            observation["httpStatus"] != 200
            or not isinstance(records, list)
            or len(records) != 1
            or records[0].get("localId") != users[role]["uid"]
            or records[0].get("email") != users[role]["email"]
        ):
            raise ValueError("trace ownership readback unavailable")
        return records[0]

    for role in ("a", "b"):
        if lookup(role)["body"].get("users", []):
            raise ValueError("setup target already present")
        response = take(
            operation(
                "auth",
                "identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake",
                {
                    "email": users[role]["email"],
                    "password": "abc123",
                    "returnSecureToken": True,
                },
            )
        )
        if (
            response["httpStatus"] != 200
            or response["body"].get("localId") != users[role]["uid"]
            or response["body"].get("idToken") != users[role]["token"]
        ):
            raise ValueError("runtime account binding differs from setup response")
    for index, row in enumerate(result["rows"][:32]):
        phase = "baseline"
        for role in ("a", "b"):
            state(role)
            response = take(
                operation(
                    "auth",
                    admin + "update",
                    {
                        "localId": users[role]["uid"],
                        "displayName": role + "-before-" + row["id"],
                        "emailVerified": False,
                    },
                    privileged=True,
                )
            )
            if response["httpStatus"] != 200:
                raise ValueError("baseline failed")
        phase = "before"
        before = {role: state(role) for role in ("a", "b")}
        if index in (26, 27):
            state("b")
        expected = auth_recipe(index, users)
        phase = "diagnostic"
        observation = take(expected)
        phase = "after"
        after = {role: state(role) for role in ("a", "b")}
        safe = safe and all(
            auth_invariants(
                auth_cases()[index], observation["httpStatus"], before, after
            ).values()
        )
        if any(
            before[r].get("displayName") != r + "-before-" + row["id"]
            or before[r].get("emailVerified") is not False
            for r in users
        ):
            raise ValueError("baseline readback mismatch")
        if (
            not equal(row["observation"], observation)
            or not equal(row["before"], before)
            or not equal(row["after"], after)
        ):
            raise ValueError("row differs from wire/readback trace")
    phase = "recovery"
    for role in ("a", "b"):
        state(role)
        state(role)
        response = take(
            operation(
                "auth",
                admin + "delete",
                {"localId": users[role]["uid"]},
                privileged=True,
            )
        )
        absent = lookup(role)
        if (
            response["httpStatus"] != 200
            or absent["httpStatus"] != 200
            or absent["body"].get("users", [])
        ):
            raise ValueError("account cleanup unconfirmed")
    for program in FS_IDS:
        name = result["documents"][program]
        get = operation("firestore", "/v1/" + name, method="GET", privileged=True)
        phase = "absence"
        if take(get)["httpStatus"] != 404:
            raise ValueError("document absence unconfirmed")
        phase = "seed"
        seed = {
            "fields": {
                "n": {"integerValue": "2"},
                "g": {"stringValue": "q"},
                "a": {"mapValue": {"fields": {"b": {"integerValue": "7"}}}},
            }
        }
        if (
            take(
                operation(
                    "firestore",
                    "/v1/" + name + "?currentDocument.exists=false",
                    seed,
                    "PATCH",
                    True,
                )
            )["httpStatus"]
            != 200
        ):
            raise ValueError("seed failed")
        versions = {}
        reads = {}
        diagnostic_status = None
        for row in [
            r for r in result["rows"][32:] if r["id"].startswith(program + "/")
        ]:
            step = row["id"].rsplit("/", 1)[1]
            expected, relation = fs_recipe(program, step, name, versions)
            phase = step
            observation = take(expected)
            if step in ("original", "before", "after"):
                body = observation["body"]
                absent = (
                    observed_outcomes
                    and step == "after"
                    and observation["httpStatus"] == 404
                )
                if not absent and (
                    observation["httpStatus"] != 200
                    or body.get("name") != name
                    or not isinstance(body.get("fields"), dict)
                    or not isinstance(body.get("updateTime"), str)
                ):
                    raise ValueError("document state unavailable")
                if not absent:
                    versions[step] = body["updateTime"]
                reads[step] = None if absent else body
            if step == "diagnostic":
                diagnostic_status = observation["httpStatus"]
            if (
                not equal(row["versions"], versions)
                or not equal(row["relation"], relation)
                or not equal(row["observation"], observation)
            ):
                raise ValueError("original version or observation detached from trace")
        if diagnostic_status is not None and diagnostic_status >= 400:
            safe = safe and equal(reads["before"], reads["after"])
        phase = "recovery"
        cleanup_read = take(get)
        if observed_outcomes and cleanup_read["httpStatus"] == 404:
            if take(get)["httpStatus"] != 404:
                raise ValueError("document cleanup incomplete")
            continue
        body = cleanup_read["body"]
        if (
            cleanup_read["httpStatus"] != 200
            or body.get("name") != name
            or not isinstance(body.get("updateTime"), str)
        ):
            raise ValueError("cleanup version unavailable")
        delete = operation(
            "firestore",
            "/v1/"
            + name
            + "?"
            + urlencode({"currentDocument.updateTime": body["updateTime"]}),
            method="DELETE",
            privileged=True,
        )
        if take(delete)["httpStatus"] != 200 or take(get)["httpStatus"] != 404:
            raise ValueError("document cleanup incomplete")
    if next(entries, None) is not None:
        raise ValueError("unexpected trailing operations")

    return safe
