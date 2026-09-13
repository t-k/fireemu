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


def validate_rows(result):
    if [r["id"] for r in result["rows"]] != expected_ids():
        raise ValueError("missing, duplicate, or reordered rows")
    if result.get("manifestDigest") != digest(manifest()):
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
    if [t.get("phase") for t in trace] != phases or [
        t.get("ordinal") for t in trace
    ] != list(range(len(phases))):
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
        **row["observation"],
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
    for label, result in (("direct", direct), ("mapped", mapped)):
        try:
            validate_rows(result)
        except (ValueError, KeyError, TypeError) as error:
            errors.append({"side": label, "reason": str(error)})
    if (
        direct.get("nonce") == mapped.get("nonce")
        or direct.get("mode") != "direct"
        or mapped.get("mode") != "mapped"
    ):
        errors.append({"reason": "distinct direct/mapped bindings required"})
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
        "manifestDigest": direct.get("manifestDigest"),
        "recordingComplete": complete,
        "safety": all(r.get("safety") is True for r in (direct, mapped)),
        "mapping": "invalid"
        if errors or not complete
        else ("match" if all(r["mapping"] == "match" for r in rows) else "mismatch"),
        "rows": rows,
        "errors": errors,
        "productionCompatibility": "unobserved",
        "inputDigests": [digest(v) for v in (direct, mapped)],
    }
