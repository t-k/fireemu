"""Source-aware inventory and conservative comparison of historical REST observations."""

from __future__ import annotations

import hashlib
import json
import subprocess
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SELECTED_FS = (
    "values/type-order",
    "values/numeric-ties",
    "queries/filters",
    "queries/aggregations",
    "writes/preconditions-and-masks",
    "writes/batch-write",
    "queries/cursors",
    "transactions/lifecycle",
    "writes/transforms",
)
DIMENSIONS = [
    "normal",
    "single-refusal",
    "boundary",
    "state",
    "sequence",
    "concurrency",
]


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def local_origin(value):
    url = urllib.parse.urlsplit(value)
    if (
        url.scheme != "http"
        or url.hostname != "127.0.0.1"
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
        or not url.port
        or url.port < 1024
    ):
        raise ValueError("only an owned numeric loopback origin is allowed")
    return value


def programs(service, commit=None):
    path = f"conformance/src/{service}-probe/programs.mjs"
    source = (
        subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=ROOT)
        if commit
        else (ROOT / path).read_bytes()
    )
    output = subprocess.check_output(
        ["node", "--input-type=module"],
        input=source + b"\nconsole.log(JSON.stringify(PROGRAMS));\n",
        cwd=ROOT,
    )
    return json.loads(output), hashlib.sha256(output.rstrip(b"\n")).hexdigest()


def historical(service):
    path = ROOT / f"conformance/{service}-production-matrix.json"
    matrix = json.loads(path.read_bytes())
    evidence = matrix["evidence"]["observations"]["production"]
    commit = evidence["source"]["gitSha"]
    corpus, sha = programs(service, commit)
    if "sha256-" + sha != evidence["inputs"]["corpusDigest"]:
        raise ValueError("historical corpus does not match its recorded digest")
    session = f"conformance/src/{service}-probe/session.mjs"
    old_session = subprocess.check_output(
        ["git", "show", f"{commit}:{session}"], cwd=ROOT
    )
    if old_session != (ROOT / session).read_bytes():
        raise ValueError(
            "historical normalizer changed; explicit adapter review required"
        )
    return (
        corpus,
        matrix,
        {
            "path": str(path.relative_to(ROOT)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "executionCommit": commit,
            "corpusDigest": sha,
            "observation": evidence["observation"],
            "configuration": evidence["runtime"],
            "inputs": evidence["inputs"],
            "normalizer": session,
            "normalizerSha256": hashlib.sha256(old_session).hexdigest(),
            "grade": "historical-reference",
            "resultApprovalInherited": False,
            "limitations": [
                "Historical normalization erased token IDs and some time/expiry fields; it cannot prove ownership or TTL.",
                "Local strict configuration and local-owner credentials differ from production; scoped REST comparison is exploratory, not whole-service verification.",
                "Firestore historical index settings differ from current configuration; no index or Rules claim follows.",
            ],
        },
    )


def replay_selection():
    """Keep unchanged historical input separate from the current same-ID program."""
    current = [p for p in programs("firestore")[0] if p["id"] in SELECTED_FS]
    old, _, _ = historical("firestore")
    legacy = [p for p in old if p["id"] == "writes/transforms"]
    return current, legacy


def first_difference(left, right, path="$"):
    if type(left) is not type(right):
        if type(left) in (int, float) and type(right) in (int, float) and left == right:
            return None
        return path
    if isinstance(left, dict):
        if set(left) != set(right):
            return path + ".keys"
        for key in sorted(left):
            found = first_difference(left[key], right[key], path + "." + key)
            if found:
                return found
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return path + ".length"
        for index, (a, b) in enumerate(zip(left, right, strict=True)):
            found = first_difference(a, b, f"{path}[{index}]")
            if found:
                return found
        return None
    return None if left == right else path


def decision(value):
    # Preserve the historical comparator's documented error-code boundary. Raw message
    # differences remain in results; body, types, keys and array order are never erased.
    return {k: v for k, v in value.items() if k != "message"}


def compare_program(current, old, actual, expected):
    rows = []
    for step in current["steps"]:
        name = step["id"]
        row = {
            "id": current["id"] + "#" + name,
            "status": "indeterminate",
            "reason": None,
        }
        got = actual.get("steps", {}).get(name)
        want = expected.get(name, {}).get("production")
        row["localExecution"] = (
            "observed"
            if got and got.get("status", 0) > 0
            else "indeterminate"
            if got
            else "not-run"
        )
        if got is not None:
            row["actual"] = got
        if digest(current) != digest(old):
            row["reason"] = "operation-sequence-changed-or-not-recorded"
        elif got is None:
            row.update(status="not-run", reason="missing-local-step")
        elif got.get("status", 0) == 0 or got.get("code") in {
            "probe-error",
            "no-response",
            "non-json",
        }:
            row["reason"] = "local-probe-failure"
        elif (
            not want
            or want.get("status", 0) == 0
            or want.get("code") in {"probe-error", "no-response", "non-json"}
        ):
            row["reason"] = "no-usable-production-observation"
        else:
            difference = first_difference(decision(got), decision(want))
            row.update(
                status="mismatch" if difference else "match",
                firstDifference=difference,
                expected=want,
                actual=got,
            )
        rows.append(row)
    for extra in set(actual.get("steps", {})) - {s["id"] for s in current["steps"]}:
        rows.append(
            {
                "id": current["id"] + "#" + extra,
                "status": "indeterminate",
                "reason": "unexpected-local-step",
            }
        )
    return rows


# Feature denominator includes intentionally unexecuted editions, protocols and external
# dependencies. The generated inventory never inherits a current pass from an old receipt.
FAMILY_SPECS = [
    (
        "auth-accounts",
        "Identity Platform",
        "account creation/lookup/update/delete",
        "REST",
        "anonymous/self/local-admin",
        "selected",
        "Existing account lifecycle programs and new state readbacks",
    ),
    (
        "auth-credentials",
        "Identity Platform",
        "password/sign-in/refresh",
        "REST",
        "self",
        "selected",
        "Existing sign-in programs plus password-change/refresh sequence",
    ),
    (
        "auth-authorization",
        "Identity Platform",
        "administrator/self/other/unauthenticated",
        "REST",
        "multiple principals",
        "selected",
        "New refusal and unchanged-account checks; preserved GAP-AUTH-005 regressions",
    ),
    (
        "auth-tenants",
        "Identity Platform",
        "tenant isolation and configuration",
        "REST",
        "tenant admin/user",
        "external-dependency",
        "Next: isolated local tenant corpus; production tenant/config scope needs approval",
    ),
    (
        "auth-providers",
        "Identity Platform",
        "federated/custom/SAML/OIDC providers",
        "REST/SDK",
        "IdP/user",
        "external-dependency",
        "Next: existing custom-token fixtures; real IdP integration needs separately scoped credentials",
    ),
    (
        "auth-mfa",
        "Identity Platform",
        "MFA enrollment/session/pending",
        "REST",
        "self/admin",
        "prepared",
        "Keep lifetime revision 3 independent and production-unobserved; GAP-AUTH-007 and AUTH-U03 remain open",
    ),
    (
        "auth-oob",
        "Identity Platform",
        "OOB/email action flows",
        "REST/SDK",
        "self/email recipient",
        "not-selected",
        "Next: existing OOB fixtures; no real email delivery in this milestone",
    ),
    (
        "auth-blocking",
        "Identity Platform",
        "blocking function integration",
        "REST/functions",
        "service account/user",
        "external-dependency",
        "Next: preserved blocking receipts/fixtures; live function/config scope separate",
    ),
    (
        "auth-admin",
        "Identity Platform",
        "project configuration/import/export/policies",
        "REST",
        "project administrator",
        "not-selected",
        "Next: existing capability/admin tests; configuration mutation requires exclusive scope",
    ),
    (
        "fs-writes",
        "Standard",
        "CRUD/masks/preconditions/atomic commit/batchWrite/transforms",
        "REST",
        "local-owner/production OAuth",
        "selected",
        "Current transforms remain separate from exact historical transform replay",
    ),
    (
        "fs-queries",
        "Standard",
        "types/filters/order/cursors/missing/null",
        "REST",
        "local-owner/production OAuth",
        "selected",
        "Types, numeric ties, filters and cursors plus seeded refusal-state cases",
    ),
    (
        "fs-transactions",
        "Standard",
        "begin/read/commit/rollback/conflict",
        "REST",
        "local-owner/production OAuth",
        "selected",
        "Existing transaction lifecycle; no-response historical rows remain indeterminate",
    ),
    (
        "fs-aggregations",
        "Standard",
        "count/sum/average",
        "REST",
        "local-owner/production OAuth",
        "selected",
        "Existing aggregation program with pinned production reference",
    ),
    (
        "fs-indexes",
        "Standard",
        "composite/index requirements",
        "REST/admin",
        "admin/query caller",
        "not-selected",
        "Next: pinned index fixture/config matching; shared index changes require exclusive scope",
    ),
    (
        "fs-rules",
        "Standard",
        "Rules and authenticated query/write authorization",
        "REST/SDK",
        "user/anonymous",
        "not-selected",
        "Next: conformance Rules sessions; owner data operations do not test Rules",
    ),
    (
        "fs-listen",
        "Standard",
        "Listen/reconnect/resume/order",
        "gRPC/WebChannel",
        "user/admin",
        "not-selected",
        "Next: existing SDK listen fixtures with invariant/partial-order checks",
    ),
    (
        "fs-sdk",
        "Standard",
        "client SDK/Admin SDK/Lite",
        "gRPC/WebChannel/REST",
        "user/admin",
        "not-selected",
        "Next: conformance SDK corpus and tools/sdk-smoke; REST pass does not cover SDK",
    ),
    (
        "fs-enterprise",
        "Enterprise",
        "pipeline/full-text/Enterprise Native",
        "REST/gRPC",
        "user/admin",
        "not-selected",
        "Next: map existing Enterprise capability stubs; separate edition oracle required",
    ),
    (
        "fs-mongodb",
        "Enterprise MongoDB",
        "MongoDB wire compatibility",
        "MongoDB",
        "database user",
        "not-selected",
        "Separate protocol and database; never import Standard expectations",
    ),
    (
        "fs-admin",
        "Standard/Enterprise",
        "database/index/backup/restore/PITR management",
        "REST/admin",
        "project administrator",
        "external-dependency",
        "Managed-service boundaries; enumerate capability limitations before owned database scope",
    ),
]


def family_for(service, program_id):
    if service == "auth":
        return (
            "auth-credentials"
            if program_id.startswith("password/")
            else "auth-accounts"
            if program_id.startswith("anonymous/")
            else "auth-authorization"
        )
    return (
        "fs-aggregations"
        if program_id == "queries/aggregations"
        else "fs-transactions"
        if program_id.startswith("transactions/")
        else "fs-queries"
        if program_id.startswith(("queries/", "values/"))
        else "fs-writes"
        if program_id.startswith("writes/")
        else "fs-admin"
    )


def catalog():
    families = [
        {
            "id": key,
            "service": "Identity Platform" if key.startswith("auth-") else "Firestore",
            "edition": edition,
            "feature": feature,
            "transport": transport,
            "principal": principal,
            "availability": availability,
            "currentStatus": "not-run",
            "implementationStatus": "unknown; consult existing capability/requirement evidence, never infer from availability",
            "capabilitySource": "spec/compatibility/contract.json",
            "reasonAndNextUnit": reason,
        }
        for key, edition, feature, transport, principal, availability, reason in FAMILY_SPECS
    ]
    surfaces = []
    discovery_path = "spec/compatibility/upstream/2026-09-09-retry/discovery.json"
    discovery = json.loads((ROOT / discovery_path).read_bytes())
    for definition in discovery["definitions"]:
        for surface in definition["surfaces"]:
            if surface["kind"] == "method":
                surfaces.append(
                    {
                        "api": surface["locator"],
                        "source": discovery_path,
                        "definition": definition["id"],
                        "transport": surface["transport"],
                        "currentStatus": "not-run",
                        "reason": "API-method denominator; case execution does not automatically cover every method variant",
                    }
                )
    proto_path = "spec/compatibility/upstream/firestore-protobuf.json"
    for surface in json.loads((ROOT / proto_path).read_bytes())["surfaces"]:
        if surface["kind"] == "method":
            surfaces.append(
                {
                    "api": surface["locator"],
                    "source": proto_path,
                    "definition": "firestore-protobuf",
                    "transport": "gRPC",
                    "currentStatus": "not-run",
                    "reason": "REST runs do not execute this protocol",
                }
            )
    cases = []
    for service in ("auth", "firestore"):
        current, corpus_sha = programs(service)
        for program in current:
            cases.append(
                {
                    "id": service + ":" + program["id"],
                    "family": family_for(service, program["id"]),
                    "entry": f"conformance/src/{service}-probe/session.mjs",
                    "corpus": f"conformance/src/{service}-probe/programs.mjs",
                    "corpusDigest": corpus_sha,
                    "programDigest": digest(program),
                    "steps": [
                        {
                            "id": step["id"],
                            "method": step.get("method", "POST"),
                            "path": step["path"],
                        }
                        for step in program["steps"]
                    ],
                    "selected": service == "auth" or program["id"] in SELECTED_FS,
                    "currentStatus": "not-run",
                    "historicalReference": f"conformance/{service}-production-matrix.json",
                    "reexecute": "uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --run --output /absolute/private/new-run",
                    "dimensions": "See explicit ordered operations; per-family coverage ledger records covered and missing dimensions",
                }
            )
    old, _, reference = historical("firestore")
    legacy = next(p for p in old if p["id"] == "writes/transforms")
    template = next(c for c in cases if c["id"] == "firestore:writes/transforms")
    cases.append(
        {
            **template,
            "id": "firestore:historical/writes/transforms",
            "programDigest": digest(legacy),
            "corpusDigest": reference["corpusDigest"],
            "corpusCommit": reference["executionCommit"],
            "executionVariant": "exact-historical-operation-sequence",
            "selected": True,
            "steps": [
                {"id": step["id"], "method": step["method"], "path": step["path"]}
                for step in legacy["steps"]
            ],
        }
    )
    family_map = {family["id"]: family for family in families}
    for case in cases:
        family_key = case["family"]
        if not isinstance(family_key, str):
            raise TypeError("case family must be a string")
        family = family_map[family_key]
        case.update(
            service=family["service"],
            edition=family["edition"],
            transport="REST",
            principal=family["principal"],
            comparator="tools/compat-broad/broad_contract.py:compare_program",
            currentArtifactReplay="available",
            currentConfiguration="strict; Standard Native; historical pinned index file",
            basis="historical-reference; not current execution",
        )
    from broad_cases import SEED, generated_programs

    for program in generated_programs():
        cases.append(
            {
                "id": "firestore:" + program["id"],
                "family": "fs-writes/fs-queries",
                "entry": "tools/compat-broad/broad_cases.py:generated_programs",
                "programDigest": digest(program),
                "seed": SEED,
                "selected": True,
                "currentStatus": "not-run",
                "basis": "local-invariant",
                "dimensions": ["normal", "single-refusal", "boundary", "state"],
                "historicalReference": None,
                "reason": "New seeded template; no fabricated production observation",
            }
        )
    for family in ("auth-accounts", "auth-credentials", "auth-authorization"):
        cases.append(
            {
                "id": family + ":short-state-sequence",
                "family": family,
                "entry": "tools/compat-broad/broad_cases.py:auth_cases",
                "seed": SEED,
                "selected": True,
                "currentStatus": "not-run",
                "basis": "local-invariant",
                "dimensions": [
                    "normal",
                    "single-refusal",
                    "boundary",
                    "state",
                    "sequence",
                ],
                "historicalReference": "crates/fireemu-adapter-http/tests/identity_toolkit.rs",
                "reason": "Reuses local regression obligations; runtime UID/token relationships are booleans, not historical token replay",
            }
        )
    for entry, family, feature in [
        (
            "client.mjs",
            "fs-rules",
            "Real SDK-issued identities: self, other owner, anonymous and sign-out",
        ),
        ("client.mjs", "fs-sdk", "Node client SDK Auth and Firestore gRPC operations"),
        (
            "listener-replacement.mjs",
            "fs-listen",
            "Node SDK listener replacement; not browser WebChannel proof",
        ),
    ]:
        cases.append(
            {
                "id": family + ":" + entry,
                "family": family,
                "entry": "tools/sdk-smoke/" + entry,
                "selected": True,
                "currentStatus": "not-run",
                "basis": "local-sdk-invariant",
                "feature": feature,
                "productionReference": None,
                "reexecute": "See docs/compatibility/broad-expansion.md for owned artifact commands and configuration",
                "dimensions": ["normal", "single-refusal", "state", "sequence"]
                if entry == "client.mjs"
                else ["sequence"],
                "coverageDebt": "No production comparison; listener callback history is a smoke invariant, not a universal stream ordering oracle",
            }
        )
    return {
        "schemaVersion": 1,
        "scope": "known pinned API methods, not all fields or all upstream semantics",
        "families": families,
        "surfaces": surfaces,
        "cases": cases,
        "currentExecutionInherited": False,
    }
