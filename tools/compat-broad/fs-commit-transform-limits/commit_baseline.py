"""Derive the production baseline a Commit permission binds from real observations.

An owner permission binds three values that cannot be recomputed from the
repository: the Identity Platform configuration digest, the Firestore database
projection and its digest, and the pricing location. Until now they were typed
into the package as literals, and a literal that no production response ever
produced is indistinguishable from a correct one until a campaign spends its
preflight budget finding out. That is exactly what stopped the Commit500/501
v10 run: its `authConfigDigest` had no provenance at all.

Every baseline value therefore comes from a named observation record here: a
recorded production response journal, identified by path and by its own SHA-256,
plus the line within it. The digests are recomputed from those bytes with the
same derivations the preflight uses, so a baseline no recorded observation
produces is refused offline, before a campaign is ever frozen.

A hash-bound journal and a hash-bound live receipt are not enough on their own:
both can be intact and correctly named while belonging to different runs, so a
replay journal carried by an unrelated live receipt would pass every individual
check. Each observation is therefore bound to the run that produced it: the
live receipt carries the run's own record of what each privileged route
answered, and the selected journal line is accepted only when its response
digest appears in that record under the same phase and route.

Reading an observation journal is not proof that the observation was made
honestly; it is proof that the bound value came from a recorded response of the
named live run rather than from someone's memory or from another run.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

from batch_contract import NUMBER, PROJECT, database_evidence
from broad_contract import digest

RECORD_KIND = "commit-production-baseline-v1"
# A recorded replay has the same line shape, the same routes and the same
# project as a production journal, and sits beside the real logs. Nothing in a
# journal line distinguishes the two, so a baseline observation must name the
# run evidence that says the responses came off the wire, and must not live
# under a directory that holds replays or fixtures.
PRODUCTION_LOG_ROOTS = (("docs.local", "logs"), ("docs.local", "runs"))
EXCLUDED_PATH_SEGMENTS = frozenset(
    {
        "cli-fixtures",
        "fixture",
        "fixtures",
        "replay",
        "replays",
        "testdata",
        "tests",
        "test",
        "spec",
        "config",
        "conformance",
    }
)
LIVE_MODE = "live"
MAX_RECORD_BYTES = 1 * 1024 * 1024
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
# The privileged metadata routes whose responses the baseline is derived from.
# A record must name each of them exactly once.
ROUTES = {
    "projectIdentity": (f"cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}"),
    "database": (f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)"),
    "authConfig": (
        f"identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config"
    ),
}
# The metadata action each privileged route is recorded under in a live run's
# own response record. A journal line is only evidence when the receipt's
# observation-phase record for that action holds the same response digest: a
# baseline is the state before the campaign acted, and a recovery-phase
# response, although the same run received it, describes the state after.
ROUTE_ACTIONS = {
    ROUTES["projectIdentity"]: "project",
    ROUTES["database"]: "database",
    ROUTES["authConfig"]: "auth",
}
BASELINE_PHASE = "observation"
BASELINE_FIELDS = (
    "projectIdentity",
    "databaseProjection",
    "databaseProjectionDigest",
    "pricingLocation",
    "authConfigDigest",
    "provenance",
)
# The permission fields this record is the authority for.
PERMISSION_BASELINE_FIELDS = (
    "authConfigDigest",
    "databaseProjection",
    "databaseProjectionDigest",
    "pricingLocation",
)


def _read_json(path, *, limit):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("bounded regular baseline file required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("bounded JSON object required")  # noqa: TRY004 -- refusal class, not a type report
    return value


def _bounded_path(evidence_root, relative, *, production_roots):
    """Resolve one named evidence path inside a recorded production log root."""
    root = Path(evidence_root).resolve()
    if not isinstance(relative, str) or not relative:
        raise ValueError("named observation path required")
    parts = Path(relative).parts
    path = (root / relative).resolve()
    if (
        Path(relative).is_absolute()
        or ".." in parts
        or not path.is_relative_to(root)
        or path.is_symlink()
        or not path.is_file()
    ):
        raise ValueError("bounded observation journal required")
    resolved = path.parts
    if any(
        segment.casefold() in EXCLUDED_PATH_SEGMENTS for segment in resolved
    ) or not any(
        resolved[index : index + len(candidate)] == tuple(candidate)
        for candidate in production_roots
        for index in range(len(resolved))
    ):
        raise ValueError("recorded production log path required")
    return path


def _live_production(evidence_root, marker, *, production_roots):
    """Require hash-bound run evidence that the responses came off the wire."""
    if not isinstance(marker, dict) or set(marker) != {"path", "sha256", "mode"}:
        raise ValueError("production execution evidence required")
    if marker["mode"] != LIVE_MODE:
        raise ValueError("live production observation required")
    path = _bounded_path(
        evidence_root, marker["path"], production_roots=production_roots
    )
    raw = path.read_bytes()
    if (
        len(raw) > MAX_RECORD_BYTES
        or hashlib.sha256(raw).hexdigest() != marker["sha256"]
    ):
        raise ValueError("named production evidence changed")
    receipt = json.loads(raw)
    if not isinstance(receipt, dict):
        raise ValueError(  # noqa: TRY004 -- refusal class, not a type report
            "named production evidence required"
        )
    kind = receipt.get("executionKind")
    if kind == "injected-transport" or not (
        kind == "fixed-production-wire" or receipt.get("productionExecuted") is True
    ):
        raise ValueError("live production execution evidence required")
    return receipt


def _produced_by(receipt, *, phase, action, response_digest) -> None:
    """Require the live run's own record to hold this exact response.

    The receipt records, per phase and privileged route, the digest of the
    response that run received. A journal line whose response is absent from
    that record was produced by some other run, so the receipt is no evidence
    for it, however well the journal's own digest checks out.

    Two runs that received byte-identical responses are indistinguishable here,
    and deliberately so: the value derived from either is the same one the named
    live run observed.
    """
    metadata = receipt.get("metadata")
    if not isinstance(metadata, list) or not metadata:
        raise ValueError("live run response record required")
    identity = phase + ":" + action
    for item in metadata:
        if not isinstance(item, dict):
            raise ValueError(  # noqa: TRY004 -- refusal class, not a type report
                "live run response record required"
            )
        if (
            item.get("id") == identity
            and item.get("status") == 200
            and item.get("responseDigest") == response_digest
        ):
            return
    raise ValueError("observation journal line the live run did not produce")


def _journal_line(evidence_root, entry, *, production_roots):
    """Read one recorded response out of a journal bound by path and digest."""
    receipt = _live_production(
        evidence_root, entry.get("production"), production_roots=production_roots
    )
    path = _bounded_path(
        evidence_root, entry.get("path"), production_roots=production_roots
    )
    if path.stat().st_size > MAX_JOURNAL_BYTES:
        raise ValueError("bounded observation journal required")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
        raise ValueError("named observation journal changed")
    index = entry.get("index")
    lines = raw.decode().splitlines()
    if type(index) is not int or isinstance(index, bool) or not 0 <= index < len(lines):
        raise ValueError("named observation line required")
    recorded = json.loads(lines[index])
    response = recorded.get("response") if isinstance(recorded, dict) else None
    if (
        not isinstance(response, dict)
        or response.get("httpStatus") != 200
        or not isinstance(response.get("body"), dict)
    ):
        raise ValueError("successful recorded observation required")
    if recorded.get("route") != entry.get("route"):
        raise ValueError("named observation route differs")
    phase, action = recorded.get("phase"), ROUTE_ACTIONS.get(entry.get("route"))
    if action is None or phase != BASELINE_PHASE:
        raise ValueError("named observation phase required")
    _produced_by(
        receipt,
        phase=phase,
        action=action,
        response_digest=digest(response["body"]),
    )
    return response["body"]


def _derive(route_key, body):
    if route_key == "projectIdentity":
        identity = {
            "projectId": body.get("projectId"),
            "projectNumber": body.get("projectNumber"),
        }
        if identity != {"projectId": PROJECT, "projectNumber": NUMBER}:
            raise ValueError("observed project identity differs from the fixed target")
        return {"projectIdentity": identity}
    if route_key == "database":
        evidence = database_evidence(body)
        location = body.get("locationId")
        if not isinstance(location, str) or not location:
            raise ValueError("observed database pricing location required")
        return {
            "databaseProjection": evidence["projection"],
            "databaseProjectionDigest": evidence["projectionDigest"],
            "pricingLocation": location,
        }
    return {"authConfigDigest": digest(body)}


def baseline_from_record(
    record_path, *, evidence_root, production_roots=PRODUCTION_LOG_ROOTS
):
    """Recompute every bound baseline value from the observations a record names.

    `production_roots` is the set of path component sequences a recorded
    production log lives under. It is a parameter so a test, or an operator
    whose logs live elsewhere, can declare its own; it is never a way to skip
    the check, which is what keeps a replay fixture out of a baseline.
    """
    record = _read_json(record_path, limit=MAX_RECORD_BYTES)
    observations = record.get("observations")
    if record.get("kind") != RECORD_KIND or not isinstance(observations, list):
        raise ValueError("bounded baseline observation record required")
    named = {}
    for entry in observations:
        if not isinstance(entry, dict) or set(entry) != {
            "route",
            "path",
            "sha256",
            "index",
            "production",
        }:
            raise ValueError("closed baseline observation entry required")
        keys = [key for key, route in ROUTES.items() if route == entry["route"]]
        if len(keys) != 1 or keys[0] in named:
            raise ValueError("each baseline route must be named exactly once")
        named[keys[0]] = entry
    if set(named) != set(ROUTES):
        raise ValueError("each baseline route must be named exactly once")
    baseline = {
        "provenance": {
            key: {"route": entry["route"], "sha256": entry["sha256"]}
            for key, entry in named.items()
        }
    }
    for key, entry in named.items():
        baseline.update(
            _derive(
                key,
                _journal_line(evidence_root, entry, production_roots=production_roots),
            )
        )
    if set(baseline) != set(BASELINE_FIELDS):
        raise ValueError("incomplete production baseline")
    return baseline


def permission_baseline(baseline):
    """The permission fields a derived baseline is the authority for."""
    return {field: baseline[field] for field in PERMISSION_BASELINE_FIELDS}


def validate_provenance(value) -> None:
    """Refuse a permission that does not name where its baseline came from.

    This is the check that survives into execution, where the observation
    journals are not available: it proves the permission was built against a
    named, hash-bound observation of each route rather than a typed literal.
    """
    if not isinstance(value, dict) or set(value) != set(ROUTES):
        raise ValueError("permission baseline provenance required")
    for key, entry in value.items():
        sha = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or set(entry) != {"route", "sha256"}
            or entry["route"] != ROUTES[key]
            or not isinstance(sha, str)
            or len(sha) != 64
            or any(character not in "0123456789abcdef" for character in sha)
        ):
            raise ValueError("permission baseline provenance required")


def validate_permission_baseline(permission, baseline) -> None:
    """Refuse a permission whose baseline no recorded observation produces."""
    required = permission_baseline(baseline)
    if any(permission.get(field) != value for field, value in required.items()):
        raise ValueError("permission baseline differs from the recorded observation")
