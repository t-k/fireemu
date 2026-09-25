"""Offline forensic resolution for one reviewed historical Auth worker defect.

This is not cleanup, absence evidence, a worker receipt, or permission to retry.
The exact pinned program rejects every production Identity Toolkit non-null body
before Request construction. Historical charged/unknown events remain untouched.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))
from broad_contract import digest

KIND = "auth-source-refusal-resolution-v1"
FIELDS = {
    "kind",
    "ticket",
    "receiptPath",
    "receiptDigest",
    "gateDigest",
    "sourceRoot",
    "approvalPath",
    "proof",
    "attestation",
}
SOURCE_COMMIT = "4bb0e9a4204d7bbaeefd9e028bea8dd85417c7fb"
SOURCE_DIGEST = "e6de1dd5670494cefeacc4bb021ac6d81cd86049f929afe5784afd0298387292"
LANE = "tools/compat-broad/auth-credential-tokens"
WORKER = f"{LANE}/credential_https_worker.py"
TRANSPORT = f"{LANE}/credential_remote_transport.py"
LAUNCHER = f"{LANE}/credential_bootstrap.py"
PINNED = {
    WORKER: "337bb2a07c3d0d6bbc69a49f5c99faadc7534178b89e1ecf57b24d6614b1f3eb",
    TRANSPORT: "509d6a95bc41daf55d30860b4c4e0bb7c40a24289caa928f227eaceef4143515",
    LAUNCHER: "8fbe1ef30660515a99c2a2ecaabb135a537d8b646703b7e1a4e71ea9c1ae5790",
}
CAMPAIGN = "AUTH-CREDENTIAL-TOKENS-01"
ROUTE = "identitytoolkit.googleapis.com/v1/accounts:signUp"
MANAGEMENT = [
    "observation:" + name
    for name in (
        "bootstrap-refresh",
        "bootstrap-tokeninfo",
        "bootstrap-project",
        "bootstrap-auth-config",
        "oauth-tokeninfo",
        "project",
        "auth",
        "sign-developer",
        "sign-reserved",
        "sign-expired",
    )
]
MAX_BYTES = 16 * 1024 * 1024


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise ValueError("canonical regular forensic evidence required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("bounded forensic evidence required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise ValueError("bounded forensic evidence required")
    return raw


def _json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate forensic field")
            value[key] = item
        return value

    def invalid(_value):
        raise ValueError("nonfinite forensic field")

    value = json.loads(_read(path), object_pairs_hook=unique, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("forensic object required")  # noqa: TRY004 -- fail-closed public refusal
    return value


def validate_source(source_root, source_inputs):
    """The fixed whole closure, not an arbitrary caller-provided source rule."""
    root = Path(source_root)
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ValueError("canonical historical source required")
    if not isinstance(source_inputs, dict) or digest(source_inputs) != SOURCE_DIGEST:
        raise ValueError("historical source closure differs")
    if any(source_inputs.get(name) != sha for name, sha in PINNED.items()):
        raise ValueError("known bad worker/transport/launcher differs")
    for name, sha in source_inputs.items():
        if hashlib.sha256(_read(root / name)).hexdigest() != sha:
            raise ValueError("historical source bytes differ")


def _quiescent():
    """A missing historical worker receipt is not rewritten into a reaped one."""
    result = subprocess.run(
        ["ps", "-axo", "pid=,args="], capture_output=True, timeout=3, check=False
    )
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise ValueError("worker inventory unavailable")
    target = Path(WORKER).name
    for line in result.stdout.decode("utf-8", errors="strict").splitlines():
        try:
            words = shlex.split(line)
        except ValueError:
            # Unknown argv text cannot establish a negative process observation.
            if target in line:
                raise ValueError("worker quiescence unknown") from None
            continue
        # A byte-identical source copy is valid evidence, but must not hide a
        # worker executing from another checkout. Conservatively require every
        # worker with this exact entrypoint name to have exited.
        if any(word == target or word.endswith("/" + target) for word in words[1:]):
            raise ValueError("historical worker still active")


def _signup(nonce):
    return {
        "service": "auth",
        "method": "POST",
        "path": ROUTE,
        "body": {
            "email": f"fireemu-cred-{nonce[:8]}-0@fireemu-credential.invalid",
            "password": "$binding:password",
            "returnSecureToken": True,
        },
        "form": False,
        "owner": False,
        "kind": "sign-up",
        "account": "acct0",
        "binds": {
            "acct0Uid": "localId",
            "acct0IdToken": "idToken",
            "acct0Refresh": "refreshToken",
        },
        "resource": f"projects/fireemu-35fe6/auth/accounts/fireemu-cred-{nonce[:8]}-0",
    }


def _proof(record, receipt, gate, row):
    output = Path(record["receiptPath"]).parent
    if str(output / "gate") != row["claim"]["gatePath"]:
        raise ValueError("forensic evidence is not beside registered Gate")
    inputs = _json(output / "inputs.json")
    permission = inputs.get("permission", {})
    source_inputs = inputs.get("sourceInputs")
    validate_source(record["sourceRoot"], source_inputs)
    if (
        inputs.get("sourceCommit") != SOURCE_COMMIT
        or inputs.get("kind") != "auth-credential-frozen-inputs-v1"
        or inputs.get("inputsDigest")
        != digest({k: v for k, v in inputs.items() if k != "inputsDigest"})
        or receipt.get("inputsDigest") != inputs["inputsDigest"]
        or permission.get("kind") != "auth-credential-owner-execution-permission-v1"
        or permission.get("fixtureOrigin") is not None
        or permission.get("sourceCommit") != SOURCE_COMMIT
        or permission.get("sourceInputs") != source_inputs
        or inputs.get("permissionDigest") != digest(permission)
        or receipt.get("permissionDigest") != digest(permission)
    ):
        raise ValueError("frozen production input binding differs")
    generation = row.get("generation", {})
    closure = {
        "credential_admission.py",
        "credential_descriptor.py",
        "o8_admission.py",
        "reservations.py",
        "shared_gate.py",
    }
    expected_generation = {
        "sourceCommit": SOURCE_COMMIT,
        "collectorSourceDigest": SOURCE_DIGEST,
        "sourceDigests": {
            Path(name).name: sha
            for name, sha in source_inputs.items()
            if Path(name).name in closure
        },
    }
    if generation != expected_generation or receipt.get("generation") != generation:
        raise ValueError("historical reservation generation differs")
    preparation = _json(output / "preparation-proof.json")
    if (
        preparation != receipt.get("preparationProof")
        or preparation.get("fixtureOrigin", "missing") is not None
        or preparation.get("ticket") != record["ticket"]
        or preparation.get("generation") != generation
        or preparation.get("claimDigest") != row["claimDigest"]
        or preparation.get("gatePlanDigest") != row["claim"]["gatePlanDigest"]
        or preparation.get("nonce") != gate["plan"]["nonce"]
        or preparation.get("requestCount") != 4
    ):
        raise ValueError("retained production preparation proof differs")
    parent_inputs = _json(output / "preparation-inputs.json")
    parent_permission = parent_inputs.get("permission", {})
    if (
        parent_inputs.get("kind") != "auth-credential-bootstrap-frozen-inputs-v1"
        or parent_inputs.get("sourceCommit") != SOURCE_COMMIT
        or parent_inputs.get("sourceInputs") != source_inputs
        or parent_inputs.get("inputsDigest")
        != digest({k: v for k, v in parent_inputs.items() if k != "inputsDigest"})
        or parent_inputs.get("inputsDigest") != preparation.get("inputsDigest")
        or parent_inputs.get("permissionDigest") != digest(parent_permission)
        or parent_inputs.get("permissionDigest") != preparation.get("permissionDigest")
        or parent_inputs.get("permissionDigest") != gate["plan"].get("permissionDigest")
        or parent_inputs.get("permissionDigest")
        != gate["plan"].get("bootstrap", {}).get("permissionDigest")
        or parent_permission.get("kind") != "auth-credential-bootstrap-permission-v1"
        or parent_permission.get("nonce") != preparation["nonce"]
        or parent_permission.get("fixtureOrigin") is not None
        or any(
            parent_permission.get(k) != permission.get(k)
            for k in ("ownerIdentity", "recoveryOwner")
        )
    ):
        raise ValueError("parent preparation authority binding differs")
    claim = row["claim"]
    plan = gate["plan"]
    nonce = plan.get("nonce")
    if (
        not isinstance(nonce, str)
        or re.fullmatch(r"[a-f0-9]{32}", nonce) is None
        or permission.get("nonce") != nonce
        or claim["nonceDigest"] != digest(nonce)
        or claim.get("campaignId") != CAMPAIGN
        or plan.get("campaignId") != CAMPAIGN
        or plan.get("project") != "fireemu-35fe6"
        or plan.get("signing") is not True
        or plan.get("collectorSourceDigest") != SOURCE_DIGEST
        or plan.get("receiptKind") != "auth-credential-acquisition-receipt-v1"
        or set(plan.get("jobs", {})) != {"auth-credential"}
        or set(gate.get("jobs", {})) != {"auth-credential"}
        or gate.get("total") != 11
        or gate.get("observation") != 11
        or gate.get("recovery") != 0
        or gate.get("costMicrousd") != 11 * plan["requestCostMicrousd"]
        or gate.get("coordinatorInflight") is not False
    ):
        raise ValueError("exact Auth source-refusal allocation required")
    job = gate["jobs"]["auth-credential"]
    operation = _signup(nonce)
    if (
        plan["jobs"]["auth-credential"]["observation"][0] != operation
        or job.get("observation") != 1
        or job.get("recovery") != 0
        or job.get("inflight") is not False
        or job.get("complete") is not False
        or job.get("owned") != []
        or job.get("absent") != []
        or job.get("creationProofs") != {}
        or job.get("captures") != {}
    ):
        raise ValueError("canonical first signup required")
    events = gate.get("events")
    if not isinstance(events, list) or len(events) != 1:
        raise ValueError("exactly one historical data attempt required")
    event = events[0]
    required = {
        "job": "auth-credential",
        "phase": "observation",
        "index": 0,
        "requestDigest": digest(operation),
        "service": "auth",
        "method": "POST",
        "completed": False,
        "creationOutcome": "pending",
        "failure": "WorkerFailure",
    }
    if set(event) != set(required) | {"started", "ended"} or any(
        event.get(k) != v for k, v in required.items()
    ):
        raise ValueError("historical pending worker failure differs")
    if (
        any(
            type(event[k]) not in (float, int) or not math.isfinite(event[k])
            for k in ("started", "ended")
        )
        or event["ended"] < event["started"]
    ):
        raise ValueError("historical attempt interval differs")
    management = gate.get("managementEvents", [])
    if (
        [e.get("id") for e in management] != MANAGEMENT
        or gate.get("managementUsed") != MANAGEMENT
        or gate.get("managementSkipped", []) != []
        or any(
            e.get("status") != 200
            or any(
                e.get(k) is not True for k in ("completed", "complete", "workerReaped")
            )
            for e in management
        )
    ):
        raise ValueError("exact completed ten-management prefix required")
    metadata = [
        {
            "id": "observation:000",
            "route": ROUTE,
            "status": None,
            "responseDigest": digest(None),
        }
    ]
    if (
        receipt.get("kind") != "auth-credential-acquisition-receipt-v1"
        or receipt.get("gateDigest") != digest(gate)
        or receipt.get("campaignId") != CAMPAIGN
        or receipt.get("chargedCalls") != 11
        or receipt.get("executionKind") != "fixed-production-wire"
        or receipt.get("productionExecuted") is not True
        or receipt.get("failure") != "collection-incomplete"
        or receipt.get("stopPoint") != "sign-up-unsettled"
        or receipt.get("preflightComplete") is not True
        or receipt.get("postflightComplete") is not False
        or receipt.get("workerSha256") != PINNED[WORKER]
        or receipt.get("metadata") != metadata
        or receipt.get("routeDigest") != digest(metadata)
    ):
        raise ValueError("immutable Auth failure receipt differs")
    admission = _json(output / "observation-admission.json")
    approval = _json(record["approvalPath"])
    expected_bootstrap = {
        "proofDigest": digest(preparation),
        "ticket": record["ticket"],
        "claimDigest": row["claimDigest"],
        "gatePlanDigest": row["claim"]["gatePlanDigest"],
        "preparationInputsDigest": parent_inputs["inputsDigest"],
        "reservationDeadline": row["deadline"],
    }
    if (
        set(admission) != {"approvalDigest", "inputsDigest", "bootstrap"}
        or admission["bootstrap"] != expected_bootstrap
        or permission.get("bootstrap") != expected_bootstrap
        or preparation.get("reservationDeadline") != row["deadline"]
        or admission["inputsDigest"] != inputs["inputsDigest"]
        or admission["approvalDigest"] != digest(approval)
        or receipt.get("observationApprovalDigest") != digest(admission)
    ):
        raise ValueError("retained observation admission differs")
    expected_approval = {
        "kind": "auth-credential-o8-approval-v1",
        "status": "approved",
        "campaignId": CAMPAIGN,
        "sourceCommit": SOURCE_COMMIT,
        "sourceInputsDigest": SOURCE_DIGEST,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": digest(permission),
        "nonceDigest": digest(nonce),
        "ledgerRoot": record["ticket"]["ledgerPath"],
        "launcherSha256": PINNED[LAUNCHER],
    }
    if any(approval.get(k) != v for k, v in expected_approval.items()):
        raise ValueError("historical launcher/approval provenance differs")
    directory = output / "responsibility"
    if directory.is_symlink() or sorted(p.name for p in directory.iterdir()) != [
        "0000.json",
        "0001.json",
    ]:
        raise ValueError("exact responsibility chain required")
    previous = None
    journal_hashes = []
    journal_events = []
    for index in range(2):
        path = directory / f"{index:04d}.json"
        raw = _read(path)
        value = _json(path)
        if (
            set(value) != {"schema", "nonce", "sequence", "previousSha256", "event"}
            or value["schema"] != "credential-responsibility-v1"
            or value["nonce"] != nonce
            or value["sequence"] != index
            or value["previousSha256"] != previous
        ):
            raise ValueError("responsibility chain binding differs")
        previous = hashlib.sha256(raw).hexdigest()
        journal_hashes.append(previous)
        journal_events.append(value["event"])
    if journal_events != [
        {
            "type": "run",
            "sourceBinding": {
                "sourceCommit": SOURCE_COMMIT,
                "inputsDigest": inputs["inputsDigest"],
            },
            "authorizesCleanup": False,
            "productionExecuted": False,
        },
        {
            "type": "intent",
            "id": "creation-0",
            "operation": "signup",
            "email": operation["body"]["email"],
            "requestedUid": None,
            "state": "unknown",
            "uid": None,
        },
    ]:
        raise ValueError("unresolved signup responsibility differs")
    _quiescent()
    evidence = {
        name: hashlib.sha256(_read(output / name)).hexdigest()
        for name in (
            "receipt.json",
            "inputs.json",
            "preparation-proof.json",
            "preparation-inputs.json",
            "observation-admission.json",
            "responsibility/0000.json",
            "responsibility/0001.json",
        )
    }
    return {
        "rule": "4bb-identity-nonnull-body-before-request-v1",
        "attemptDispatched": False,
        "sourceCommit": SOURCE_COMMIT,
        "sourceInputsDigest": SOURCE_DIGEST,
        "pinnedSources": PINNED,
        "nonceDigest": claim["nonceDigest"],
        "claimDigest": row["claimDigest"],
        "planDigest": claim["gatePlanDigest"],
        "requestDigest": digest(operation),
        "managementDigest": digest(management),
        "responsibilityChainDigest": digest(journal_hashes),
        "evidenceSha256": evidence,
        "approvalSha256": hashlib.sha256(_read(record["approvalPath"])).hexdigest(),
        "ownerIdentityDigest": digest(permission.get("ownerIdentity")),
        "recoveryOwnerDigest": digest(permission.get("recoveryOwner")),
        "chargedCalls": 11,
        "allocationDigest": digest(claim["budget"]),
    }


def prepare_resolution(*, ticket, receipt_path, source_root, approval_path):
    """Read-only proposal. A fresh independent attestation must be supplied later."""
    from reservations import Ledger
    from shared_gate import Gate

    ledger = Ledger(ticket["ledgerPath"])
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    ledger.bound_claim(ticket)
    receipt = _json(Path(receipt_path).resolve())
    gate = Gate(row["claim"]["gatePath"], "auth-credential").snapshot()
    record = {
        "kind": KIND,
        "ticket": ticket,
        "receiptPath": str(Path(receipt_path).resolve()),
        "receiptDigest": digest(receipt),
        "gateDigest": digest(gate),
        "sourceRoot": str(Path(source_root).resolve()),
        "approvalPath": str(Path(approval_path).resolve()),
        "attestation": None,
    }
    if row["state"] != "held" or row.get("recoveryChildren"):
        raise ValueError("unresolved parent without a recovery child required")
    ledger._terminal_gate(row, ticket, receipt, record)
    record["proof"] = _proof(record, receipt, gate, row)
    return record


def validate_resolution(record, *, receipt, gate, row, now, replay=False):
    proof = _proof(record, receipt, gate, row)
    if record["proof"] != proof:
        raise ValueError("source-refusal proof differs from immutable evidence")
    attestation = record["attestation"]
    fields = {
        "kind",
        "status",
        "purpose",
        "resolutionDigest",
        "ownerIdentity",
        "recoveryOwner",
        "reviewerIdentity",
        "attestedAt",
        "expiresAt",
        "executionHost",
    }
    if (
        not isinstance(attestation, dict)
        or set(attestation) != fields
        or attestation["kind"] != "auth-source-refusal-attestation-v1"
        or attestation["status"] != "approved"
        or attestation["purpose"] != "retire-source-proven-unsent"
        or attestation["resolutionDigest"]
        != digest({k: v for k, v in record.items() if k != "attestation"})
        or digest(attestation["ownerIdentity"]) != proof["ownerIdentityDigest"]
        or digest(attestation["recoveryOwner"]) != proof["recoveryOwnerDigest"]
        or any(
            not isinstance(attestation[k], str)
            or not attestation[k].strip()
            or len(attestation[k]) > 256
            for k in ("ownerIdentity", "recoveryOwner", "reviewerIdentity")
        )
        or attestation["reviewerIdentity"]
        in (attestation["ownerIdentity"], attestation["recoveryOwner"])
        or attestation["executionHost"]
        != {"platform": platform.system().lower(), "machine": platform.machine()}
    ):
        raise ValueError("independent source-refusal authority required")
    if (
        any(
            type(attestation[k]) not in (int, float)
            or not math.isfinite(attestation[k])
            for k in ("attestedAt", "expiresAt")
        )
        or not 0 < attestation["expiresAt"] - attestation["attestedAt"] <= 3600
        or (
            not replay
            and not attestation["attestedAt"] <= now < attestation["expiresAt"]
        )
    ):
        raise ValueError("fresh source-refusal authority required")
