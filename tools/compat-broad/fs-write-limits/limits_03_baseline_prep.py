"""Bounded pre-O7 metadata baseline preparation for FS-WRITE-LIMITS-03."""

# ruff: noqa: TRY004 -- Malformed private inputs have one public refusal class.

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

import limits_03_admission as admission
import limits_03_descriptor as campaign
import o8_admission
from batch_contract import database_evidence
from broad_contract import digest
from limits_03_production import _write_receipt
from o8_campaign import CampaignDescriptor
from production_plan import baseline_preparation_plan
from reservations import Ledger
from shared_gate import Gate, create, validate_limits_preparation_response

NONCE = re.compile(r"^[0-9a-f]{32}$")
PREPARATION_KIND = "limits-03-baseline-preparation-v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_CUSTODY_BYTES = 16 * 1024
# The coordinator's whole preparation, including its six authenticated requests.
COORDINATOR_DEADLINE_SECONDS = 420
# How long an exited coordinator's custody pipe may stay open before the
# handoff is treated as lost; only a leaked descriptor keeps it open.
CUSTODY_CLOSE_SECONDS = 5
CAMPAIGN = "FS-WRITE-LIMITS-03"
METADATA_IDS = ("project", "database", "auth", "key")
CUSTODY_KIND = "limits-03-preparation-custody-v1"


def descriptor():
    """A distinct PREP O7 identity, with no final-baseline prerequisite."""
    members = campaign.descriptor().members()
    members.update(
        frozen_inputs_kind="limits-03-preparation-frozen-inputs-v1",
        permission_kind=PREPARATION_KIND,
        approval_kind="limits-03-preparation-o7-approval-v1",
        manifest_kind="limits-03-preparation-o7-manifest-v1",
        campaign_seconds=300,
        recovery_seconds=120,
        frozen_bounds={
            "managementRequests": 6,
            "dataRequests": 0,
            "ownedResources": 0,
            "costMicrousd": 600,
            "perRequestTimeoutSeconds": 12,
        },
        budget={"requests": 6, "accounts": 0, "resources": 0, "costMicrousd": 600},
        plan_compiler=preparation_plan,
        lock_scopes=lambda plan: plan["resourceLocks"],
        cost_model=lambda: {
            "preparationCostMicrousd": 600,
            "stableTaskCapMicrousd": 1_000_000,
            "requests": 6,
        },
        abort_closure_sources=(
            *campaign.ABORT_CLOSURE_SOURCES,
            "tools/compat-broad/fs-write-limits/limits_03_baseline_prep.py",
            "tools/compat-broad/fs-write-limits/production_plan.py",
        ),
        binding_verifier=_verify_binding,
        transport_bound=_prep_transport,
    )
    return CampaignDescriptor(**members)


def _verify_binding(binding, binding_digest, source_inputs):
    expected = campaign.source_map()
    if (
        not isinstance(binding, dict)
        or set(binding) != {"sources", "fixtureOrigin", "permissionDigest"}
        or binding["sources"] != expected
        or binding_digest != digest(binding)
        or (source_inputs is not None and source_inputs != expected)
    ):
        raise ValueError("PREP frozen worker source differs")


def _metadata_transport_failure(request_digest, process_receipt):
    return {
        "requestDigest": request_digest,
        "status": None,
        "complete": False,
        "workerReaped": process_receipt.get("workerReaped") is True,
        "bodyKind": None,
        "body": None,
    }


def _prep_transport(value, *, binding, binding_digest, capability):
    o8_admission.authorize_transport(
        capability, binding=binding, binding_digest=binding_digest
    )
    _verify_binding(binding, binding_digest, None)
    if not isinstance(value, dict) or set(value) != {"slot", "secret", "deadline"}:
        raise ValueError("closed PREP wire input required")
    slot, secret, deadline = value["slot"], value["secret"], value["deadline"]
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("absolute PREP wire deadline required")
    duration = min(
        12.0, deadline - time.monotonic(), capability.window_expires_at - time.time()
    )
    if duration <= 0:
        raise ValueError("PREP wire deadline expired")
    from credential_prep import _private_request, build_request, private_string

    origin = binding["fixtureOrigin"]
    if slot in ("refresh", "oauth-tokeninfo"):
        request = build_request("refresh" if slot == "refresh" else "tokeninfo", secret)
        request_digest = digest(
            {
                **request,
                "body": request["body"].decode("ascii"),
                "fixtureOrigin": origin,
            }
        )
        response = _private_request(
            "refresh" if slot == "refresh" else "tokeninfo",
            secret,
            fixture_origin=origin,
            deadline=duration,
        )
        return {
            "requestDigest": request_digest,
            "status": response.get("status"),
            "complete": response.get("complete") is True,
            "workerReaped": response.get("workerReaped") is True,
            "bodyKind": "json" if isinstance(response.get("body"), dict) else None,
            "body": response.get("body"),
        }
    if slot == "key":
        if (
            not isinstance(secret, dict)
            or set(secret) != {"token", "apiKey"}
            or not private_string(secret["apiKey"], 256)
        ):
            raise ValueError("closed key readback input required")
        token = secret["token"]
        route = "https://apikeys.googleapis.com/v2/keys:lookupKey?" + urlencode(
            {"keyString": secret["apiKey"]}
        )
    elif slot in ("project", "database", "auth"):
        token = secret
        route = campaign.preflight.metadata_url(slot)
    else:
        raise ValueError("closed PREP wire slot required")
    if not private_string(token, 8192):
        raise ValueError("bounded PREP bearer required")
    if origin is not None:
        parsed = urlsplit(route)
        route = origin + parsed.path + (("?" + parsed.query) if parsed.query else "")
    from batch_adapter import WorkerProcessError, wire

    headers = {
        "Authorization": "Bearer " + token,
        "x-goog-user-project": campaign.PROJECT,
    }
    request_digest = digest(
        {"url": route, "method": "GET", "body": None, "headers": headers}
    )
    try:
        response = wire(
            route,
            "GET",
            None,
            headers,
            local=origin is not None,
            timeout=duration,
            receipt=True,
            process_receipt=True,
        )
    except WorkerProcessError as error:
        return _metadata_transport_failure(request_digest, error.process_receipt)
    return {
        "requestDigest": request_digest,
        "status": response.get("status"),
        "complete": response.get("complete") is True,
        "workerReaped": response.get("workerReaped") is True,
        "bodyKind": response.get("bodyKind"),
        "body": response.get("body"),
    }


def approve_preparation(*, source_root, **bindings):
    """Validate independently supplied artifacts through the generic issuer."""
    inputs, permission = bindings["inputs"], bindings["permission"]
    if Path(bindings["launcher_path"]).resolve() != Path(__file__).resolve():
        raise ValueError("executing PREP launcher binding required")
    _permission(permission, inputs["plan"]["nonce"])
    if inputs["plan"] != preparation_plan(permission["nonce"]):
        raise ValueError("PREP frozen plan differs")
    admission._provenance(source_root, inputs["sourceCommit"], inputs["sourceInputs"])
    binding = {
        "sources": campaign.source_map(),
        "fixtureOrigin": permission["fixtureOrigin"],
        "permissionDigest": digest(permission),
    }
    return o8_admission.issue_production_capability(
        descriptor(), **bindings, binding=binding, binding_digest=digest(binding)
    )


def permission_bindings(plan, *, source_commit, artifact_sha256):
    """Non-authorizing exact facts an independent owner must approve."""
    nonce = plan.get("nonce")
    if plan != preparation_plan(nonce):
        raise ValueError("fixed PREP plan required")
    return {
        "kind": PREPARATION_KIND,
        "campaignId": CAMPAIGN,
        "preparationId": nonce,
        "nonce": nonce,
        "project": campaign.PROJECT,
        "projectNumber": campaign.NUMBER,
        "database": campaign.DATABASE,
        "sourceCommit": source_commit,
        "sourceInputs": campaign.source_map(),
        "artifactSha256": artifact_sha256,
        "planDigest": digest(plan),
        "wallSeconds": 300,
        "recoverySeconds": 120,
        # This cap is cumulative across PREP, retries and the separate final
        # observation. The exact six-request allocation below grants no data.
        "costCapMicrousd": 1_000_000,
        "preparationLedgerBudget": {
            "requests": 6,
            "accounts": 0,
            "resources": 0,
            "costMicrousd": 600,
        },
        "fixtureOrigin": None,
    }


def _permission(permission: dict, nonce: str) -> None:
    if not isinstance(permission, dict):
        raise ValueError("exact baseline preparation permission required")
    expected = permission_bindings(
        preparation_plan(nonce),
        source_commit=permission.get("sourceCommit"),
        artifact_sha256=permission.get("artifactSha256"),
    )
    expected["fixtureOrigin"] = permission.get("fixtureOrigin")
    extra = {
        "issuedAt",
        "expiresAt",
        "ownerIdentity",
        "recoveryOwner",
        "credentialPrincipal",
        "authorizedUserDigest",
        "apiKeyDigest",
    }
    if set(permission) != set(expected) | extra or any(
        permission[key] != value for key, value in expected.items()
    ):
        raise ValueError("exact baseline preparation permission required")
    if permission["fixtureOrigin"] is not None:
        from broad_contract import local_origin

        local_origin(permission["fixtureOrigin"])
    for key in ("authorizedUserDigest", "apiKeyDigest", "artifactSha256"):
        if (
            not isinstance(permission[key], str)
            or re.fullmatch(r"[a-f0-9]{64}", permission[key]) is None
        ):
            raise ValueError("PREP private input digest required")
    campaign.preflight.validate_principal(permission["credentialPrincipal"])
    if permission["kind"] != PREPARATION_KIND or permission["campaignId"] != CAMPAIGN:
        raise ValueError("baseline preparation campaign differs")
    if (
        permission["nonce"] != nonce
        or not isinstance(permission["preparationId"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", permission["preparationId"])
    ):
        raise ValueError("baseline preparation identity differs")
    if (
        permission["project"] != "fireemu-35fe6"
        or permission["projectNumber"] != "592603257417"
    ):
        raise ValueError("baseline preparation project differs")
    if permission["database"] != "(default)":
        raise ValueError("baseline preparation database differs")
    if any(
        not isinstance(permission[key], str) or not permission[key].strip()
        for key in ("ownerIdentity", "recoveryOwner")
    ):
        raise ValueError("baseline preparation owner required")
    now = time.time()
    if (
        type(permission["issuedAt"]) not in (int, float)
        or type(permission["expiresAt"]) not in (int, float)
        or not math.isfinite(permission["issuedAt"])
        or not math.isfinite(permission["expiresAt"])
        or permission["issuedAt"] > now
        or permission["expiresAt"] > permission["issuedAt"] + 86400
        or now + 300 > permission["expiresAt"]
    ):
        raise ValueError("baseline preparation window too short")


def reserve_preparation(
    permission: dict, *, ledger_root: Path, output: Path, capability=None, inputs=None
):
    """Reserve one bounded metadata-only preparation in a supplied Ledger."""
    if not o8_admission.issued_capability(capability):
        raise ValueError("independent PREP O7 approval required")
    if not isinstance(inputs, dict) or inputs.get("permissionDigest") != digest(
        permission
    ):
        raise ValueError("independent PREP O7 permission differs")
    nonce = permission.get("nonce") if isinstance(permission, dict) else None
    if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh preparation nonce required")
    _permission(permission, nonce)
    allocation = preparation_plan(nonce)
    gate_plan = allocation["gatePlan"]
    gate_plan["permissionDigest"] = digest(permission)
    generation = o8_admission.abort_generation(descriptor(), inputs)
    gate_plan.update(generation)
    reservation_now = time.time()
    gate_plan["permissionExpiresAt"] = min(
        permission["expiresAt"], capability.window_expires_at, reservation_now + 300
    )
    locks = allocation["resourceLocks"]
    budget = {"requests": 6, "accounts": 0, "resources": 0, "costMicrousd": 600}
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": budget,
        "concurrency": 1,
        "scopes": locks,
    }
    output = Path(output).resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("fresh preparation output required")
    gate_path = output / "gate"
    claim = {
        "campaignId": CAMPAIGN,
        "manifestDigest": digest(allocation),
        "nonceDigest": digest(nonce),
        "gatePath": str(gate_path.resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": "limits",
        "locks": locks,
        "budget": budget,
        "durationSeconds": 300,
    }
    ledger = Ledger(ledger_root)
    capability._consume(
        campaign_id=CAMPAIGN,
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    o8_admission.validate_frozen_inputs(descriptor(), inputs)
    ticket = ledger.reserve(
        envelope,
        claim,
        gate_plan,
        generation=generation,
        now=reservation_now,
    )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _write_receipt(
        output / "reservation.json",
        {
            "ticket": ticket,
            "claim": claim,
            "envelope": envelope,
            "generation": generation,
        },
    )
    create(gate_path, gate_plan)
    return ledger, ticket, allocation, gate_plan


def validate_handoff(value, permission):
    from credential_prep import ADC_FIELDS, private_string

    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "permissionDigest", "adc", "apiKey"}
        or value["kind"] != "limits-03-preparation-handoff-v1"
        or value["permissionDigest"] != digest(permission)
    ):
        raise ValueError("bound PREP private handoff required")
    adc = value["adc"]
    if (
        not isinstance(adc, dict)
        or set(adc) != ADC_FIELDS
        or adc["type"] != "authorized_user"
        or any(
            not private_string(adc[key], maximum)
            for key, maximum in (
                ("client_id", 512),
                ("client_secret", 4096),
                ("refresh_token", 8192),
            )
        )
        or not private_string(value["apiKey"], 256)
        or digest(adc) != permission["authorizedUserDigest"]
        or adc["client_id"] != permission["credentialPrincipal"]["clientId"]
        or digest(value["apiKey"]) != permission["apiKeyDigest"]
    ):
        raise ValueError("PREP private identity or key differs")
    return value


def _public_metadata(slot, response):
    """Validate identities before projecting credential-free baseline values."""
    if (
        response.get("complete") is not True
        or response.get("workerReaped") is not True
        or response.get("status") != 200
        or response.get("bodyKind") != "json"
        or not isinstance(response.get("body"), dict)
    ):
        raise ValueError("complete PREP metadata response required")
    body = response["body"]
    if slot == "project":
        if (
            body.get("projectId") != campaign.PROJECT
            or body.get("projectNumber") != campaign.NUMBER
        ):
            raise ValueError("PREP project identity differs")
        value = {"projectId": campaign.PROJECT, "projectNumber": campaign.NUMBER}
    elif slot == "database":
        value = database_evidence(body)
        if (
            body.get("name")
            != f"projects/{campaign.PROJECT}/databases/{campaign.DATABASE}"
            or body.get("type") != "FIRESTORE_NATIVE"
            or body.get("databaseEdition") != "STANDARD"
        ):
            raise ValueError("PREP database identity differs")
        identity = {
            key: body[key]
            for key in ("name", "uid", "databaseEdition", "type", "locationId")
        }
        value = {
            "projection": identity,
            "projectionDigest": value["projectionDigest"],
            "identityProjectionDigest": digest(identity),
            "responseDigest": value["responseDigest"],
            "contractDigest": value["contractDigest"],
        }
    elif slot == "auth":
        if body.get("name") != f"projects/{campaign.NUMBER}/config":
            raise ValueError("PREP Auth project differs")
        value = {"name": body["name"]}
    elif slot == "key":
        parent = f"projects/{campaign.NUMBER}/locations/global"
        if (
            body.get("parent") != parent
            or not isinstance(body.get("name"), str)
            or not re.fullmatch(
                re.escape(parent) + r"/keys/[A-Za-z0-9_-]{1,128}", body["name"]
            )
        ):
            raise ValueError("PREP API-key project differs")
        value = {"parent": parent, "name": body["name"]}
    else:
        raise ValueError("closed PREP metadata slot required")
    return {
        "kind": "limits-03-preparation-metadata-v1",
        "slot": slot,
        "responseDigest": digest(body),
        "value": value,
    }


def _write_custody_pipe(fd, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_CUSTODY_BYTES:
        raise ValueError("bounded custody handoff required")
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ValueError("custody handoff write failed")
        view = view[written:]


def _validate_custody_destination(fd):
    if type(fd) is not int or fd < 0:
        raise ValueError("private custody output descriptor required")
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size != 0
    ):
        raise ValueError("empty owned private custody output required")
    os.lseek(fd, 0, os.SEEK_SET)


def _validate_custody(value, permission):
    from credential_prep import private_string

    if (
        not isinstance(value, dict)
        or set(value) != {
            "kind", "token", "project", "principalDigest", "expiresAt",
            "preparationPermissionDigest",
        }
        or value["kind"] != CUSTODY_KIND
        or not private_string(value["token"], 8192)
        or value["project"] != campaign.PROJECT
        or value["principalDigest"] != digest(permission["credentialPrincipal"])
        or value["preparationPermissionDigest"] != digest(permission)
        or type(value["expiresAt"]) not in (int, float)
        or isinstance(value["expiresAt"], bool)
        or not math.isfinite(value["expiresAt"])
        or value["expiresAt"] <= time.time()
    ):
        raise ValueError("verified private custody handoff required")
    return value


def _drain_custody_pipe(fd, outcome):
    """Read the custody pipe on its own thread while the coordinator runs.

    The coordinator writes the whole bounded handoff synchronously before it
    exits, so a parent that only reads after the exit waits for a writer that
    is waiting for it whenever the handoff exceeds the pipe capacity (review
    CUSTODY-PIPE-01). The bound and the deadline are unchanged; only the order
    of reading and waiting is.
    """
    try:
        outcome["value"] = _read_custody_pipe(fd)
    except BaseException as error:  # noqa: BLE001
        outcome["error"] = error


def _read_custody_pipe(fd):
    raw = bytearray()
    while len(raw) <= MAX_CUSTODY_BYTES:
        chunk = os.read(fd, MAX_CUSTODY_BYTES + 1 - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > MAX_CUSTODY_BYTES:
        raise ValueError("bounded custody handoff required")
    if not raw:
        return None
    try:
        value = json.loads(bytes(raw))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("verified private custody handoff required") from error
    if not isinstance(value, dict):
        raise ValueError("verified private custody handoff required")
    return value


def _publish_custody(fd, value):
    _validate_custody_destination(fd)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_CUSTODY_BYTES:
        raise ValueError("bounded custody handoff required")
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ValueError("custody handoff write failed")
        view = view[written:]
    os.fsync(fd)


def _clear_custody(fd):
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.fsync(fd)
    except (OSError, ValueError):
        pass


def _publish_custody_or_clear(fd, value):
    try:
        _publish_custody(fd, value)
    except Exception:
        _clear_custody(fd)
        raise


def _reap_child(child):
    if child.poll() is not None:
        return
    try:
        child.kill()
    except BaseException:  # noqa: BLE001, S110
        pass
    for _ in range(2):
        try:
            child.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            try:
                child.kill()
            except BaseException:  # noqa: BLE001, S110
                pass
        except BaseException:  # noqa: BLE001, S112
            continue
    try:
        child.wait()
    except BaseException:  # noqa: BLE001, S110
        pass


def _require_released_preparation(ledger_root, output):
    result = Ledger._read_bounded_json(Path(output) / "coordinator-result.json")
    reservation = result["receipt"]["ticket"]["reservation"]
    row = Ledger(ledger_root).snapshot()["reservations"].get(reservation)
    if not isinstance(row, dict) or row.get("state") != "released":
        raise ValueError("released PREP reservation required before custody publication")


def _run_preparation(bindings, output, handoff_fd, custody_pipe_fd=None):
    """The coordinator child owns the Gate; its parent observes its exit."""
    from credential_prep import private_string

    capability = approve_preparation(**bindings)
    permission, inputs = bindings["permission"], bindings["inputs"]
    rows, values, request_digests = [], {}, []
    failure = None
    custody = None
    try:
        ledger, ticket, _allocation, gate_plan = reserve_preparation(
            permission,
            ledger_root=bindings["ledger_root"],
            output=output,
            capability=capability,
            inputs=inputs,
        )
        gate = Gate(output / "gate", "limits")
        gate.claim()
        token = None
        try:
            handoff = validate_handoff(_read_private_json(handoff_fd), permission)
            for slot in (
                "refresh",
                "oauth-tokeninfo",
                "project",
                "database",
                "auth",
                "key",
            ):
                secret = (
                    handoff["adc"]
                    if slot == "refresh"
                    else {"token": token, "apiKey": handoff["apiKey"]}
                    if slot == "key"
                    else token
                )
                ledger.validate(ticket, duration=12)

                def send(deadline, slot=slot, secret=secret):
                    nonlocal token, custody
                    # Gate calls this after its rate wait. Recheck authority and
                    # the original reservation deadline before spawning a worker.
                    ledger.validate(
                        ticket, duration=max(1, math.ceil(deadline - time.monotonic()))
                    )
                    sent = time.monotonic()
                    raw = capability._transmit(
                        {"slot": slot, "secret": secret, "deadline": deadline}
                    )
                    request_digests.append(raw["requestDigest"])
                    response = {
                        key: raw[key]
                        for key in ("status", "complete", "workerReaped", "bodyKind")
                    }
                    response["body"] = None
                    try:
                        if (
                            raw["complete"] is not True
                            or raw["workerReaped"] is not True
                            or raw["status"] != 200
                            or not isinstance(raw["body"], dict)
                        ):
                            raise ValueError("PREP HTTP response incomplete")
                        if slot == "refresh":
                            body = raw["body"]
                            if (
                                not private_string(body.get("access_token"), 8192)
                                or body.get("token_type") != "Bearer"
                                or type(body.get("expires_in")) is not int
                                or not 420 <= body["expires_in"] <= 3600
                            ):
                                raise ValueError("PREP refresh refused")
                            token = body["access_token"]
                            response["body"] = {
                                "kind": "limits-03-preparation-refresh-v1",
                                "expiresInSeconds": body["expires_in"],
                                "authorizedUserDigest": permission[
                                    "authorizedUserDigest"
                                ],
                            }
                        elif slot == "oauth-tokeninfo":
                            response["body"] = campaign.preflight.credential_evidence(
                                raw,
                                permission["credentialPrincipal"],
                                sent=sent,
                                now=time.monotonic(),
                                required_seconds=300,
                            )
                            custody = {
                                "kind": CUSTODY_KIND,
                                "token": token,
                                "project": campaign.PROJECT,
                                "principalDigest": digest(permission["credentialPrincipal"]),
                                "expiresAt": time.time() + response["body"]["remainingSecondsAtVerification"],
                                "preparationPermissionDigest": digest(permission),
                            }
                        else:
                            response["body"] = _public_metadata(slot, raw)
                            values[slot] = response["body"]
                        validate_limits_preparation_response(slot, response)
                    except (ValueError, TypeError, KeyError):
                        response["complete"] = False
                        response["body"] = None
                    if slot in ("refresh", "oauth-tokeninfo"):
                        _write_receipt(output / f"credential-{slot}.json", response)
                    rows.append(
                        {
                            "id": "observation:" + slot,
                            "response": response,
                            "responseDigest": digest(response),
                        }
                    )
                    return response

                response = gate.management_dispatch("observation", slot, send)
                if (
                    not response["complete"]
                    or not response["workerReaped"]
                    or response["status"] != 200
                ):
                    raise ValueError("PREP attestation refused")
            gate.finish()
        except Exception as error:  # noqa: BLE001 -- Keep only a secret-free failure class.
            failure = type(error).__name__
        snapshot = gate.snapshot()
        generation = o8_admission.abort_generation(descriptor(), inputs)
        packet = {
            "kind": PREPARATION_KIND,
            "campaignId": CAMPAIGN,
            "preparationId": permission["preparationId"],
            "nonce": permission["nonce"],
            "permissionDigest": digest(permission),
            "sourceCommit": inputs["sourceCommit"],
            "sourceDigest": digest(inputs["sourceInputs"]),
            "manifestDigest": digest(bindings["manifest"]),
            "ticketDigest": digest(ticket),
            "claimDigest": ticket["claimDigest"],
            "ownerIdentityDigest": digest(permission["ownerIdentity"]),
            "principalDigest": digest(permission["credentialPrincipal"]),
            "issuedAt": permission["issuedAt"],
            "expiresAt": permission["expiresAt"],
            "slots": snapshot["managementUsed"],
            "requestDigests": request_digests,
            "evidence": snapshot["managementEvents"],
            "chargedCalls": snapshot["total"],
            "costMicrousd": snapshot["costMicrousd"],
            "completed": failure is None,
            "failed": failure is not None,
            "failureClass": failure,
        }
        if failure is None:
            packet.update(
                project=values["project"]["value"],
                database=values["database"]["value"],
                authConfigDigest=values["auth"]["responseDigest"],
                apiKey=values["key"],
            )
            if custody_pipe_fd is not None:
                if custody is None:
                    raise ValueError("verified custody required")
                _validate_custody(custody, permission)
                _write_custody_pipe(custody_pipe_fd, custody)
        packet["packetDigest"] = digest(packet)
        receipt = {
            "kind": gate_plan["receiptKind"],
            "ticket": ticket,
            "claimDigest": ticket["claimDigest"],
            "planDigest": digest(gate_plan),
            "gateDigest": digest(snapshot),
            "generation": generation,
            "reservationStateAtPublication": "held",
            "executionKind": "fixed-production-wire",
            "releaseEligible": failure is None,
            "failure": failure,
            "chargedCalls": snapshot["total"],
            "ownedResources": [],
            "collection": packet if failure is None else None,
            "managementEvidence": rows,
        }
        if failure is not None:
            receipt.update(
                productionExecuted=False,
                credentialEvidence=[rows[1]["response"]["body"]]
                if len(rows) > 1 and rows[1]["response"]["complete"]
                else [],
                metadata=[],
                routeDigest=digest([]),
                mayHaveCreated=False,
                preflightComplete=False,
                postflightComplete=False,
            )
        _write_receipt(
            output / "coordinator-result.json", {"receipt": receipt, "packet": packet}
        )
    finally:
        o8_admission.revoke_production_capability(capability)


def capture_baseline(*, bindings, output, handoff_fd, custody_output_fd=None):
    """Execute an independently approved preparation and observe child exit."""
    output = Path(output).resolve()
    if custody_output_fd is not None:
        _validate_custody_destination(custody_output_fd)
    # Admission fails without reading the private descriptor or reserving.
    capability = approve_preparation(**bindings)
    o8_admission.revoke_production_capability(capability)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh preparation output required")
    serial = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in bindings.items()
        if key != "manifest_bytes"
    }
    serial["manifest_bytes"] = bindings["manifest_bytes"].decode("utf-8")
    custody_read_fd = custody_write_fd = None
    if custody_output_fd is not None:
        custody_read_fd, custody_write_fd = os.pipe()
    payload = json.dumps(
        {
            "bindings": serial,
            "output": str(output),
            "handoffFd": handoff_fd,
            "custodyPipeFd": custody_write_fd,
        }
    ).encode()
    child = None
    reader = None
    drained = {}
    try:
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=tuple(fd for fd in (handoff_fd, custody_write_fd) if fd is not None),
            env={"PATH": os.defpath, "LANG": "C"},
        )
        # The child holds its own copy of the write end; closing ours makes the
        # child's exit the end of the handoff.
        if custody_write_fd is not None:
            os.close(custody_write_fd)
            custody_write_fd = None
        if custody_read_fd is not None:
            reader = threading.Thread(
                target=_drain_custody_pipe,
                args=(custody_read_fd, drained),
                name="limits-03-custody-reader",
                daemon=True,
            )
            reader.start()
        try:
            child.communicate(payload, timeout=COORDINATOR_DEADLINE_SECONDS)
        except subprocess.TimeoutExpired:
            raise ValueError(
                "PREP coordinator deadline; retained recovery context"
            ) from None
        custody = None
        if reader is not None:
            reader.join(timeout=CUSTODY_CLOSE_SECONDS)
            if reader.is_alive():
                raise ValueError("custody handoff still open after coordinator exit")
            os.close(custody_read_fd)
            custody_read_fd = None
            if "error" in drained:
                raise drained["error"]
            custody = drained.get("value")
            if custody is not None:
                _validate_custody(custody, bindings["permission"])
        if child.returncode != 0:
            raise ValueError("PREP coordinator failed; retained recovery context")
        if custody_output_fd is not None and custody is None:
            result = Ledger._read_bounded_json(output / "coordinator-result.json")
            if result["packet"].get("completed") is not False:
                raise ValueError("verified custody handoff required")
        packet = retire_preparation(ledger_root=bindings["ledger_root"], output=output)
        if custody_output_fd is not None and custody is not None:
            _require_released_preparation(bindings["ledger_root"], output)
            _validate_custody(custody, bindings["permission"])
            _publish_custody_or_clear(custody_output_fd, custody)
        return packet
    finally:
        if child is not None:
            _reap_child(child)
        if reader is not None:
            # A reaped child has closed its write end, so the reader ends before
            # its descriptor is closed underneath it.
            reader.join(timeout=CUSTODY_CLOSE_SECONDS)
            if reader.is_alive():
                # Only a leaked write end keeps the reader blocked. Closing the
                # descriptor under a blocked read would let its number be
                # reused by a later open and the thread read that file, so the
                # one descriptor is left to the reader instead.
                custody_read_fd = None
        for fd_name in ("custody_read_fd", "custody_write_fd"):
            fd = locals()[fd_name]
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _publish_or_verify(path, value):
    if path.exists():
        if Ledger._read_bounded_json(path) != value:
            raise ValueError("immutable PREP evidence differs")
        return
    _write_receipt(path, value)


def retire_preparation(*, ledger_root, output):
    """Replay only terminal publication after the coordinator and workers exit."""
    output = Path(output).resolve()
    result = Ledger._read_bounded_json(output / "coordinator-result.json")
    receipt, packet = result["receipt"], result["packet"]
    _publish_or_verify(output / "receipt.json", receipt)
    ledger = Ledger(ledger_root)
    ticket = receipt["ticket"]
    if receipt["failure"] is None:
        collection_digest = digest(receipt["collection"])
        if (
            ledger.snapshot()["reservations"]
            .get(ticket["reservation"], {})
            .get("state")
            == "held"
        ):
            ledger.attach_evidence(
                ticket, digest(receipt), receipt["gateDigest"], collection_digest
            )
        ledger.finish_limits_preparation(
            ticket,
            {
                "kind": "limits-03-baseline-preparation-release-v1",
                "ticket": ticket,
                "receiptPath": str(output / "receipt.json"),
                "receiptDigest": digest(receipt),
                "gateDigest": receipt["gateDigest"],
                "collectionDigest": collection_digest,
                "generation": receipt["generation"],
            },
        )
    else:
        ledger.abort_no_data(
            ticket,
            {
                "kind": "shared-no-data-abort-v1",
                "ticket": ticket,
                "planDigest": receipt["planDigest"],
                "gateDigest": receipt["gateDigest"],
                "receiptPath": str(output / "receipt.json"),
                "receiptDigest": digest(receipt),
                **receipt["generation"],
            },
        )
    packet["reservationReleased"] = True
    packet["terminalReceiptDigest"] = digest(receipt)
    packet["packetDigest"] = digest(
        {key: value for key, value in packet.items() if key != "packetDigest"}
    )
    _publish_or_verify(output / "baseline-packet.json", packet)
    return packet


def validate_packet(packet):
    """Validate the public packet before a separate final owner freeze."""
    if not isinstance(packet, dict) or packet.get("packetDigest") != digest(
        {key: value for key, value in packet.items() if key != "packetDigest"}
    ):
        raise ValueError("terminal PREP packet digest differs")
    expected_slots = [
        "observation:" + slot
        for slot in ("refresh", "oauth-tokeninfo", "project", "database", "auth", "key")
    ]
    evidence = packet.get("evidence")
    database = packet.get("database")
    if (
        packet.get("kind") != PREPARATION_KIND
        or packet.get("campaignId") != CAMPAIGN
        or packet.get("completed") is not True
        or packet.get("failed") is not False
        or packet.get("failureClass") is not None
        or packet.get("reservationReleased") is not True
        or packet.get("chargedCalls") != 6
        or packet.get("costMicrousd") != 600
        or packet.get("slots") != expected_slots
        or not isinstance(packet.get("requestDigests"), list)
        or len(packet["requestDigests"]) != 6
        or any(
            not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None
            for value in packet["requestDigests"]
        )
        or not isinstance(evidence, list)
        or len(evidence) != 6
        or [event.get("id") for event in evidence] != expected_slots
        or any(
            event.get("completed") is not True
            or event.get("workerReaped") is not True
            or event.get("status") != 200
            for event in evidence
        )
        or packet.get("project")
        != {"projectId": campaign.PROJECT, "projectNumber": campaign.NUMBER}
        or not isinstance(database, dict)
        or database.get("identityProjectionDigest")
        != digest(database.get("projection"))
        or database.get("projection", {}).get("name")
        != f"projects/{campaign.PROJECT}/databases/{campaign.DATABASE}"
        or packet.get("preparationId") != packet.get("nonce")
    ):
        raise ValueError("terminal PREP packet is incomplete")
    for key in (
        "ticketDigest",
        "claimDigest",
        "sourceDigest",
        "manifestDigest",
        "terminalReceiptDigest",
        "authConfigDigest",
        "ownerIdentityDigest",
        "principalDigest",
    ):
        if (
            not isinstance(packet.get(key), str)
            or re.fullmatch(r"[a-f0-9]{64}", packet[key]) is None
        ):
            raise ValueError("terminal PREP digest required")
    return packet


def preparation_plan(nonce: str) -> dict:
    if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh hexadecimal nonce required")
    allocation = baseline_preparation_plan(nonce)
    allocation["nonce"] = nonce
    allocation["preparationKind"] = PREPARATION_KIND
    return allocation


def _read_private_json(fd: int) -> dict:
    if type(fd) is not int or fd < 0:
        raise ValueError("private handoff descriptor required")
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_size > MAX_INPUT_BYTES
    ):
        raise ValueError("private handoff descriptor required")
    chunks = []
    size = 0
    while True:
        chunk = os.read(fd, min(8192, MAX_INPUT_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_INPUT_BYTES:
            break
    raw = b"".join(chunks)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("bounded private handoff required")
    from credential_prep import decode_json

    value = decode_json(raw)
    if not isinstance(value, dict):
        raise ValueError("private handoff object required")
    return value


def main(argv: list[str] | None = None) -> int:
    if (sys.argv[1:] if argv is None else argv) == ["--worker"]:
        from credential_prep import decode_json

        message = decode_json(sys.stdin.buffer.read(8 * 1024 * 1024 + 1))
        if not isinstance(message, dict) or set(message) != {
            "bindings", "output", "handoffFd", "custodyPipeFd"
        }:
            raise ValueError("closed PREP coordinator input required")
        bindings = message["bindings"]
        for key in (
            "source_root",
            "manifest_path",
            "ledger_root",
            "artifact_path",
            "launcher_path",
        ):
            bindings[key] = Path(bindings[key])
        bindings["manifest_bytes"] = bindings["manifest_bytes"].encode("utf-8")
        _run_preparation(
            bindings,
            Path(message["output"]),
            message["handoffFd"],
            message["custodyPipeFd"],
        )
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--handoff-fd", type=int, required=True)
    parser.add_argument("--custody-output-fd", type=int)
    for name in (
        "inputs",
        "approval",
        "manifest",
        "permission",
        "source",
        "artifact",
        "ledger",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    from limits_03_o8 import _read_json

    bindings = {
        name: _read_json(getattr(args, name), private=True)[0]
        for name in ("inputs", "approval", "manifest", "permission")
    }
    bindings.update(
        source_root=args.source,
        manifest_path=args.manifest,
        manifest_bytes=args.manifest.read_bytes(),
        artifact_path=args.artifact,
        ledger_root=args.ledger,
        launcher_path=Path(__file__),
    )
    packet = capture_baseline(
        bindings=bindings,
        output=args.output,
        handoff_fd=args.handoff_fd,
        custody_output_fd=args.custody_output_fd,
    )
    print("PREP completed" if packet["completed"] else "PREP failed and retired")
    return 0 if packet["completed"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 -- Never print credential-bearing exceptions.
        print(f"PREP refused ({type(error).__name__}).", file=sys.stderr)
        raise SystemExit(2) from None
