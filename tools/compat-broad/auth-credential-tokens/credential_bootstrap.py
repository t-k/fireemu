"""Admitted Auth preparation and independently approved reserved continuation.

The file-bound CLI consumes independently supplied preparation and observation
approvals through the generic issuer. It retains private credentials in memory
while waiting under the original reservation deadline; it never creates owner
permission or approval artifacts. The separate retirement command requires real
worker/coordinator exit evidence through the Ledger and Gate.
"""

from __future__ import annotations

import copy
import math
import os
import stat
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "fs-write-txn"))

import credential_gate as gate_module
import credential_remote_transport as remote
from broad_contract import digest

PROJECT = "fireemu-35fe6"
PROJECT_NUMBER = "592603257417"
SERVICE_ACCOUNT = "fireemu-oracle@fireemu-35fe6.iam.gserviceaccount.com"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PERMISSION_KIND = "auth-credential-bootstrap-permission-v1"
HANDOFF_KIND = "auth-credential-handoff-v1"
ADC_FIELDS = frozenset({"type", "client_id", "client_secret", "refresh_token"})
PREP_REQUEST_SECONDS = 5.0
PREP_REQUESTS = 4
TASK_MAX_REQUESTS = 60
TASK_MAX_SECONDS = 600
TASK_MAX_COST_MICROUSD = 50_000
RECOVERY_SECONDS = 60
MIN_TASK_REQUESTS = 53


@dataclass(frozen=True)
class BootstrapBudget:
    max_requests: int = TASK_MAX_REQUESTS
    max_seconds: int = TASK_MAX_SECONDS
    cost_microusd: int = TASK_MAX_COST_MICROUSD

    def validate(self) -> None:
        if (
            any(
                type(value) is not int
                for value in (self.max_requests, self.max_seconds, self.cost_microusd)
            )
            or self.max_requests < MIN_TASK_REQUESTS
            or self.max_requests > TASK_MAX_REQUESTS
            or self.max_seconds <= RECOVERY_SECONDS
            or self.max_seconds > TASK_MAX_SECONDS
            or self.cost_microusd <= 0
            or self.cost_microusd > TASK_MAX_COST_MICROUSD
        ):
            raise ValueError("bootstrap budget differs")


@dataclass(frozen=True)
class BootstrapResult:
    prepared: dict = field(repr=False)
    proof: dict
    charged_requests: int
    ticket: dict | None = None
    gate: object = field(default=None, repr=False)
    budget: dict | None = field(default=None, repr=False)


def validate_deadline(seconds: float) -> None:
    if (
        type(seconds) not in (int, float)
        or isinstance(seconds, bool)
        or not math.isfinite(seconds)
        or seconds <= PREP_REQUEST_SECONDS
    ):
        raise ValueError("bootstrap deadline must cover four bounded requests")


def token_lifetime(body, *, sent_monotonic, sent_at):
    """Conservative expiry from the response, anchored before its worker send."""
    seconds = body.get("expires_in") if isinstance(body, dict) else None
    if isinstance(seconds, str) and seconds.isascii() and seconds.isdecimal():
        seconds = int(seconds)
    if (
        type(seconds) is not int
        or not 1 < seconds <= 3600
        or any(
            type(value) not in (int, float) or not math.isfinite(value) or value < 0
            for value in (sent_monotonic, sent_at)
        )
    ):
        raise ValueError("typed token lifetime required")
    return {
        "expiresInSeconds": seconds,
        "sentMonotonic": sent_monotonic,
        "sentAt": sent_at,
        "expiresMonotonic": sent_monotonic + seconds,
        "expiresAt": sent_at + seconds,
    }


def require_lifetime(
    lifetime, *, deadline_monotonic, deadline_at, now_monotonic, now_at
):
    """Cover the original total deadline, including its recovery tail, once."""
    if not isinstance(lifetime, dict) or set(lifetime) != {
        "expiresInSeconds",
        "sentMonotonic",
        "sentAt",
        "expiresMonotonic",
        "expiresAt",
    }:
        raise ValueError("bound token lifetime required")
    expected = token_lifetime(
        {"expires_in": lifetime["expiresInSeconds"]},
        sent_monotonic=lifetime["sentMonotonic"],
        sent_at=lifetime["sentAt"],
    )
    if (
        lifetime != expected
        or any(
            type(value) not in (int, float) or not math.isfinite(value)
            for value in (deadline_monotonic, deadline_at, now_monotonic, now_at)
        )
        or not lifetime["sentMonotonic"]
        <= now_monotonic
        < deadline_monotonic
        <= lifetime["expiresMonotonic"]
        or not lifetime["sentAt"] <= now_at < deadline_at <= lifetime["expiresAt"]
    ):
        raise ValueError("token lifetime cannot cover original reservation")


def read_private_input(path):
    """Inspect and read the same owned private regular FD without following links."""
    import json

    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
            or not 0 < before.st_size <= 65536
        ):
            raise ValueError("bounded private input required")
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(fd, min(8192, 65537 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            len(raw) != before.st_size
            or len(raw) > 65536
            or any(getattr(before, name) != getattr(after, name) for name in fields)
        ):
            raise ValueError("stable bounded private input required")
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"adc", "apiKey"}:
            raise ValueError("closed private input required")
        return value
    except (OSError, ValueError, UnicodeError):
        raise ValueError("bounded regular owned private input required") from None
    finally:
        if fd is not None:
            os.close(fd)


def _validate_permission(permission: dict, adc: dict) -> None:
    if not isinstance(permission, dict) or permission.get("kind") != PERMISSION_KIND:
        raise ValueError("bootstrap permission required")
    principal = permission.get("credentialPrincipal")
    import credential_preflight

    credential_preflight.validate_principal(principal)
    if (
        not isinstance(principal["clientId"], str)
        or not principal["clientId"]
        or principal["requiredScopes"] != [SCOPE]
    ):
        raise ValueError("bootstrap principal required")
    if principal["clientId"] != adc.get("client_id"):
        raise ValueError("bootstrap principal differs")
    if (
        permission.get("project") != PROJECT
        or permission.get("projectNumber") != PROJECT_NUMBER
    ):
        raise ValueError("bootstrap project differs")
    if not isinstance(permission.get("nonce"), str) or len(permission["nonce"]) != 32:
        raise ValueError("bootstrap nonce required")
    if permission.get("authorizedUserDigest") != digest(adc):
        raise ValueError("authorized-user binding differs")


def _validate_handoff_input(permission: dict, adc: dict) -> None:
    if (
        not isinstance(adc, dict)
        or set(adc) != ADC_FIELDS
        or adc.get("type") != "authorized_user"
    ):
        raise ValueError("private bootstrap input required")
    if permission.get("authorizedUserDigest") != digest(adc):
        raise ValueError("private bootstrap input required")


def _origin_url(host: str, path: str, fixture_origin: str | None) -> str:
    return (
        (fixture_origin + "/" if fixture_origin is not None else "https://")
        + host
        + path
    )


def _request(
    slot: str, secret, *, fixture_origin: str | None, deadline: float | None = None
):
    slot = {
        "bootstrap-refresh": "refresh",
        "bootstrap-tokeninfo": "tokeninfo",
        "bootstrap-project": "project",
        "bootstrap-auth-config": "auth",
    }.get(slot, slot)
    if slot not in {"refresh", "tokeninfo", "project", "auth"}:
        raise ValueError("closed bootstrap slot required")
    if deadline is not None and (
        not math.isfinite(deadline) or deadline <= time.monotonic()
    ):
        raise ValueError("bootstrap deadline already expired")
    seconds = (
        PREP_REQUEST_SECONDS
        if deadline is None
        else min(PREP_REQUEST_SECONDS, deadline - time.monotonic())
    )
    if slot == "refresh":
        return remote.request_with_lifecycle(
            _origin_url("oauth2.googleapis.com", "/token", fixture_origin),
            {
                "grant_type": "refresh_token",
                "client_id": secret["client_id"],
                "client_secret": secret["client_secret"],
                "refresh_token": secret["refresh_token"],
            },
            headers={},
            seconds=seconds,
            form=True,
            fixture_origin=fixture_origin,
        )
    if slot == "tokeninfo":
        return remote.request_with_lifecycle(
            _origin_url(
                "oauth2.googleapis.com",
                "/tokeninfo?access_token=" + urllib.parse.quote(secret, safe=""),
                fixture_origin,
            ),
            None,
            headers={},
            seconds=seconds,
            fixture_origin=fixture_origin,
        )
    if slot == "project":
        return remote.request_with_lifecycle(
            _origin_url(
                "cloudresourcemanager.googleapis.com",
                "/v1/projects/" + PROJECT,
                fixture_origin,
            ),
            None,
            headers={
                "Authorization": "Bearer " + secret,
                "x-goog-user-project": PROJECT,
            },
            seconds=seconds,
            fixture_origin=fixture_origin,
        )
    return remote.request_with_lifecycle(
        _origin_url(
            "identitytoolkit.googleapis.com",
            "/admin/v2/projects/" + PROJECT + "/config",
            fixture_origin,
        ),
        None,
        headers={"Authorization": "Bearer " + secret, "x-goog-user-project": PROJECT},
        seconds=seconds,
        fixture_origin=fixture_origin,
    )


def prepare(
    permission: dict,
    *,
    adc: dict,
    api_key: str,
    fixture_origin: str | None = None,
    budget: BootstrapBudget | None = None,
    gate=None,
    ledger=None,
    ticket=None,
    capability=None,
    source_root=None,
    inputs=None,
    absolute_deadline=None,
    management_evidence=None,
) -> BootstrapResult:
    """Run exactly refresh, tokeninfo, project and Auth-config operations.

    `fixture_origin` is test-only; production leaves it unset so the pinned
    transport enforces its reviewed HTTPS allowlist. This function intentionally
    returns private prepared values and typed proof, not a finalized handoff or O7 capability.
    """
    budget = budget or BootstrapBudget()
    prepared_start_monotonic, prepared_start_at = time.monotonic(), time.time()
    budget.validate()
    validate_deadline(budget.max_seconds - RECOVERY_SECONDS)
    _validate_permission(permission, adc)
    _validate_handoff_input(permission, adc)
    import credential_admission as admission

    if not admission._private_string(api_key, 256) or any(
        not admission._private_string(adc[key], 8192)
        for key in ("client_id", "client_secret", "refresh_token")
    ):
        raise ValueError("private Web API key required")
    if permission.get("apiKeyDigest") is not None and permission[
        "apiKeyDigest"
    ] != digest(api_key):
        raise ValueError("approved API key differs")
    if gate is None and fixture_origin is None:
        raise ValueError("production bootstrap Gate required")
    if fixture_origin is None and capability is None:
        raise ValueError("admitted preparation Gate required")
    if gate is not None:
        snapshot = gate.snapshot()
        bootstrap = snapshot.get("plan", {}).get("bootstrap")
        if not isinstance(bootstrap, dict) or bootstrap.get(
            "permissionDigest"
        ) != digest(permission):
            raise ValueError("bootstrap Gate permission binding differs")
        if (
            tuple(bootstrap.get("operationIds", ()))
            != gate_module.bootstrap_management_ids()
        ):
            raise ValueError("bootstrap Gate operation binding differs")
        if snapshot.get("plan", {}).get("nonce") != permission["nonce"]:
            raise ValueError("bootstrap Gate nonce binding differs")
        before_events = len(snapshot.get("managementEvents", []))
    else:
        before_events = 0

    evidence = [] if management_evidence is None else management_evidence
    lifetime = None

    def record_lifetime(slot, exchange, sent_monotonic, sent_at):
        nonlocal lifetime
        if slot == "bootstrap-tokeninfo":
            try:
                lifetime = token_lifetime(
                    exchange.body, sent_monotonic=sent_monotonic, sent_at=sent_at
                )
            except ValueError:
                lifetime = None

    def dispatch(slot: str, secret):
        request_slot = {
            "bootstrap-refresh": "refresh",
            "bootstrap-tokeninfo": "tokeninfo",
            "bootstrap-project": "project",
            "bootstrap-auth-config": "auth",
        }[slot]
        if gate is None:
            sent_monotonic, sent_at = time.monotonic(), time.time()
            exchange = _request(request_slot, secret, fixture_origin=fixture_origin)
            record_lifetime(slot, exchange, sent_monotonic, sent_at)
            return exchange.status, exchange.body

        private_response = []

        def send(deadline):
            if absolute_deadline is not None:
                deadline = min(deadline, absolute_deadline)
            if capability is not None:
                admission._provenance(
                    source_root, inputs["sourceCommit"], inputs["sourceInputs"]
                )
                if (
                    ledger.bound_claim(ticket)["gatePlanDigest"]
                    != snapshot["planDigest"]
                ):
                    raise ValueError("bootstrap reservation Gate differs")
                ledger.validate(
                    ticket, duration=math.ceil(PREP_REQUEST_SECONDS + RECOVERY_SECONDS)
                )
                try:
                    sent_monotonic, sent_at = time.monotonic(), time.time()
                    exchange = capability._transmit(
                        {
                            "kind": "preparation",
                            "slot": slot,
                            "secret": secret,
                            "deadline": deadline,
                            "fixtureOrigin": fixture_origin,
                        }
                    )
                except remote.WorkerFailure as error:
                    if not error.worker_reaped:
                        raise
                    receipt = {
                        "status": None,
                        "complete": False,
                        "workerReaped": True,
                        "bodyKind": None,
                        "body": None,
                    }
                    evidence.append(
                        {
                            "id": "observation:" + slot,
                            "response": receipt,
                            "responseDigest": digest(receipt),
                        }
                    )
                    private_response.append((None, None))
                    return receipt
            else:
                sent_monotonic, sent_at = time.monotonic(), time.time()
                exchange = _request(
                    request_slot,
                    secret,
                    fixture_origin=fixture_origin,
                    deadline=deadline,
                )
            if type(exchange) is not remote.WorkerExchange:
                raise ValueError("typed worker lifecycle required")
            record_lifetime(slot, exchange, sent_monotonic, sent_at)
            private_response.append((exchange.status, exchange.body))
            receipt = {
                "status": exchange.status,
                "complete": exchange.status == 200,
                "workerReaped": exchange.worker_reaped,
                "bodyKind": "json",
                "body": {
                    "kind": "auth-bootstrap-attestation-v1",
                    "slot": slot,
                    "responseBodyDigest": digest(exchange.body),
                },
            }
            if slot == "bootstrap-tokeninfo":
                receipt["body"]["tokenLifetime"] = lifetime
            evidence.append(
                {
                    "id": "observation:" + slot,
                    "response": receipt,
                    "responseDigest": digest(receipt),
                }
            )
            return receipt

        gate.management_dispatch("observation", slot, send)
        return private_response[0]

    status, refresh = dispatch("bootstrap-refresh", adc)
    if (
        status != 200
        or not isinstance(refresh, dict)
        or not isinstance(refresh.get("access_token"), str)
    ):
        raise ValueError("OAuth refresh refused")
    token = refresh["access_token"]
    status, tokeninfo = dispatch("bootstrap-tokeninfo", token)
    if status != 200 or not isinstance(tokeninfo, dict):
        raise ValueError("tokeninfo refused")
    principal = permission["credentialPrincipal"]
    identity_matches = (
        tokeninfo.get("sub") == principal["subject"]
        if "subject" in principal
        else tokeninfo.get("email") == principal["verifiedEmail"]
        and tokeninfo.get("email_verified") == "true"
    )
    if (
        tokeninfo.get("azp") != principal["clientId"]
        or tokeninfo.get("aud") != principal["clientId"]
        or not identity_matches
        or SCOPE not in str(tokeninfo.get("scope", "")).split()
        or lifetime is None
    ):
        raise ValueError("tokeninfo principal or lifetime differs")
    total_deadline = (
        absolute_deadline + RECOVERY_SECONDS
        if absolute_deadline is not None
        else prepared_start_monotonic + budget.max_seconds
    )
    wall_deadline = (
        ledger.snapshot()["reservations"][ticket["reservation"]]["deadline"]
        if ledger is not None
        else prepared_start_at + budget.max_seconds
    )
    require_lifetime(
        lifetime,
        deadline_monotonic=total_deadline,
        deadline_at=wall_deadline,
        now_monotonic=time.monotonic(),
        now_at=time.time(),
    )
    status, project = dispatch("bootstrap-project", token)
    if (
        status != 200
        or not isinstance(project, dict)
        or project.get("projectId") != PROJECT
        or project.get("projectNumber") != PROJECT_NUMBER
    ):
        raise ValueError("project identity differs")
    status, auth = dispatch("bootstrap-auth-config", token)
    if status != 200 or not isinstance(auth, dict):
        raise ValueError("Auth config readback refused")
    prepared_monotonic, prepared_at = time.monotonic(), time.time()
    require_lifetime(
        lifetime,
        deadline_monotonic=total_deadline,
        deadline_at=wall_deadline,
        now_monotonic=prepared_monotonic,
        now_at=prepared_at,
    )
    prepared = {
        "token": token,
        "apiKey": api_key,
        "signing": {"serviceAccount": SERVICE_ACCOUNT},
    }
    proof = {
        "kind": "auth-credential-bootstrap-proof-v1",
        "permissionDigest": digest(permission),
        "nonce": permission["nonce"],
        "authorizedUserDigest": digest(adc),
        "principalDigest": digest(principal),
        "preparedDigest": digest(prepared),
        "apiKeyDigest": digest(api_key),
        "project": {
            "projectId": project["projectId"],
            "projectNumber": project["projectNumber"],
        },
        "authConfigDigest": digest(auth),
        "tokeninfoExpiresInSeconds": lifetime["expiresMonotonic"] - prepared_monotonic,
        "tokenLifetime": lifetime,
        "preparedMonotonic": prepared_monotonic,
        "preparedAt": prepared_at,
        "requestCount": PREP_REQUESTS,
        "taskMaxRequests": TASK_MAX_REQUESTS,
        "taskMaxSeconds": TASK_MAX_SECONDS,
        "recoverySeconds": RECOVERY_SECONDS,
    }
    if (
        not isinstance(auth.get("name"), str)
        or auth.get("name") != "projects/592603257417/config"
    ):
        raise ValueError("Auth config project binding differs")
    if gate is not None:
        snapshot = gate.snapshot()
        used = snapshot.get("managementUsed", [])
        expected = [
            "observation:" + item for item in gate_module.bootstrap_management_ids()
        ]
        events = snapshot.get("managementEvents", [])
        if (
            used[:PREP_REQUESTS] != expected
            or len(events) - before_events != PREP_REQUESTS
        ):
            raise ValueError("bootstrap Gate completion differs")
        proof["gatePlanDigest"] = snapshot["planDigest"]
        proof["managementJournalDigest"] = digest(events[before_events:])
        proof["managementEvidence"] = evidence
    charged_requests = (
        PREP_REQUESTS
        if gate is None
        else len(snapshot.get("managementEvents", [])) - before_events
    )
    return BootstrapResult(prepared, proof, charged_requests)


def execute_preparation(
    *,
    capability,
    inputs,
    permission,
    source_root,
    ledger_root,
    output,
    credential_reader,
    fixture_origin=None,
):
    """Consume preparation authority and reserve the single combined attempt."""
    import credential_admission as admission
    import credential_descriptor as campaign
    import credential_production as production
    import o8_admission
    import reservations

    if not admission.issued_capability(capability):
        raise ValueError("issued preparation O7 required")
    admission.validate_preparation_permission(inputs, permission)
    admission._provenance(source_root, inputs["sourceCommit"], inputs["sourceInputs"])
    if permission.get("fixtureOrigin") != fixture_origin:
        raise ValueError("approved preparation origin differs")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh preparation output required")
    gate_plan = admission.preparation_gate_plan_for(inputs, permission)
    generation = o8_admission.abort_generation(
        campaign.preparation_descriptor(), inputs
    )
    gate_plan["collectorSourceDigest"] = generation["collectorSourceDigest"]
    claim = admission.bootstrap_reservation_claim(
        inputs, permission=permission, gate_path=output / "gate", gate_plan=gate_plan
    )
    capability._consume(
        campaign_id=campaign.CAMPAIGN,
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    ledger = reservations.Ledger(ledger_root)
    ticket = ledger.reserve(
        production._envelope(permission, claim), claim, gate_plan, generation=generation
    )
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    absolute_deadline = (
        time.monotonic() + row["deadline"] - time.time() - RECOVERY_SECONDS
    )
    task_budget = production.new_budget(
        TASK_MAX_REQUESTS,
        TASK_MAX_SECONDS,
        TASK_MAX_COST_MICROUSD / 1_000_000,
        started_monotonic=absolute_deadline + RECOVERY_SECONDS - TASK_MAX_SECONDS,
        recovery_requests=12,
        recovery_wall_seconds=RECOVERY_SECONDS,
    )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    gate_module.create(output / "gate", gate_plan)
    gate = gate_module.CredentialGate(output / "gate")
    gate.claim()
    evidence = []
    production._write_record(output / "preparation-inputs.json", inputs)
    try:
        private = credential_reader()
        result = prepare(
            permission,
            adc=private["adc"],
            api_key=private["apiKey"],
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            capability=capability,
            source_root=source_root,
            inputs=inputs,
            absolute_deadline=absolute_deadline,
            fixture_origin=fixture_origin,
            management_evidence=evidence,
        )
        proof = {
            **result.proof,
            "ticket": ticket,
            "claimDigest": digest(claim),
            "inputsDigest": inputs["inputsDigest"],
            "approvalDigest": capability.approval_digest,
            "generation": generation,
            "reservationDeadline": row["deadline"],
            "reservationMonotonicDeadline": absolute_deadline + RECOVERY_SECONDS,
            "reservationStartedAt": row["deadline"] - claim["durationSeconds"],
            "fixtureOrigin": fixture_origin,
        }
        production._write_record(
            output / "preparation-proof.json",
            proof,
            [*private["adc"].values(), private["apiKey"], result.prepared["token"]],
        )
        task_budget["requests"] = gate.snapshot()["total"]
        return BootstrapResult(
            result.prepared, proof, result.charged_requests, ticket, gate, task_budget
        )
    except Exception as error:
        snapshot = gate.snapshot()
        record = admission.build_receipt(
            inputs,
            None,
            rows=[],
            generation=generation,
            failure=type(error).__name__,
            stop_point="preflight",
        )
        record.update(
            ticket=ticket,
            claimDigest=digest(claim),
            planDigest=digest(gate_plan),
            gateDigest=digest(snapshot),
            chargedCalls=snapshot["total"],
            managementEvidence=evidence,
            credentialEvidence=[],
            metadata=[],
            routeDigest=digest([]),
            mayHaveCreated=False,
            preflightComplete=False,
            postflightComplete=False,
            productionExecuted=False,
            coordinatorMustExit=True,
            reservationStateAtPublication="held",
            executionKind="fixed-production-wire",
            releaseEligible=False,
        )
        production._write_record(output / "preparation-failure.json", record)
        production._write_record(output / "receipt.json", record)
        raise
    finally:
        admission.revoke_production_capability(capability)


def validate_proof(proof, *, snapshot, reservation, inputs):
    """Reconstruct all four sanitized receipts against the original reservation."""
    import credential_admission as admission
    import credential_descriptor as campaign
    import o8_admission

    admission.validate_preparation_permission(
        inputs, inputs["permission"], check_window=False
    )
    expected_plan = admission.preparation_gate_plan_for(
        inputs, inputs["permission"], check_window=False
    )
    generation = o8_admission.abort_generation(
        campaign.preparation_descriptor(), inputs
    )
    expected_plan["collectorSourceDigest"] = generation["collectorSourceDigest"]
    events = snapshot.get("managementEvents", [])[:4]
    evidence = proof.get("managementEvidence", [])
    expected_ids = [
        "observation:" + slot for slot in gate_module.bootstrap_management_ids()
    ]
    if (
        proof.get("kind") != "auth-credential-bootstrap-proof-v1"
        or proof.get("requestCount") != PREP_REQUESTS
        or proof.get("taskMaxRequests") != TASK_MAX_REQUESTS
        or proof.get("taskMaxSeconds") != TASK_MAX_SECONDS
        or proof.get("recoverySeconds") != RECOVERY_SECONDS
        or proof.get("nonce") != inputs["plan"]["nonce"]
        or proof.get("inputsDigest") != inputs["inputsDigest"]
        or proof.get("permissionDigest") != inputs["permissionDigest"]
        or proof.get("generation") != generation
        or reservation.get("generation") != generation
        or proof.get("claimDigest") != reservation.get("claimDigest")
        or proof.get("reservationDeadline") != reservation.get("deadline")
        or proof.get("reservationStartedAt")
        != reservation["deadline"] - TASK_MAX_SECONDS
        or not inputs["permission"]["issuedAt"]
        <= proof["reservationStartedAt"]
        < reservation["deadline"]
        <= inputs["permission"]["expiresAt"]
        or not admission.bounded_number(proof.get("reservationMonotonicDeadline"))
        or not snapshot["started"]
        < proof["reservationMonotonicDeadline"]
        <= snapshot["started"] + TASK_MAX_SECONDS
        or proof.get("fixtureOrigin") != inputs["permission"].get("fixtureOrigin")
        or reservation["claim"]["durationSeconds"] != TASK_MAX_SECONDS
        or reservation["claim"]["budget"] != campaign.ledger_budget()
        or reservation["claim"]["manifestDigest"] != inputs["planDigest"]
        or reservation["claim"]["gatePlanDigest"] != digest(expected_plan)
        or snapshot.get("plan") != expected_plan
        or snapshot.get("planDigest") != digest(expected_plan)
        or proof.get("gatePlanDigest") != digest(expected_plan)
        or proof.get("managementJournalDigest") != digest(events)
        or [event.get("id") for event in events] != expected_ids
        or [row.get("id") for row in evidence] != expected_ids
        or proof.get("apiKeyDigest") != inputs["permission"]["apiKeyDigest"]
        or proof.get("principalDigest")
        != digest(inputs["permission"]["credentialPrincipal"])
        or proof.get("authorizedUserDigest")
        != inputs["permission"]["authorizedUserDigest"]
    ):
        raise ValueError("anchored preparation proof differs")
    for event, row in zip(events, evidence, strict=True):
        response = row.get("response")
        if (
            not isinstance(response, dict)
            or row.get("responseDigest") != digest(response)
            or event.get("responseDigest") != digest(response)
            or event.get("bodyDigest") != digest(response.get("body"))
            or event.get("completed") is not True
            or event.get("workerReaped") is not True
            or not event["started"] <= event["ended"] <= event["deadline"]
        ):
            raise ValueError("preparation worker evidence differs")
    if evidence[-1]["response"]["body"]["responseBodyDigest"] != proof.get(
        "authConfigDigest"
    ):
        raise ValueError("preparation baseline evidence differs")
    lifetime = evidence[1]["response"]["body"].get("tokenLifetime")
    if (
        proof.get("tokenLifetime") != lifetime
        or not isinstance(lifetime, dict)
        or not events[1]["started"]
        <= lifetime.get("sentMonotonic", -1)
        <= events[1]["ended"]
        or not events[-1]["ended"] <= proof.get("preparedMonotonic", -1)
        or proof.get("tokeninfoExpiresInSeconds")
        != lifetime["expiresMonotonic"] - proof["preparedMonotonic"]
    ):
        raise ValueError("anchored token lifetime evidence differs")
    require_lifetime(
        lifetime,
        deadline_monotonic=proof["reservationMonotonicDeadline"],
        deadline_at=reservation["deadline"],
        now_monotonic=proof["preparedMonotonic"],
        now_at=proof["preparedAt"],
    )


def observation_binding(proof):
    return {
        "proofDigest": digest(proof),
        "ticket": proof["ticket"],
        "claimDigest": proof["claimDigest"],
        "gatePlanDigest": proof["gatePlanDigest"],
        "preparationInputsDigest": proof["inputsDigest"],
        "reservationDeadline": proof["reservationDeadline"],
    }


def retire_no_data(output, *, ledger_root):
    """Ask the Ledger to retire real no-data evidence after the coordinator exits."""
    import credential_production as production
    import reservations

    output = Path(output).resolve()
    receipt = production._read_saved(output / "receipt.json")
    ledger = reservations.Ledger(ledger_root)
    ticket = receipt["ticket"]
    claim = ledger.bound_claim(ticket)
    if claim["gatePath"] != str(output / "gate"):
        raise ValueError("original preparation evidence path required")
    record = {
        "kind": "shared-no-data-abort-v1",
        "ticket": ticket,
        "planDigest": claim["gatePlanDigest"],
        "gateDigest": receipt["gateDigest"],
        "receiptPath": str(output / "receipt.json"),
        "receiptDigest": digest(receipt),
        **receipt["generation"],
    }
    ledger.abort_no_data(ticket, record)
    return ledger.snapshot()["reservations"][ticket["reservation"]]


def finalize_handoff(
    prepared: dict,
    observation_permission,
    proof: dict,
    *,
    snapshot=None,
    reservation=None,
    inputs=None,
) -> dict:
    """Bind the private prepared values only after observation permission exists."""
    if (
        not isinstance(observation_permission, dict)
        or snapshot is None
        or reservation is None
        or inputs is None
    ):
        raise ValueError(
            "independent observation permission and anchored proof required"
        )
    validate_proof(proof, snapshot=snapshot, reservation=reservation, inputs=inputs)
    require_lifetime(
        proof["tokenLifetime"],
        deadline_monotonic=proof["reservationMonotonicDeadline"],
        deadline_at=reservation["deadline"],
        now_monotonic=time.monotonic(),
        now_at=time.time(),
    )
    if (
        observation_permission.get("bootstrap") != observation_binding(proof)
        or observation_permission.get("authConfigDigest") != proof["authConfigDigest"]
        or observation_permission.get("credentialPrincipal")
        != inputs["permission"]["credentialPrincipal"]
        or observation_permission.get("fixtureOrigin") != proof.get("fixtureOrigin")
    ):
        raise ValueError("independent observation permission binding differs")
    if not isinstance(prepared, dict) or set(prepared) != {
        "token",
        "apiKey",
        "signing",
    }:
        raise ValueError("prepared credential required")
    if (
        not isinstance(proof, dict)
        or proof.get("kind") != "auth-credential-bootstrap-proof-v1"
        or proof.get("requestCount") != PREP_REQUESTS
        or proof.get("taskMaxRequests") != TASK_MAX_REQUESTS
        or proof.get("taskMaxSeconds") != TASK_MAX_SECONDS
        or proof.get("recoverySeconds") != RECOVERY_SECONDS
    ):
        raise ValueError("independent bootstrap proof required")
    if proof.get("preparedDigest") != digest(prepared):
        raise ValueError("prepared credential differs from bootstrap proof")
    return {
        "kind": HANDOFF_KIND,
        "permissionDigest": digest(observation_permission),
        **copy.deepcopy(prepared),
    }


__all__ = [
    "HANDOFF_KIND",
    "PERMISSION_KIND",
    "PREP_REQUESTS",
    "SCOPE",
    "SERVICE_ACCOUNT",
    "BootstrapBudget",
    "BootstrapResult",
    "finalize_handoff",
    "prepare",
    "validate_deadline",
]


def publish_approval_stop(preparation, *, inputs, output, reason):
    """Publish the actual four-call prefix when final approval cannot be used."""
    import credential_admission as admission
    import credential_production as production

    snapshot = preparation.gate.snapshot()
    if snapshot["events"] or snapshot["total"] != PREP_REQUESTS:
        raise ValueError("preparation-only stop required")
    proof = preparation.proof
    record = admission.build_receipt(
        inputs,
        None,
        rows=[],
        generation=proof["generation"],
        failure=reason,
        stop_point="preflight",
    )
    record.update(
        ticket=preparation.ticket,
        claimDigest=proof["claimDigest"],
        planDigest=proof["gatePlanDigest"],
        gateDigest=digest(snapshot),
        chargedCalls=snapshot["total"],
        managementEvidence=proof["managementEvidence"],
        credentialEvidence=[],
        metadata=[],
        routeDigest=digest([]),
        mayHaveCreated=False,
        preflightComplete=False,
        postflightComplete=False,
        productionExecuted=False,
        coordinatorMustExit=True,
        reservationStateAtPublication="held",
        executionKind="fixed-production-wire",
        releaseEligible=False,
    )
    production._write_record(
        Path(output) / "receipt.json",
        record,
        [preparation.prepared["token"], preparation.prepared["apiKey"]],
    )


def main(argv=None):
    """Keep preparation secrets alive only within the original admitted attempt."""
    import argparse
    import json

    import credential_admission as admission
    import credential_production as production

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "retire-no-data"))
    for name in (
        "inputs",
        "permission",
        "approval",
        "manifest",
        "source",
        "artifact",
        "credential-file",
        "observation-directory",
    ):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approval-wait-seconds", type=float)
    args = parser.parse_args(argv)
    preparation = None
    capability = None
    inputs = None
    try:
        if args.command == "retire-no-data":
            result = retire_no_data(args.output, ledger_root=args.ledger)
            print(json.dumps({"state": result["state"]}))
            return 0
        if any(
            getattr(args, name) is None
            for name in (
                "inputs",
                "permission",
                "approval",
                "manifest",
                "source",
                "artifact",
                "credential_file",
                "observation_directory",
            )
        ):
            raise ValueError("complete file-bound bootstrap arguments required")
        if args.approval_wait_seconds is not None and (
            not math.isfinite(args.approval_wait_seconds)
            or not 0 < args.approval_wait_seconds <= TASK_MAX_SECONDS - RECOVERY_SECONDS
        ):
            raise ValueError("bounded approval wait required")
        inputs = admission._read(args.inputs)
        permission = admission._read(args.permission)

        def issue(inputs_, permission_, approval_path, manifest_path, issuer):
            approval = admission._read(approval_path)
            manifest = admission._read(manifest_path)
            binding, binding_digest = remote.worker_binding()
            return issuer(
                inputs=inputs_,
                permission=permission_,
                approval=approval,
                manifest=manifest,
                manifest_bytes=manifest_path.read_bytes(),
                manifest_path=manifest_path,
                ledger_root=args.ledger,
                artifact_path=args.artifact,
                launcher_path=Path(__file__).resolve(),
                binding=binding,
                binding_digest=binding_digest,
            )

        capability = issue(
            inputs,
            permission,
            args.approval,
            args.manifest,
            admission.issue_preparation_capability,
        )

        def private_reader():
            return read_private_input(args.credential_file)

        preparation = execute_preparation(
            capability=capability,
            inputs=inputs,
            permission=permission,
            source_root=args.source,
            ledger_root=args.ledger,
            output=args.output,
            credential_reader=private_reader,
            fixture_origin=permission.get("fixtureOrigin"),
        )
        deadline = min(
            preparation.proof["reservationMonotonicDeadline"] - RECOVERY_SECONDS,
            time.monotonic() + permission["expiresAt"] - time.time(),
        )
        if args.approval_wait_seconds is not None:
            deadline = min(deadline, time.monotonic() + args.approval_wait_seconds)
        paths = {
            name: args.observation_directory / (name + ".json")
            for name in ("inputs", "permission", "approval", "manifest")
        }
        while not all(path.exists() for path in paths.values()):
            remaining = min(
                deadline - time.monotonic(),
                preparation.proof["reservationDeadline"]
                - RECOVERY_SECONDS
                - time.time(),
            )
            if remaining <= 0:
                raise ValueError("independent observation approval timeout")
            time.sleep(min(0.1, remaining))
        observation_inputs = admission._read(paths["inputs"])
        observation_permission = admission._read(paths["permission"])
        capability = issue(
            observation_inputs,
            observation_permission,
            paths["approval"],
            paths["manifest"],
            admission.issue_production_capability,
        )
        result = production.execute_reserved(
            capability=capability,
            inputs=observation_inputs,
            permission=observation_permission,
            preparation=preparation,
            preparation_inputs=inputs,
            source_root=args.source,
            ledger_root=args.ledger,
            output=args.output,
        )
        print(
            json.dumps(
                {
                    "chargedCalls": result["chargedCalls"],
                    "reservationReleased": result["reservationReleased"],
                    "failure": result["failure"],
                }
            )
        )
        return 0 if result["reservationReleased"] else 2
    except Exception as error:  # noqa: BLE001 -- publish a bounded class, never credential-bearing exception text.
        if preparation is not None and not (args.output / "receipt.json").exists():
            publish_approval_stop(
                preparation,
                inputs=inputs,
                output=args.output,
                reason=type(error).__name__,
            )
        print(
            json.dumps({"failure": type(error).__name__, "reservationReleased": False})
        )
        return 2
    finally:
        if capability is not None:
            admission.revoke_production_capability(capability)
        if preparation is not None:
            preparation.prepared.clear()


if __name__ == "__main__":
    raise SystemExit(main())
