"""Four-request, keyless Auth credential bootstrap.

This module is preparation only. It does not issue O7, reserve the canonical
Ledger, or approve the observation campaign. The caller must supply an
independently approved preparation permission and a private authorized-user
descriptor; secrets stay in memory and the returned handoff is for a later
observation permission whose digest is not created here.
"""

from __future__ import annotations

import copy
import hashlib
import math
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "fs-write-txn"))

from broad_contract import digest
import credential_remote_transport as remote
import credential_gate as gate_module

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
            any(type(value) is not int for value in (self.max_requests, self.max_seconds, self.cost_microusd))
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


def validate_deadline(seconds: float) -> None:
    if type(seconds) not in (int, float) or isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= PREP_REQUEST_SECONDS:
        raise ValueError("bootstrap deadline must cover four bounded requests")


def _validate_permission(permission: dict, adc: dict) -> None:
    if not isinstance(permission, dict) or permission.get("kind") != PERMISSION_KIND:
        raise ValueError("bootstrap permission required")
    principal = permission.get("credentialPrincipal")
    import credential_preflight
    credential_preflight.validate_principal(principal)
    if not isinstance(principal["clientId"], str) or not principal["clientId"] or principal["requiredScopes"] != [SCOPE]:
        raise ValueError("bootstrap principal required")
    if principal["clientId"] != adc.get("client_id"):
        raise ValueError("bootstrap principal differs")
    if permission.get("project") != PROJECT or permission.get("projectNumber") != PROJECT_NUMBER:
        raise ValueError("bootstrap project differs")
    if not isinstance(permission.get("nonce"), str) or len(permission["nonce"]) != 32:
        raise ValueError("bootstrap nonce required")
    if permission.get("authorizedUserDigest") != digest(adc):
        raise ValueError("authorized-user binding differs")


def _validate_handoff_input(permission: dict, adc: dict) -> None:
    if not isinstance(adc, dict) or set(adc) != ADC_FIELDS or adc.get("type") != "authorized_user":
        raise ValueError("private bootstrap input required")
    if permission.get("authorizedUserDigest") != digest(adc):
        raise ValueError("private bootstrap input required")


def _origin_url(host: str, path: str, fixture_origin: str | None) -> str:
    return (fixture_origin + "/" if fixture_origin is not None else "https://") + host + path


def _request(slot: str, secret, *, fixture_origin: str | None, deadline: float | None = None):
    slot = {"bootstrap-refresh": "refresh", "bootstrap-tokeninfo": "tokeninfo", "bootstrap-project": "project", "bootstrap-auth-config": "auth"}.get(slot, slot)
    if slot not in {"refresh", "tokeninfo", "project", "auth"}:
        raise ValueError("closed bootstrap slot required")
    if deadline is not None and (not math.isfinite(deadline) or deadline <= time.monotonic()):
        raise ValueError("bootstrap deadline already expired")
    seconds = PREP_REQUEST_SECONDS if deadline is None else min(
        PREP_REQUEST_SECONDS, deadline - time.monotonic()
    )
    if slot == "refresh":
        return remote.request_with_lifecycle(
            _origin_url("oauth2.googleapis.com", "/token", fixture_origin),
            {"grant_type": "refresh_token", "client_id": secret["client_id"], "client_secret": secret["client_secret"], "refresh_token": secret["refresh_token"]},
            headers={}, seconds=seconds, form=True, fixture_origin=fixture_origin,
        )
    if slot == "tokeninfo":
        return remote.request_with_lifecycle(
            _origin_url("oauth2.googleapis.com", "/tokeninfo?access_token=" + secret, fixture_origin),
            None, headers={}, seconds=seconds, fixture_origin=fixture_origin,
        )
    if slot == "project":
        return remote.request_with_lifecycle(
            _origin_url("cloudresourcemanager.googleapis.com", "/v1/projects/" + PROJECT, fixture_origin),
            None,
            headers={"Authorization": "Bearer " + secret, "x-goog-user-project": PROJECT},
            seconds=seconds,
            fixture_origin=fixture_origin,
        )
    return remote.request_with_lifecycle(
        _origin_url("identitytoolkit.googleapis.com", "/admin/v2/projects/" + PROJECT + "/config", fixture_origin),
        None,
        headers={"Authorization": "Bearer " + secret, "x-goog-user-project": PROJECT},
        seconds=seconds,
        fixture_origin=fixture_origin,
    )


def prepare(permission: dict, *, adc: dict, api_key: str, fixture_origin: str | None = None, budget: BootstrapBudget | None = None, gate=None, ledger=None, ticket=None, capability=None, source_root=None, inputs=None, absolute_deadline=None) -> BootstrapResult:
    """Run exactly refresh, tokeninfo, project and Auth-config operations.

    `fixture_origin` is test-only; production leaves it unset so the pinned
    transport enforces its reviewed HTTPS allowlist. This function intentionally
    returns private prepared values and typed proof, not a finalized handoff or O7 capability.
    """
    budget = budget or BootstrapBudget()
    budget.validate()
    validate_deadline(budget.max_seconds - RECOVERY_SECONDS)
    _validate_permission(permission, adc)
    _validate_handoff_input(permission, adc)
    import credential_admission as admission
    if not admission._private_string(api_key, 256) or any(not admission._private_string(adc[key], 8192) for key in ("client_id", "client_secret", "refresh_token")):
        raise ValueError("private Web API key required")
    if permission.get("apiKeyDigest") is not None and permission["apiKeyDigest"] != digest(api_key):
        raise ValueError("approved API key differs")
    if gate is None and fixture_origin is None:
        raise ValueError("production bootstrap Gate required")
    if gate is not None:
        snapshot = gate.snapshot()
        bootstrap = snapshot.get("plan", {}).get("bootstrap")
        if not isinstance(bootstrap, dict) or bootstrap.get("permissionDigest") != digest(permission):
            raise ValueError("bootstrap Gate permission binding differs")
        if tuple(bootstrap.get("operationIds", ())) != gate_module.bootstrap_management_ids():
            raise ValueError("bootstrap Gate operation binding differs")
        if snapshot.get("plan", {}).get("nonce") != permission["nonce"]:
            raise ValueError("bootstrap Gate nonce binding differs")
        before_events = len(snapshot.get("managementEvents", []))
    else:
        before_events = 0

    evidence = []

    def dispatch(slot: str, secret):
        request_slot = {
            "bootstrap-refresh": "refresh",
            "bootstrap-tokeninfo": "tokeninfo",
            "bootstrap-project": "project",
            "bootstrap-auth-config": "auth",
        }[slot]
        if gate is None:
            exchange = _request(request_slot, secret, fixture_origin=fixture_origin)
            return exchange.status, exchange.body

        private_response = []
        def send(deadline):
            if absolute_deadline is not None:
                deadline = min(deadline, absolute_deadline)
            if capability is not None:
                admission._provenance(source_root, inputs["sourceCommit"], inputs["sourceInputs"])
                if ledger.bound_claim(ticket)["gatePlanDigest"] != snapshot["planDigest"]:
                    raise ValueError("bootstrap reservation Gate differs")
                ledger.validate(ticket, duration=math.ceil(PREP_REQUEST_SECONDS + RECOVERY_SECONDS))
                exchange = capability._transmit({"kind": "preparation", "slot": slot, "secret": secret, "deadline": deadline, "fixtureOrigin": fixture_origin})
            else:
                exchange = _request(request_slot, secret, fixture_origin=fixture_origin, deadline=deadline)
            if type(exchange) is not remote.WorkerExchange:
                raise ValueError("typed worker lifecycle required")
            private_response.append((exchange.status, exchange.body))
            receipt = {"status": exchange.status, "complete": exchange.status == 200, "workerReaped": exchange.worker_reaped, "bodyKind": "json", "body": {"kind": "auth-bootstrap-attestation-v1", "slot": slot, "responseBodyDigest": digest(exchange.body)}}
            evidence.append({"id": "observation:" + slot, "receipt": receipt})
            return receipt

        gate.management_dispatch("observation", slot, send)
        return private_response[0]

    status, refresh = dispatch("bootstrap-refresh", adc)
    if status != 200 or not isinstance(refresh, dict) or not isinstance(refresh.get("access_token"), str):
        raise ValueError("OAuth refresh refused")
    token = refresh["access_token"]
    status, tokeninfo = dispatch("bootstrap-tokeninfo", token)
    if status != 200 or not isinstance(tokeninfo, dict):
        raise ValueError("tokeninfo refused")
    principal = permission["credentialPrincipal"]
    expires_in = tokeninfo.get("expires_in")
    if isinstance(expires_in, str) and expires_in.isdecimal():
        expires_in = int(expires_in)
    identity_matches = tokeninfo.get("sub") == principal["subject"] if "subject" in principal else tokeninfo.get("email") == principal["verifiedEmail"] and (tokeninfo.get("email_verified") is True or tokeninfo.get("email_verified") == "true")
    if tokeninfo.get("azp") != principal["clientId"] or tokeninfo.get("aud") != principal["clientId"] or not identity_matches or SCOPE not in str(tokeninfo.get("scope", "")).split() or type(expires_in) is not int or not TASK_MAX_SECONDS < expires_in <= 86400:
        raise ValueError("tokeninfo principal or lifetime differs")
    status, project = dispatch("bootstrap-project", token)
    if status != 200 or not isinstance(project, dict) or project.get("projectId") != PROJECT or project.get("projectNumber") != PROJECT_NUMBER:
        raise ValueError("project identity differs")
    status, auth = dispatch("bootstrap-auth-config", token)
    if status != 200 or not isinstance(auth, dict):
        raise ValueError("Auth config readback refused")
    prepared = {"token": token, "apiKey": api_key, "signing": {"serviceAccount": SERVICE_ACCOUNT}}
    proof = {"kind": "auth-credential-bootstrap-proof-v1", "permissionDigest": digest(permission), "nonce": permission["nonce"], "authorizedUserDigest": digest(adc), "principalDigest": digest(principal), "preparedDigest": digest(prepared), "apiKeyDigest": digest(api_key), "project": copy.deepcopy(project), "authConfigDigest": digest(auth), "tokeninfoExpiresInSeconds": expires_in, "requestCount": PREP_REQUESTS, "taskMaxRequests": TASK_MAX_REQUESTS, "taskMaxSeconds": TASK_MAX_SECONDS, "recoverySeconds": RECOVERY_SECONDS}
    if not isinstance(auth.get("name"), str) or auth.get("name") != "projects/592603257417/config":
        raise ValueError("Auth config project binding differs")
    if gate is not None:
        snapshot = gate.snapshot()
        used = snapshot.get("managementUsed", [])
        expected = ["observation:" + item for item in gate_module.bootstrap_management_ids()]
        events = snapshot.get("managementEvents", [])
        if used[:PREP_REQUESTS] != expected or len(events) - before_events != PREP_REQUESTS:
            raise ValueError("bootstrap Gate completion differs")
        proof["gatePlanDigest"] = snapshot["planDigest"]
        proof["managementJournalDigest"] = digest(events[before_events:])
        proof["managementEvidence"] = evidence
    charged_requests = PREP_REQUESTS if gate is None else len(snapshot.get("managementEvents", [])) - before_events
    return BootstrapResult(prepared, proof, charged_requests)


def execute_preparation(*, capability, inputs, permission, source_root, ledger_root, output, credential_reader, fixture_origin=None):
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
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh preparation output required")
    gate_plan = admission.preparation_gate_plan_for(inputs, permission)
    generation = o8_admission.abort_generation(campaign.preparation_descriptor(), inputs)
    gate_plan["collectorSourceDigest"] = generation["collectorSourceDigest"]
    claim = admission.reservation_claim(inputs, gate_path=output / "gate", gate_plan=gate_plan)
    capability._consume(campaign_id=campaign.CAMPAIGN, inputs_digest=inputs["inputsDigest"], ledger_root=ledger_root)
    ledger = reservations.Ledger(ledger_root)
    ticket = ledger.reserve(production._envelope(permission, claim), claim, gate_plan, generation=generation)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    absolute_deadline = time.monotonic() + row["deadline"] - time.time() - RECOVERY_SECONDS
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    gate_module.create(output / "gate", gate_plan)
    gate = gate_module.CredentialGate(output / "gate")
    gate.claim()
    try:
        private = credential_reader()
        result = prepare(permission, adc=private["adc"], api_key=private["apiKey"], gate=gate, ledger=ledger, ticket=ticket, capability=capability, source_root=source_root, inputs=inputs, absolute_deadline=absolute_deadline, fixture_origin=fixture_origin)
        proof = {**result.proof, "ticket": ticket, "claimDigest": digest(claim), "inputsDigest": inputs["inputsDigest"], "approvalDigest": capability.approval_digest, "generation": generation, "reservationDeadline": row["deadline"], "reservationStartedAt": row["deadline"] - claim["durationSeconds"]}
        production._write_record(output / "preparation-proof.json", proof, [*private["adc"].values(), private["apiKey"], result.prepared["token"]])
        return BootstrapResult(result.prepared, proof, result.charged_requests, ticket, gate)
    finally:
        admission.revoke_production_capability(capability)


def finalize_handoff(prepared: dict, observation_permission_digest: str, proof: dict) -> dict:
    """Bind the private prepared values only after observation permission exists."""
    if not isinstance(observation_permission_digest, str) or len(observation_permission_digest) != 64:
        raise ValueError("observation permission digest required")
    if not isinstance(prepared, dict) or set(prepared) != {"token", "apiKey", "signing"}:
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
    return {"kind": HANDOFF_KIND, "permissionDigest": observation_permission_digest, **copy.deepcopy(prepared)}


__all__ = ["BootstrapBudget", "BootstrapResult", "HANDOFF_KIND", "PERMISSION_KIND", "PREP_REQUESTS", "SCOPE", "SERVICE_ACCOUNT", "finalize_handoff", "prepare", "validate_deadline"]
