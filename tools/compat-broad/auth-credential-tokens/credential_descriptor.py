"""Campaign descriptor for the AUTH-CREDENTIAL token and session-cookie observation.

This module declares, in one hard-coded place, every binding the shared O8
admission core checks for `AUTH-CREDENTIAL-TOKENS-01`: the schema kinds, the window,
the source map, the plan compiler, the budget, the Ledger lock scopes, the collector
and comparator the campaign runs, the cost model, the abort closure, and the
integrity binding of the worker that performs the HTTPS exchange.

It authorizes nothing. The case runner, the collector, the comparator and the remote
transport are used exactly as they are; the members below adapt the core's calls to
their signatures.

The plan this campaign freezes is a reference to the shared-Gate plan `credential_gate`
compiles from the nonce and the signing capability. Without signing the eleven
signing-dependent cases are not in the plan at all; the run records them as not run,
never as observed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import credential_gate as gate_module
import credential_preflight as preflight
import credential_remote_transport as remote
from batch_contract import NUMBER, PROJECT
from broad_contract import digest
from credential_cases import CAMPAIGN_ID, CASE_COUNT, SIGNING_DEPENDENT_CASE_COUNT
from credential_comparator import CONTRACT, compare
from credential_plan import BUDGET, COST_BASIS, cases_digest
from credential_shadow import cleanup, collect, run_cases
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

CAMPAIGN = CAMPAIGN_ID
_NONCE = re.compile(r"^[0-9a-f]{32}$")
FROZEN_INPUTS_KIND = "auth-credential-frozen-inputs-v1"
PERMISSION_KIND = "auth-credential-owner-execution-permission-v1"
APPROVAL_KIND = "auth-credential-o8-approval-v1"
MANIFEST_KIND = "auth-credential-o8-manifest-v1"
RECEIPT_KIND = "auth-credential-acquisition-receipt-v1"
PREPARATION_FROZEN_INPUTS_KIND = "auth-credential-bootstrap-frozen-inputs-v1"
PREPARATION_PERMISSION_KIND = "auth-credential-bootstrap-permission-v1"
PREPARATION_APPROVAL_KIND = "auth-credential-bootstrap-approval-v1"
PREPARATION_MANIFEST_KIND = "auth-credential-bootstrap-manifest-v1"
SHADOW_RECORD = "spec/compatibility/broad-runs/auth-credential-tokens-local-shadow-20260923-lookup-v2.json"
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
SERVICE_ACCOUNT = "fireemu-oracle@fireemu-35fe6.iam.gserviceaccount.com"
SIGNING_PERMISSION = "iam.serviceAccounts.signBlob"
SIGNING_ROLE = "roles/iam.serviceAccountTokenCreator"
MAX_ACCOUNTS = 4

LANE_DIRECTORY = "tools/compat-broad/auth-credential-tokens"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/credential_shadow.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/credential_comparator.py"
WORKER_ENTRY = f"{LANE_DIRECTORY}/{remote.WORKER_ENTRY}"
TRANSPORT_ENTRY = f"{LANE_DIRECTORY}/credential_remote_transport.py"
GATE_ENTRY = f"{LANE_DIRECTORY}/credential_gate.py"
PREFLIGHT_ENTRY = f"{LANE_DIRECTORY}/credential_preflight.py"
SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    preflight.SHARED_PREFLIGHT_MODULE,
)
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    f"{LANE_DIRECTORY}/credential_admission.py",
    f"{LANE_DIRECTORY}/credential_descriptor.py",
)
MINIMUM_WINDOW_SECONDS = 600


def shadow_record() -> dict:
    """The published local shadow this campaign's production run is compared to."""
    path = ROOT / SHADOW_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published local shadow record required")
    value = json.loads(path.read_bytes())
    binding = (
        value.get("receipt", {}).get("sourceBinding")
        if isinstance(value, dict) and isinstance(value.get("receipt"), dict)
        else None
    )
    if (
        not isinstance(binding, dict)
        or value.get("campaignId") != CAMPAIGN
        or value.get("kind") != "local-shadow"
        or not isinstance(binding.get("commit"), str)
        or len(binding["commit"]) != 40
        or not isinstance(binding.get("artifactSha256"), str)
    ):
        raise ValueError("published local shadow record required")
    return value


ARTIFACT_PROFILE_BASIS = {
    "kind": "auth-credential-artifact-profile-v1",
    "registry": "none",
    "derivedFrom": "the published local shadow record's receipt.sourceBinding.commit",
    "establishes": (
        "which build the comparison reference was produced by, and that the "
        "retained bytes hash to the digest the approval binds"
    ),
    "doesNotEstablish": (
        "that the build was reviewed; no profile registry entry exists for this "
        "lane and O7 must accept the profile explicitly"
    ),
    "ownerAcceptanceRequired": True,
}


def artifact_profile() -> str:
    return (
        "auth-credential-" + shadow_record()["receipt"]["sourceBinding"]["commit"][:9]
    )


def artifact_profile_basis() -> dict:
    binding = shadow_record()["receipt"]["sourceBinding"]
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": binding["commit"],
        "shadowArtifactSha256": binding["artifactSha256"],
    }


def campaign_seconds() -> int:
    return int(BUDGET["maxWallSeconds"])


def recovery_seconds() -> int:
    return int(BUDGET["recoveryWallSeconds"])


def observation_window_seconds() -> int:
    return int(BUDGET["observationWallSeconds"])


def transport_deadline_seconds() -> float:
    """The per-request wire ceiling the Gate reserves per data slot."""
    return float(gate_module.DATA_SLOT_SECONDS)


def budget() -> dict:
    """The lane's published budget, unmodified."""
    return copy.deepcopy(BUDGET)


def ledger_budget() -> dict:
    """The four Ledger dimensions this campaign claims.

    `requests` is the bound the campaign is approved against, sixty, which covers
    the forty-two data slots plus the management slots of a signing run. `accounts`
    is the campaign's account ceiling. `resources` counts the Gate's resources, the
    two cleanup routes. The cost is the published runaway guard, not a forecast:
    Identity Platform bills active users, not requests, and these accounts are
    deleted within the run.
    """
    return {
        "requests": int(BUDGET["maxRequests"]),
        "accounts": MAX_ACCOUNTS,
        "resources": MAX_ACCOUNTS,
        "costMicrousd": math.ceil(BUDGET["maxCostUsd"] * 1_000_000),
    }


def cost_model() -> dict:
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": 0,
        "maximumCostMicrousd": math.ceil(BUDGET["maxCostUsd"] * 1_000_000),
        "hardCeilingMicrousd": math.ceil(BUDGET["maxCostUsd"] * 1_000_000),
        "totalCostMicrousd": ledger_budget()["costMicrousd"],
        "requests": int(BUDGET["maxRequests"]),
        "basis": list(COST_BASIS),
    }


def frozen_bounds() -> dict:
    """The bounded shape of one run, every figure taken from the published budget."""
    signing = gate_module.gate_plan(
        PROJECT,
        "0" * 32,
        signing=True,
        wall_seconds=campaign_seconds(),
        recovery_seconds=recovery_seconds(),
        cost_microusd=ledger_budget()["costMicrousd"],
        observation_window_seconds=observation_window_seconds(),
    )
    return {
        "totalRequests": int(BUDGET["maxRequests"]),
        "recoveryRequests": int(BUDGET["recoveryRequests"]),
        "dataRequests": signing["dataRequests"],
        "managementRequests": signing["managementRequests"],
        "observationRequests": len(signing["jobs"][gate_module.JOB]["observation"]),
        "cleanupRequests": len(signing["jobs"][gate_module.JOB]["recovery"]),
        "maxAccounts": MAX_ACCOUNTS,
        "createdAccounts": len(gate_module.planned_accounts(True)),
        "caseCount": CASE_COUNT,
        "signingDependentCases": SIGNING_DEPENDENT_CASE_COUNT,
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
        "maxWallSeconds": campaign_seconds(),
        "recoveryWallSeconds": recovery_seconds(),
        "observationWallSeconds": observation_window_seconds(),
    }


def compile_gate_plan(nonce: str, *, signing: bool) -> dict:
    return gate_module.gate_plan(
        PROJECT,
        nonce,
        signing=signing,
        wall_seconds=campaign_seconds(),
        recovery_seconds=recovery_seconds(),
        cost_microusd=ledger_budget()["costMicrousd"],
        observation_window_seconds=observation_window_seconds(),
    )


def _ops_digest(plan: dict) -> str:
    job = plan["jobs"][gate_module.JOB]
    payload = json.dumps(
        {"observation": job["observation"], "recovery": job["recovery"]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def plan_compiler(nonce: str, *, signing: bool) -> dict:
    """The plan as the admission sees it: a reference derived from the nonce.

    Every field here is derived from the nonce and the signing flag by the reviewed
    plan compiler, so the reference names exactly one Gate plan and an executor can
    rebuild it. Without signing, the signing-dependent cases are absent from the
    plan rather than present and skipped.
    """
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("a 32-character hexadecimal nonce is required")
    if type(signing) is not bool:
        raise ValueError("signing capability must be declared")
    plan = compile_gate_plan(nonce, signing=signing)
    return {
        "schemaVersion": gate_module.SCHEMA_VERSION,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "nonce": nonce,
        "signing": signing,
        "planDigest": _ops_digest(plan),
        "gatePlanShapeDigest": digest(
            {key: value for key, value in plan.items() if key != "jobs"}
        ),
        "casesSha256": cases_digest(),
        "runnableCases": gate_module.runnable_case_ids(signing),
        "plannedAccounts": list(gate_module.planned_accounts(signing)),
        "accountResources": plan["accountResources"],
        "bounds": {
            "observationRequests": len(plan["jobs"][gate_module.JOB]["observation"]),
            "cleanupRequests": len(plan["jobs"][gate_module.JOB]["recovery"]),
            "managementRequests": len(preflight.management_ids(signing)["observation"])
            + len(preflight.management_ids(signing)["recovery"]),
        },
    }


def execution_plan(reference: dict) -> dict:
    """Recompile the Gate plan a frozen reference names, and refuse any other."""
    nonce = reference.get("nonce") if isinstance(reference, dict) else None
    signing = reference.get("signing") if isinstance(reference, dict) else None
    if (
        not isinstance(nonce, str)
        or _NONCE.fullmatch(nonce) is None
        or type(signing) is not bool
    ):
        raise ValueError("frozen credential plan reference required")
    canonical = plan_compiler(nonce, signing=signing)
    if digest(reference) != digest(canonical):
        raise ValueError("frozen credential plan reference differs")
    return compile_gate_plan(nonce, signing=signing)


def lock_scopes(plan: dict) -> list[dict]:
    """The owned accounts, the read scopes a preflight observes, and the signer.

    The account namespace is held as a whole because the Gate's cleanup routes act
    on it, and each owned account is named under it so the claim says exactly which
    accounts the run may create and delete.
    """
    nonce = plan["nonce"]
    scope = f"project/{PROJECT}"
    locks = [{"key": f"{scope}/auth/accounts/*", "mode": "WRITE"}]
    locks += [
        {
            "key": f"{scope}/auth/accounts/{gate_module.account_identifier(nonce, account)}",
            "mode": "WRITE",
        }
        for account in gate_module.planned_accounts(plan["signing"])
    ]
    locks += [
        {"key": f"{scope}/identity", "mode": "READ"},
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]
    if plan["signing"]:
        locks.append(
            {
                "key": f"{scope}/iam/serviceAccounts/{SERVICE_ACCOUNT}/signBlob",
                "mode": "READ",
            }
        )
    return locks


def lane_sources() -> tuple[str, ...]:
    directory = ROOT / LANE_DIRECTORY
    return tuple(
        sorted(f"{LANE_DIRECTORY}/{path.name}" for path in directory.glob("*.py"))
    )


def source_map() -> dict[str, str]:
    """Digest every source this campaign binds: the whole lane, plus the closure."""
    values = {}
    for name in (*lane_sources(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def management_contract(signing: bool) -> dict:
    ids = preflight.management_ids(signing)
    return {
        "version": "auth-credential-preflight-v1",
        "dispatchKind": "closed-v1",
        "observation": list(ids["observation"]),
        "recovery": list(ids["recovery"]),
        "credentialIds": ["oauth-tokeninfo"],
        "credentialSlots": ["tokeninfo"],
        "slotSeconds": gate_module.MANAGEMENT_SLOT_SECONDS,
        "durationSeconds": gate_module.MANAGEMENT_DURATION_SECONDS,
        "intervalSeconds": gate_module.GATE_INTERVAL_SECONDS,
        "totalRequests": len(ids["observation"]) + len(ids["recovery"]),
        "configTouched": False,
        "principal": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "claims": [
                "issued_to",
                "audience",
                "user_id",
                "email",
                "verified_email",
                "scope",
                "expires_in",
            ],
        },
    }


def signing_contract(signing: bool) -> dict:
    """What a signing run needs of the owner, stated where O7 reads it."""
    return {
        "required": signing,
        "serviceAccount": SERVICE_ACCOUNT,
        "mechanism": "iamcredentials.googleapis.com signBlob; no key is fetched or stored",
        "iamPermission": SIGNING_PERMISSION,
        "roleOnServiceAccount": SIGNING_ROLE,
        "principal": "the bearer named by credentialPrincipal",
        "casesWithout": CASE_COUNT - SIGNING_DEPENDENT_CASE_COUNT,
        "casesNotRunWithout": SIGNING_DEPENDENT_CASE_COUNT,
    }


def collector(gate, plan, output, *, transmit):
    """Drive the case runner and the cleanup through the facade's poster.

    The driver lives in `credential_production`; this member names it so the
    descriptor's collector is the one the production execution actually runs.
    """
    import credential_production

    return credential_production.collect_hosted(gate, plan, output, transmit=transmit)


def comparator(result, shadow=None):
    """Compare a production receipt with the published local shadow's receipt.

    The published shadow is the reference this campaign is bound to. The comparison
    is the lane's own contract; it classifies rows and never claims parity.
    """
    published = shadow_record() if shadow is None else shadow
    report = compare(published["receipt"], result)
    return {
        "campaignId": CAMPAIGN,
        "contract": CONTRACT,
        "report": report,
        "shadowRecordDigest": digest(published),
        "formalCompatibilityClaim": False,
    }


def transport_bound(
    value,
    *,
    binding,
    binding_digest,
    capability=None,
    fixture_origin=None,
    modern_management=False,
):
    """Adapt one bound wire call to the reviewed transport's own signature.

    Three closed shapes reach the wire: a shared management slot (tokeninfo, project
    or Auth config, sent by the request-byte lane's reviewed management transport), a
    signing slot, and a data slot carrying the frozen Gate operation and its
    run-time body. Every one re-checks the worker binding and the capability.
    """
    if not isinstance(value, dict) or capability is None:
        raise ValueError("closed credential wire call required")
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    remote.verify_worker_binding(binding, binding_digest, None)
    kind = value.get("kind")
    if kind == "management":
        if set(value) != {"kind", "phase", "slot", "token", "deadline"}:
            raise ValueError("closed management wire call required")
        if value["slot"] not in preflight.SHARED_SLOTS or value["phase"] not in (
            "observation",
            "recovery",
        ):
            raise ValueError("closed management slot required")
        if modern_management:
            return preflight.modern_management_transport(
                value["slot"],
                value["token"],
                deadline=value["deadline"],
                fixture_origin=fixture_origin,
            )
        return preflight.shared_preflight.management_transport(
            value["slot"],
            value["token"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
        )
    if kind == "sign":
        if set(value) != {"kind", "payload", "serviceAccount", "token", "deadline"}:
            raise ValueError("closed signing wire call required")
        if value["serviceAccount"] != SERVICE_ACCOUNT:
            raise ValueError("signing account differs from the campaign's")
        return remote.sign_custom_token(
            value["payload"],
            service_account=value["serviceAccount"],
            token=value["token"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
            **(
                {"fixture_origin": fixture_origin} if fixture_origin is not None else {}
            ),
        )
    if kind == "data":
        if set(value) != {"kind", "declared", "body", "token", "apiKey", "deadline"}:
            raise ValueError("closed data wire call required")
        return remote.transmit(
            value["declared"],
            value["body"],
            token=value["token"],
            api_key=value["apiKey"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
            **(
                {"fixture_origin": fixture_origin} if fixture_origin is not None else {}
            ),
        )
    raise ValueError("closed credential wire call required")


def retained_artifact_validator(artifact_path, manifest_path, profile):
    """Bind the retained artifact and manifest by digest; the profile is a label."""
    if profile != artifact_profile():
        raise ValueError("retained artifact profile differs")
    values = {}
    for key, path in (
        ("artifactSha256", artifact_path),
        ("retainedManifestSha256", manifest_path),
    ):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("retained regular artifact required")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def forbidden_transports():
    """Objects an injected preparation transport must not be able to reach."""
    return (
        remote,
        remote.request,
        remote.transmit,
        remote.sign_custom_token,
        preflight.shared_preflight.management_transport,
        transport_bound,
    )


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    """Required non-authorizing fields for an independently supplied permission."""
    canonical = plan_compiler(plan["nonce"], signing=plan["signing"])
    if digest(plan) != digest(canonical):
        raise ValueError("fixed production project and plan reference required")
    if baseline is not None:
        raise ValueError("this campaign carries no derived Firestore baseline")
    return {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "nonce": plan["nonce"],
        "signing": plan["signing"],
        "planDigest": plan["planDigest"],
        "casesSha256": plan["casesSha256"],
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "workerSha256": inputs[WORKER_ENTRY],
        "transportSha256": inputs[TRANSPORT_ENTRY],
        "gateSha256": inputs[GATE_ENTRY],
        "comparisonContract": CONTRACT,
        "budget": budget(),
        "ledgerBudget": ledger_budget(),
        "ownedAccounts": [
            gate_module.account_identifier(plan["nonce"], account)
            for account in plan["plannedAccounts"]
        ],
        "accountResources": list(plan["accountResources"]),
        "runnableCases": list(plan["runnableCases"]),
        "wallSeconds": campaign_seconds(),
        "campaignSeconds": campaign_seconds(),
        "recoverySeconds": recovery_seconds(),
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
        "concurrency": 1,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "costModel": cost_model(),
        "artifactProfileBasis": artifact_profile_basis(),
        "credentialPrincipalContract": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "requiredScopes": [PRINCIPAL_SCOPE],
            "identitySource": "owner-frozen permission; never inferred from tokeninfo",
        },
        "managementContract": management_contract(plan["signing"]),
        "signingContract": signing_contract(plan["signing"]),
        "configTouched": False,
        "productionPreflight": {
            "version": "auth-credential-preflight-v1",
            "managementRequests": plan["bounds"]["managementRequests"],
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "source": PREFLIGHT_ENTRY,
        },
    }


def descriptor() -> CampaignDescriptor:
    """The credential campaign as the shared admission core sees it."""
    if campaign_seconds() + recovery_seconds() < MINIMUM_WINDOW_SECONDS:
        raise ValueError("approved window below the campaign minimum")
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=artifact_profile(),
        campaign_seconds=campaign_seconds(),
        recovery_seconds=recovery_seconds(),
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(
            COLLECTOR_ENTRY,
            COMPARATOR_ENTRY,
            WORKER_ENTRY,
            TRANSPORT_ENTRY,
            GATE_ENTRY,
        ),
        frozen_bounds=frozen_bounds(),
        budget=budget(),
        plan_compiler=plan_compiler,
        lock_scopes=lock_scopes,
        collector=collector,
        comparator=comparator,
        cost_model=cost_model,
        permission_bindings=permission_bindings,
        transport_bound=transport_bound,
        binding_verifier=remote.verify_worker_binding,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )


def preparation_descriptor() -> CampaignDescriptor:
    """The independent four-request preparation descriptor variant."""
    members = descriptor().members()
    members.update(
        frozen_inputs_kind=PREPARATION_FROZEN_INPUTS_KIND,
        permission_kind=PREPARATION_PERMISSION_KIND,
        approval_kind=PREPARATION_APPROVAL_KIND,
        manifest_kind=PREPARATION_MANIFEST_KIND,
        permission_bindings=preparation_permission_bindings,
        transport_bound=preparation_transport_bound,
    )
    return CampaignDescriptor(**members)


def preparation_permission_bindings(
    plan, source_commit, artifact_digest, inputs, baseline=None
):
    """Bindings for prep authority; no Auth baseline is invented pre-wire."""
    bindings = permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )
    combined = gate_module.bootstrap_plan(
        execution_plan(plan), permission_digest="0" * 64
    )
    return {
        **bindings,
        "kind": PREPARATION_PERMISSION_KIND,
        "preparationPlanDigest": gate_module.bootstrap_plan_digest(combined),
        "preparationOperations": combined["management"]["observation"][:4],
        "preparationRequests": 4,
        "combinedRequestCeiling": 60,
        "combinedCostMicrousd": ledger_budget()["costMicrousd"],
        "combinedWallSeconds": campaign_seconds(),
        "observationAuthority": "separate-owner-permission-and-O7-required",
    }


def preparation_transport_bound(
    value, *, capability, binding, binding_digest, fixture_origin=None
):
    """Only the four preparation slots can pass this admitted transport."""
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    remote.verify_worker_binding(binding, binding_digest, None)
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "slot", "secret", "deadline", "fixtureOrigin"}
        or value["kind"] != "preparation"
        or value["slot"] not in gate_module.bootstrap_management_ids()
    ):
        raise ValueError("closed preparation wire call required")
    if value["fixtureOrigin"] != fixture_origin:
        raise ValueError("approved preparation origin differs")
    import credential_bootstrap

    return credential_bootstrap._request(
        value["slot"],
        value["secret"],
        deadline=value["deadline"],
        fixture_origin=value["fixtureOrigin"],
    )


__all__ = [
    "CAMPAIGN",
    "SERVICE_ACCOUNT",
    "SIGNING_PERMISSION",
    "SIGNING_ROLE",
    "cleanup",
    "collect",
    "compile_gate_plan",
    "descriptor",
    "execution_plan",
    "ledger_budget",
    "lock_scopes",
    "permission_bindings",
    "plan_compiler",
    "preparation_descriptor",
    "preparation_permission_bindings",
    "preparation_transport_bound",
    "run_cases",
    "source_map",
    "transport_bound",
]
