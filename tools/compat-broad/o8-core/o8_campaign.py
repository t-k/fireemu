"""Campaign descriptor for the generic O8 admission and execution core.

A descriptor is a value object, not an authority. It names the schema kinds,
window, source map, plan compiler, budget, lock scopes, collector, comparator,
cost model and transport a single campaign executes under. Authority still comes
from the independently supplied owner permission, the private credential handoff
and the shared Ledger reservation.

The security value of the descriptor is that a campaign's bindings are declared
in one hard-coded place, and that construction refuses an incomplete one: a lane
cannot reach production while silently missing a member the admission checks
depend on.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# The 16 approval bindings every O8 campaign carries. A campaign-generic
# approval adds `campaignId`; the Commit lane keeps the original 16-key schema
# because its campaign identity is already bound through the frozen plan.
BASE_APPROVAL_FIELDS = frozenset(
    {
        "kind",
        "status",
        "manifestSha256",
        "inputsDigest",
        "permissionDigest",
        "sourceCommit",
        "sourceInputsDigest",
        "artifactSha256",
        "planDigest",
        "nonceDigest",
        "ledgerRoot",
        "launcherSha256",
        "artifactProfile",
        "windowStartsAt",
        "windowExpiresAt",
        "executionHost",
    }
)
CAMPAIGN_APPROVAL_FIELDS = BASE_APPROVAL_FIELDS | {"campaignId"}

_TEXT_MEMBERS = (
    "campaign_id",
    "frozen_inputs_kind",
    "permission_kind",
    "approval_kind",
    "manifest_kind",
    "artifact_profile",
)
_CALLABLE_MEMBERS = (
    "source_map",
    "plan_compiler",
    "lock_scopes",
    "collector",
    "comparator",
    "cost_model",
    "permission_bindings",
    "transport_bound",
    "binding_verifier",
    "retained_artifact_validator",
    "forbidden_transports",
)
_MAPPING_MEMBERS = ("frozen_bounds", "budget")
_SEQUENCE_MEMBERS = ("abort_closure_sources", "required_source_entries")
_WINDOW_MEMBERS = ("campaign_seconds", "recovery_seconds")
REQUIRED_MEMBERS = (
    *_TEXT_MEMBERS,
    *_CALLABLE_MEMBERS,
    *_MAPPING_MEMBERS,
    *_SEQUENCE_MEMBERS,
    *_WINDOW_MEMBERS,
    "approval_fields",
)


def _text(value: object, *, member: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"campaign descriptor member {member} required")
    return value


def _entries(value: object, *, member: str) -> tuple[str, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, str)
        or not value
        or any(not isinstance(entry, str) or not entry for entry in value)
    ):
        raise ValueError(f"campaign descriptor member {member} required")
    return tuple(value)


class CampaignDescriptor:
    """One campaign's complete, immutable O8 binding set."""

    __slots__ = (*REQUIRED_MEMBERS, "_frozen")

    def __init__(self, **members: object) -> None:
        object.__setattr__(self, "_frozen", False)
        missing = [name for name in REQUIRED_MEMBERS if members.get(name) is None]
        unknown = sorted(set(members) - set(REQUIRED_MEMBERS))
        if missing or unknown:
            raise ValueError(
                "campaign descriptor requires every member: missing "
                f"{sorted(missing)}, unknown {unknown}"
            )
        for name in _TEXT_MEMBERS:
            object.__setattr__(self, name, _text(members[name], member=name))
        for name in _CALLABLE_MEMBERS:
            if not callable(members[name]):
                raise ValueError(  # noqa: TRY004 -- refusal class, not a type report
                    f"campaign descriptor member {name} must be callable"
                )
            object.__setattr__(self, name, members[name])
        for name in _MAPPING_MEMBERS:
            value = members[name]
            if not isinstance(value, Mapping) or not value:
                raise ValueError(f"campaign descriptor member {name} required")
            object.__setattr__(self, name, dict(value))
        for name in _SEQUENCE_MEMBERS:
            object.__setattr__(self, name, _entries(members[name], member=name))
        for name in _WINDOW_MEMBERS:
            value = members[name]
            if type(value) is not int or value <= 0:
                raise ValueError(f"campaign descriptor member {name} required")
            object.__setattr__(self, name, value)
        fields = members["approval_fields"]
        if not isinstance(fields, (set, frozenset)) or not (
            BASE_APPROVAL_FIELDS <= set(fields) <= CAMPAIGN_APPROVAL_FIELDS
        ):
            raise ValueError("campaign descriptor member approval_fields required")
        object.__setattr__(self, "approval_fields", frozenset(fields))
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("a campaign descriptor is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("a campaign descriptor is immutable")

    def __repr__(self) -> str:
        return f"<CampaignDescriptor campaign={self.campaign_id!r}>"

    @property
    def window_seconds(self) -> int:
        """The approval window a campaign needs: its wall budget plus recovery.

        A window sized to the wall budget alone admits a run that cannot finish
        its recovery allocation inside the time the owner approved.
        """
        return self.campaign_seconds + self.recovery_seconds

    @property
    def binds_campaign_id(self) -> bool:
        """Whether this campaign's approval schema carries `campaignId`."""
        return "campaignId" in self.approval_fields

    def members(self) -> dict[str, object]:
        """The descriptor's members, so a variant can be built explicitly."""
        return {name: getattr(self, name) for name in REQUIRED_MEMBERS}
