# Campaign-generic O8 admission and execution core

This directory holds the parts of the O8 boundary that are not specific to one
broad-compatibility campaign: the frozen-input record, the complete O7 admission
check set, the one-shot production wire capability and the campaign descriptor
that names everything a campaign brings of its own.

It grants no authority and has no command line. Authority for a production run
remains what it was: an independently supplied owner permission, a private
credential handoff on a file descriptor, and a reservation in the shared Ledger.

## Files

| File | Role |
| --- | --- |
| `o8_campaign.py` | `CampaignDescriptor`, an immutable value object; construction refuses a descriptor missing any required member |
| `o8_admission.py` | `freeze_inputs`, `validate_frozen_inputs`, `validate_o7_admission`, `issue_production_capability`, `ProductionWireCapability`, `abort_generation`, `reject_production_transport` |
| `o4_partition_cursor_descriptor.py` | Preparation-only proof that a second campaign fits. Not wired to production; see below |

## What a campaign supplies

A descriptor declares its schema kinds (`frozen_inputs_kind`, `permission_kind`,
`approval_kind`, `manifest_kind`), its reviewed `artifact_profile`, its window
(`campaign_seconds`, `recovery_seconds`), its `approval_fields`, its
`source_map`, its `abort_closure_sources` and `required_source_entries`, its
`frozen_bounds` and `budget`, and the callables it executes through:
`plan_compiler`, `lock_scopes`, `collector`, `comparator`, `cost_model`,
`permission_bindings`, `transport_bound`, `archive_verifier`,
`retained_artifact_validator` and `forbidden_transports`.

Every one of those is required. A descriptor built without one is refused at
construction rather than at the moment an admission check would have needed it.

## Invariants the core keeps

- `validate_o7_admission` is the single definition of "the O7 checks passed". A
  lane's CLI and `issue_production_capability` call exactly this function, so a
  capability can never be issued on a weaker check set than the CLI enforces.
- The approval is bound to the launcher that is actually running, to the
  resolved shared Ledger root, to the execution host, and to a window that must
  contain the whole campaign.
- The capability is one-shot, is not constructible, copyable or serializable,
  and is admitted by object identity in a private registry rather than by shape.
  It is spent before any file, Ledger or wire is touched, and a failed run
  revokes it.
- A campaign's frozen inputs must name its collector and comparator, and the
  frozen plan must declare the descriptor's own campaign. One campaign's
  descriptor cannot admit another campaign's approval.
- The saved-evidence comparison is bound to an execution kind, so a directory
  produced by an injected local transport fails closed and cannot be mistaken
  for production evidence.

## Approval schema

`BASE_APPROVAL_FIELDS` is the 16-key schema. `CAMPAIGN_APPROVAL_FIELDS` adds
`campaignId` for campaigns whose approval carries its identity explicitly. The
Commit lane keeps the 16-key schema, because its campaign identity is bound
through the frozen plan and its existing O7 artifacts are issued against it; the
core checks the plan's campaign against the descriptor either way.

## Clients

- `tools/compat-broad/fs-commit-transform-limits/commit_acquisition.py` declares
  the `COMMIT` descriptor and is the core's first client.
- `o4_partition_cursor_descriptor.py` is a proof only. It reads the O4 lane's
  modules and modifies nothing. The members that would let it reach production
  (retained artifact profile, bound transport, worker archive closure, collector
  and comparator) have no working default: each refuses when called, so the
  descriptor can freeze inputs and pass the O7 check set against a synthetic
  approval and can do nothing else. The O4 lane's own admission stays closed.

## Tests

```
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/o8-core
```

No test here uses a credential, a network origin, a production project or the
canonical Ledger.
