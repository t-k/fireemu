# AUTH-CREDENTIAL-TOKENS-01 preparation

Status: `PREPARATION`. `productionExecuted=false`. Nothing here holds a production receipt, and production-unobserved conditions reduced by this package: 0.

This lane prepares a bounded production observation of the `AUTH-CREDENTIAL` conditions that existing evidence explicitly excludes: refresh-token timestamp preservation, the same-second revocation boundary, session-cookie duration bounds and claim composition, custom-token developer and reserved claims, and ID-token claim precedence. The published [revision 2 session observations](../../../docs/compatibility/auth-session-v2.md) already cover password-change revocation at 0/10/30-second offsets and the malformed and unknown refresh controls; those rows appear here only as controls and are marked with the evidence that already covers them.

## Files

| File | What it holds |
| --- | --- |
| `credential_cases.py` | The 17 observation cases with their expected local results, boundary controls and prior-evidence references. Logical inputs only: no host, key or account identifier. |
| `credential_collector.py` | Redaction, subject comparison, owned-resource tracking, cleanup accounting, the reserved budget and receipt assembly. Imports no network client, so it cannot make a request. |
| `credential_comparator.py` | The `auth-credential-tokens-v1` comparison contract. Fail-closed, and it never claims parity. |
| `credential_plan.py` | The inert campaign manifest: frozen inputs, budget, permission envelope, owner preconditions, cleanup contract and failure rehearsal. |
| `credential_shadow.py` | The case runner and the local shadow. The runner takes an environment (project, API key, passwords, custom-token signer, endpoints) so a production transport drives the same code; the shadow owns a `fireemu` process, runs every case against it and records what the local runtime does. Local evidence only. |
| `credential_gate.py` | The shared-Gate plan (every request in order, with `$binding:` placeholders) and `CredentialGate`, the facade that resolves placeholders from this run's responses and records account creation and absence evidence. |
| `credential_descriptor.py` | The O8 `CampaignDescriptor`: kinds, window, budget, lock scopes, source map, plan compiler, permission bindings and the bound transport adapter. |
| `credential_admission.py` | Frozen inputs, provenance, the owner permission, the handoff shape and the Ledger claim. |
| `credential_preflight.py` | The charged management slots: bearer attestation, project and Auth-config readbacks, and the signBlob slots that mint the custom tokens. |
| `credential_remote_transport.py`, `credential_https_worker.py` | The digest-pinned HTTPS worker and the capability-bound transport (identitytoolkit, securetoken, iamcredentials only). |
| `credential_production.py` | One admitted execution: reserve, Gate, preflight, cases, cleanup, receipt, release. |
| `credential_o8.py` | The launcher. Exit 0 released, 1 held with a receipt, 2 refused before any wire call. |
| `credential_recovery_prepare.py` | The offline packet05 recovery preparer. It reads the held parent and Ledger, creates a fresh child nonce and review request, validates separately reviewed permission/O7/O8 documents, and never sends a request or mutates the Ledger. |
| `credential_recovery_runner.py` | The bounded commander-facing handoff runner. It revalidates a prepared packet, detached review evidence and fixed source closure, then emits a redacted no-network handoff without allocating or mutating the Ledger. |

## Offline packet05 recovery preparation

The recovery preparer is the commander-facing entrypoint for an unresolved
custom sign-in. It requires the held parent packet, source-bound provenance, and
the canonical shared Ledger. The output directory must be new and outside the
Ledger root; all files are mode `0600` in a mode `0700` directory.

```sh
uv run --python 3.12 python tools/compat-broad/auth-credential-tokens/credential_recovery_prepare.py \
  --parent /private/auth-packet05/parent.json \
  --provenance /private/auth-packet05/provenance.json \
  --source /private/auth-packet05/source-checkout \
  --ledger /private/auth-packet05/ledger \
  --permission /private/auth-packet05/reviewed/permission.json \
  --o7 /private/auth-packet05/reviewed/o7.json \
  --o8 /private/auth-packet05/reviewed/o8.json \
  --permission-review /private/auth-packet05/reviewed/permission-review.json \
  --o7-review /private/auth-packet05/reviewed/o7-review.json \
  --o8-review /private/auth-packet05/reviewed/o8-review.json \
  --output /private/auth-packet05/recovery-preparation
```

The command prints only a status line. It produces `plan.json`,
`permission.json`, `o7.json`, `o8.json`, `parent-evidence.json`,
`permission-review.json`, `o7-review.json`, `o8-review.json`,
`review-request.json`, and the same redacted bundle as `packet.json`. The
permission/O7/O8 files and detached review evidence must be supplied
separately by the review process; the preparer never manufactures an approval
or capability. Each review evidence document is content-bound to the exact
authority digest and names an independent reviewer. It does not call
`begin_child`, consume O8, send production traffic, read credentials, or close
the held parent. The preparer checks the requested nonce against the Ledger
history, derives the child source closure from the canonical parent generation,
verifies the clean source checkout and every declared source digest,
and preserves the immutable parent `sourceCommit` and exact packet05 parent
evidence. Provenance must also include an exact `generationPaths` map from
every generation name to its checked-out `tools/...` path; a digest appearing
in another source file is not accepted as equivalent.

To create the review input before approvals exist, use the same command with
`--draft-only` and omit `--permission`, `--o7`, and `--o8`. This writes only
`draft.json`, `review-request.json`, `plan.json`, and `parent-evidence.json`;
the draft contains no permission or approval claims.

After independent review, run the bounded handoff runner:

```sh
uv run --python 3.12 python tools/compat-broad/auth-credential-tokens/credential_recovery_runner.py \
  --packet /private/auth-packet05/recovery-preparation/packet.json \
  --parent /private/auth-packet05/parent.json \
  --ledger /private/auth-packet05/ledger \
  --source /private/auth-packet05/source-checkout \
  --now 1780000000 \
  --output /private/auth-packet05/recovery-handoff
```

The handoff contains only digests and immutable source binding, with explicit
`networkAllowed=false` and `ledgerMutationAllowed=false` controls. The runner
does not allocate a child, send traffic, acquire credentials or close the
parent; a separately authorized production executor must consume this handoff.

## Signing dependence

Eleven of the nineteen cases carry `requiresSigning`. Production custom tokens must be RS256-signed by a service account while local ones are unsigned, and the session-cookie group derives its cookie from the custom-token session, so it depends on signing too. A run without signing access can only cover the refresh and revocation groups.

## Three rules that carry the weight

The local runtime issues unsigned emulator tokens; production issues signed ones. A trust-root difference is therefore expected and is never counted as a semantic difference, though both roots are recorded.

The same-second boundary is classified `EXPECTED_NONDETERMINISM` unless both sides recorded that they pinned it from server-reported values: the token's own `auth_time` read back, `validSince` set to exactly that whole second, and that value confirmed by an admin readback. The comparator checks the recorded seconds rather than the pinning flag, so a row claiming a pinned boundary across a two-second gap is unpinned. Each control declares the outcome it must produce, and both are checked on each side independently before the boundary row is read: two sides that both accepted the older session agree with each other and have placed no boundary, so the row is `INDETERMINATE`. A refusal counts only when it is the expiry the endpoint documents, which for the lookup, session-cookie and refresh operations is a 400 carrying `TOKEN_EXPIRED` or `USER_DISABLED`. An `INVALID_ID_TOKEN`, an unauthenticated caller, a denied permission or a rate limit is recorded and compared as data, but it refuses the call for a reason that has nothing to do with the session's age, so it places no boundary and the row above it stays `INDETERMINATE` however well the two sides agreed.

Time is bounded by deadlines taken from a monotonic reading at the start of the run, not by the durations of the requests that were sent. The observation phase may run until the total less the recovery reserve, five hundred and forty seconds, and the cleanup tail then gets the reserved sixty seconds from the moment it starts, granted absolutely however the observation ended. The campaign is declared as that pair rather than as one total, so a run stopped by its own deadline still deletes the accounts it created; the tail is bounded in turn by its own deadline and the requests held back for it. Every wait is checked against the deadline, so a machine that stalls between two cases opens no further observation; each request is capped to the time its phase has left, so a call started just inside the deadline cannot carry the run past it. A response that did arrive is still returned, because discarding it could lose an account the run just created. The receipt records which phase a deadline stopped, when recovery started and what each limit was.

A receipt says separately whether its recording is complete and whether its cleanup is complete. Every row carries its own observed state, and the comparator derives that from the row rather than from the receipt's boolean, so a case nobody ran can never be classified `MATCH`.

## Running the contract checks

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-credential-tokens
uvx ruff check tools/compat-broad/auth-credential-tokens
```

## Running the local shadow

The shadow needs a `fireemu` binary built from this checkout. A binary from another commit records that commit's behavior, not this one's.

```sh
cargo build -p fireemu
uv run --python 3.12 python tools/compat-broad/auth-credential-tokens/credential_shadow.py \
  --binary target/debug/fireemu --output /absolute/private/credential-shadow.json
```

It starts one strict Auth-only daemon on an OS-assigned port, refuses any non-loopback target, deletes every account it created and reads both the UID and the address back as absent, then stops the process and reports whether any child survived. It exits non-zero when a case disagrees with its declared expected local result.

## What this package does not do

It performs no production request and acquires no credential. A nonce checked here is syntax only. A well-formed owner permission validated by `credential_plan.validate_permission` is still not permission granted by this repository, and the prepared package is never itself the permission.

## Shared Gate and Ledger on the current tree

The shared Ledger's reservation admits only Firestore document resources (`reservations._firestore_resource_scope`), the shared Gate requires at least one resource per job and derives a cleanup target from the request path, and its absence proof is a Firestore typed 404 (`shared_gate.validate_absence_proofs`). The campaign therefore names its two cleanup routes as Gate resources, tracks the accounts in the facade's own evidence, and is refused by `Ledger.reserve` with `canonical Firestore resource required` on this tree. `test_credential_production.py` pins that refusal and, separately, demonstrates the proposed two-function extension of the shared modules in the test process only. See `docs/compatibility/auth-credential-tokens-campaign-preparation.md`, section "O8 launch path".

## Bounded local runtime (offline continuation)

The local runtime uses a fixed five-second HTTP worker, bounded startup and ongoing
stdout draining, typed per-account cleanup, and independent process/resource
completion. Use numeric loopback addresses, not `localhost`. Output and its `.work`
directory must be new. The worker/process/shared framing sources are part of the
collector binding; historical receipts are not regenerated by this change. See
`docs/compatibility/auth-credential-local-runtime.md` for the exact limits and remaining
native/SDK, instance-identity, orphan and OS-level boundaries.
