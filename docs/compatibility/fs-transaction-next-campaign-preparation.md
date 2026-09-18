# FS-TRANSACTION next campaign preparation (`FS-TRANSACTION-EXPIRY-RETRY-04`)

## Status

`WAITING_ORACLE`. This is preparation only. No production request was sent, no
credential was read or bound, and no parent group is promoted. The number of
production-unobserved FS-TRANSACTION conditions is unchanged by this work.

The package is credential-free by contract: nothing here discovers, reads or
stores an access token, a refresh token or an API key, and the comparator
refuses a receipt that carries credential material.

## What the FS-TRANSACTION row still needs

The compatibility inventory records the remaining boundary as "production
conflict/error/retention behavior and SDK retry semantics need bounded
observations". Reviewing the recorded evidence narrows that considerably,
because a large part of it is already observed:

- The gRPC Write-stream precedence campaign at `dee737c14` observed transaction
  lock acquisition, a contended multiwrite refused with `ABORTED`, the absence
  of partial publication, rollback, and a successful post-rollback write.
- The conformance production matrix program `transactions/lifecycle` observed 32
  REST steps on 2026-09-07, including commit after commit, commit after
  rollback, rollback of an unknown transaction, both read-only commit refusals,
  the happy `readWrite.retryTransaction` path, and a `read_time` before database
  creation.

What no recorded production observation covers is the behavior of a transaction
that ran out of time rather than being finished by the client, the state of a
token after a rollback rather than a commit, and every refusal path of the retry
token. That is this campaign's scope.

## Observation cases

The frozen table lives in `tools/compat-broad/fs-write-txn/txn_expiry_cases.py`.
It is closed: every observation case names at least one control, every control
is referenced, every case declares its expected local result, and a case that
repeats an already recorded production observation may only appear as a control
and must name the evidence it repeats. A test enforces each of those rules.

### Idle expiry

| Case | Kind | Expected local result |
| --- | --- | --- |
| `idle-expiry/commit-before-idle` | control | `OK` after 20 seconds idle |
| `idle-expiry/commit-after-idle` | observation | `ABORTED`, the referenced transaction has expired or is no longer valid |
| `idle-expiry/rollback-after-idle` | observation | `ABORTED`, same refusal |
| `idle-expiry/lock-held-before-idle` | control | `ABORTED`, too much contention on these documents |
| `idle-expiry/lock-released-after-idle` | observation | `OK`, the out-of-band write succeeds once the holder expired |

The controls matter here. Without `commit-before-idle` an `ABORTED` could mean
the transaction was broken all along rather than expired. Without
`lock-held-before-idle` the later success would not prove that a lock ever
existed to be released. `lock-held-before-idle` repeats the recorded
`transactions/lifecycle#out-of-band-write` observation on purpose, because a
control that cannot fail proves nothing.

### Finished tokens

| Case | Kind | Expected local result |
| --- | --- | --- |
| `finished-token/rollback-after-begin` | control | `OK` |
| `finished-token/rollback-after-commit` | observation | `ABORTED`, expired or no longer valid |
| `finished-token/rollback-after-rollback` | observation | `ABORTED`, expired or no longer valid |

Production has been observed committing a finished transaction again. It has not
been observed rolling one back.

### Retry tokens

| Case | Kind | Expected local result |
| --- | --- | --- |
| `retry-token/retry-with-rolled-back-previous` | control | `OK`, a rolled-back attempt can seed one retry |
| `retry-token/retry-with-committed-previous` | observation | `INVALID_ARGUMENT`, invalid retry transaction |
| `retry-token/retry-with-read-only-previous` | observation | `INVALID_ARGUMENT`, a read-only transaction cannot be retried as read-write |
| `retry-token/retry-with-unissued-previous` | observation | `INVALID_ARGUMENT`, invalid transaction |
| `retry-token/retry-with-malformed-previous` | control | `INVALID_ARGUMENT`, invalid base64 |

The malformed control separates a request-decoding refusal from a semantic one,
so a single `INVALID_ARGUMENT` on the unissued case cannot be mistaken for a
parser rejection.

## The timing problem, stated plainly

The local emulator runs a virtual clock. It does not follow wall time, so the
local side reaches the idle limit by calling the control endpoint
`clock:advance`. Production has no such control and reaches it by waiting real
seconds. The two sides therefore produce their elapsed time by different
mechanisms, and the package refuses to hide that:

- Every row records the mechanism and the number of seconds it produced.
- The collector refuses to build a production collection with simulated time.
- The comparator refuses a production receipt whose timing is not wall-clock,
  and refuses either receipt that did not actually reach the seconds a case
  declares.
- The comparison result carries `timing.mechanismDiffers` and an explicit note.

What is compared across the two sides is the observed code, the normalized
diagnostic and the post-state. The mechanism that produced the elapsed time is
not compared, because it cannot be the same.

The waits are placed well away from the limit so that neither side depends on
the exact boundary: controls sit at 20 seconds and observations at 90 seconds,
against a locally declared limit of 60. If production's real limit is different,
the campaign still produces a usable observation as long as it is between those
two points, and a production result that disagrees with the 60-second placement
is itself the finding.

## Collector

`tools/compat-broad/fs-write-txn/txn_expiry_collector.py`.

- Bounded. Every response is capped at 64 KiB, every request at 8 KiB, and the
  whole collection runs against an absolute deadline.
- Owned. It creates only documents below `compat/o3-txn-expiry/<nonce>/`, each
  carrying an owner, role and nonce marker.
- Recoverable. Cleanup reads each document, proves ownership from all three
  markers plus a present update time, deletes it conditional on the observed
  update time, and then checks typed absence. A document it cannot prove it owns
  is retained and reported, never deleted. A refused delete is reported as
  unrecovered, never as success.
- Honest about failure. A transport failure stops the collection and is recorded
  as a failure. It is never turned into a semantic result.
- Loopback-locked. A local collection must target a loopback host; a production
  collection must target the fixed Firestore host.

## Campaign manifest and budget

The frozen proposal is
`spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-manifest.json`. It
is `BLOCKED_OWNER` and carries no permission. The nonce and owner identity in it
are reference values so the plan can be reviewed; execution must recompile with
a fresh nonce and the real owner identity.

| Bound | Value |
| --- | --- |
| Total request slots | 78 |
| Data slots | 68 |
| Metadata slots | 8 |
| Credential preparation slots | 2 |
| Owned documents | 5 |
| Accounts created | 0 |
| Concurrency | 1 |
| Wall-clock envelope | 600 seconds |
| Planning ceiling | US$0.014988 |

The cost is a conservative planning ceiling, not an invoice. It is 78 request
slots at US$0.0001 plus a fixed US$0.007188 network reserve, which is a 32 MiB
allowance at US$0.23 per GiB against an actual expected transfer of a few MiB.
The local rehearsal used 60 of the 68 data slots.

The permission envelope holds one `EXCLUSIVE` lock on the owned document prefix
and five `READ` locks on indexes, Rules, database configuration, Auth
configuration and the API-key binding. No case creates or changes an index, a
ruleset, a database, an account or any configuration, and a test enforces that.
`allowedReobservations` is zero.

## Comparator contract

`tools/compat-broad/fs-write-txn/txn_expiry_comparison.py` reports one of four
verdicts and never claims acquisition validity or promotion.

- `MATCH`: every case agrees after projecting away volatile identities, and the
  identities agree too.
- `EXPECTED_NONDETERMINISM`: every case agrees, but the project, prefix, nonce or
  database differ. Two runs against different projects always land here.
- `SEMANTIC_MISMATCH`: a case's code or normalized diagnostic differs.
- `INDETERMINATE`: a receipt is incomplete, unbound, unrecovered, collected
  against the wrong target, produced with simulated production time, short of a
  declared elapsed time, or carrying credential material.

Infrastructure failure is never reported as a semantic mismatch. Diagnostic
normalization replaces only request-bound resource identities and instants; it
does not touch diagnostic grammar, so a wording difference stays visible.

A separate `local_self_contract` checks a local receipt against the frozen
expected local results. It is explicitly not a production comparison.

## Local shadow run

`tools/compat-broad/fs-write-txn/txn_expiry_shadow.py` copies the built artifact
into a private directory, runs it as `fireemu exec --only firestore` with
OS-assigned ports, launches itself as the child inside that instance, proves the
instance identity through the control endpoint including a wrong-token rejection,
runs the collector, and then stops the child by PID after verifying the process
argument vector names the artifact it started.

The recorded run is
`spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-local-shadow.json`.

| Result | Value |
| --- | --- |
| Cases observed | 13 of 13 |
| Local self-contract | `MATCH` |
| Resources recovered with typed absence | 5 of 5 |
| Data requests used | 60 of 68 |
| Elapsed | 15.2 seconds |
| Child exit | 0, no signal needed |

The runtime artifact is SHA-256
`8c6bae9e7e5f72a315e88c9afb6b9a5f0a479239d856c04a98a4503e02830994`
(`fireemu 0.7.1`), built with `cargo build -p fireemu` inside this lane's own
worktree. The rehearsal records the source commit, the hashed Rust input set
(`32a872989f5e0d8fabf17a2a30cda85a2467574e23c4712a37711f0dbd196d18`, 400 files)
and that those inputs were clean. That digest is byte-identical to the one at the
lane base `3d0e56bdf`, so the artifact provably describes this branch.

A binary taken from the shared checkout or a sibling worktree describes a
different source and must not be used. An earlier rehearsal did exactly that and
produced a different artifact digest; the evidence test now refuses a recorded
artifact whose source root is not this worktree, or whose Rust input digest no
longer matches the working tree.

The first rehearsal disagreed on one case and the frozen expectation was wrong,
not the runtime: the emulator says `invalid base64` where the table claimed
`Base64 decoding failed`. The table now records what the runtime actually does,
and the wording gap is carried below as an open repair rather than hidden.

## Cleanup and failure rehearsal

Cleanup behavior is exercised offline rather than assumed:

- A document whose owner marker does not match is never deleted; the run reports
  `ownership-not-proven` and the resource stays unrecovered.
- A refused conditional delete reports `conditional-delete-refused` and the run
  is incomplete.
- An exhausted deadline stops the observation, and cleanup still runs against
  its own separate recovery deadline.
- An incomplete transport response stops the collection with
  `incomplete-response` rather than producing a semantic row.

In the real rehearsal all five documents were deleted under their observed
update time and proved absent afterwards.

## What this campaign will not observe

Recorded in the case table as `NOT_PREPARED`, so the package cannot be read as
complete:

1. **Total-lifetime expiry** (locally 270 seconds). A production observation
   would hold one transaction open past 270 real seconds while refreshing it
   below the idle limit. It needs its own long-window budget.
2. **A transaction token replayed against another database.** It needs a second
   named database in the oracle project, and creating one is a configuration
   change this campaign only holds a read lock on.
3. **A read-only transaction at a `read_time` outside the retention window.** The
   refusal depends on the project's retention configuration; it belongs with the
   read-time retention campaign.
4. **Query-range (phantom) lock precedence.** The single production attempt at
   `transactions/lifecycle#phantom-write` timed out and is recorded as
   unverified. Re-attempting it needs a query-shaped collector.
5. **Client SDK transaction retry semantics.** Observing what a declared SDK does
   on `ABORTED` needs a pinned SDK version and an SDK-driven collector. This
   campaign observes the backend contract the SDK reacts to, not the SDK.

## Open repair

**Malformed transaction token diagnostic.** The emulator refuses a
non-base64 `readWrite.retryTransaction` with `INVALID_ARGUMENT` and the message
`invalid base64`. Production was observed refusing a non-base64 `transaction` on
the commit path with `Invalid value at 'transaction' (TYPE_BYTES), Base64
decoding failed for "not base64!"`. The two are different request fields, so this
is a strong indication of a wording gap rather than a proven one, and the
campaign's malformed control is what would settle it. It is recorded here rather
than fixed, because it is a runtime change outside this lane.

## Verification

```
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/fs-write-txn
uv run --python 3.12 --with ruff ruff check tools/compat-broad/fs-write-txn
uv run --python 3.12 --with ruff ruff format --check tools/compat-broad/fs-write-txn
```

The published manifest is a bound input. Editing any of the five campaign
modules changes the source digest and fails
`test_txn_expiry_evidence.py`; the failure message carries the regeneration
command.

## Before execution

None of the following is done, and none of it may be inferred from this
document:

- A fresh owner permission naming this campaign, with issue and expiry instants,
  an owner identity, a recovery owner and recovery diagnostics.
- A fresh nonce and a plan recompiled against it.
- A credential path. This package binds none; the existing
  `credential_prep.py` contract is the nearest reviewed precedent and its
  envelope numbers do not apply here.
- Shared Gate and Ledger admission for the reservation and the six locks.
- A rebuilt, source-bound runtime artifact and a renewed local rehearsal against
  it.
- O7 admission review.
