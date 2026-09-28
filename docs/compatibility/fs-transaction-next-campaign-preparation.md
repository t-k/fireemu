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
| `retry-token/retry-with-malformed-previous` | control | `INVALID_ARGUMENT`, `Base64 decoding failed for "not base64!"` at `options.read_write.retry_transaction` |

The malformed control separates a request-decoding refusal from a semantic one,
so a single `INVALID_ARGUMENT` on the unissued case cannot be mistaken for a
parser rejection.

The unissued token is the same eight zero bytes (`AAAAAAAAAAA=`) that the
recorded corpus already sent for `rollback-unknown` and
`commit-with-unknown-transaction`, where production answered `Invalid
transaction.` rather than a decoding error. Reusing the published constant makes
the new row directly comparable to that corpus instead of introducing a fresh
value whose shape production has never been asked about.

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

The numbers being checked are measured, not declared. Each wait records the
interval the run observed, and each elapsed-dependent case records the idle time
of the specific transaction it uses, measured from that transaction's own
lock-taking read. The comparator refuses a receipt whose measured wait is shorter
than the requested one, whose idle time is below the case's declared seconds, or
whose wait was never measured at all. A collector wired to a sleeper that does
not sleep therefore fails, and a test drives exactly that case end to end.

The controls are bounded on the other side too. A slow production run could age
the 20-second control past the idle limit, which would look like a semantic
disagreement while actually being an invalid control. The comparator reports that
as `INDETERMINATE`.

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
- Owned. It creates only documents below `oracle/<nonce>/txn-expiry-04/`, each
  carrying an owner, role and nonce marker.
- Established before observed. A setup step's own success is judged separately
  from any case's result. The preflight read that expects absence, the
  create-only commit, the transactional reads that take the locks and every
  other non-case step have to succeed on their own terms. A case's refusal is a
  result to record; a setup step's refusal means the workspace this run promised
  to own was never established, and the run stops there.

  When the create-only commit is refused, the role stays unestablished and no
  later commit naming it is sent at all. Against a foreign document already
  sitting at one of the roles, the only write the run ever issues for it is that
  refused create, and no delete follows. The preflight finding alone does not
  stop the run, because the create-only commit cannot damage what is there and
  its refusal is the authoritative proof; a create accepted after the preflight
  saw a document is a contradiction and stops the run too.
- Answerable for a create whose answer never came. Each owned document moves
  through four states: no create sent, a create sent whose outcome is unknown, a
  confirmed creation, and a confirmed absence of this run's creation. The target
  is recorded as unknown before the create leaves the process, so a response
  that is lost to a timeout or an exception still leaves the run answerable for
  a document the backend may have created. The receipt carries those resources
  on a separate responsibility list, and recovery gives each one a safe readback
  rather than skipping it.

  A readback settles the question without guessing. Absent means this run's
  create never landed and the responsibility is discharged. A document carrying
  this run's owner, role and nonce can only have come from that create, because
  no other write to an unestablished role is ever sent, so it becomes the
  creation evidence the lost response would have been and the document is
  recovered under the usual conditional delete. Anything else is retained, never
  deleted, and the resource stays unrecovered. A role whose preflight had
  already seen a document is never attributed this way.
- Recoverable. Cleanup reads each document, proves ownership from all three
  markers plus a present update time, deletes it conditional on the observed
  update time, and then checks typed absence. A document it cannot prove it owns
  is retained and reported, never deleted. A refused delete is reported as
  unrecovered, never as success.

  Recovery is bound to this run's creation record, not to the marker the
  document currently carries. A marker can be written by a mutation the run
  should never have made; a creation record cannot. A role this run did not
  create is never deleted and never counted as unrecovered.

  One document failing to come back says nothing about the others. An exception
  from a recovery read becomes that document's result and the loop continues
  within the recovery deadline, so a receipt is always produced naming the
  documents still outstanding, the transactions still open and the sites where
  it failed.
- Stopped once by an authority refusal. `PERMISSION_DENIED` and `UNAUTHENTICATED`
  say the caller may not act at all, which is not a property of the phase that
  met them. One latch at the single place requests leave the run holds for every
  phase: observation, transaction release, the ownership read, the conditional
  delete and the final absence read. The first such refusal is recorded, and
  nothing is sent afterwards; no credential is swapped and no retry is made. The
  receipt still names every document this run created or may have created, every
  transaction left open and every responsibility it did not discharge. `ABORTED`
  and a diagnostic the case table disagrees with are ordinary results and keep
  their normal follow-up.
- Verified by readback of the document that was asked for. A response code says
  what the backend answered, not what it did. The plan places a readback
  immediately after every case that names a document, before anything can
  overwrite it, and the receipt keeps the body with the resource names, the
  instants and this run's identities replaced by fixed slots.

  The reply has to name the document the request named. Because the recorded
  body replaces the resource name with a fixed slot, a body describing another
  project, another database or another document would otherwise be recorded
  exactly like the right one. A name that does not match is recorded as
  `get-wrong-document`, an incomplete response rather than a readback: it never
  becomes an observed document, it never stands in for a declared post state,
  and in recovery it can never justify a delete. The comparator reports it as
  indeterminate, not as a state anyone disagreed about. It also records where each observed version sits in the sequence
  of versions seen for that document, which is the version relation a post-state
  comparison needs and the one thing a volatile instant cannot carry across two
  runs. A commit that returns `OK` without writing, and a refusal that writes
  anyway, are both visible here and invisible to a code-only comparison.
- Answerable for every transaction. Every `BeginTransaction` goes through the
  same path and registers whatever token came back, whether or not the case
  expected a refusal. A transaction the backend really started is live and has
  to be released during recovery; the expectation only classifies the row
  afterwards. A success-shaped reply whose token is missing or cannot be decoded
  is recorded as an incomplete acquisition, not as a transaction this run holds.
- Honest about failure. A transport failure stops the collection and is recorded
  as a failure. It is never turned into a semantic result.
- Loopback-locked. A local collection must target a loopback host; a production
  collection must target the fixed Firestore host.
- Time-bounded per request. Every operation carries its own timeout from the
  plan, which the transport must honour. The two contended writes get 120
  seconds because production does not refuse a write to a locked document
  immediately; everything else gets 10. The worst case, every timeout plus every
  wait, is 960 seconds against a 1200-second envelope.
- Self-releasing. Cleanup rolls back every transaction still open before it
  touches a document, because a conditional delete is an out-of-band write and a
  live transaction's lock would refuse it. A receipt that still holds an open
  transaction is incomplete. Without this, aborting after the transactional
  reads stranded four of the five owned documents.

  A rollback answered `OK` released the transaction. A rollback answered
  `ABORTED` counts as released only when that transaction's measured idle time
  has passed the idle limit, because `ABORTED` also means contention and says
  nothing about whether the locks are gone. Every release records the rollback
  message and the measured idle time, so the judgement is reviewable rather than
  implied by the code alone.

Waiting blocks the collector. A wall-clock wait is served in five-second steps
and each step records a checkpoint, so the run reports progress and can be
interrupted between steps, but a collector that is killed mid-wait still loses
the run and must start over. This is progress recording, not process resumption.

## Campaign manifest and budget

The frozen proposal is
`spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-manifest.json`. It
is `BLOCKED_OWNER` and carries no permission. The nonce and owner identity in it
are reference values so the plan can be reviewed; execution must recompile with
a fresh nonce and the real owner identity.

| Bound | Value |
| --- | --- |
| Total request slots | 95 |
| Data slots | 85 |
| Metadata slots | 8 |
| Credential preparation slots | 2 |
| Owned documents | 5 |
| Accounts created | 0 |
| Concurrency | 1 |
| Default request timeout | 10 seconds |
| Contended request timeout | 120 seconds |
| Worst case, timeouts plus waits | 960 seconds |
| Observation envelope | 1200 seconds |
| Recovery window, after observation | 180 seconds |
| Wall-clock envelope the permission must cover | 1380 seconds |
| Planning ceiling | US$0.016688 |

The cost is a conservative planning ceiling, not an invoice. It is 95 request
slots at US$0.0001 plus a fixed US$0.007188 network reserve, which is a 32 MiB
allowance at US$0.23 per GiB against an actual expected transfer of a few MiB.
The data slots include one rollback for every `BeginTransaction` the plan sends,
not one per transaction it expects to receive, because a begin the case table
expects to be refused can still issue a token the run has to release.

The permission envelope holds one `EXCLUSIVE` lock on the owned document prefix
and five `READ` locks on indexes, Rules, database configuration, Auth
configuration and the API-key binding. No case creates or changes an index, a
ruleset, a database, an account or any configuration, and a test enforces that.
`allowedReobservations` is zero.

The declared time bound is the two windows in sequence, not the observation
envelope alone. Recovery runs on its own deadline precisely so that an exhausted
observation budget still leaves room to give the owned documents back, so a run
that spends its whole observation envelope can still occupy the project for the
recovery window afterwards. The permission names 1380 seconds for that reason.

## Comparator contract

`tools/compat-broad/fs-write-txn/txn_expiry_comparison.py` reports one of four
verdicts and never claims acquisition validity or promotion.

- `MATCH`: every case agrees after projecting away volatile identities, and the
  identities agree too.
- `EXPECTED_NONDETERMINISM`: every case agrees, but the project, prefix, nonce or
  database differ. Two runs against different projects always land here.
- `SEMANTIC_MISMATCH`: a case's code, normalized diagnostic or post state
  differs.
- `INDETERMINATE`: a receipt is incomplete, unbound, unrecovered, collected
  against the wrong target, produced with simulated production time, short of a
  declared elapsed time, missing a readback for a post state a case declares,
  holding a resource whose ownership was never confirmed, stopped by an
  authority refusal, carrying a post-state readback that named another document,
  or carrying credential material.

Infrastructure failure is never reported as a semantic mismatch. Diagnostic
normalization replaces only request-bound resource identities and instants; it
does not touch diagnostic grammar, so a wording difference stays visible.

The post state is compared as well as the code. Each case's readback is
compared leaf for leaf between the two receipts, and a post state a case
declares but no readback recorded makes the comparison indeterminate rather than
a mismatch nobody observed.

A separate `local_self_contract` checks a local receipt against the frozen
expected local results, including each case's declared post state. It is
explicitly not a production comparison.

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
| Transactions left open | 0 |
| Post states read back and matching their declaration | 3 of 3 |
| Requests used | 68 of 85 data slots |
| Elapsed | 15.3 seconds |
| Child exit | 0, no signal needed |

The three declared post states were read back from the emulator and all three
held: the commit inside the idle limit moved `locked-d` to a new version
carrying `committed-before-idle`, the commit refused after the idle limit left
`locked-a` on its creation version carrying `created`, and the out-of-band
commit after expiry moved `locked-a` to a new version carrying
`written-after-expiry`. Before the readbacks existed, none of that was
observed; only the three response codes were.

The runtime artifact is SHA-256
`c83194a08e6ef139f0f495886a029c574126a08519c159ca37615564e0d53e11`
(`fireemu 0.7.1`), built with `cargo build -p fireemu` inside this lane's own
worktree. The rehearsal records the source commit, the hashed Rust input set
(`32a872989f5e0d8fabf17a2a30cda85a2467574e23c4712a37711f0dbd196d18`, 400 files)
and that those inputs were clean. That digest is byte-identical to the one at the
lane base `3d0e56bdf`, so the artifact provably describes this branch.

The record never carries an absolute filesystem path. `sourceRoot` is the marker
`repository-root`, and the child records the artifact's basename rather than its
path. This repository is published, so an operator's directory layout is not
evidence, and a test refuses any published record containing one. The claim that
the binary was built from this repository rests on the Rust input digest, which
is checked path-independently and therefore still holds from any checkout.

The Rust input digest, not the artifact digest, is the stable binding. A debug
build is not bit-reproducible, so rebuilding the same source yields a different
binary: three rehearsals in this lane recorded three different artifact digests
from byte-identical inputs. The cross-run comparison therefore scrubs the
artifact digest and asserts instead that both runs report the same Rust input
digest, and that within each run the parent's digest, the runtime block and the
child's own independently computed digest all agree. That combination was
verified against a deliberately rebuilt, different binary, and again here by
comparing the published record against a second independent rehearsal, which
differed in nothing outside the declared volatile keys.

A binary taken from the shared checkout or a sibling worktree describes a
different source and must not be used. An earlier rehearsal did exactly that and
produced a different artifact digest; the evidence test now refuses a recorded
artifact whose source root is not this worktree, whose Rust input digest no
longer matches the working tree, or whose child observed a different binary.

The published record is exactly what `run_shadow` writes. There is no
hand-editing step: the publication fields, the note and the runtime block are all
emitted by the generator, and `receipt.instance` is kept rather than redacted so
the child's independent artifact proof survives. Two tests enforce this. One
rebuilds the record from the generator and requires equality. The other, run with
`FIREEMU_O3_FRESH_SHADOW` pointing at an independently produced `shadow.json`,
requires the committed file to equal that fresh run once per-run identities,
instants and the per-build artifact digest are scrubbed. Both were run against
genuinely separate rehearsals before this evidence was committed, including one
produced by a different binary built from the same source.

The first rehearsal disagreed on one case and the frozen expectation was wrong,
not the runtime: the emulator then said `invalid base64` where the table claimed
`Base64 decoding failed`. The table recorded what the runtime actually did, and
the wording gap was carried as an open repair rather than hidden. That repair
has since landed in the runtime, and the table records the new wording; see
below.

## Cleanup and failure rehearsal

Cleanup behavior is exercised offline rather than assumed:

- A document whose owner marker does not match is never deleted; the run reports
  `ownership-not-proven` and the resource stays unrecovered.
- A refused conditional delete reports `conditional-delete-refused` and the run
  is incomplete.
- An exhausted deadline stops the observation, and cleanup still runs against
  its own separate recovery deadline.
- An abort taken while all four transactional reads hold their locks still
  returns all five documents, because cleanup rolls the transactions back first.
  A transaction whose rollback is refused stays recorded as open and the receipt
  is incomplete.
- An incomplete transport response stops the collection with
  `incomplete-response` rather than producing a semantic row.
- A create whose response is lost, to a timeout or to an exception, leaves the
  resource on the responsibility list; recovery reads it back and either proves
  it absent or recovers it, and a document it cannot attribute is retained.
- A readback answered with another project's, another database's or another
  document's name deletes nothing and is never recorded as that document's
  state.
- An authority refusal injected at each of the five send sites stops every later
  send, while a contention `ABORTED` at the same position does not.

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

## Closed repair, and what it leaves open

**Malformed transaction token diagnostic.** The emulator used to refuse a
non-base64 `readWrite.retryTransaction` with the bare message `invalid base64`.
It now answers

```
Invalid value at 'options.read_write.retry_transaction' (TYPE_BYTES), Base64 decoding failed for "not base64!"
```

which is production's recorded grammar, `Invalid value at '<proto field>'
(TYPE_BYTES), Base64 decoding failed for "<value>"`, applied to the proto path
of the field this request actually carries the bad value in. The frozen table
records the new wording, and the rehearsal observes it.

The repair landed in the runtime outside this lane; this lane only follows it.
It does not close the question the malformed control exists to answer. The
recorded production observations of that grammar are on other requests,
`transaction` on the commit path and
`writes[0].update.fields[0].value.bytes_value` on a write, so what production
names this field remains unobserved. A production run that answers with a
different field path is still a finding, and it is now a narrow one about the
path rather than a broad one about the whole diagnostic.

## Verification

```
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/fs-write-txn
uv run --python 3.12 --with ruff ruff check tools/compat-broad/fs-write-txn
uv run --python 3.12 --with ruff ruff format --check tools/compat-broad/fs-write-txn
```

To check the published rehearsal against an independent one, run the shadow into
a fresh directory and point the evidence suite at its result:

```
uv run --python 3.12 python tools/compat-broad/fs-write-txn/txn_expiry_shadow.py \
  --artifact target/debug/fireemu --output /tmp/txn-expiry-fresh
FIREEMU_O3_FRESH_SHADOW=/tmp/txn-expiry-fresh/shadow.json \
  uv run --python 3.12 --with pytest pytest -q \
  tools/compat-broad/fs-write-txn/test_txn_expiry_evidence.py
```

The published manifest is a bound input. Editing any of the five campaign
modules changes the source digest and fails
`test_txn_expiry_evidence.py`; the failure message carries the regeneration
command.

## O8 descriptor and launcher

The campaign now has an O8 descriptor, admission, Gate projection and launcher
in `tools/compat-broad/fs-write-txn/txn_expiry_{descriptor,admission,gate,
preflight,remote_transport,https_worker,production,o8}.py`, built on the
shared O8 core. The descriptor binds a 1200-second Gate wall (240 seconds of it
reserved for recovery inside the Gate) plus this plan's 180-second recovery
window, so the owner window is 1380 seconds; 95 Ledger request slots; five
owned documents below `oracle/<nonce>/txn-expiry-04/`; the 16,688 micro-USD
planning ceiling; one `EXCLUSIVE` document lock and five `READ` locks. The
nonce is 32 lowercase hex characters and the owner marker identity is derived
from it. Timing is wall-clock only: the descriptor refuses a clock advance and
refuses the documented sleeper-shortening rehearsal switch on the production
wire, and a rehearsal receipt is rejected by the comparator on its short waits.
The launcher reads the bearer token on a private descriptor only after the
Ledger reservation and the Gate claim; exit 0 is complete and released, exit 1
is a held reservation with a receipt carrying the stop point and the retirement
disposition (`aborted-no-data`, `closed-after-abandon` or `owner-escalation`),
exit 2 is a refusal before any reservation. The lane README carries the exact command line.

The credential-free integration proof runs the real Ledger, Gate and receipt
path against an offline backend: all 13 cases, a no-data stop retired through
`abort_no_data`, and a stop after the first case whose open transactions are
rolled back and whose documents are recovered and closed through
`close_after_abandon`. It is local evidence about the launcher, not a production
observation, and the FS-TRANSACTION condition count is unchanged by it.

## Before execution

None of the following is done, and none of it may be inferred from this
document:

- A fresh owner permission naming this campaign, with issue and expiry instants,
  an owner identity, a recovery owner, a frozen credential principal and the
  database-projection and Auth-configuration baseline digests.
- A fresh 32-hex nonce and a plan recompiled against it.
- A credential handoff on a private descriptor at launch time. This package
  binds none.
- A retained, source-bound runtime artifact matching the current shadow's
  profile.
- Independent O7 admission review and an owner-minted approval outside the
  package.
