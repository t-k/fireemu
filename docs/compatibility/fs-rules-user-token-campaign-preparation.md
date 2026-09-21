# FS-RULES user-token observation campaign preparation

Campaign ID: `FS-RULES-USER-TOKEN-MATRIX-01`

Parent feature groups: `FS-RULES`, `AUTH-FS-CROSS`

Status: `WAITING_ORACLE`. Production-unobserved conditions reduced by this
document: **0**.

This document describes a prepared, credential-free, unexecuted production
campaign, together with a local shadow of it that has been executed against
`fireemu`. No production operation was performed, no production credential was
acquired, no production Ruleset was published and no production account was
created.

## Why this campaign exists

The `FS-RULES` row of the [acceptance table](ip-fs-production-compatibility.md)
is blocked on one sentence: user-token production Rules behavior and Ruleset
transition cases cannot be substituted with administrator REST evidence. That
is a statement about the principal, not about coverage. An administrator
credential bypasses Rules evaluation entirely, so every administrator receipt
in the repository is silent about whether production would have allowed or
denied the same request made by an end user.

The campaign therefore fixes a finite matrix in which each request is made with
an end-user identity token: an Identity Toolkit sign-in for a throwaway account
owned by this campaign produces an ID token, and the Firestore request carries
that token as its bearer credential.

## Prepared conditions

Twenty-six observation rows cover ten conditions. Every condition carries at
least one control, negative or post-state row.

| Condition | Rows | What the rows separate |
| --- | --- | --- |
| `principal-separation` | 4 | Owner A allowed on its own document, second user B denied on A's document, B allowed on its own, an anonymous-provider principal denied |
| `request-auth-null` | 4 | An unauthenticated request denied where ownership is required, allowed where the rule requires `request.auth == null`, and both an anonymous-provider principal and an authenticated principal denied by that same explicit-null clause |
| `custom-claim` | 2 | A token carrying `o5role == 'editor'` allowed, a token without the claim denied |
| `tenant` | 2 | A tenant member allowed by `request.auth.token.firebase.tenant`, a project-level principal denied |
| `exists` | 2 | A rule whose `exists()` guard is present allows, the same shape with a guard no row ever creates denies |
| `get` | 2 | A rule reading another document with `get()` allows the matching principal and denies the other |
| `getAfter` | 2 | An atomic commit that also writes the partner document satisfies `getAfter()`; a separate control document whose guard is never created is denied |
| `atomic-multiwrite` | 2 | A commit pairing one allowed and one denied write is refused as a whole, and a post-state read of the pinned field value proves the allowed half was not applied |
| `credential-refusal` | 3 | An expired token, a malformed bearer and an empty bearer are authentication refusals, not Rules denials |
| `ruleset-transition` | 3 | Under Ruleset B the owner is denied on the same resource, while the explicit-null and custom-claim clauses still allow |

The anonymous rows matter because an implementation that treats an
anonymous-provider principal as an absent principal would pass the ownership
denial for the wrong reason. It is separated by testing that same principal
against the clause that only an absent principal satisfies.

The `getAfter` control uses its own target document and a guard no row ever
creates. An earlier version reused the primary row's documents, which made the
denial an already-exists refusal rather than an unsatisfied `getAfter`.

Two Rulesets differ by exactly one line. Ruleset A allows the owner to read
`owned-a`; Ruleset B denies it. A regression test asserts that one-line
difference.

### Every payload is frozen

Each fixture and each write carries its field values in the compiled plan, so
an executor never invents one. A value is either a literal or the typed
reference `{"$principal": "<ref>"}`, which resolves to the uid of the account
the campaign created for that reference. The Rules read `resource.data.ownerUid`
and the fixtures carry `ownerUid`, checked by a test, so a row whose expectation
depends on document contents is reproducible.

The frozen template of the matrix is
[`spec/compatibility/fs-rules-user-token-matrix.json`](../../spec/compatibility/fs-rules-user-token-matrix.json).
The project, database, nonce and tenant in it are placeholders. The tenant in
particular is assigned by Identity Platform, so a real run always recompiles.

## Collector, budget and cleanup

The collector performs no I/O of its own except its journal. All traffic goes
through an injected callable, so the whole contract is exercised by tests
without a network, a credential or a process.

Redaction is structural. A compiled operation carries a credential reference
label, never a token. The collector never holds an ID token, a refresh token,
an API key or a password; the transport resolves the label. Every receipt is
scanned recursively: a credential-shaped key or a token-shaped value at any
depth aborts the run, and observation and recovery receipts share one
allowlist. A row is bound to its principal by a per-nonce fingerprint derived
from the label. Nothing is passed on a command line, and transport exceptions
are recorded by exception type only.

An append-only, fsynced journal records the run, the owned accounts, every
attempted create before the request is sent, every row outcome and every
recovery step. A process that dies mid-run still leaves the list of resources
it touched.

Bounds are enforced. Observation stops at the compiled row count and at a
monotonic deadline checked before each request. Recovery draws on a separate
reserve and its own, longer deadline, so cleanup is neither starved nor
unbounded.

Cleanup covers documents and accounts. Every document is read back, deleted
under its observed version precondition, then verified absent. Every throwaway
account is looked up, deleted under its observed uid, then verified absent. A
subject that cannot be read back stays outstanding and is never force deleted.

### Budget estimate

| Quantity | Value |
| --- | --- |
| Observation requests | 26 |
| Fixture, Auth and Rules requests | 26 |
| Recovery requests | 54 |
| Request upper bound | 106 |
| Concurrency | 1 |
| Observation deadline | 600 s |
| Recovery deadline | 900 s |
| Estimated cost | under US$0.001 |
| Cost ceiling | US$1.00 |

The cost figure uses public Firestore Standard list prices. It is an estimate,
not a quoted tariff.

## Local shadow, executed

The shadow runs the same compiled matrix against one `fireemu` built from this
worktree. `fireemu exec` requires a trailing command, so the driver runs as the
`--` child inside the instance's lifetime and inherits the assigned loopback
origins through its environment. Every listener port is operating-system
assigned, and the environment handed to the instance is an allowlist that
excludes every production credential variable.

The executed record is
[`spec/compatibility/fs-rules-user-token-local-shadow.json`](../../spec/compatibility/fs-rules-user-token-local-shadow.json).
It binds the artifact digest, the `rustc` version and the source commit it was
built from, and, since the collector became a bound collector, the digests of
every manifest-bound lane module that produced it, the loopback endpoint and
wire sequence of every receipt, the two Ruleset releases with their publish
echo readback, the monotonic and wall clocks, and a fingerprint per principal
derived from the nonce and the assigned uid. In the current run the local
runtime produced all twenty-six expected decisions, including the field values
of the multiwrite post-state row, with complete recording, complete document
and account cleanup, the tenant deleted and both origins closed afterwards.
There are no repair tickets from it.

That is local evidence. The local Auth emulator mints unsigned tokens, so a
local allow proves a Rules decision and never production token verification.
Changing the compiled matrix or any manifest-bound lane module invalidates the
record, and the binding tests say so: the recorded source digests must equal
the sources on disk, and the recorded source commit must be `HEAD` or an
ancestor within a bounded number of commits. The shadow then has to be re-run
on a committed tree.

## Comparator contract

There are two comparator modules, recording two different decisions.

The first, `o5_user_token_comparator.py`, has no positive classification and
every call returns `INDETERMINATE`. That is deliberate and unchanged. A
collected pair of bundles is not evidence about production until each bundle
binds the facts that make it an acquisition rather than a recording: the
endpoint each request reached, the observer identity, the campaign manifest the
run was admitted under, the Ruleset releases with their readback, an exclusive
nonce reservation, sequential wire and cost counts, and version-bound cleanup
with final absence. The first module names each missing binding and refuses.

The second, `o5_user_token_comparator_v2.py`, is the separately reviewed
acquisition comparator. It can reach `MATCH`, `SEMANTIC_MISMATCH`,
`INDETERMINATE` or `REFUSED`, and it reaches a positive classification only
when both bundles carry every binding above and each one verifies against
something the bundle cannot fabricate: the lane source digests recomputed from
disk, a production host allowlist on one side and loopback on the other, the
Ruleset source digests from the plan and the activation order relative to the
rows, principal fingerprints recomputed from the nonce, the admitted manifest
digest recomputed from the campaign module, typed cleanup steps for every owned
document and account, and monotonic time and wire-sequence consistency against
the enforced budget. The production side must also carry a nonce reservation,
an owner permission reference and an approval window; the local side must
carry its artifact binding and no reservation.

A self-declared role string is still not an acquisition. Collecting the same
matrix twice locally and labelling one bundle as the production side is
refused as `local-mislabelled-as-production`, by its environment label, by its
loopback endpoints, by its artifact binding and by the principals it shares
with the local side. A manifest digest that is not the recomputed one, a
Ruleset whose readback is not the plan's source, a principal that does not
match the plan, an incomplete record, a cleanup step with an unknown outcome,
a time or count contradiction, the same run on both sides, and an authority
claim without bindings are each a named error and never `MATCH`. The full
table is in the lane README.

The collector records these bindings in a bound run. The local shadow is one,
and the O8 descriptor `o5_user_token_descriptor.py` declares the campaign to
the shared admission core with the bound collector as its production side and
the acquisition comparator against the published shadow; its wire members
refuse, because the lane has no reviewed production transport.

Expectation drift is reported by the local shadow, not by the comparator. A row
where the local runtime disagrees with the compiled expectation is a repair
ticket against the local runtime, never a statement about production.

## Owner preconditions

None of the following is satisfied by this repository, and each one blocks
execution on its own.

1. Project and database identity confirmed by the owner.
2. A fresh nonce reserved for this campaign only.
3. An execution window with a named owner present for its whole duration.
4. An administrator credential for fixture setup, custom-claim minting and cleanup.
5. Identity Platform multi-tenancy enabled with the named tenant already created.
6. The two Rulesets already released by the owner, or an owner-held publication lock together with the captured bytes and version of the preexisting release.
7. A recovery owner who restores the preexisting release if the window ends early.
8. An accepted cost ceiling and a data-retention decision for the run directory.

Publishing Rules changes the Rules state of the whole database. Releasing a
fixed deny-all Ruleset is not a safe automatic recovery, and no production
publication, release or restoration step is implemented here.

## What remains unobserved

Everything about production. This preparation reduces no production-unobserved
condition, and `FS-RULES` and `AUTH-FS-CROSS` remain `WAITING_ORACLE`.

The matrix is also narrower than the parent rows. It does not cover Rules query
proofs, rule and expression limits, Rules behavior through the gRPC Listen or
WebChannel paths, declared client SDKs, token revocation timing, or Rules
publication consistency during a release. Those remain separate units.
