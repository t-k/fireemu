# FS-RULES user-token observation campaign preparation

Campaign ID: `FS-RULES-USER-TOKEN-MATRIX-01`

Parent feature groups: `FS-RULES`, `AUTH-FS-CROSS`

Status: `WAITING_ORACLE`. Production-unobserved conditions reduced by this
document: **0**.

This document describes a prepared, credential-free, unexecuted campaign. No
production operation was performed, no credential was acquired, no Ruleset was
published and no account was created. Nothing here is an execution permission.

## Why this campaign exists

The `FS-RULES` row of the [acceptance table](ip-fs-production-compatibility.md)
is blocked on one sentence: user-token production Rules behavior and Ruleset
transition cases cannot be substituted with administrator REST evidence. That
is a statement about the principal, not about coverage. An administrator
credential bypasses Rules evaluation entirely, so every administrator receipt
in the repository is silent about whether production would have allowed or
denied the same request made by an end user.

The campaign therefore fixes a finite matrix in which each request is made with
an end-user identity token: an Identity Toolkit email/password sign-in for a
throwaway account owned by this campaign produces an ID token, and the Firestore
request carries that token as its bearer credential. The same matrix runs
against a locally owned `fireemu` instance so the two sides can be compared.

## Prepared conditions

Twenty-five observation rows cover ten conditions. Every condition carries at
least one control, negative or post-state row, so a row that passes for the
wrong reason is visible.

| Condition | Rows | What the rows separate |
| --- | --- | --- |
| `principal-separation` | 4 | Owner A allowed on its own document, second user B denied on A's document, B allowed on its own, an anonymous-provider principal denied |
| `request-auth-null` | 3 | An unauthenticated request denied where ownership is required, allowed where the rule requires `request.auth == null`, and an authenticated principal denied by that same explicit-null clause |
| `custom-claim` | 2 | A token carrying `o5role == 'editor'` allowed, a token without the claim denied |
| `tenant` | 2 | A tenant member allowed by `request.auth.token.firebase.tenant`, a project-level principal denied |
| `exists` | 2 | A rule whose `exists()` guard is present allows, the same shape with an absent guard denies |
| `get` | 2 | A rule reading another document with `get()` allows the matching principal and denies the other |
| `getAfter` | 2 | An atomic commit that also writes the partner document satisfies `getAfter()`; the same write alone is denied |
| `atomic-multiwrite` | 2 | A commit pairing one allowed and one denied write is refused as a whole, and the allowed half is proven unapplied by a post-state read |
| `credential-refusal` | 3 | An expired token, a malformed bearer and an empty bearer are authentication refusals, not Rules denials |
| `ruleset-transition` | 3 | Under Ruleset B the owner is denied on the same resource, while the explicit-null and custom-claim clauses still allow |

Two Rulesets differ by exactly one line. Ruleset A allows the owner to read
`owned-a`; Ruleset B denies it. Everything else is identical, so a transition
row that changes decision isolates the Rules change rather than any other
variable. A regression test asserts that one-line difference.

The frozen template of the matrix is
[`spec/compatibility/fs-rules-user-token-matrix.json`](../../spec/compatibility/fs-rules-user-token-matrix.json).
The project, database, nonce and tenant in it are placeholders; a real run
recompiles the matrix from owner-confirmed identities.

## Collector, budget and cleanup

The collector in `tools/compat-broad/fs-rules-publication/o5_user_token_collector.py`
performs no I/O of its own. All traffic goes through an injected callable, so
the whole contract is exercised by tests without a network, a credential or a
process.

Redaction is structural rather than best effort. A compiled operation carries a
credential reference label, never a token. The collector never holds an ID
token, a refresh token, an API key or a password; the transport resolves the
label. A receipt containing any credential-shaped key is treated as a leak: the
row is recorded as failed, the run aborts and no later row is attempted. A row
is bound to its principal by a per-nonce fingerprint derived from the label.
Nothing is passed on a command line, and transport exceptions are recorded by
exception type only, never by message.

Bounds are enforced rather than declared. Observation stops at the compiled row
count and at a monotonic deadline checked before each request. Recovery draws
on a separate reserve, so cleanup cannot be starved by an exhausted observation
budget.

Cleanup is version bound. Every resource is read back first; an absent resource
is already recovered, a present one is deleted under its observed version
precondition, and the deletion is followed by an absence check. A resource that
cannot be read back stays an open responsibility and is never force deleted.
Every document a row attempted to create is an owned resource from the moment
the request was sent, including when the response was lost.

### Budget estimate

| Quantity | Value |
| --- | --- |
| Observation requests | 25 |
| Fixture, Auth and Rules requests | 39 |
| Recovery requests | 53 |
| Request upper bound | 117 |
| Concurrency | 1 |
| Wall-clock deadline | 600 s |
| Estimated cost | under US$0.001 |
| Cost ceiling | US$1.00 |

The cost figure uses public Firestore Standard list prices to show the campaign
is small. It is an estimate, not a quoted tariff.

## Local shadow

`o5_user_token_shadow.py` fixes the owned local `fireemu` instance the matrix
needs: the `auth` and `firestore` services, operating-system-assigned ports for
every listener, an environment allowlist that excludes every production
credential variable, both Ruleset sources, and a teardown that terminates only
the owned process and asserts its origins are closed.

Wiring that specification to `tools/compat-inventory/owned_runner.py` is
deliberately left to the next unit. An untested process launcher inside a
preparation package would be a liability, not evidence.

The local Auth emulator mints unsigned tokens. A local allow therefore proves a
Rules decision and never production token verification. When a local row
disagrees with the compiled expectation, the shadow reports it as a repair
ticket against the local runtime, never as a statement about production.

## Comparator contract

The comparator joins one production bundle with one local shadow bundle and
classifies each row as `MATCH`, `EXPECTED_NONDETERMINISM`, `SEMANTIC_MISMATCH`
or `INDETERMINATE`, and reports the worst classification per condition.

It refuses to classify anything it cannot bind. Both bundles must carry the
checked-in collector contract and the same compiled case digest. The production
side must declare the production user-token role, so a local shadow bundle with
a flipped flag cannot stand in for it. The two sides must be distinct runs, so a
bundle cannot be compared with itself. Neither side may claim acquisition or
promotion authority. Incomplete recording, incomplete cleanup, drifted row
identity and drifted principals are all refusals. Two sides that agree on a
status the matrix did not expect are a mismatch, not a match.

A `MATCH` here is agreement between two collected bundles. It is not a
compatibility verdict: `promotionReady` is always false, and promoting this lane
is a separate review.

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
fixed deny-all Ruleset is not a safe automatic recovery, and no publication,
release or restoration step is implemented here.

## What remains unobserved

Everything about production. This preparation reduces no production-unobserved
condition, and `FS-RULES` and `AUTH-FS-CROSS` remain `WAITING_ORACLE`.

The matrix is also narrower than the parent rows. It does not cover Rules query
proofs, rule and expression limits, Rules behavior through the gRPC Listen or
WebChannel paths, declared client SDKs, token revocation timing, or Rules
publication consistency during a release. Those remain separate units. The
campaign covers one principal dimension, one claim, one tenant, the three
document-lookup functions, one atomic multiwrite refusal and one Ruleset
transition, which is what the `FS-RULES` blocking sentence names.
