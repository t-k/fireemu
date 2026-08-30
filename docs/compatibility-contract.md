# The compatibility contract and how it is gated

`spec/compatibility/contract.json` is the one machine-readable statement of what `fireemu`
claims about Firebase emulator compatibility. `tools/compat-check` is the gate:
`cargo run -p compat-check` exits non-zero whenever the contract, the capability manifest, the
README and the executed evidence disagree.

The rule the gate enforces is the same one the requirement ledger enforces
(`docs/verification-ledger.md`): **a statement that claims to hold names artifacts that exist**.
A claim nothing executes is not a claim, it is marketing.

## Why a contract at all

The Local Emulator Suite is a moving target. `firebase-tools` ships fifteen emulators today and
adds more; an unversioned claim is therefore never true for long, and an unqualified "superset"
claim is false the moment the pinned release contains one product this repository does not
implement. The contract makes both facts structural rather than editorial:

- the claim is pinned to one `firebase-tools` release with its integrity and its bundled
  emulator versions recorded;
- every emulator that release ships is enumerated with a scope and a recorded decision, so a
  product cannot be quietly forgotten;
- every parity claim names the capability manifest entries it depends on and the tests and
  conformance fixtures that execute it.

## The baseline

`baseline` pins `firebase-tools@15.28.2` (audit date 2026-08-30) and records what makes that pin
verifiable: the lockfile integrity of the package, a digest of the installed manifest, every
bundled downloadable emulator with its upstream SHA-256, the pinned client and Admin SDK
versions, and the official documentation URLs. Those values come from `conformance/ORACLE.md`,
which the recorder regenerates from the installed CLI and which is never maintained by hand.

`baseline.officialEmulators` is the inventory of `src/emulator/types.ts` at that tag, together
with the service, downloadable and import/export subsets. It is what the taxonomy is checked
against.

### What an upstream upgrade does

The upgrade is fail-closed by construction, in three places:

- `CC-02` compares `baseline.version` with the version `conformance/package.json` actually
  installs. Bumping the pin fails the gate immediately, before anything is re-recorded.
- `CC-02` also requires the claim sentence to name that version, so the public claim can never
  be qualified by a release the repository does not run against.
- Any surface the new baseline adds is absent from this contract, so `CC-02` keeps failing until
  it is enumerated with a scope and a decision.

Re-recording then turns every newly detected difference into a `debt` row in
`conformance/DEBT.md`, because a row can only become a documented divergence once a human writes
it into `conformance/divergences.json`.

## The taxonomy

Every surface carries a `scope` and a `state`.

| Scope | Meaning |
| --- | --- |
| `active` | in the supported-surface milestone: either parity is claimed with evidence, the surface is a fireemu addition, or it is an open gap that blocks the complete-suite claim |
| `deferred` | in the pinned baseline, deliberately not implemented for now; blocks any complete-suite or unqualified superset claim |
| `not-planned` | in the pinned baseline, deliberately never implemented; blocks any complete-suite claim against this baseline |

| State | Meaning |
| --- | --- |
| `claimed` | parity is claimed against the pinned official emulator, with executed evidence |
| `addition` | a fireemu surface with no official counterpart; never described as parity |
| `gap` | an active surface with no parity claim yet |
| `none` | nothing is served |

A `deferred` or `not-planned` surface declares `prohibitedClaimTerms`: the words that may never
read as supported. `App Check` and the control API are `active` surfaces with `official: false`,
so they can never be counted as official parity.

## What a claim carries

Each claim under a surface names, separately:

- `capabilities`: the capability manifest IDs it depends on, each with the status the manifest
  must declare for it;
- `evidence`: the executed proof, as `tests` (function names), `integration` (repository-relative
  files) and `conformance` (fixture IDs);
- `officialLimitations`: what the official emulator documents or ships as a limitation and which
  the `firebase` profile must therefore reproduce rather than "fix";
- `fireemuOnly`: behaviour that has no official counterpart, each with its precision;
- `productionOnly`: real-service behaviour that is out of scope for any local emulator;
- `preview`: surfaces whose compatibility is scoped more narrowly because upstream is preview.

Keeping those five lists apart is what stops extra strictness from reading as parity.

## Compatibility profiles

Two profiles are declared as configuration key sets:

- **`firebase`** reproduces what the pinned suite ships and Firebase documents, including its
  documented limitations. Nothing in this profile may refuse a request the official emulator
  admits.
- **`strict`** adds fireemu's own validation. Every key here may only refuse more than the
  official emulator, and every refusal it adds must be published as a capability precision or as
  a documented divergence in `conformance/divergences.json`.

One value is worth calling out, and the contract records it as an explicit
`officialEmulatorDivergence`: `firestore.indexValidationPolicy = firebase` reproduces the
Firebase *backend*, which refuses a query whose composite index is missing, while the pinned
official Firestore *emulator* serves it. A run that must reproduce the emulator rather than the
backend sets `emulator`. Both are official behaviour of a different oracle; `conservative` is
neither, and belongs to the `strict` profile.

There is no single runtime switch that applies a profile yet: the canonical schema's top-level
`profile` key is accepted and not yet interpreted. `compat-check` checks every key and value both
profiles name against `spec/config/fireemu.schema.json`, so the sets cannot drift from the
configuration surface.

## The capability manifest is a data file

`crates/fireemu/src/capabilities.json` holds the manifest entries and
`crates/fireemu/src/control.rs` embeds it with `include_str!`. The checker therefore reads
exactly what `GET /v1/capabilities` publishes without linking or starting the binary, and the
manifest cannot drift from the contract behind a compilation step.
`crates/fireemu/tests/capabilities.rs` still reads the manifest from a running daemon, so a
malformed file fails the test suite as well.

## The rules

| Rule | What it refuses |
| --- | --- |
| `CC-01` | a malformed contract: a bad schema version, a missing audit date, a duplicate surface or claim ID, an unknown scope or state, a surface with no recorded decision |
| `CC-02` | an official emulator of the pinned baseline that no surface enumerates, an emulator enumerated twice, or a surface that names an emulator the baseline does not ship |
| `CC-03` | a manifest capability that is `implemented` or `partial` and is bound to no existing executed test or conformance fixture, and any evidence name that does not resolve |
| `CC-04` | a manifest entry and the contract that disagree on status, a claim naming a capability the manifest does not declare, or a manifest entry no claim covers |
| `CC-05` | a README that does not carry the version-qualified claim sentence of the contract |
| `CC-06` | a deferred or not-planned product that reads as supported: named in a manifest `implemented` list, named on a README line with no scope disclaimer, carrying a parity claim, or declaring no prohibited terms at all |
| `CC-07` | contradictory public statements (below) |
| `CC-08` | a compatibility profile that sets a configuration key the canonical schema does not define, or a value it does not allow |

Evidence names resolve the way `tools/traceability-check` resolves them, so the two gates agree
on what "an existing test" means: a `tests` name is a function defined in a Rust file under a
`tests/` directory anywhere in the workspace, an `integration` name is a repository-relative file
that exists, and a `conformance` name is a fixture under `conformance/fixtures/`.

`CC-05` and `CC-06` read the README differently on purpose. The claim sentence is matched with
whitespace normalized, so wrapping it is allowed. A prohibited term is matched one line at a
time, so a line that names a deferred product must carry its disclaimer on the same line -- which
is why the claim sentence itself is kept on one line in `README.md`.

### CC-07: contradictory public statements

Two shapes, both mechanical:

1. **A cross-reference that denies its owner.** An `unimplemented` item that names another
   capability ID which the manifest declares `implemented`. `ST-OBJ-1` listed
   `"Storage triggers (FN-EVT-1)"` as unimplemented while `FN-EVT-1` listed exactly those
   triggers as implemented. Such a sentence is not a gap, it is a pointer, and it belongs in
   `notes`.
2. **A shared term written with the wrong status.** `vocabulary.sharedTerms` is the contract's
   vocabulary of behaviours that more than one public statement talks about. Each term has one
   status and the entries that own it. The gate refuses the term in an `implemented` list when
   the contract calls it unsupported, in an `unimplemented` list when the contract calls it
   implemented, an owner whose manifest status differs from the declared one, and a README line
   that says an implemented term is "not implemented". The README said `ExecutePipeline` was not
   implemented while `FS-PIPE-RPC-1` declared validation-only support implemented; the README now
   states the validation-only semantics instead.

Adding a term to `sharedTerms` is a deliberate act, which is the point: the contract owns the
vocabulary that more than one document uses, so the two documents cannot drift apart quietly.

## Running it

```sh
cargo run -p compat-check              # the gate; exits non-zero on any problem
cargo test -p compat-check             # the checker's own fixtures, one per failure class
cargo run -p traceability-check        # the sibling gate for the requirement ledger
```

`tools/compat-check/tests/contract_rules.rs` holds the table-driven fixtures: each case builds a
throw-away repository root that passes every rule, mutates exactly one thing and asserts which
rule fires. The last case runs the checker over this repository, so `cargo nextest run` fails as
soon as the contract, the manifest and the README drift apart.

## The ledger entries

`verification/requirements/requirements.json` carries `CLAIM-01` to `CLAIM-06`, the coverage
obligations of the contract issue, each with the artifacts that prove it.
