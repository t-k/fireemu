# The compatibility contract and how it is gated

`spec/compatibility/contract.json` is the one machine-readable statement of what `fireemu`
claims about Firebase emulator compatibility. `tools/compat-check` is the gate:
`cargo run -p compat-check` exits non-zero whenever the contract, the capability manifest, the
README and the executed evidence disagree.

The rule the gate enforces is the same one the requirement ledger enforces
(`docs/verification-ledger.md`): **a statement that claims to hold names artifacts that exist**.
A claim nothing executes is not a claim, it is marketing.

The [generated compatibility inventory](compatibility/README.md) adds a separate source-to-requirement view for Auth and Firestore. Existing artifact references establish traceability; they do not establish that a particular release, configuration or SDK run succeeded. The normal `compat-check` CLI also validates the inventory and its generated pages. Regenerate them with `cargo run -p compat-check -- --write-inventory`; schema 1 accepts discovery pointers and mappings, but cannot accept completed source reviews or feature execution receipts. Unknown and deferred scope remains visible.

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
  files) and `conformance` (fixture IDs). A fixture is evidence only through the steps the local
  oracle answered: its `parity` and `documented-divergence` rows. A `pending` row (one only the
  production service could answer) proves nothing and is ignored; a `debt` row (a recorded
  mismatch nobody has ruled on) invalidates the claim, unless the claim leaves that step out of
  its scope by name: `{"fixture": id, "excludedSteps": [{"step", "issue", "reason"}]}`, where
  `issue` is the issue that owns the mismatch. The exclusion is a scope statement, not evidence,
  and it becomes an error the moment the step stops being debt, so it cannot outlive the fix;
- `officialLimitations`: what the official emulator documents or ships as a limitation and which
  the `emulator` profile must therefore reproduce rather than "fix";
- `fireemuOnly`: behaviour that has no official counterpart, each with its precision;
- `productionOnly`: real-service behaviour that is out of scope for any local emulator;
- `preview`: surfaces whose compatibility is scoped more narrowly because upstream is preview.

Keeping those five lists apart is what stops extra strictness from reading as parity.

## Compatibility profiles

Two profiles are declared as configuration key sets, and the canonical schema's top-level
`profile` key selects one at runtime:

- **`strict`** (the default) behaves like production Firebase where the official emulator does
  not: composite indexes are checked with production's rules, Standard query limits refuse the
  query, and ID tokens are verified. Every key here may only refuse more than the official
  emulator, and every refusal it adds must be published as a capability precision or as a
  documented divergence in `conformance/divergences.json`.
- **`emulator`** reproduces what the pinned suite ships and Firebase documents, including its
  documented limitations. Nothing in this profile may refuse a request the official emulator
  admits.

A profile's `sets` lists exactly what the daemon derives from it — `firestore.enforceLimits`,
which an explicit key may still override; the other derived settings, how composite indexes are
validated and how a caller's ID token is verified on the Firestore and Storage Security Rules
surfaces, have no key of their own and follow the profile. A unit test in
`crates/fireemu/src/config.rs` reads the contract and fails when `sets` and what `set_profile`
derives disagree. Every other key a profile names is under `declared`, each with a `status`:
`hand-written` means the loader reads the key but does not derive it from the profile, and
`not-implemented` means the loader refuses the value or reads nothing of the section, so the
value is a statement of intent and not a switch (`events.delivery = at-least-once` and
`scheduler.clock = wall` of the `emulator` profile are of that kind, as are the `limits.*` and
`rules.staticLimitChecks` / `rules.runtimeBudgets` keys of both). `fireemu capabilities` and
`GET /v1/capabilities` publish the active profile and the start banner prints it.

Where the `emulator` profile cannot reproduce the official emulator exactly, the difference is
recorded in that profile's `officialEmulatorDivergences`, whose `key` names either a
configuration key or the profile-derived behaviour. Two are recorded today:

- `firestore.indexValidation`: the `emulator` profile assumes every composite index a query
  needs, because the pinned official Firestore emulator does not check composite indexes at all,
  and reports each assumption. The `strict` profile applies production's rules instead, verified
  against a real project, including the index merges production performs.
- Storage per-profile rulings: the strict profile answers as production was recorded answering; the emulator profile follows production too, except that where production would make it refuse more than the official emulator (firebase-tools 15.28.2) it gives the official answer and the difference is recorded here. The rulings are in the owner ledger line "STORAGE-RULES local parity: per-profile rulings" (2026-10-01, `docs.local/instructions/owner-decisions.md`).
- Storage credentials, limited to what was recorded (stage 3 v9, 2026-09-30, recording `stage3-20260930c`; response blobs by sha256). Strict: `Firebase ` followed by a non-empty value without a dot is an unauthenticated caller (the recorded value is 32 base64url characters; an empty value, `Firebase ` with nothing after it, was not recorded and is refused with 401; `case/token-malformed/subject/subject` 403 `8cb089d6475d64276d4e54aa50c0296082f88546c0ae4b44797bde6ac541a35e`, `case/precedence-{absent,present}-firebase-malformed-valid/subject/subject` 403 the same blob, `case/precedence-{absent,present}-firebase-malformed-malformed/subject/subject` 400 `523829e6a7bba3faca59653aea66fef2b2f7f1049ded5baed2390771bb09ae9e`, where the body parser answers before any credential is read). Nothing else is loosened: every other value that fails to decode, whatever its segment count, a `Bearer` value on the Firebase dialect, and a three-segment value with a tampered signature, an unknown `kid` or an unsupported algorithm, is refused with 401, because no recording shows production answering them as no credential. In both profiles an ID token whose refresh tokens were revoked is honoured (`case/token-revoked/subject/subject` 200 `cae662172fd450bb0cd710a769079c05bfc5d8e35efa6576edc7d0377afdd4a2`); production's Storage Rules do not check revocation, and revocation is the last check of the verification, after signature, expiry, audience, account and disabled. Emulator profile: every value that fails to decode or verify is an unauthenticated caller and never the claimed user (ledger "Rules emulator-profile signed-token verification"); the official emulator (firebase-tools 15.28.2, measured) treats a value without a dot, with two or with four segments as unauthenticated but admits a three-segment value with a decodable payload as its user (a tampered RS256 signature, an unknown `kid` and an unsigned token all answered 200 under auth-required rules), so the emulator profile refuses more there, a published difference recorded in `rules.idTokenVerification`. A malformed `Bearer` credential on the JSON API `PATCH` is refused with production's 401 under strict and ignored under the emulator profile; a token of another project is described in the ID token verification bullet below.
- Storage with no ruleset loaded: production answers a bucket without a release with 400 and "Your bucket has not been set up properly for Firebase Storage. Please visit '<console URL>/storage/rules' to set up security rules." (both recordings, `management/no-release/entry/subject`, blob `c5bd4ebab5dc80714e6460a478a3f218f0e55b8a2072506b465a68a012d09193`); the strict profile answers those bytes for the bucket's project. The official emulator refuses to start a project that is not a `demo-*` one without a rules file and loads its default open rules (`allow read, write`) for a `demo-*` project (measured, firebase-tools 15.28.2). The emulator profile follows it: it admits every end-user request for a `demo-*` project without Storage rules, and keeps its own fail-closed 403 "Permission denied. Storage Emulator has no loaded ruleset." for any other project, where the official emulator has no running state to compare; that 403 is fireemu's choice and differs from production's 400, recorded here. A ruleset cleared through the control API lands in the same no-ruleset state, so for a `demo-*` project it too falls into the open state in the emulator profile. The project that decides is the owning project of the request's bucket; the startup banner, which has no bucket, names the default project's state only.
- Storage headers and bytes, strict profile: JSON answers carry `Content-Type: application/json; charset=UTF-8` on both dialects, the JSON API's error bodies use the Google-fronted pretty layout (code, message, errors[message, domain, reason], final line feed) and its 204 carries `Content-Type: application/json`, as compared against the two stage 3 v9 recordings (3641 rows: status, content type and, for error rows, bytes). The emulator profile keeps the official emulator's lowercase charset and compact bodies. The JSON API's absent-media 404 is `text/html` in both profiles, as production and the official emulator answer it (measured on the four routes that reach it); fireemu typed it `text/plain` for reflected-HTML safety until the owner ruled that matching production takes priority for a tool that runs locally (owner ledger, "STORAGE-RULES media 404 content type", 2026-10-01, `docs.local/instructions/owner-decisions.md`), and strict writes production's uppercase charset. One difference remains: the Firestore programs of the corpus read the Firestore adapter, whose JSON content type (`charset=utf-8`) is outside the Storage framing. Headers other than `Content-Type` (`Vary`, `Cache-Control`, `Pragma`, `Expires`, upload and trace headers) are not compared except where a recorded answer pins them above.
- Storage object guards, ranges, names and media headers (recorded, STORAGE-OBJECT lean-v4 and lean-v5, probe-v4; official behaviour measured with firebase-tools 15.28.2). Guards: strict answers as production does (304 for a not-match guard that names the current value, production's 412 body for a match guard that fails or has a negative value (recorded: `-1`), a not-match guard with a negative value accepted, production's 400 `Invalid long value` for a value that is no `long`, the write not done); the official emulator reads no guard and the emulator profile ignores them too. `PUT` on the object updates metadata in both profiles (production 200; the official emulator 501) and, unlike `PATCH`, replaces the custom metadata and drops the download tokens when the body carries `metadata` (recorded, lean-v4); what it does to omitted fields was not recorded. A read of a name with a line feed is a 404 in both profiles (the official emulator answers 404 too). Under strict an unsatisfiable range is production's 416 (the JSON API: the `text/html` sentence with `Content-Range: bytes */N`; the Firebase dialect: an XML `InvalidRange` body naming the range; an empty 206 for a nonzero suffix of an empty object on the JSON API), where the emulator profile keeps the official emulator's whole object. The JSON API list with `maxResults=0` is the bare kind under strict, the official emulator's token answer in the emulator profile. Media answers (200) carry production's headers under strict (not `date`, `expires`, `last-modified`, `server`, `alt-svc`, `x-guploader-uploadid`, `x-goog-gcs-base-ts`), the official emulator's in the emulator profile. The Firebase list pages as production does in both profiles (token = the base64 of the last entry returned, items and prefixes in one merged order); `maxResults=0` is production's 400 under strict and the official emulator's empty page in the emulator profile. Not reproduced, and so not claimed: malformed guards on reads (a GET with a guard that is no `long` gets the JSON 400, but production's answer was never recorded for a read; the recorded failing guard on a media read was a `text/html` sentence), the headers of the 416 and 206 answers beyond status, content type and body, the two-space layout and key order of Firebase list success bodies (compared after JSON normalization), the XML API route (`GET /<bucket>/<object>`, answered as the official emulator does in both profiles), and the order of the line-feed 404 against Rules (it comes first; production's answer under a denying rule was not recorded).
- Storage response shapes: where no refusal is involved, both profiles answer the Storage success and error bodies production was recorded answering (stage 3 v9, 2026-09-30) rather than the official emulator's: millisecond timestamps, `timeFinalized` on the JSON API object resource, base64 `crc32c` and a default `contentDisposition` on the Firebase dialect, no empty `metadata` map or absent `downloadTokens`, first-metadata-read token minting only, the `Not Found.` JSON body for an absent Firebase object, the recorded parser-error bodies of a malformed `PATCH`, an empty resumable start answer and the `Upload has already been finalized.` cancel. The storage probe pins each difference from the official emulator as a documented divergence (`conformance/storage-matrix.json`, `conformance/divergences.json`).
- ID token verification on the Rules surfaces: the official emulators verify nothing at all — the Storage emulator runs `jwt.decode` and the Firestore emulator was measured to admit an unknown subject, a 1970 expiry, a missing issuer, another project's audience and a garbage `RS256` signature. The `emulator` profile reproduces the part `@firebase/rules-unit-testing` depends on and keeps two differences from the official emulators: on Firestore the audience must name the routed resource project, and a token that fails verification is never admitted as its claimed user (Firestore refuses it; Storage treats the caller as anonymous). Both are refusals of requests the official emulator admits, which is why they are recorded rather than left implicit. On Storage the emulator profile admits a token minted for another project, as firebase-tools 15.28.2 does (it never reads `aud`); the strict profile refuses it with production's 403 `Permission denied.` (measured: stage 3 v9, `token-foreign-project`), so the emulator profile accepts a foreign-project ID token on Storage where production does not. The Storage refusal bodies differ the same way: the strict profile answers a rules refusal with production's recorded bytes (`Permission denied.`, pretty-printed JSON, `application/json; charset=UTF-8`), while the emulator profile keeps the official emulator's `Permission denied. No READ|WRITE|LIST permission.` envelope. The Cloud Storage JSON API differs the same way for a credential: the strict profile refuses a malformed `Bearer` credential on `PATCH /storage/v1/b/<bucket>/o/<object>` with production's recorded 401 `Invalid Credentials` (measured: stage 3 v9, the `precedence-*-gcs-malformed-*` rows; the other JSON API routes were not recorded and are not refused), while the emulator profile ignores the credential on every JSON API route, as the official emulator does. In that profile, an unregistered Firestore project owned by the default session can use a rules-unit-testing mock token whose audience names the routed project. The configured default Auth project is not substituted for the resource namespace. Storage continues to use the owning session for tenancy, App Check, fault injection, resumable-upload state and object storage; a tenant-qualified request cannot use this fallback, and no session or bucket registry entry is created.

`compat-check` checks every key and value both profiles name against
`spec/config/fireemu.schema.json`, and checks that the profile names the contract declares are
exactly the values that schema's `profile` key accepts, so neither the sets nor the names can
drift from the configuration surface.

The release workflow checks both profiles on the linux-x64 package it publishes, installed the way a user installs it, before anything is published. `verify-artifact` replays the conformance corpus under the `emulator` profile against the recordings of the pinned official Local Emulator Suite (`conformance/fixtures`). `strict-production` reruns, under the `strict` profile and in a network namespace with loopback only, every local comparison a `COMPAT_VERIFIED` parent's closure names in its `integratedRegression`, and requires each to equal the committed file row by row (status and row summary) with `conformance/src/release-strict-regression.mjs`. Two comparisons cannot run there because their production inputs are not published: the saved 23-row stream transaction replay of FS-DATA-WRITE (`FS-DATA-WRITE/stream-transaction-precedence` stays on the lane evidence), and the row-by-row comparison of FUNCTIONS-HTTP, whose production recordings are private; for FUNCTIONS-HTTP the job requires the local strict recording to be the same bytes the lane compared with them, which fixes every row's result. Platform packages other than linux-x64 are compared after publication.

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
| `CC-06` | a deferred or not-planned product that reads as supported: named in a manifest `implemented` list, named with no scope disclaimer on a line of the README or of a document the claim scopes (`claim.scopedDocuments`, the npm package description a release ships; the npm package page is generated from the README), carrying a parity claim, or declaring no prohibited terms at all |
| `CC-07` | contradictory public statements (below) |
| `CC-08` | a compatibility profile that sets or declares a configuration key the canonical schema does not define, or a value it does not allow; a `declared` key without a `hand-written` / `not-implemented` status and a note, or one that is also under `sets`; a profile name the schema's `profile` key does not accept (a profile no run can select is a document, not a switch), and a name that key accepts which the contract does not declare |
| `CC-09` | a conformance fixture cited as evidence that carries an unresolved `debt` step the claim does not exclude by name with its owning issue; an exclusion without an issue or a reason, or one whose step is no longer debt (stale); a fixture with no `parity` or `documented-divergence` step, which nothing local answered and which is therefore not evidence; and a step status the conformance suite does not define |

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
