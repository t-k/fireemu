# Production-first differential pilot

Task: `PROD-DIFF-PILOT-001`. Additive, opt-in Node 22+ tooling; no dependency install,
package-script edit, CI change, runtime edit, permission, or new production observation.

## What this implements

`list → plan → replay → compare → report` for two complete historical programs, selected
with `--case`:

- `fs.batch-write.saved-20260907.v1` (default): `writes/batch-write`, five ordered steps.
  It uses **only the production side** of the published
  `conformance/firestore-production-matrix.json`, not the official emulator or its
  divergence register. The historical test names are kept, but are NOT expectations:
  `non-atomic-batch` actually returns `400 INVALID_ARGUMENT` because it writes duplicate
  documents, `one-was-written` actually observes absence, and `existing-was-deleted`
  actually observes the unchanged existing document. Other assertions include empty
  BatchWrite and the rejected unknown transaction field.
- `fs.commit-transform-limits.saved-031c74bfe.v1`: the Commit field-transform 500/501
  per-document boundary (`FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT`), 17 ordered steps.
  This campaign's public result
  (`spec/compatibility/broad-runs/fs-commit-transform-limits-*.json`) is a digest/summary
  record; the raw production request/response journal is private and not published. This
  case therefore does **not** replay production bytes: it compiles the campaign's own
  deterministic request plan locally (a pinned, test-cross-checked JS port of
  `tools/compat-broad/fs-commit-transform-limits/transform_compiler.py`) and compares the
  local execution against a typed reference built from that plan's own declared contract
  plus the one literal fact the summary record publishes verbatim -- the refusal message
  text. See `commit-transform.mjs`'s module docstring and `registry.mjs`'s `compared` /
  `notEstablished` fields for the exact, disclosed scope of what this case does and does
  not establish; it is a materially weaker evidence kind than the batch-write case's
  saved production reference (`evidenceKind: "documented-production-outcome-reference"`
  in `plan`'s output, vs. `"saved-production-reference"`).

No existing campaign is delayed or replaced by either case.

## Commands from the repository root

```sh
# No emulator, credentials, Java, package installation or production I/O.
node conformance/production-diff/pilot.mjs list
node conformance/production-diff/pilot.mjs plan

# Test the adapter and its failure paths. The recorder test reads the actual pinned
# conformance/src/firestore-probe/{session,credentials}.mjs from this checkout.
node --test conformance/production-diff/test/*.test.mjs

# Check the adapter against the actual saved production + historical local rows.
# This does NOT execute a current native artifact.
node conformance/production-diff/check-installed.mjs

# Build fireemu through the existing session wrapper, separately from offline replay.
scripts/cargo-session --session prod-diff-pilot -- cargo build --locked -p fireemu
TARGET="$(scripts/cargo-session --session prod-diff-pilot --print-target-dir)"

# Parent exists; run directory MUST NOT exist and MUST be outside the repository.
# Use a new, private directory name for each invocation.
node conformance/production-diff/pilot.mjs replay \
  --binary "$TARGET/debug/fireemu" \
  --out /absolute/private/new-pilot-run

# Pure saved-record recomparison. Does not start fireemu or contact any service.
node conformance/production-diff/pilot.mjs compare \
  --run-dir /absolute/private/new-pilot-run \
  --out /absolute/private/new-pilot-recomparison

# Same four verbs for the Commit field-transform case, via --case.
node conformance/production-diff/pilot.mjs plan \
  --case fs.commit-transform-limits.saved-031c74bfe.v1
node conformance/production-diff/pilot.mjs replay \
  --case fs.commit-transform-limits.saved-031c74bfe.v1 \
  --binary "$TARGET/debug/fireemu" \
  --out /absolute/private/new-commit-run
```

`--repo /absolute/checkout` selects a checkout explicitly. `--case` accepts
`fs.batch-write.saved-20260907.v1` (default) or
`fs.commit-transform-limits.saved-031c74bfe.v1`; `pilot.mjs list` prints the full
registry. There is deliberately no `observe`, `production`, endpoint, shell-command,
arbitrary-module, or arbitrary-oracle option. No CLI writes under the repository. The
default parent supervision deadline is 180 seconds; `--timeout` accepts 10–600 seconds.
This deadline is an operational bound, not a timing assertion.

The build command is not run by `replay`, and replay never installs dependencies or
fetches missing git objects. A shallow repository missing the historical object must
obtain it during a separate explicit repository-setup step. Do not weaken a pin or use
an unverified summary just to get a green run.

## Reused code, and why a temporary extraction bridge exists

- The input is compiled from `programs.mjs` at the recorded source
  `2526c61eda5fc53ac91250307786127ae3c601be`. Both the Git blob and full serialized corpus
  digest must match the production metadata. The selected whole-program digest and step
  order must also match. Matching row names alone is never sufficient.
- The existing `session.mjs` and `credentials.mjs` are copied byte-identically into a
  private run directory. Their blobs also match the original observation's source. The
  existing recorder executes the requests and normalizes responses.
- `compareProductionToFireemu` is reused with its three existing pure helpers. Importing
  its entire `run.mjs` would load the official-emulator divergence authority and unrelated
  acquisition dependencies. To avoid editing shared code or making the official emulator
  a prerequisite, `legacy.mjs` extracts only these four declarations from the existing
  source using fixed boundaries and checks an exact effective-code SHA-256 before import.
  It does NOT carry a second production comparator implementation. Changes outside the
  selected declarations do not require changing the effective-code pin. The complete
  source blob actually read is still recorded for provenance.
- Once the owner of `run.mjs` provides a side-effect-free export module, replace this
  temporary bridge with an ordinary import and prove the same complete/mutated/incomplete
  classifications. Do not generalize it into an arbitrary JavaScript extractor.

The test-only excerpt contains those same four declarations for tests that need no
complete repository. Its effective-code hash equals the bridge pin. It is not a full
upstream file and cannot pass the oracle/source acquisition checks.

## Local isolation and recording

`replay` copies the explicitly supplied **native** binary (ELF/Mach-O) and records its
SHA-256. A script masquerading as a native binary is refused. The binary is launched via
its existing `fireemu exec` path, with a private `strict` Standard/Native configuration,
only Firestore enabled, `demo-firestore-probe`, and OS-assigned ports. This does not
change the project's default profile. Production credentials, proxies and Node options
are not inherited. The child uses the endpoint assigned by that owned process, never a
caller-supplied server. It must be IPv4 loopback.

The pinned recorder is wrapped with an exact request-sequence check: for batch-write,
reset, seed, then the five known operations (`local-session.mjs`); for
commit-transform-limits, the plan's own 17 compiled operations with no separate
reset/seed prefix (`commit-transform-session.mjs`) -- its own `create-only-patch` steps
are the seeding. Method, route, body and local owner authorization are checked before
dispatch. Redirects, DNS, subprocess/credential commands and off-origin requests are
refused in the recorder process. Response sizes and elapsed time are bounded. This Node
guard is **not an OS sandbox for an arbitrary or malicious native binary**; use a trusted
caller-built fireemu. The source pin is code identity, not upstream correctness.

Finally the owned local database is reset and all four possible document target paths are checked for
typed absence. Only this throwaway daemon may be reset. The existing exec teardown plus
parent process-group supervision must complete, and the recorded listener must refuse a
new connection. No shared process is killed or remote resource deleted. Failed setup,
incomplete recording, failed cleanup, lingering processes and changed relevant source
are not accepted, even if some rows happen to match.

Run files are private and no-replace. They include local output, the request journal,
cleanup result, binary/source/input hashes, a machine-readable result and a small report.
No passwords or actual cloud credentials are inputs to this program. Logs remain private.

## Verdict and evidence scope

Exit 0: every scoped row comparison matches (five for batch-write, 17 for
commit-transform-limits), local execution and cleanup completed. Exit 1: complete
recording, at least one semantic mismatch. Exit 2: invalid/unavailable inputs, timeout,
missing rows, setup/cleanup failure or other indeterminate execution. An error report is
not a successful compatibility gate.

The old comparator's aggregate `mismatches` count includes indeterminate rows. The new
summary counts `MATCH`, `MISMATCH` and `INDETERMINATE` separately, while preserving the
legacy summary for inspection. Missing/extra/reordered rows and setup errors are checked
outside that comparator, rather than being lost in its permissive input projection.

This contract compares HTTP status, canonical error codes, normalized success bodies,
and the two historical post-state reads. It does **not** establish error-message/detail
parity, exact times, token behavior, user Rules, SDK/WebChannel/gRPC, concurrency, valid
non-duplicate BatchWrite continuation, or Commit 500/501 limits. The old recorder erased
information; the adapter does not recover it. Original raw acquisition/cleanup journals
are not in this normalized matrix, so this is explicitly a legacy scoped reference.

A supplied binary's bytes are bound to its observed result. Its derivation from the
checkout is NOT proven by taking the current HEAD: `sourceBinding` says that a separate
build receipt is required for final acceptance. `compare` retains the previous artifact
and execution provenance and reports `freshLocalExecution: false`. Neither command
promotes a parent or replaces independent review / final G1/G2 acceptance.

## Work ownership

Only `conformance/production-diff/` is added. Shared runtime, Gate/Ledger, live campaigns,
existing receipts, package files, lockfiles, CI, `.claude`, task ledgers and GitHub metadata
are unchanged. Keep current G1/G2 work running. The integrator reviews, commits and pushes
this patch normally; this tool never runs git writes.

`check-installed.mjs` still checks only the batch-write case (it compares against
`conformance/firestore-production-matrix.json`'s own recorded `fireemu` rows, a shape the
commit-transform-limits case has no equivalent of -- see `commit-transform.mjs`). The
commit-transform-limits case's own self-consistency checks (compiler-plan drift, saved
record pin, refusal-message pin) run inside `prepareCommitTransform`, exercised by
`pilot.mjs plan`/`replay`/`compare` and by `test/commit-transform.test.mjs`.

The five other FS-EVID-001 references named in
`docs.local/agent-dags/compat-v2-20260921/raw/prod-diff-replay.md` (first46, second45, G0,
limits-02, write-txn) are still not wired into this pilot; each has its own Python-recorded
saved matrix under `spec/compatibility/broad-runs/` in a shape this module does not read.
Extending to any of them is unscheduled follow-on work, same as commit-transform-limits was
before this case.
