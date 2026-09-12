# Broad Identity Platform and Firestore inspection

This milestone changes priority, not historical evidence. Lifetime revisions 1/2 retain their receipts and subjects; revision 3 remains a prepared, offline-validated, production-unobserved deep-dive corpus. GAP-AUTH-007 and AUTH-U03 remain open independently of broad work. No new production operation is authorized or performed here.

## Reuse and current execution

`tools/compat-broad/broad.py` is a thin local-only owner over the existing Auth and Firestore `PROGRAMS` and `session.mjs` implementations. It builds and copies one artifact, starts an isolated strict Standard Native instance with OS-assigned ports, validates the parent/control relationship, runs both services, and confirms process/listener shutdown. It does not call either `record-production` entry, including reuse mode: those paths can authenticate/contact production before deciding to reuse a file.

The entry captures a common manifest, explicit selected operation inputs and seed, case results, current source/runtime/artifact/configuration hashes, original observation identities and a generated summary. No database, UI or replacement DSL is introduced. Existing historical tools and lifetime recorders stay intact.

The checked-in catalog separates pinned API-method denominators, functional families and existing executable cases. An unexecuted catalog row never becomes passed because an old receipt exists. Use the current run manifest for executed family/case status and the catalog for unselected scope. The 169 pinned methods are a known-source denominator, not proof of a complete upstream specification or coverage of every field.

## Initial selection and coverage

The [next expansion](../../docs/compatibility/broad-expansion.md) adds exact historical transform replay, type/numeric/filter/aggregation comparisons, real SDK/Rules/Listen local checks, and an offline-reviewed production batch adapter. The table below describes the initial milestone; current selected cases and execution variants are in the catalog.

| Family | Reused assets and added coverage | Important remaining limits |
| --- | --- | --- |
| Auth accounts | Password/anonymous create, lookup, update, delete; new six/five-character boundary, rejected-create absence and deletion readback | Tenant/provider/import/export cases not executed |
| Auth credentials | Existing normal/wrong/unknown password cases; new password change, old/new sign-in and refresh identity | Token expiry/propagation and external custom IdP behavior remain unobserved |
| Auth authorization | Existing invalid-token errors; new admin/self/other-user/unauthenticated update and rejection-state checks | New checks are local regression invariants; historical token normalization cannot prove ownership |
| Firestore writes | Preconditions, masks, atomic commit, non-atomic batchWrite, empty writes, state after refusal; current transforms executed but old sequence is different | Changed transform sequence is not joined by reused row ID |
| Firestore queries | Inclusive/exclusive/prefix cursors, limits and cursor errors; new zero/negative limit with unchanged document readback | Broader filters/types and index permutations are next units |
| Firestore transactions | Begin/read/write/commit/rollback/conflict and poststate | Timed-out historical/local writes remain indeterminate; no single stream history is promoted to a universal order |

These were selected for existing stateful programs, usable historical observations and user impact. They exercise normal, isolated refusal, representative boundary and operation/poststate dimensions. Auth concurrency is not exercised in the initial batch. Firestore transaction contention has incomplete timed-out observations; it is not treated as a proven concurrent-history oracle. The local SDK, Rules, Listen, Enterprise/Pipeline/full-text and MongoDB paths remain separately listed with next units or blockers.

## Historical comparison contract

The comparator retrieves the recorded corpus's source commit from the stored matrix, reproduces its serialized corpus digest, and checks the session/normalizer bytes. It compares only whole programs whose typed canonical definitions match. This avoids false joins when an old row ID was reused for a different transform request. Missing or unexpected steps, seed failures, non-JSON responses and no-response sentinels are retained as not-run/indeterminate, not matches.

Successful bodies preserve field presence, JSON types, values and array order. Error status and canonical code use the existing comparator boundary; textual message differences remain visible. Python boolean/numeric equality is not allowed to equate different operations. Auth `$from` and Firestore transaction/updateTime references bind to newly returned runtime values, never old production tokens.

Historical normalizers erased some token/ID/time/expiry information and did not retain ownership mappings. Therefore historical comparisons are exploratory scoped references, not formal whole-service verification. Additional live-local identity/state checks preserve concrete ownership relationships as booleans, without inventing production answers. Production OAuth versus local owner operations do not verify user Rules. REST does not verify gRPC/WebChannel/SDK. Standard results do not cover Enterprise.

The first run found one apparent cursor mismatch caused by omitted index configuration under strict. Its minimal query orders by g,n with a prefix cursor q, requiring a composite already present in the recorded production index file. This is a harness configuration cause, not evidence for changing the cursor runtime. Preserve the original mismatch; recompare with the pinned historical index bytes and record the changed configuration independently.

## Reproduction

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --check-catalog
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --run --output /absolute/private/new-broad-run
```

The owned run requires a clean frozen checkout. Do not edit it during execution, review or mutation verification. Node sessions are bounded by a local-origin/redirect guard, request and wall limits; environment credentials/production probe overrides are not inherited. Firestore reset routes are permitted only on the owned instance. The new Auth sequence has a separate request/time bound. Private process registrations support PID/argv-verified cleanup; cleanup errors cannot skip parent termination or final failure recording.

See the common results/triage report for exact executed SHA, artifact and commands, and the proposed production envelope for a future owner decision. Technical review is separate from execution permission and result approval. No case-level approval/publisher system is added to this broad milestone.

## Prepared batch adapter

`batch_adapter.py` validates the closed candidate offline by default. `batch_local.py` runs the mapped operations on a newly owned artifact; `batch_comparison.py` checks local mapping against the same current abstract inputs. The local branch never acquires Google credentials. The remote branch requires a separately supplied, manifest/observer/nonce-bound owner approval, approved metadata baselines, API-key project verification and confirmed tariff ceilings. No approval is supplied by this repository.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output /absolute/private/new-mapped-batch
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_comparison.py --batch /absolute/private/new-mapped-batch/batch/result.json --baseline spec/compatibility/broad-runs/bf12f631-expanded.json --output /absolute/private/mapping-comparison.json
```

The first candidate contains 19 Auth checks and 27 Firestore diagnostics, with at most three attempted accounts and eight possible document targets. Its collection IDs are preserved beneath owned parent documents; collection-group queries and composite-index-dependent query candidates are excluded. Journals are private, append-only and fsynced before attempts. The email/path nonce and journaled UID binding are adapter ownership evidence, not an immutable Firebase account attribute.

All requests and credential commands consume one phase budget. A sequential rate limiter permits at most four starts per second; a subprocess watchdog bounds the whole request including DNS and body reading. Privileged HTTP401/403 or failed expiry verification disables subsequent privileged work, including recovery; unconfirmed targets remain in the journal/report. No broad reset, recursive root deletion or configuration mutation is implemented.

## Same-batch production/local comparison

`batch_pair.py` is the separate production/local entry. Schema2 reports bind the frozen observer, candidate manifest, abstract operation definitions, each actual principal and request, compiled namespace, and the versioned normalization implementation. Both sides must contain the same46 ordered diagnostic rows with the expected canonical requests; query preconditions, fields, types, array order and mapped ownership are preserved. Only Auth API-key values are replaced in query bindings. A changed or missing operation on both sides is invalid, even when the two records agree with each other.

Auth response tokens/verifiers and known absolute server-time values are normalized with type/presence checks; relative expiry remains compared. Known creation-ledger emails, including password-provider federated IDs, and UIDs are mapped by observed ownership. Unknown values remain different. These comparisons do not prove cryptographic token validity, rotation, exact server time/TTL or error prose equality. Raw bounded response status, Content-Type and parsed body are retained in the private `responses.jsonl` before response stop conditions. This file can contain live credentials and verifier data: keep the entire run directory private and do not publish it. Response digests use canonical typed JSON, not raw HTTP wire bytes. Auth rows are emitted incrementally, so a later failure cannot erase earlier observations.

Recording completion requires all46 rows, no collection failure and no unrecovered resources. A complete incompatibility is a valid observation. Adapter/local wrapper failures exit nonzero; the local wrapper also requires owned processes stopped and listeners closed. Pair comparison exits2 for incomplete or invalid inputs,0 for a complete report including mismatches, and1 for complete mismatches when `--check` requires equality. Old schema1 mapping reports cannot be promoted into production/local comparison evidence.

```sh
# Offline preparation from a clean frozen execution checkout; this creates no permission.
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json --prepare-inputs /absolute/private/execution-inputs.json
# Local recording at that same frozen observer.
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output /absolute/private/new-local-batch
# After a separately authorized production recording exists, report actual differences.
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --production /absolute/private/production-batch/result.json --local /absolute/private/new-local-batch/batch/result.json --output /absolute/private/pair.json
# Add --check only when the caller requires compatibility equality.
```

An owner permission must use `kind=owner-execution-permission`, retain the prepared frozen commit, observer/manifest/comparison/projection contract hashes and project identity, and explicitly supply every `ownerInputs` value. The prepared package itself is not accepted as permission. Execute from that exact clean commit; keep run outputs outside the checkout. The owner must approve the current Database projection/Auth baseline, location-specific tariff confirmation, validity window, unused32-hex nonce, budgets and recovery terms. The production command, only after that separate permission, is `batch_adapter.py --manifest <manifest> --approval <owner-permission> --nonce <approved-nonce> --output <new-private-directory>`, using the preconfigured `PRODUCTION_ORACLE_API_KEY`. This milestone does not run it or obtain credentials.

Database evidence records separate full parsed-response and settings-projection hashes. Projection `database-settings-v2` excludes `earliestVersionTime` and `etag` from settings equality; both remain in complete saved responses and full response hashes. The saved approval/preflight/postflight responses from the stopped7be6cf08 attempt differ only in these response metadata fields. Historical v1 records remain unchanged; identity, edition, location, other settings, unknown fields and field presence/types remain bound. The same contract is used before and after execution. Google documents that `earliestVersionTime` continuously advances with the retention window, so its isolated movement is not configuration drift. [Database REST reference](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases) supplies this distinction. UID/edition/location changes still stop execution.

The existing CI broad pytest step discovers the pair/exit/projection tests, alongside candidate/catalog checks; lifetime revisions1/2/3 and all four existing publisher checks remain independent. Input fixtures, local invariants, local mapping checks, historical production references and future production/local comparisons remain separately labeled.

## Re-evaluate the saved initial46 after runtime fixes

`--saved-ab7bd698` is an explicit offline comparison mode for the immutable `bc38f392` production observations published at `ab7bd698`. It verifies the byte hashes of both the published normalized rows and the independent completion/cleanup receipt. The original observer, manifest, comparison contract and35-match/11-mismatch result remain unchanged. The new local recording must bind the current observer, manifest and comparison contract, expected ordered46 operations/principals and owned namespace, and must complete collection and cleanup. Changed assertions alter the scenario source digest, but do not change those46 requests. No production acquisition occurs in this mode.

`batch-response-v2` additionally normalizes valid RFC3339 strings only at Auth `users/*/lastRefreshAt`. Calendar-invalid strings, invalid timezone offsets, field absence, JSON types and other locations remain significant. The field represents the stored last successful ID-token issuance time, not lookup time. The comparison cannot recover token bytes or timestamps already erased by the old normalization. It reports separate old and new bindings instead of pretending both recordings used the same observer. The ordinary `--production` mode still requires the same observer on both sides.

The local wrapper explicitly configures `daemon.authProjectNumbers` for its target project. The runtime accepts project-ID keys and positive decimal-string project numbers; refresh uses the configured number while JWT audience/issuer keep the project ID. An unmapped project retains the project-ID fallback, without inventing a numeric identity. Namespace routing, tenants and snapshot restore preserve the destination mapping.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output /absolute/private/postfix-local46
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local /absolute/private/postfix-local46/batch/result.json --output /absolute/private/postfix-comparison.json --check
```

Run both commands from the same frozen source checkout. The result is a candidate comparison to saved production evidence, not new production observation or owner result approval. The historical193 matches,26 local checks,23 indeterminate cases and46 mapping checks retain their original scopes. The current20 transform rows compared here are recorded separately from older indeterminate histories.
