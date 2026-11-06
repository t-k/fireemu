# Proposed Data Connect compatibility parent

Status: design proposal awaiting owner decision. Data Connect remains deferred in fireemu. This document proposes a future compatibility parent; it does not register a parent, enable a service, claim parity or authorize implementation. The owner must choose an approach before the offline fixture phase begins.

## Current behavior

The [`dataconnect` surface](../../spec/compatibility/contract.json) is deferred with no compatibility claims. [`UNSERVED_OFFICIAL_SERVICES`](../../crates/fireemu/src/config.rs) rejects `--only dataconnect`. The [capability inventory](../../crates/fireemu/src/capabilities.json) records that the Hub clear-data operation is unimplemented. [Import handling](../../crates/fireemu/src/import_export.rs) refuses a Data Connect section before restoring supported sections, avoiding a silently partial restoration. The existing [`a_data_connect_section_is_refused_with_the_deferred_status` test](../../crates/fireemu/tests/import_export.rs) checks failure and that the requested child command does not start.

Two premises in the existing deferral explanation need qualification. Data Connect has client-facing protocols, but reproducing them requires its schema, authorization and query semantics, not just PostgreSQL forwarding. Also, Firebase [announced general availability on April 9, 2025](https://firebase.blog/posts/2025/04/dataconnect-general-availability/); the contract's preview rationale is stale. Current documentation calls the product SQL Connect, while configuration and CLI names still use `dataconnect`. These corrections do not remove the distribution constraint or establish compatibility. The executable behavior and contract remain unchanged by this proposal.

## Official emulator architecture

The reference baseline is firebase-tools **15.28.2**, which pins the separately downloaded Data Connect toolkit to **3.4.18**. These findings come from source inspection, not emulator or production executions.

The [CLI lifecycle implementation](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/dataconnectEmulator.ts) invokes the toolkit for schema building and SDK generation, launches its development server, and configures its PostgreSQL connection. Setting `FIREBASE_DATACONNECT_POSTGRESQL_STRING` selects an external database. Export is explicitly unsupported in that external-database mode. Credential environment forwarding and production Vertex AI integration are possible, so starting an emulator alone does not guarantee offline execution.

The default database is [PGlite behind a PostgreSQL wire gateway in Node](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/dataconnect/pgliteServer.ts), rather than a standalone PostgreSQL container. The gateway advertises PostgreSQL 17.4/PGlite 0.3.3 and loads vector and UUID extensions. That advertised string is not an independently verified package-lock version. Its export is a PGlite data-directory snapshot; it must not be assumed interchangeable with a generic PostgreSQL dump.

[Download handling](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/downloadableEmulators.ts) uses a cached executable and verifies ordinary downloads. The version override bypasses checksum and size checks, so a reproducible runner must prohibit it. The [pinned artifact manifest](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/downloadableEmulatorInfo.json) lists macOS amd64/arm64, Windows amd64 and Linux amd64 artifacts of approximately 32–34 MB each; it does not list Linux arm64. Node dependencies and database storage are additional costs.

The [official emulator guide](https://firebase.google.com/docs/sql-connect/data-connect-emulator-suite) describes local PGlite use. The [CLI reference](https://firebase.google.com/docs/sql-connect/cli-reference) documents startup and import/export workflows. Those current pages supplement the pinned source; they are not versioned behavioral recordings.

## Alternatives and estimated cost

Estimates below are engineering judgments for one experienced engineer delivering a restricted local MVP with verification. They exclude complete parity, production authorization and recording, external review delays and major upstream feature additions. Every option also needs a common offline fixture phase, estimated at 1–2 engineer-weeks after the owner decision.

| Approach | Initial estimate | Recurring cost and constraints |
| --- | --- | --- |
| A. Wrap the official toolkit | 2–4 engineer-weeks for lifecycle, configuration, verified artifact handling, isolation and tests | Approximately 1–3 engineer-days per compatible upstream update, with platform failures separately scoped. Reuses official schema/SDK behavior but requires the Google executable. |
| B. Implement the client protocol and a schema subset over PostgreSQL started with podman | 8–16 engineer-weeks for a small named-operation CRUD, relationship and authorization slice | Several engineer-days per relevant compatible protocol release; new schema features require separate estimates. PostgreSQL supplies relational storage and transactions, but fireemu still owns GraphQL directives, compilation, authorization and response semantics. |
| C. Implement the engine and storage natively | 6–12 or more engineer-months for a useful restricted subset | Dedicated ongoing ownership of query planning, SQL types, constraints, isolation, migration, GraphQL and authorization. No credible complete-parity date follows from this estimate. |

### Distribution and licensing

The existing contract explicitly excludes downloading or redistributing the Google toolkit. Option A therefore needs an owner decision changing that policy, or accepting a separately specified user-supplied-toolkit model. Its smaller implementation estimate does not override that constraint. The [firebase-tools source license](https://github.com/firebase/firebase-tools/blob/v15.28.2/LICENSE) is MIT; this does **not** establish the separately distributed toolkit's redistribution or embedding rights. Those terms remain unverified, and no binary should be bundled on the assumption that the CLI license covers it.

Option B avoids the Google binary in the fireemu runtime but introduces podman and a user-provisioned PostgreSQL image as explicit dependencies. The owner must accept this departure from a dependency-free local runtime. The image and included extensions need pinned versions/digests and a dependency-license inventory before implementation is shipped. This proposal neither selects an image nor asserts its redistribution terms. Docker is not an option.

Option C offers the strongest eventual single-binary packaging but places PostgreSQL compatibility inside fireemu. An embedded database or existing storage abstraction does not by itself reproduce PostgreSQL behavior.

### Offline operation

For A, installation and verification of the toolkit and Node dependencies must happen before an offline run. For B, podman and the exact PostgreSQL image must already exist locally; startup must prohibit image pulls. Both need bounded owned-process cleanup, explicit loopback endpoints and disabled external egress. Missing artifacts must fail before startup rather than trigger downloads. Do not pass credentials, enable remote resolvers or use production-backed embeddings in the offline fixture suite.

The official emulator used as a test oracle is a separate development dependency from the shipped fireemu runtime. Acquiring that oracle for future fixtures does not imply approval to distribute it with fireemu.

## Recommendation and initial scope

Recommend **B**, subject to owner acceptance of the PostgreSQL/podman dependency and its cost. It respects the existing exclusion of the Google toolkit from fireemu's distribution while delegating relational storage to PostgreSQL. It is a schema and protocol implementation project, not a thin SQL proxy. If the owner instead changes the distribution policy and resolves the toolkit terms, A provides the shorter route to official-emulator compatibility. C has the highest cost and semantic risk with the evidence currently available.

A first proposed B slice would support one local service and connector, checked-in schema and named operations, scalar CRUD, one relationship, deterministic response envelopes and verified local Auth integration. Schema compilation and generated-SDK interoperability need their own evidence. Initial exclusions would include service provisioning, Cloud SQL IAM, remote resolvers, production-backed embeddings, subscriptions, SDK generation and official snapshot compatibility. Excluded features remain gaps, not completed parity. Data Connect stays deferred until a separately reviewed implementation and evidence justify changing that status.

## Common fixture phase after the decision

No fixtures are introduced by this design. The next phase would define synthetic schema, connector, data and requests with a configurable target endpoint. The same suite must first run against the pinned official emulator offline and later against fireemu. Keep toolkit digests, dependency locks, schema bytes, target identity and raw results with the fixture provenance.

Cover successful named queries and mutations, invalid variables and nullability, relationships, ordering/pagination, error envelopes, absent/valid/invalid authentication, transaction rollback and concurrent visibility, schema reload, reset and persistence. Treat default PGlite and external PostgreSQL as distinct configurations; the latter's export refusal is an expected observation to capture. Normalization may hide volatile values only when it preserves their semantic shape.

The runner must enforce the offline boundary, use a synthetic demo project, validate cached artifacts before launch and terminate only its own processes. Design the coverage ledger before tests, explicitly seed common and boundary combinations, and model transaction/lifecycle state changes before implementation. No unrecorded emulator response or production behavior should become an expected result by assumption.

## What production parity would require

No production requests were made for this design. Public documentation and official-emulator source do not establish production parity. A future parent needs separately authorized recordings of token and App Check behavior, directive coercion, constraint errors, JSON response shapes, rollback/isolation/retry semantics, SQL types and collation, ordering/null handling, migration failures and limits. Management-plane and vector integrations need separate scopes.

For an already provisioned synthetic schema, a minimal later data-plane proposal would contain 12 requests: six queries for public success, protected denial without authentication, protected success with authentication, invalid variables, an ordering/null boundary and a missing operation; two mutations for a successful write and a failing multi-step transaction; two reads to verify the write and rollback; one cleanup mutation; and one cleanup verification read. This is a proposed serial sample, not complete coverage or permission to send. It excludes provisioning, obtaining authentication, retries, recovery and concurrency. A future packet must count those separately and define how unknown results prevent blind retries and require verified recovery before execution is authorized.

## Owner decision and validation boundary

Choose whether to approve B's restricted scope and external dependency, pursue A with a distribution-policy decision and toolkit-terms review, fund C, or retain deferral. The offline fixture phase and implementation stop until that decision is recorded. Naming the prospective parent `DATACONNECT` here creates no registered claim or closure record.

This change is documentation only. Validation consists of checking source references, option completeness, privacy, diff whitespace and whether the new document is bound by existing evidence digests. Runtime tests, failing-first evidence, mutation testing and executable formal models are not applicable; zero tests or mutants were executed. Future implementation must supply those forms of evidence for its own behavior changes.
