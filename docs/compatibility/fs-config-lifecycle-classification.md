# FS-CONFIG-LIFECYCLE surface classification

Status: `PREPARATION_ONLY`. Parent group `FS-CONFIG-LIFECYCLE` stays `WAITING_ORACLE`. Production-unobserved conditions reduced: **0**. No production request was issued, no credential was acquired, and no existing receipt, manifest or comparison count changed.

This page answers the first half of the blocking condition on the `FS-CONFIG-LIFECYCLE` row of [the parent table](ip-fs-production-compatibility.md): the data-plane contract and the managed-infrastructure responsibilities are separated, every management surface is placed in exactly one class with a stated reason, and each row names where the behavior lives in this checkout or records that it does not exist.

## Denominator

The enumeration is taken from the Discovery document already pinned in this repository at `spec/compatibility/upstream/2026-09-09-retry/discovery.json`, definition `firestore-v1`, revision `20260826`, SHA-256 `1efd1c81aba1cd530d39565a97b3e719cdf48b2518e8e9905d1fc4367bcca40b`. Nothing was fetched to produce this page.

That file carries locators only: a method, parameter, schema or field name with no type, description, required marker or output-only marker. It therefore supports an enumeration of names, which is what this page relies on, and it cannot supply a message shape. Any claim below about what a response contains comes from reading this checkout, not from that input.

That definition declares 60 methods. 18 of them are the document methods under `firestore.projects.databases.documents.`; they are the Firestore data plane itself and belong to the `FS-DATA-WRITE`, `FS-QUERY-INDEX`, `FS-TRANSACTION` and `FS-LISTEN-SDK` rows. They are listed in the machine-readable specification so the management denominator is provably the complement of a published set rather than an unstated selection. The remaining 42 methods are classified below.

The machine-readable form is [`spec/compatibility/fs-config-lifecycle-surfaces.json`](../../spec/compatibility/fs-config-lifecycle-surfaces.json), compiled and checked by `tools/compat-broad/fs-config-lifecycle/surface_matrix.py`.

## Classes

A **data-plane contract** surface changes what an ordinary Firestore request returns, so fireemu has to match production even when the surface itself is a management call. A **local-safety extension** is a surface fireemu offers that production does not, or offers differently, so that a local run stays isolated and reproducible; it must never be mistaken for production behavior. A **managed-infrastructure** surface allocates, retains, bills or schedules something only Google operates, and fireemu is not obliged to serve it. A managed row still records the data-plane consequence that survives it, because classifying a call out of scope never removes an obligation the data plane keeps.

## Summary

| Population | data-plane contract | local-safety extension | managed-infrastructure | Total |
| --- | --- | --- | --- | --- |
| Admin v1 management methods | 9 | 0 | 33 | 42 |
| Local-only surfaces | 0 | 7 | 0 | 7 |
| Database resource fields | 11 | 0 | 14 | 25 |

## Data-plane contract methods

| Method | Rationale | Data-plane consequence | Local |
| --- | --- | --- | --- |
| `databases.collectionGroups.fields.get` | Field configuration carries the TTL policy and the single-field index exemption, both of which change document lifetime and query acceptance. | A caller can read back the TTL policy and the single-field index configuration, so the expiry and refusal behavior each implies is observable locally. | `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:218` `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:314` `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:189` `crates/fireemu-core-firestore/src/ttl.rs:226` |
| `databases.collectionGroups.fields.list` | Enumeration with the ttlConfig and indexConfig filters is how tooling discovers every non-default field policy affecting the data plane. | Both documented filters are served and any other filter is refused, so an exemption set and a TTL policy set are each discoverable through a read path. | `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:441` `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:140` `crates/fireemu-core-firestore/src/index.rs:239` |
| `databases.collectionGroups.fields.patch` | Patching ttlConfig schedules server-side document deletion and patching indexConfig exempts a field from single-field indexing; both change what later reads and queries return. | The ttlConfig transition is driven at runtime and an expiry sweep applies it. The indexConfig transition is refused with UNIMPLEMENTED: the local runtime still accepts exemptions only from static configuration, so that half of the surface cannot be driven at runtime. | `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:345` `crates/fireemu-core-firestore/src/ttl.rs:242` `crates/fireemu-adapter-grpc/src/local.rs:3037` `crates/fireemu/src/control.rs:148` |
| `databases.collectionGroups.indexes.create` | Composite index existence decides whether a query is accepted or refused with FAILED_PRECONDITION, so index creation directly determines data-plane results. | Without this method an index can only be declared through configuration, so a caller cannot reach the accepted state a production query depends on. | `crates/fireemu/src/control.rs:48` `crates/fireemu/src/control.rs:88` |
| `databases.collectionGroups.indexes.delete` | Deleting an index flips previously accepted queries back to refusal, which is a data-plane observable transition. | Without deletion the refusal direction of the transition cannot be reached at runtime. | not implemented |
| `databases.collectionGroups.indexes.get` | Index state is how a caller learns that a query will now be accepted; the CREATING to READY transition is observable from the data plane. | A missing readback leaves index-dependent query acceptance untestable against the same contract production exposes. | not implemented |
| `databases.collectionGroups.indexes.list` | Enumeration is the denominator for index-merge and index-selection decisions that the query planner then makes on the data plane. | Local index selection is driven by configuration instead, so the two catalogs can diverge without any request revealing it. | `crates/fireemu-core-firestore/src/index.rs:949` `crates/fireemu-core-firestore/src/index.rs:597` |
| `databases.get` | Client tooling and the emulator suite read database settings before choosing a data-plane code path, and several returned fields change what the data plane accepts, so the projection is part of the contract rather than provisioning. | A wrong concurrencyMode, databaseEdition or versionRetentionPeriod makes a caller choose transaction, edition and read-time behavior the local runtime will then refuse or accept differently from production. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:847` `crates/fireemu-adapter-grpc/src/rest/mod.rs:922` `crates/fireemu-adapter-grpc/src/rest/mod.rs:303` |
| `databases.list` | Enumeration decides whether a named database exists at all, which is the precondition every data-plane request on that database depends on. | A database absent in production but present locally lets a caller address a database that would return NOT_FOUND against the real service. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:847` `crates/fireemu-adapter-grpc/src/rest/mod.rs:911` `crates/fireemu-adapter-grpc/src/rest/mod.rs:890` |

## Managed-infrastructure methods

| Method | Rationale | Data-plane consequence | Local |
| --- | --- | --- | --- |
| `databases.backupSchedules.create` | Backup schedules allocate managed retention with a billed storage footprint. | None; scheduled backups are never readable through the data plane. | not implemented |
| `databases.backupSchedules.delete` | Removing a schedule changes managed retention only. | None; no data-plane result depends on it. | not implemented |
| `databases.backupSchedules.get` | Schedule readback describes managed retention policy only. | None; no data-plane result depends on it. | not implemented |
| `databases.backupSchedules.list` | Schedule enumeration describes managed retention policy only. | None; no data-plane result depends on it. | not implemented |
| `databases.backupSchedules.patch` | Changing retention changes a billed managed policy. | None; no data-plane result depends on it. | not implemented |
| `databases.bulkDeleteDocuments` | Bulk delete is an eventually consistent long-running operation whose progress, partial completion and quota behavior are properties of managed infrastructure. | The final post-state, absence of the deleted documents, is observable from the data plane; the local emulator wipe route is the local-safety counterpart. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:667` `crates/fireemu-adapter-grpc/src/rest/mod.rs:698` |
| `databases.changeStreams.create` | Change streams provision managed retention for a change feed with its own billing and lifecycle. | The delivered changes overlap the Listen contract, which the listen lane owns. | not implemented |
| `databases.changeStreams.delete` | Deleting a change stream releases managed retention. | None directly; delivered changes are owned by the listen lane. | not implemented |
| `databases.changeStreams.get` | Change stream readback describes managed retention state. | None directly; delivered changes are owned by the listen lane. | not implemented |
| `databases.changeStreams.list` | Change stream enumeration describes managed retention state. | None directly; delivered changes are owned by the listen lane. | not implemented |
| `databases.clone` | Clone depends on point-in-time recovery retention held by the managed service. | The cloned database's data plane is covered by the ordinary data-plane rows. | not implemented |
| `databases.create` | Creation allocates a regional, billed, quota-limited resource with an edition, location and CMEK binding that no local process can reproduce or account for. | Existence and non-existence remain observable from the data plane, so the NOT_FOUND boundary for an uncreated database stays a contract obligation even though the provisioning call itself does not. | not implemented |
| `databases.delete` | Deletion destroys a managed resource, is gated by delete protection and produces a long-running operation with no local analogue. | Post-deletion NOT_FOUND on the data plane remains a contract obligation. | not implemented |
| `databases.exportDocuments` | Export writes to Cloud Storage under a long-running operation with managed quota, retries and object lifecycle; none of that exists locally. | The written export format is a contract: fireemu's own export and import must read and write what the official tooling produces, which is already covered by local format evidence. | `crates/fireemu/src/import_export.rs:2891` `crates/fireemu-core-export/src/firestore.rs:480` `crates/fireemu-core-export/src/metadata.rs:142` |
| `databases.importDocuments` | Import is a long-running operation reading managed Cloud Storage objects, with server-side validation and quota behavior that is not locally reproducible. | The accepted on-disk format, partition enumeration and refusal of corrupt or duplicated output references are a contract the local importer already holds. | `crates/fireemu/src/import_export.rs:353` `crates/fireemu/src/import_export.rs:1136` `crates/fireemu/src/import_export.rs:1168` |
| `databases.operations.cancel` | Cancellation is best-effort against managed work already in flight. | Cancellation is part of the abort path of a management campaign, not of any local data-plane behavior. | not implemented |
| `databases.operations.delete` | Deleting an operation record only prunes managed bookkeeping. | None; no data-plane result depends on operation record retention. | not implemented |
| `databases.operations.get` | Long-running operation state belongs to the managed control plane; the local runtime applies a field configuration synchronously and records the resulting operation only so the name its patch returned can still be polled. | A campaign that drives fields.patch can poll the operation it was handed, and it is always already done; every other long-running operation of the Admin API remains managed infrastructure the runtime does not hold. A campaign must still bound its own polling, which the collector contract handles. | `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:548` `crates/fireemu-adapter-grpc/src/local.rs:2873` `crates/fireemu-adapter-grpc/src/local.rs:2915` |
| `databases.operations.list` | Operation enumeration reflects managed scheduling and retention, not any behavior a local emulator can hold; the local listing reports only the bounded tail of field-configuration operations this runtime produced. | Enumeration is how an interrupted campaign resumes its cleanup. Locally it enumerates the field-configuration operations alone, and the record is bounded, so a campaign must not treat it as the managed operation history. | `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:548` `crates/fireemu-adapter-grpc/src/local.rs:2927` |
| `databases.patch` | Updating delete protection, point-in-time recovery or CMEK changes a billed managed configuration and runs as a long-running operation. | The patched values are readable through databases.get, so the resulting projection stays inside the data-plane contract row above. | not implemented |
| `databases.restore` | Restore reads a managed backup artifact that only Google retains; the local runtime has no backup store to restore from. | A restored database must still serve the ordinary data plane, which is covered by the existing data-plane rows rather than by this method. | not implemented |
| `databases.userCreds.create` | User credentials mint a managed password bound to an IAM-adjacent identity; issuing real credentials from an emulator would be a local security hazard. | The resulting principal is visible to Security Rules, so principal shape stays a contract obligation of the Rules lane rather than of this method. | not implemented |
| `databases.userCreds.delete` | Credential deletion revokes a managed identity. | Revocation is observable through Rules evaluation, which the Rules lane owns. | not implemented |
| `databases.userCreds.disable` | Disabling a credential toggles managed identity state. | The disabled principal is observable through Rules, owned by the Rules lane. | not implemented |
| `databases.userCreds.enable` | Enabling a credential toggles managed identity state. | The enabled principal is observable through Rules, owned by the Rules lane. | not implemented |
| `databases.userCreds.get` | Reading a managed credential record describes control-plane state only. | None directly; the principal it names is covered by the Rules lane. | not implemented |
| `databases.userCreds.list` | Credential enumeration is managed control-plane state. | None directly; the principals it names are covered by the Rules lane. | not implemented |
| `databases.userCreds.resetPassword` | Password reset mints new managed secret material. | None directly; secret material must never be emitted by a local emulator. | not implemented |
| `locations.backups.delete` | Backup deletion releases managed storage. | None; backup content is never readable through the data plane. | not implemented |
| `locations.backups.get` | Backups are managed artifacts retained by Google with their own storage cost. | None; backup content is never readable through the data plane. | not implemented |
| `locations.backups.list` | Backup enumeration describes managed artifacts. | None; backup content is never readable through the data plane. | not implemented |
| `locations.get` | Locations describe Google's regional footprint, which no local process defines. | The location a database was created in is echoed by databases.get, so only that projection field carries a contract. | not implemented |
| `locations.list` | Location enumeration describes Google's regional footprint. | None beyond the locationId field echoed by databases.get. | not implemented |

## Local-safety extensions

| Local surface | Rationale | Data-plane consequence | Where |
| --- | --- | --- | --- |
| `emulator.clearFirestoreData` | The emulator-only wipe route gives a test suite a synchronous reset that no production API offers; it exists to keep local runs isolated, not to imitate bulkDeleteDocuments. | Its post-state is ordinary document absence, which the data-plane lanes already cover; the route itself must never be reachable against production. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:667` `crates/fireemu-adapter-grpc/src/rest/mod.rs:698` |
| `config.firestoreIndexes` | Composite indexes and field overrides are loaded from the project's index configuration at startup because the Admin index methods are not served; this substitutes configuration for a control-plane call. | Query acceptance and refusal are decided from this catalog, so a configuration loaded differently from production's index set changes data-plane results. | `crates/fireemu/src/control.rs:48` `crates/fireemu/src/control.rs:88` `crates/fireemu/src/control.rs:148` |
| `config.singleFieldExemption` | Single-field exemptions, including the wildcard field path, are honored from configuration; the production equivalent is a fields.patch call. | An exemption changes which single-field queries are refused, so the two paths must agree on the resulting refusal even though the transition differs. | `crates/fireemu/src/control.rs:148` `crates/fireemu/src/control.rs:215` `crates/fireemu-core-firestore/src/index.rs:133` `crates/fireemu-core-firestore/src/index.rs:157` |
| `cli.exportImport` | Export and import run as local commands over a directory tree rather than as long-running operations over Cloud Storage, so a developer can snapshot and restore a local run without any managed dependency. | The on-disk format must match what official tooling writes, otherwise a real export cannot be loaded locally. | `crates/fireemu/src/import_export.rs:2891` `crates/fireemu/src/import_export.rs:353` `crates/fireemu-core-export/src/metadata.rs:142` |
| `cli.namedDatabaseExportExtension` | The named-database export extension records databases beyond the default one in a metadata extension block; the official format has no such section, so this is an additive local convenience. | Cross-database reference values must survive a round trip and a malformed database identity must be refused before any document is published. | `crates/fireemu-core-export/src/metadata.rs:133` `crates/fireemu-core-export/src/metadata.rs:195` `crates/fireemu/src/import_export.rs:1378` |
| `runtime.lazyDatabaseCreation` | Any syntactically valid database id is materialized on first touch so that a test does not need a provisioning step; production requires databases.create first and answers NOT_FOUND until then. | A request against an uncreated named database succeeds locally and fails in production, which is recorded as an open repair ticket rather than a fix here. | `crates/fireemu-adapter-grpc/src/local.rs:2629` `crates/fireemu-core-types/src/ids.rs:183` |
| `control.textIndexLifecycle` | fireemu's own control API exposes an Enterprise text-index resource that has no Firestore Admin v1 counterpart in the pinned discovery input. | It must stay Enterprise-gated so a Standard Native run cannot reach a surface production would not serve. | `crates/fireemu-adapter-http/src/control.rs:1346` |

## Database resource fields

| Field | Class | Rationale | Data-plane consequence | Local |
| --- | --- | --- | --- | --- |
| `name` | data-plane-contract | The resource name identifies the project and database every data-plane request addresses. | A mismatched name routes requests to a different database. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:316` |
| `type` | data-plane-contract | FIRESTORE_NATIVE and DATASTORE_MODE expose different APIs entirely. | A caller that trusts this field picks the wrong API surface. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:321` |
| `databaseEdition` | data-plane-contract | Edition decides which methods are served at all; the local inventory route already refuses non-Standard Native combinations. | The projection reports the configured edition in the API's upper-case spelling; only Standard reaches the route because every other edition is refused above it (fixed at 62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:332` `crates/fireemu-adapter-grpc/src/rest/mod.rs:862` `crates/fireemu-core-types/src/edition.rs:12` |
| `concurrencyMode` | data-plane-contract | PESSIMISTIC and OPTIMISTIC change when a transaction blocks and when it aborts. | Transaction contention and retry behavior depend on this value. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:322` |
| `versionRetentionPeriod` | data-plane-contract | Retention bounds how far back a read_time query may address. | A read_time older than the retention window must be refused; a wrong period moves that boundary. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:323` |
| `earliestVersionTime` | data-plane-contract | The earliest addressable version time is the concrete lower bound a read_time request is checked against, and it advances continuously. | It is excluded from settings equality by the database projection because it moves on its own, but the data-plane bound it expresses is still a contract. The local projection derives it from the retention window floored at the database's creation, the bound read_time is checked against (62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:324` |
| `pointInTimeRecoveryEnablement` | data-plane-contract | Enabling point-in-time recovery extends the retention window, which widens the range of accepted read_time values. | The accepted read_time range changes with this setting. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:326` |
| `realtimeUpdatesMode` | data-plane-contract | Realtime updates decide whether Listen is served for the database. | A disabled mode must refuse Listen; the local projection reports enabled unconditionally. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:333` |
| `firestoreDataAccessMode` | data-plane-contract | The Firestore data access mode gates whether the Firestore data API is served for the database at all. | A disabled mode must refuse data-plane requests; the local projection omits the field. | not implemented |
| `mongodbCompatibleDataAccessMode` | data-plane-contract | The MongoDB-compatible access mode gates a second data API on the same database. | A caller cannot learn from the local projection whether that API is available. | not implemented |
| `locationId` | managed-infrastructure | The region is fixed by provisioning and cannot be chosen by a local process. | It is echoed to callers, so a hardcoded value must be recognised as declared rather than observed; the local value is a constant. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:320` |
| `appEngineIntegrationMode` | managed-infrastructure | App Engine integration is a legacy managed binding with no local analogue. | None; the local projection reports DISABLED as a declared constant. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:325` |
| `deleteProtectionState` | managed-infrastructure | Delete protection only gates the managed databases.delete call. | None; no data-plane request observes it. It is an abort precondition for any campaign that creates and deletes a database. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:327` |
| `uid` | managed-infrastructure | The server-assigned unique id identifies one provisioning instance. | None, but it is an identity field the database projection requires, so a change must stop a campaign rather than be normalized away. The local value is derived deterministically from the project and database ids (62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:317` |
| `etag` | managed-infrastructure | The etag supports optimistic concurrency on managed patch calls. | None; it is excluded from settings equality by the database projection. The local value is a digest of the projected resource (62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:342` |
| `freeTier` | managed-infrastructure | Free tier eligibility is a billing attribute of the managed resource. | None, but it is the precondition that decides whether a second named database costs anything. The local projection reports true for the default database and omits the field for any other, as production does (62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:339` |
| `createTime` | managed-infrastructure | Provisioning timestamps describe the managed resource lifecycle. | None; no data-plane result depends on it. The local value is the database's creation instant on the logical clock (62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:318` |
| `updateTime` | managed-infrastructure | Provisioning timestamps describe the managed resource lifecycle. | None; no data-plane result depends on it. The local value equals createTime because no local call updates the resource (62d8a1d22). | `crates/fireemu-adapter-grpc/src/rest/mod.rs:319` |
| `deleteTime` | managed-infrastructure | The deletion timestamp appears only for soft-deleted managed databases. | It is the field that makes showDeleted meaningful; the local inventory accepts showDeleted but has no deleted state to report. | not implemented |
| `keyPrefix` | managed-infrastructure | The key prefix is a Datastore-era managed identifier. | None; no data-plane result depends on it. | not implemented |
| `cmekConfig` | managed-infrastructure | Customer-managed encryption keys are a managed KMS binding. | None; encryption is transparent to the data plane. | not implemented |
| `tags` | managed-infrastructure | Resource tags are a Cloud Resource Manager concern. | None; no data-plane result depends on them. | not implemented |
| `previousId` | managed-infrastructure | The previous id records a managed rename or restore lineage. | None; no data-plane result depends on it. | not implemented |
| `sourceInfo` | managed-infrastructure | Source info records the backup or clone a managed database came from. | None; no data-plane result depends on it. | not implemented |
| `enhancedTextSearchQueryMode` (absent from the pinned Discovery document) | data-plane-contract | This field is absent from the pinned discovery document but is present in the saved production database response and is emitted by the local projection, so it is an undocumented surface that must be carried rather than dropped. | It reports whether the enhanced text search query mode is available, which changes which queries a caller may issue. | `crates/fireemu-adapter-grpc/src/rest/mod.rs:334` |

## Repair tickets

Each ticket was an open local runtime gap when the matrix was first built. None was fixed by the work that renders this page; a ticket marked FIXED or PARTIALLY_FIXED cites the commit that changed the runtime, and its summary and reproduction are kept as the historical statement of the gap.

### FS-CONFIG-RT-001: A named database is materialized on first touch instead of returning NOT_FOUND

Any syntactically valid database id becomes usable without a create call, so a request that production refuses with NOT_FOUND succeeds locally.

Reproduction: Start fireemu with only the default database configured, then issue any Firestore REST read against projects/{project}/databases/never-created/documents/c/d. The local runtime creates the database and answers NOT_FOUND for the document; production answers NOT_FOUND for the database before the document is considered.

Class: local-safety-extension. Status: FIXED. Evidence: `crates/fireemu-adapter-grpc/src/local.rs:1682` `crates/fireemu-adapter-grpc/src/local.rs:1439` `crates/fireemu-core-types/src/ids.rs:183`

Resolution (`cb429f2c4`): The strict profile answers NOT_FOUND for a database nothing created and does not materialize it on the refusal; the emulator profile keeps materializing any database on first touch, as the official emulator does. Fixed for the strict profile only, by design.

### FS-CONFIG-RT-002: The database projection reports a constant edition and location

databaseEdition is hardcoded to STANDARD and locationId to us-central1, so the projection reflects neither the configured edition enum nor any configured location.

Reproduction: Start fireemu configured for the Enterprise edition and read projects/{project}/databases/(default) on the Firestore REST port. The response still reports STANDARD while the same route refuses non-Standard Native traffic a few lines earlier.

Class: data-plane-contract. Status: PARTIALLY_FIXED. Evidence: `crates/fireemu-adapter-grpc/src/rest/mod.rs:332` `crates/fireemu-adapter-grpc/src/rest/mod.rs:862` `crates/fireemu-adapter-grpc/src/rest/mod.rs:320`

Resolution (`62d8a1d22`): databaseEdition now comes from the configuration; locationId is still the constant us-central1. The remaining half is FS-LIFE-003 (database projection completeness).

### FS-CONFIG-RT-003: The database projection omits fields the saved production response carries

uid, freeTier, etag, createTime, updateTime and earliestVersionTime are absent from the local projection although the saved production response contains them and the database projection contract requires uid as an identity field.

Reproduction: Compare the local response of projects/{project}/databases/(default) with the saved offline fixture at tools/compat-broad/fixtures/database-settings-7be6cf08.json. The local body is a strict subset and would fail the identity check the batch contract applies.

Class: data-plane-contract. Status: FIXED. Evidence: `crates/fireemu-adapter-grpc/src/rest/mod.rs:303` `tools/compat-broad/batch_contract.py:230` `tools/compat-broad/fixtures/database-settings-7be6cf08.json:1`

Resolution (`62d8a1d22`): uid, createTime, updateTime, earliestVersionTime, freeTier and etag are emitted; the local rehearsal record of 2026-09-21 shows the local projection carrying the same field set as the saved production response, with local values for uid and the timestamps.

### FS-CONFIG-RT-004: The indexConfig half of fields.patch has no runtime transition

The field configuration surface is served and the ttlConfig half is complete: the policy is stored per database, read back as ACTIVE, and an expiry sweep on the virtual clock deletes documents whose TTL field has elapsed. Patching indexConfig is refused with UNIMPLEMENTED, because single-field exemptions are still taken from the project's index configuration at startup and there is no runtime path that changes them.

Reproduction: Issue PATCH on projects/{project}/databases/(default)/collectionGroups/{group}/fields/{field} with updateMask=indexConfig and observe UNIMPLEMENTED, while production applies the exemption and reports usesAncestorConfig false on the next get.

Class: data-plane-contract. Status: OPEN. Evidence: `crates/fireemu-adapter-grpc/src/rest/admin_fields.rs:345` `crates/fireemu/src/control.rs:148` `crates/fireemu-core-firestore/src/index.rs:216`

### FS-CONFIG-RT-005: An invalid database id is answered NOT_FOUND rather than INVALID_ARGUMENT

A syntactically invalid database id is deliberately mapped to NOT_FOUND on the data plane. Whether production agrees is exactly one of the error shapes this lane's campaign is prepared to compare.

Reproduction: Issue a Firestore REST read against projects/{project}/databases/Invalid_Id/documents/c/d and observe NOT_FOUND with the message naming the database.

Class: data-plane-contract. Status: OPEN. Evidence: `crates/fireemu-adapter-grpc/src/decode.rs:169` `crates/fireemu-core-types/src/ids.rs:183`

## What this page does not establish

The classification was derived from the pinned Discovery document and from reading this checkout. It is not a production observation. Whether production agrees with any local behavior recorded here is unknown, and the local column describes only what this source tree does today.

The repair tickets above are reproductions. Where one is marked fixed, the fix landed in the cited commit; no runtime file was changed by the work that produced this page.

The bounded observation that would begin answering the second half of the blocking condition is prepared separately in [the campaign preparation](fs-config-lifecycle-campaign-preparation.md). It has not run.
