# Firestore Admin database inventory

This repository implements a finite, local-only read surface for the Firestore Admin REST methods `projects.databases.list` and `projects.databases.get`.

The routes are served on the Firestore REST port:

- `GET /v1/projects/{project}/databases`
- `GET /v1/projects/{project}/databases/{database}`

Both methods require the emulator owner credential (`Authorization: Bearer owner`). Authorization is checked before the local catalog is inspected, so an unauthorized request cannot disclose whether a project or database exists. Project and database names are matched exactly. Unknown databases return `404 NOT_FOUND`.

The catalog contains databases that have already been registered by local Firestore operations. Listing is lexicographically ordered by the full database name. `showDeleted` is accepted as the Discovery-defined optional boolean and is currently equivalent to the active catalog because deleted database history is not retained. Paging parameters are rejected because they are not part of the pinned v1 Discovery contract. A catalog read never creates a database and does not mutate Firestore state. A healthy list response includes `unreachable: []`.

Each database uses a stable local projection: `name`, `locationId`, `type`, `concurrencyMode`, `versionRetentionPeriod`, `appEngineIntegrationMode`, `pointInTimeRecoveryEnablement`, `deleteProtectionState`, `databaseEdition`, `realtimeUpdatesMode`, and `enhancedTextSearchQueryMode`. Fields whose production semantics require a UUID or per-project billing state (`uid`, `freeTier`) are omitted because the local registry does not model them. The values describe the bounded Standard/Native local model. They are not a production parity claim.

The implementation is intentionally limited. Enterprise databases and Admin create/update/delete, indexes, TTL, backups, import/export, restore, and long-running operations are not served. The pinned Discovery input is `spec/compatibility/upstream/2026-09-09-retry/discovery.json`; the historical database projection v2 is used only as a bounded field reference.
