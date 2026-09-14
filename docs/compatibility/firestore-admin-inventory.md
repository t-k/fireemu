# Firestore Admin database inventory

This repository implements a finite, local-only read surface for the Firestore Admin REST methods `projects.databases.list` and `projects.databases.get`.

The routes are served on the Firestore REST port:

- `GET /v1/projects/{project}/databases`
- `GET /v1/projects/{project}/databases/{database}`

Both methods require the emulator owner credential (`Authorization: Bearer owner`). Authorization is checked before the local catalog is inspected, so an unauthorized request cannot disclose whether a project or database exists. Project and database names are matched exactly. Unknown databases return `404 NOT_FOUND`.

The catalog contains databases that have already been registered by local Firestore operations. Listing is lexicographically ordered by the full database name and uses deterministic page tokens bound to the project and page size. A catalog read never creates a database and does not mutate Firestore state. A healthy list response includes `unreachable: []`.

Each database uses a stable local projection: `name`, deterministic local `uid`, `locationId`, `type`, `concurrencyMode`, `versionRetentionPeriod`, `appEngineIntegrationMode`, `pointInTimeRecoveryEnablement`, `deleteProtectionState`, `databaseEdition`, `freeTier`, `realtimeUpdatesMode`, and `enhancedTextSearchQueryMode`. The values describe the bounded Standard/Native local model. They are not a production parity claim.

The implementation is intentionally limited. Enterprise databases and Admin create/update/delete, indexes, TTL, backups, import/export, restore, and long-running operations are not served. The pinned Discovery input is `spec/compatibility/upstream/2026-09-09-retry/discovery.json`; the historical database projection v2 is used only as a bounded field reference.
