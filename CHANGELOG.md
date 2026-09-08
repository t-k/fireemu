# Changelog

All notable changes to fireemu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, a minor release may change configuration, unsupported behavior, and edge-case semantics.

Each release is a Git tag; the binaries and the npm packages are built from that tag by the release workflow. Behavior described as "matching production" was measured against a real Firebase project on the date named in the commit that introduced it.

## [Unreleased]

## [0.2.0] - 2026-09-08

### Added

- Firestore aggregation queries are validated against the index configuration, both locally and when proxied, so a `count`, `sum`, or `average` that would need a missing composite index in production is refused under the `strict` profile.
- Firestore per-document index budgets are enforced: the automatic and composite entry count, the largest single entry, and the entry size sum, checked before a write is published. Partition reconstruction is verified against production.
- Under the `firebase` index policy, a conjunction of scalar equality filters can be served by merging automatic single-field indexes, and explicit composite indexes that share the query's order suffix are merged the way the production index overview describes.
- Query execution statistics (index paths visited, filter evaluations, retained paths and bytes, per-page counters) are recorded by the local backend for every streamed query execution, so the work behind a stream is measurable in tests.
- A Firestore performance smoke script under `tools/sdk-smoke` measures SDK round trips against a running daemon.
- The Emulator UI shows a context header with the session selector, project, clock mode, and daemon connection; an admin badge on Firestore and Storage when the owner credential bypasses Rules; progress and partial counts for recursive collection deletion; and a path box that jumps straight to a path.
- Stryker mutation testing for the UI logic.

### Changed

- User-supplied timestamp fields are stored at microsecond precision, matching production truncation, and are normalized before validation and no-op detection.
- Stored vectors follow production limits: 1 through 2048 dimensions and no NaN components; infinities are stored.
- A bare `orderBy(__name__, desc)` requires an explicit `(__name__ DESC)` composite index, as production does; an equality prefix still rides its automatic descending index.
- An equality or `in` filter on `__name__` is served from the primary key and is no longer rejected by a wildcard single-field index exemption.
- Automatic single-field indexes carry the ordered field's direction as their implicit `__name__` tie-break, so the opposite name direction requires a composite index.
- Auth route error shapes and Firestore field limits were aligned with production responses.
- Pub/Sub honors subscription retry policies and refuses unsupported topic, subscription, and push configuration options instead of silently ignoring them.
- TOTP enrollment eligibility is enforced at enrollment and rechecked during finalize; the ambiguous finalize API was removed and retry state follows the verified model.
- `fireemu.json` rejects runtime limits that no service reads, and the Firestore capability manifest entries were aligned with the actual scope.
- The npm packages are published with OIDC Trusted Publishing and provenance. Releases are represented by Git tags rather than GitHub Releases.
- The workspace version is now `0.2.0`, so `fireemu doctor`, the UI, the hub locator, and export metadata report the same version as the npm package.

### Fixed

- Firestore: writes that rewrote a NaN payload, kept NaN through a `maximum` or `minimum` transform, or verified an unchanged document produced a spurious document change and version; they are now no-ops as in production.
- Firestore: array operands are normalized before array transforms, and timestamp comparisons inside arrays match production.
- Firestore: multi-page queries complete only after every internal page, preserve public continuation tokens, and keep their continuation inside transactions; name-ordered continuations seek instead of scanning.
- Firestore: repeated query executions inside one transaction are isolated, paged transaction observations are aggregated, and read-only results are excluded from conflict accounting.
- Firestore: internal read-only query transactions are owned until stream delivery and rolled back when a handler is cancelled before the first page, so cancelled clients no longer leak transactions.
- Firestore: key query constraints are enforced, and extrema transforms and page counters were corrected.
- Firestore: canonical index keys are separated from structural values, so values that compare equal for indexing but differ structurally no longer collide.
- Firestore: a `__name__` equality or `in` filter looks up its candidates directly instead of scanning the collection or collection-group scope; parent-scoped descending name scans are bounded.
- Firestore: history accounting no longer allocates diagnostics on the hot path.
- gRPC: Nagle delays are disabled on multiplexed connections, removing latency spikes in SDK round trips.
- Pub/Sub: bridge and dead-letter delivery are atomic, dead-letter retries are serialized and resume after bridge recovery, ordered push resumes after dead lettering, push retries resume after logical backoff and are deferred outside worker slots, and unsupported push updates are rejected.
- Functions: a Node executable reached through a symlink (for example the Volta shim) is run by its link name, so discovery no longer fails with exit status 126 and an unavailable Functions runtime.
- Emulator UI: editors stay bound to one target and unsaved drafts are guarded on target switches, route changes, and unloads; stale paged reads no longer overwrite the view; loading, failure, stale, and empty states are distinguished; the log tail stays in view after render; recursive subcollection deletion is paginated; path segments in in-app links are percent-encoded; amber primary buttons meet WCAG AA contrast and focus rings are visible.
- Conformance: production comparisons are bound to the live fireemu output and to the evidence identity, and a missing live comparison is rejected instead of passing vacuously.

## [0.1.0] - 2026-09-06

### Added

- Initial public release of the `fireemu` launcher and the `@fireemu/*` platform packages for macOS (Apple silicon, Intel), Linux (x86-64, arm64), and Windows (x86-64).
- Cloud Firestore in Native mode over gRPC, REST, and WebChannel, with transactions, queries, listeners, index validation, production limits, and Security Rules.
- Firebase Authentication client and Admin REST surfaces, emulator actions, custom tokens, email and phone flows, MFA including TOTP, tenants, and fixture identity providers.
- Cloud Storage for Firebase with the Firebase and JSON object APIs, resumable uploads, generations, listing, and Security Rules.
- Cloud Functions for Firebase v2 HTTP and callable functions, including callable streaming, plus Firestore, Storage, and scheduled triggers through the bundled Node.js runner.
- Cloud Pub/Sub gRPC subset, Eventarc publication, the EmulatorLog WebSocket, a fireemu-specific App Check implementation, and the Emulator UI.
- The `strict` and `firebase` compatibility profiles, the Capability Manifest, and the Compatibility Contract pinned to firebase-tools 15.28.2.
- `fireemu init`, `up`, `exec`, `emulators:export`, `doctor`, and `capabilities` commands, with the official `emulators:start` and `emulators:exec` spellings as aliases.

[Unreleased]: https://github.com/t-k/fireemu/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/t-k/fireemu/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/t-k/fireemu/releases/tag/v0.1.0
