# Changelog

All notable changes to fireemu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, a minor release may change configuration, unsupported behavior, and edge-case semantics.

Each release is a Git tag; the binaries and the npm packages are built from that tag by the release workflow. Behavior described as "matching production" was measured against a real Firebase project on the date named in the commit that introduced it.

## [Unreleased]

Behavior below was measured against a real Identity Platform project on 2026-09-24 (AUTH-CREDENTIAL). Each item names the profiles it affects; "unlike the official emulator" marks where the emulator profile now differs from the Firebase Emulator Suite.

### Added

- `auth.customTokenSigners` maps service accounts to their public JWK sets (RSA keys of at least 2048 bits). With it, `signInWithCustomToken` verifies RS256 signatures and applies production's custom-token rules in either profile; a verifying token of another project's service account is refused with `CREDENTIAL_MISMATCH`.
- `auth.apiKeys` declares the project's Web API keys. A client request with any other key is refused with production's `400 API_KEY_INVALID` envelope (unlike the official emulator, which validates no key). An unknown key under a registered session now gets the same envelope instead of `INVALID_API_KEY`.

### Changed

- Both profiles: a tenant created with a display name of the documented form (4-20 letters, digits and hyphens, beginning with a letter) is named as production names it: the display name, `-` and five characters of `[a-z0-9]`, drawn reproducibly from the creation sequence. A tenant without such a display name keeps the `fireemu-<sequence>` name.
- Strict profile: `signInWithCustomToken` accepts only signed tokens, as production does. Without `auth.customTokenSigners` every custom token, including the Admin SDK's unsigned emulator tokens and JSON fake tokens, is refused with `INVALID_CUSTOM_TOKEN`, and the startup banner says so. Use `auth.customTokenSigners`, or the emulator profile for the Admin SDK's emulator tokens.
- Strict profile: password and custom-token sign-in without `returnSecureToken` return production's legacy Identity Toolkit token (issuer `https://identitytoolkit.google.com/`, two-week lifetime) and no refresh token. The routes production was observed to honour it on accept it: account lookup, update and delete, a verification mail, phone linking, a sign-up upgrade and MFA enrollment. Email-link and identity-provider linking and session-cookie creation refuse it. A request whose blocking trigger runs keeps secure tokens. The emulator profile keeps secure tokens.
- Strict profile: `createSessionCookie` decodes `validDuration` as an int64, refusing a fraction or text with `INVALID_ARGUMENT` and zero with `INVALID_DURATION`. The emulator profile keeps the official emulator's `Number(validDuration) || two weeks`.
- Both profiles: Identity Toolkit honours an ID token for five minutes past its `exp`, then refuses it with `INVALID_ID_TOKEN` instead of `TOKEN_EXPIRED`. A strict custom token gets the same allowance and `INVALID_CUSTOM_TOKEN`. A revoked session still answers `TOKEN_EXPIRED`. Unlike the official emulator, which never reads an ID token's `exp`.
- Both profiles: an administrator's `validSince` is stored as given and may move back, and sessions are judged against it when they are used, so a refresh token is `TOKEN_EXPIRED` below it and works again once it moves back. A client update's `validSince` is ignored. Unlike the official emulator, which sets `validSince` to the current time for any value from either caller.
- Both profiles: session cookies carry `{alg, kid}` with no `typ` (unlike the official emulator's `typ: JWT`, which the Admin SDK does not read).
- Both profiles: `createSessionCookie` answers an API key without a credential with production's `401 UNAUTHENTICATED` (`CREDENTIALS_MISSING`), and a deleted account's ID token with `USER_NOT_FOUND`.
- Both profiles: a custom-token sign-in marks the account `customAuth`, and the account then reports `validSince` (the official emulator reports `customAuth` only). Custom-token answers never include `localId` or `email`, and anonymous ID tokens carry a top-level `provider_id`, as with the official emulator.
- Both profiles: Secure Token reads an empty `grant_type` or `refresh_token` as missing (`MISSING_GRANT_TYPE`, `MISSING_REFRESH_TOKEN`). In the strict profile a Secure Token request with no API key gets its front end's 403 without an `errors` list; the emulator profile keeps accepting a keyless request.
- Strict profile: MFA enrollment answers `OPERATION_NOT_ALLOWED : TOTP based MFA not enabled.` when TOTP is off, and its refusals carry the v2 API's shape (a status name and no `errors` list). The emulator profile keeps the official emulator's answers.
- Both profiles: linking a phone number answers with a session whose `sign_in_provider` is `phone`, as production does and as the official emulator does.

### Firestore queries (FS-QUERY-INDEX)

#### Added

- `firestore.databaseCreateTime` sets the creation time the daemon's databases report and the instant before which a `read_time` is refused (strict profile). It defaults to the daemon's start.
- Firestore Explain reports the index each query disjunct scans and production's billing (index and document entries, read operations, minimum query cost) for queries, aggregations and nearest-neighbour searches, in both profiles.
- REST routes `{database}/documents:executePipeline` under the strict profile, answering production's Standard-edition refusal.

#### Changed

These follow production Firestore as recorded on 2026-09-24 (FS-QUERY-INDEX). Unless marked strict, they apply under the `emulator` profile too, where they change results or shapes but add no rejection.

- REST `runQuery`, `runAggregationQuery` and `executePipeline` answer an error inside a one-element JSON array; refusal texts, `google.rpc` details (ErrorInfo, Help, BadRequest) and the missing-index console link (strict) are production's.
- REST request bodies are read with production's JSON grammar: bare keys, single-quoted strings and trailing commas are accepted, and a body that is not JSON is refused in production's words with 20 bytes of context.
- Strict only: query bodies go through production's transcoder check (schema, case-insensitive and numeric enums, wrapper forms, field violations).
- A kindless query without `allDescendants` reads the parent's direct children, not every descendant.
- `IS_NOT_NAN` excludes null, and a range against NaN matches nothing.
- gRPC `RunQuery` no longer marks a response `done`.
- findNearest ranks equal distances by document name, and count, sum and avg aggregate over its results. Strict only: a query-level limit, offset or cursor is refused, and a cosine search that meets a zero vector is refused with FAILED_PRECONDITION; the emulator profile keeps applying those stages before the ranking and leaves a zero vector out.
- A count capped at zero answers without reading, after authorization. Strict only: unnamed aggregations are numbered `field_1`, `field_2`, ... over the unnamed ones only, and an alias that is reserved (`__x__`) or longer than 1500 bytes is refused; the emulator profile keeps numbering them by position and admits any alias.
- PartitionQuery splits at sampled keys (about one in 141): `partition_count` cursors, nested across counts, in key order, without `before`, with production's refusal texts; a small group, a kindless query or one without an explicit order gets no partition.
- Index selection merges automatic indexes with an array-contains filter, lets a collection-group composite serve a collection query, and checks aggregations over findNearest against their vector index.
- Strict only: refusals only production makes during query canonicalization (a kindless filter or order, a duplicate order field, an empty OR, array membership and unary filters on `__name__`, a cursor longer than the explicit order), a `__name__` filter on a reference that is not a document, and a projection on a PartitionQuery.
- Strict only: over REST, a query method on a root collection (`documents/users:runQuery`) is routed to the create template and refused for its query keys, as production's front end does; the emulator profile keeps the query route, which refuses the collection parent.
- Under the emulator profile, a REST body that production's grammar refuses but standard JSON admits (nesting deeper than 100 levels) is read as standard JSON. In both profiles a JSON `-0` in a REST body is the integer 0, as production's grammar reads it.
- findNearest's `distanceResultField` names one property, as production reads it: `a.b` is a field named `a.b`, not a nested path.
- A `read_time` before the database's creation time is refused in production's words, in both profiles.

#### Fixed

- A refusal echoes at most 1 KiB of the value, key, path or property path it names, and a transcoder refusal lists at most 16 violations, so a large request cannot grow the response or the daemon's memory many times its size.
- The partition page token is bound to its snapshot version.

### Security Rules (FS-RULES)

Behavior below was measured against a real Firestore database with end-user ID tokens on 2026-09-24 (FS-RULES).

- Added, both profiles: `existsAfter()` answers whether a document exists once the request's writes are applied. It shares `getAfter()`'s access budget for a path.
- Changed, both profiles: a Security Rules denial answers with production's `PERMISSION_DENIED` and the message `Missing or insufficient permissions.`, on REST and gRPC, unlike the official emulator's evaluation trace. The reason fireemu found stays in the ruleset's request traces (`GET /v1/sessions/{session}/rules/requests` on the control API).
- Changed, both profiles: in Firestore rules, `get()` and `getAfter()` of a missing document answer `null` instead of an error (reading a member of it is still an error). In a read, where no write applies, `getAfter()` and `existsAfter()` read the current state instead of failing. `get()` and `getAfter()` of one path count as one document access. Storage rules keep their answers: `firestore.get()` of a missing document is an error, and `getAfter()`/`existsAfter()` are refused.
- Changed, both profiles: on a delete, `request.resource` is present and `null`.
- Changed, both profiles: Firestore honours an unexpired ID token of an account whose refresh tokens were revoked, that was disabled, or that was deleted, as production does; Identity Toolkit still refuses those tokens.
- Changed, both profiles: an end user's `listCollectionIds` and `partitionQuery` are refused with production's `Missing or insufficient permissions.`
- Changed, strict profile: a credential Firestore cannot use is refused in production's shapes: a token past its allowance is `UNAUTHENTICATED` `Missing or invalid authentication.`, a bearer value that is not a JWT is `UNAUTHENTICATED` with the front end's OAuth text, and every other unusable credential (a JWT that does not verify, an empty bearer, another scheme) is `PERMISSION_DENIED` `Missing or insufficient permissions.`. The emulator profile keeps its own texts.
- Changed, both profiles: rulesets compile as production's compiler compiles them. Expressions up to 99 levels deep compile, where each operator of a chain, `!`, a pair of parentheses, a ternary, a list or map literal and a call's arguments count one level, and 100 levels are refused with `Expression is too complex to evaluate safely.`. The following compile: a call with the wrong number of arguments (false when evaluated), an access method in any letter case, an unknown access method (it grants nothing), a missing semicolon after an allow statement or `rules_version`, 11 `let` bindings in a function, and ten match levels below `/databases/{database}/documents`. A function defined twice in one scope is refused with `Function <name> is already defined.`. These match the official emulator's compiler, which answers the same on every case recorded in production. The daemon's runtime threads get an 8 MiB stack, and rulesets are parsed on a thread of their own. Evaluation still stops at 64 nested levels, where the condition is false.
- Changed, both profiles: allow statements are alternatives. One that holds allows the request even if another one raises an error (a document-access budget, an invalid regex, an unsupported feature), in either order; an error decides only when nothing holds. Running out of the 1,000-expression budget still ends the request, as in production, even before an allow with no condition. A request may exhaust fireemu's regex step budget in at most four matches; the fifth ends the request (`FIREEMU-REGEX-EXHAUSTIONS-PER-REQUEST`), so a ruleset of many regex allows cannot multiply the work one request costs.
- Changed, both profiles: a pair of parentheses counts as one expression evaluated toward the 1,000-expression budget. A query's rule may read 20 distinct documents, as a multi-document request may. `request.query.orderBy` is a map in every query, empty when it has no order. `request.query` carries production's nine keys, not only the three documented: `limit`, `offset`, `orderBy`, `allDescendants`, `distinct`, `groupBy`, `kind` (the collection id), `parent` (null for a root query) and `selectOnlyKeys`, so a rule that checks `request.query.keys()` sees what production shows it. Their values were observed for a plain root query only; the ninth key's full name is inferred from its first 12 characters.
- Changed, both profiles: an end user's `BatchWrite` is refused with `Missing or insufficient permissions.`, whatever the rules say of its writes. The official emulator refuses it too, with its own text.
- Changed, both profiles: Security Rules judge a write by the method its precondition names: `exists: false` is a create and `exists: true` or `updateTime` an update, whatever the document is now. A write the rules then allow is refused by its failed precondition (`ALREADY_EXISTS`, `NOT_FOUND`), as production answers.
- Changed, strict profile: over REST, the refusal of a bearer value that is not a JWT carries production's `ErrorInfo` (`CREDENTIALS_MISSING`, with the service and the gRPC method the route transcodes to; a document read is `GetOrListDocuments`).
- Changed: callable Functions keep ID-token verification when they decide `context.auth`. Firestore's allowances (30 seconds past `exp`, and the token of a revoked, disabled or deleted account) are not extended to them, because nothing observed a callable honouring such a token.
- Changed: Firestore honours a verified ID token for 30 seconds past its `exp`, as production does (accepted 26 seconds after it, refused from 30), where fireemu refused it at `exp`. This applies wherever tokens are verified: the strict profile, and the emulator profile with `auth.idTokenSigning: session-rsa` (otherwise that profile admits an unsigned mock token whatever its `exp`, as before). Identity Toolkit keeps its own five-minute allowance.
- Changed, both profiles: a REST `batchGet` error, a malformed body or a Security Rules denial alike, comes inside a one-element JSON array, as production answers a streaming method and fireemu already answered `runQuery`.
- Changed, strict profile: an end user, signed in or not, may not open a read-write transaction, whether by `BeginTransaction` (whose default is read-write) or by the `newTransaction` of `BatchGetDocuments`, `RunQuery` or `RunAggregationQuery`. It is refused with `Missing or insufficient permissions.` whatever the rules say, as production refuses it. A read-only transaction still opens, and the owner credential is unaffected. The emulator profile opens every transaction, as the official emulator does.
- Changed, strict profile (the default): while a database has no ruleset, every client request is refused with `PERMISSION_DENIED`, because production refuses every client request when there is no `cloud.firestore` release. A daemon started without rules therefore refuses SDK requests until rules are loaded (`rules.source`, `firebase.json`, `PUT /v1/rules`); the owner credential is unaffected. The emulator profile still allows everything until rules are loaded, as the official emulator does. The startup banner says which applies.

## [0.7.1] - 2026-09-10

### Fixed

- Configuration files containing fireemu-only keys such as `profile` or `auth.totp` without `schemaVersion` are refused with an actionable diagnostic instead of silently ignoring those settings as Firebase project configuration. The check covers `--config`, `--firebase-json`, and `firebaseJson` references.
- The npm launcher forwards PID-directed `SIGTERM` and `SIGINT` to the native daemon on Unix and waits for shutdown, so stopping the launcher no longer leaves an emulator serving in the background. The launcher preserves child exit status and waits for cleanup after repeated signals.

## [0.7.0] - 2026-09-09

### Changed

- The compatibility profiles are now `strict` (the default) and `emulator`; `firebase` was renamed to `emulator` because it reproduces the pinned Firebase Emulator Suite, not Firebase itself. A `fireemu.json` or `fireemu init --profile` that still says `firebase` is refused with a message naming the new spelling.
- `strict` follows production Firestore's index rules instead of a stricter local approximation: the index merges production performs for equality filters (verified against a real project on 2026-09-08) are accepted, and a query is refused only when production would refuse it.

### Removed

- `firestore.indexValidationPolicy` and its `conservative` value. The index policy has no configuration key any more and follows the profile: `strict` applies production's rules, `emulator` assumes every index the official emulator would. A configuration that still sets the key is refused with a message saying so. `firestore.enforceLimits` remains as an explicit override.

## [0.6.0] - 2026-09-09

### Changed

- The default compatibility profile is now `strict`. A `fireemu.json` that names no `profile` runs under the same validation `fireemu init` recommends: missing composite indexes are refused with production's `FAILED_PRECONDITION`, Standard query limit violations refuse the query, and ID tokens on the Security Rules surfaces are verified. Set `"profile": "firebase"` explicitly to keep reproducing the pinned official emulator. `spec/config/fireemu.schema.json` records the new default.

## [0.5.0] - 2026-09-09

### Added

- `fireemu --version` (also `-V` and `version`) prints the build's version without starting a daemon, so packaging and benchmark tooling can record which build it drove.
- A paired benchmark against the official Firestore emulator (`.github/workflows/benchmark.yml`, harness in `tools/bench/`): both emulators run sequentially on the same GitHub Actions Linux runner under the `firebase` profile and the same SDK workloads, and startup, cgroup memory, CPU and throughput are reported as paired ratios with confidence intervals. The workflow is manual-only and its results are summarized in the README.
- Emulator UI: the Auth user list shows each user's enrolled second factors (TOTP, phone).
- Emulator UI: Functions rows describe task queue, Eventarc and blocking Auth triggers instead of leaving those triggers without a description.

### Fixed

- Emulator UI: Auth and Functions console drafts survive the background session refresh; a new Auth user draft survives a cancelled scope switch, and a scope switch asks every mounted editor before the header target changes, with focus returned to the draft when the user keeps it.
- Emulator UI: a late Auth read for the previous project can no longer replace the newly selected project's rows, and a scope switch clears the old rows and armed confirmations.
- Emulator UI: an Auth user deleted outside the console keeps its draft and reports the save failure; saving a Firestore field rename preserves the original numeric wire value; Auth actions fit narrow viewports with long identifiers.

## [0.4.0] - 2026-09-09

### Added

- `GET /emulator/action`, the email action link the Auth emulator prints (`follow this link: ...`), is served like the official emulator's handler: `verifyEmail` and `verifyAndChangeEmail` apply the code, `resetPassword` needs a `newPassword` other than the placeholder and sets it, `signIn` forwards the link's parameters to `continueUrl`, and a `continueUrl` on the other modes is followed with a 303 once the code has acted. Missing parameters, unknown modes and used, expired or mismatched codes answer the official `authEmulator` JSON. The link opened with a browser answered 404 before.
- The action link is an App Check bypass surface (it stands in for the Firebase-hosted action page), published in the specification's bypass matrix as `identity-toolkit-action-link`.

### Changed

- The npm package page (`npm/README.md`) and the crate description now open with the same positioning as the repository README: an experimental local runtime for testing Firebase SDK and Functions code, not a replacement for the official Emulator Suite. The page had kept the earlier wording.

## [0.3.0] - 2026-09-09

### Added

- The Auth emulator prints every issued email action link and SMS verification code to the daemon's standard output with the official emulator's wording (`To verify the email address ..., follow this link: ...`, `To enroll MFA with ..., use the code ...`), once per issued code, and streams the same line to the Logging emulator for the UI Logs page. The banner says that these lines are credentials. `auth.logActionCodes = false` or `--log-verbosity quiet` silences them; the codes stay readable from the emulator inspection routes. Admin link generators (`returnOobLink`) receive the link in the response and print nothing, as before.
- The `auth.logActionCodes` configuration key.
- The tenant-scoped emulator inspection routes `/emulator/v1/projects/{project}/tenants/{tenant}/oobCodes`, `verificationCodes` and `accounts` (DELETE) of the official API, which answered 404.

### Changed

- A tenant's email action links carry `tenantId`, as the official emulator's tenant state appends it, in the Admin link generator response, the console line and the inspection route.

### Fixed

- The release binary no longer embeds the build checkout's absolute path. The workspace runner candidate used when running out of a cargo `target/` directory is now resolved at run time from the executable's location, so the same commit builds to the same bytes from any directory and the release workflow's reproducibility check passes.
- The reproducibility check now blocks publication instead of being advisory.

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
- Conformance: the composite-index fixtures record that two equality filters are served by index merging on both sides, and that a REST `runQuery` response omits the `done` flag the official emulator adds, as production does.
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

[Unreleased]: https://github.com/t-k/fireemu/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/t-k/fireemu/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/t-k/fireemu/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/t-k/fireemu/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/t-k/fireemu/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/t-k/fireemu/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/t-k/fireemu/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/t-k/fireemu/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/t-k/fireemu/releases/tag/v0.1.0
