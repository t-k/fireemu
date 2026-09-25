# Changelog

All notable changes to fireemu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, a minor release may change configuration, unsupported behavior, and edge-case semantics.

Each release is a Git tag; the binaries and the npm packages are built from that tag by the release workflow. Behavior described as "matching production" was measured against a real Firebase project on the date named in the commit that introduced it.

## [Unreleased]

Behavior below was measured against a real Identity Platform project on 2026-09-24 and 2026-09-25 (AUTH-CREDENTIAL, AUTH-ACTION and AUTH-MFA). Each item names the profiles it affects; "unlike the official emulator" marks where the emulator profile now differs from the Firebase Emulator Suite.

### Added

- Both profiles: the Admin config API holds the project's `mfa` member (`state`, `enabledProviders`, `providerConfigs`) and reads it back in production's shape, starting from `{"state": "DISABLED"}` as a new production project does. A value whose TOTP provider is enabled enables TOTP enrollment and sign-in without `auth.totp`, with its `adjacentIntervals` as the acceptance window (fireemu-only in the emulator profile, which has no project `mfa` config in the official emulator).
- Both profiles: the project `mfa` config reads back and refuses as production does (sandbox recording 2026-09-24, `auth-mfa/config`): an `adjacentIntervals` of 0 reads back as `totpProviderConfig: {}`, a provider entry without `totpProviderConfig` is dropped, `MANDATORY` is accepted, an out-of-range window is `INVALID_ADJACENT_INTERVAL_RANGE` and an unknown enum value production's parse error with its field violation.
- Strict profile: while the project's MFA is off, a phone enrollment is `OPERATION_NOT_ALLOWED : SMS based MFA not enabled.` and an account's enrolled factors are not asked for at sign-in, as in production (`auth-mfa/disabled`); the answer that asks for a second factor keeps a password sign-in's `displayName` and leaves out an email link's `isNewUser`. Tenants keep asking for enrolled factors (tenant MFA config belongs to AUTH-TENANT-BLOCKING).
- Both profiles: a TOTP enrollment start answers `hashingAlgorithm: SHA1`, and its session lives 900 seconds (both as production; the fireemu-only `auth.totp` default was 300 seconds); factors are listed in the order they were enrolled, whatever their kind; a TOTP factor keeps its display name.
- Strict profile: TOTP enrollment answers as production (sandbox recording 2026-09-24, `auth-mfa/totp/enroll`): the v2 error shape; `Request contains an invalid argument.` without enrollment info and production's oneof error with both kinds; the session, then `MISSING_DISPLAY_NAME`, then the code; `totpAuthInfo` in the answer; a session counts three finalize attempts (`TOO_MANY_ENROLLMENT_ATTEMPTS : restart enrollment`) and keeps answering `SESSION_EXPIRED` after its lifetime; a session offered again after it was finalized is `MFA_ENROLLMENT_ALREADY_COMPLETE` (seen in an exploration on the sandbox, not in the recorded corpus); a second TOTP factor and a sixth factor are `SECOND_FACTOR_LIMIT_EXCEEDED` with production's words; enrollment ids are UUIDs and enrollment times are protobuf timestamps (microseconds when a user enrolls, milliseconds when the Admin API writes the factor).
- Strict profile: second-factor sign-in answers as production (sandbox recording 2026-09-24, `auth-mfa/totp/sign-in`, `sms`, `interactions`): the v2 error shape; `Request contains an invalid argument.` for a missing pending credential, factor id, code or phone sign-in info; `INVALID_PENDING_TOKEN` for an unknown pending credential and `USER_NOT_FOUND` once its account is deleted; `INVALID_MFA_ENROLLMENT_ID` for a factor that is not the account's; `INVALID_PHONE_NUMBER : Invalid format.` for a phone start on a TOTP factor; a code already used is a plain `INVALID_CODE`. As production does, a pending credential stays usable after it succeeds (until it expires), an account disabled after its first factor completes a TOTP sign-in, and a configured test number's SMS session can be used again. Tenants keep their earlier rules (tenant MFA belongs to AUTH-TENANT-BLOCKING).
- Strict profile: a factor withdrawal ends every session before it, as a phone enrollment does (a TOTP enrollment does not), and answers without `expiresIn` with a session that keeps the asking session's second factor unless that factor was withdrawn (also when sessions are RS256-signed); a missing token is `INVALID_ID_TOKEN` and a missing factor id `MFA_ENROLLMENT_NOT_FOUND` (sandbox recording 2026-09-24, `auth-mfa/totp/withdraw`, `sms`).
- Both profiles: the Admin `accounts:update` `mfa` member replaces every factor, TOTP ones included, and clears them without `enrollments`, as production and the official emulator do; an entry with only `totpInfo` is `UNSUPPORTED_SECOND_FACTOR : attempting to add a new TOTP enrollment` (an entry with `phoneInfo` stays a phone factor) and an invalid number `INVALID_PHONE_NUMBER : Invalid format.`
- Both profiles: a snapshot restored into another namespace keeps the destination's project `mfa` config, as it keeps its other control-plane settings.
- Strict profile: the per-user budget of 32 outstanding second-factor flows no longer fills with entries production's rules keep only for their answers (a pending credential that already succeeded, an expired or completed enrollment session). At the budget the oldest such entry is dropped first; it then answers as unknown (`INVALID_PENDING_TOKEN`, `INVALID_SESSION_INFO`). This bound is local to fireemu, not a production quota. Tenants keep their earlier second-factor rules, phone enrollment included.
- Strict profile: the SMS step of a pending credential 602 seconds old or older is `INVALID_MFA_PENDING_CREDENTIAL : MFA pending credential is expired.` (sandbox recording 2026-09-25, `auth-mfa/lifetime-sms`: production started it at about 453 seconds and refused it at about 603 and 1803 seconds). A finalize after an accepted start is not refused; the emulator profile keeps the pending credential's hour.
- Strict profile: a TOTP sign-in whose pending credential is 302 seconds old or older is `TOTP_CHALLENGE_TIMEOUT : TOTP challenge timeout, provide first factor again.`, and a TOTP enrollment start whose session signed in 333 seconds ago or earlier is `CREDENTIAL_TOO_OLD_LOGIN_AGAIN` (sandbox recordings 2026-09-24, `auth-mfa/lifetime` and `auth-mfa/lifetime-short`: production accepted 293 and 244 seconds and refused 303 and 333; the pending boundary sits a second below the refusal to absorb request latency). Younger ages are unobserved and stay accepted. The recent sign-in is not asked for a phone enrollment start, whose need for one was not seen; the emulator profile is unchanged.
- Strict profile: a phone enrollment session does not expire, instead of lasting the ten minutes of a phone code. Production accepted sessions of every age it was shown, up to about 1803 seconds (sandbox recording 2026-09-24, `auth-mfa/lifetime`), and refused none. An account holds at most 32 of them; at that number, or at the project's cap of 1000 outstanding phone codes, its own oldest enrollment session older than that makes room, and another account's sessions are never dropped. Other phone codes and the emulator profile keep ten minutes.
- Strict profile, as production (sandbox recording 2026-09-24, `auth-mfa/first-factor/custom-token`): a custom-token sign-in returns tokens without asking for the account's enrolled second factor.
- Strict profile: `accounts:batchCreate` refuses a row with a TOTP factor as `Importing TOTP MFA is not supported.`, with or without the fireemu-only `sharedSecretKey`, and gives an imported factor without an id a UUID and one without a time the import time in milliseconds (sandbox recording 2026-09-24, `auth-mfa/admin-factors`). The emulator profile keeps its own ids and the TOTP import.
- `auth.customTokenSigners` maps service accounts to their public JWK sets (RSA keys of at least 2048 bits). With it, `signInWithCustomToken` verifies RS256 signatures and applies production's custom-token rules in either profile; a verifying token of another project's service account is refused with `CREDENTIAL_MISMATCH`.
- The Admin project config reads and replaces `authorizedDomains`, starting with `localhost` and the project's `firebaseapp.com` and `web.app` domains. The strict profile refuses an action-code `continueUrl` outside them with `UNAUTHORIZED_DOMAIN`, as production does; the emulator profile does not check the domain, as the official emulator does not.
- `auth.apiKeys` declares the project's Web API keys. A client request with any other key is refused with production's `400 API_KEY_INVALID` envelope (unlike the official emulator, which validates no key). An unknown key under a registered session now gets the same envelope instead of `INVALID_API_KEY`.

### Changed

- Both profiles: a tenant created with a display name of the documented form (4-20 letters, digits and hyphens, beginning with a letter) is named as production names it: the display name, `-` and five characters of `[a-z0-9]`, drawn reproducibly from the creation sequence. A tenant without such a display name keeps the `fireemu-<sequence>` name.
- Strict profile: `signInWithCustomToken` accepts only signed tokens, as production does. Without `auth.customTokenSigners` every custom token, including the Admin SDK's unsigned emulator tokens and JSON fake tokens, is refused with `INVALID_CUSTOM_TOKEN`, and the startup banner says so. Use `auth.customTokenSigners`, or the emulator profile for the Admin SDK's emulator tokens.
- Strict profile: password and custom-token sign-in without `returnSecureToken` return production's legacy Identity Toolkit token (issuer `https://identitytoolkit.google.com/`, two-week lifetime) and no refresh token. The routes production was observed to honour it on accept it: account lookup, update and delete, a verification mail and an email change, phone linking, email-link linking (AUTH-ACTION), a sign-up upgrade and MFA enrollment. Identity-provider linking and session-cookie creation refuse it. A request whose blocking trigger runs keeps secure tokens. The emulator profile keeps secure tokens.
- Strict profile: `createSessionCookie` decodes `validDuration` as an int64, refusing a fraction or text with `INVALID_ARGUMENT` and zero with `INVALID_DURATION`. The emulator profile keeps the official emulator's `Number(validDuration) || two weeks`.
- Both profiles: Identity Toolkit honours an ID token for five minutes past its `exp`, then refuses it with `INVALID_ID_TOKEN` instead of `TOKEN_EXPIRED`. A strict custom token gets the same allowance and `INVALID_CUSTOM_TOKEN`. A revoked session still answers `TOKEN_EXPIRED`. Unlike the official emulator, which never reads an ID token's `exp`.
- Both profiles: an administrator's `validSince` is stored as given and may move back, and sessions are judged against it when they are used, so a refresh token is `TOKEN_EXPIRED` below it and works again once it moves back. A client update's `validSince` is ignored. Unlike the official emulator, which sets `validSince` to the current time for any value from either caller.
- Both profiles: session cookies carry `{alg, kid}` with no `typ` (unlike the official emulator's `typ: JWT`, which the Admin SDK does not read).
- Both profiles: `createSessionCookie` answers an API key without a credential with production's `401 UNAUTHENTICATED` (`CREDENTIALS_MISSING`), and a deleted account's ID token with `USER_NOT_FOUND`.
- Both profiles: a custom-token sign-in marks the account `customAuth`, and the account then reports `validSince` (the official emulator reports `customAuth` only). Custom-token answers never include `localId` or `email`, and anonymous ID tokens carry a top-level `provider_id`, as with the official emulator.
- Both profiles: Secure Token reads an empty `grant_type` or `refresh_token` as missing (`MISSING_GRANT_TYPE`, `MISSING_REFRESH_TOKEN`). In the strict profile a Secure Token request with no API key gets its front end's 403 without an `errors` list; the emulator profile keeps accepting a keyless request.
- Strict profile: `auth.totp` alone no longer enables TOTP; only the project `mfa` config does, as in production (`auth-mfa/disabled#totp-start`). While that config is off, an account with a TOTP factor is still asked for it (fail closed); production was seen to skip only a phone factor then (`auth-mfa/disabled#sign-in-a-with-factor`). The emulator profile keeps `auth.totp`.
- Strict profile: MFA enrollment answers `OPERATION_NOT_ALLOWED : TOTP based MFA not enabled.` when TOTP is off, and its refusals carry the v2 API's shape (a status name and no `errors` list). The emulator profile keeps the official emulator's answers.
- Both profiles: linking a phone number answers with a session whose `sign_in_provider` is `phone`, as production does and as the official emulator does.
- Both profiles, as production and the official emulator: an Admin link request for a password reset of an unknown address is answered 200 without a code under improved email privacy; a verification or change link for an unknown address is `USER_NOT_FOUND` and one with neither address nor token `MISSING_EMAIL`; a client `returnOobLink` is `INSUFFICIENT_PERMISSION`; an email link used with another address is `INVALID_EMAIL : The email provided does not match the sign-in email address.` and one without an address `MISSING_EMAIL`; linking an address to a session by email link answers an `EmailLinkSigninResponse` whose token is a `password` session; lookups report `emailLinkSignin`; the emulator profile refuses a non-absolute `continueUrl` with the official `INVALID_CONTINUE_URI` and reads an empty `newPassword` as an inspection.
- Both profiles: an account an email link created reports `validSince`, and an Admin-created account with only a phone number is a phone account whose sessions carry no anonymous `provider_id`, as in production.
- Strict profile: action codes follow production. A newer password reset, email change or sign-in code of an address retires the older one; a deleted account's codes are refused; a reset finds the account by the code's address (`USER_NOT_FOUND` once it has another), refuses an empty password with a bare `WEAK_PASSWORD`, only inspects a sign-in code offered with a password, and leaves earlier sessions `TOKEN_EXPIRED` rather than forgetting their refresh tokens; a verification finds its account by address (`EMAIL_NOT_FOUND`) and a disabled account refuses both kinds of code; an applied email change answers like an account update, records the replaced address as `initialEmail` (the official emulator records it on a direct update only) and revokes earlier sessions; an update with an ID token ignores `oobCode`; request types, continue URLs, addresses and new addresses are refused with production's codes, and a taken or unchanged new address is hidden behind a sent-mail answer under improved email privacy; an email link honours a legacy ID token and removes the password of an account whose address was never verified, which then becomes an email-link account; a reset refused for a disabled account spends its code; only the Admin generator is told a sign-in link's address belongs to a disabled account; the action page treats a code past its lifetime as gone; a continue URL's authority ends at a backslash, as a browser reads it; an applied email change also voids the replaced address's verification codes.
- Strict profile: a password reset code lives an hour and is then refused as `EXPIRED_OOB_CODE`; verification, email-change and sign-in codes are never refused as expired (production answered them 3900 seconds after their generation, and no Google document states their lifetime, so refusing them at any later age could refuse what production accepts); at the per-project cap of outstanding codes, the oldest of them that is older than 3900 seconds makes room. The emulator profile keeps its one-hour local policy for every kind.
- Strict profile: an Admin email-link request is refused with `OPERATION_NOT_ALLOWED` while email links are off, as production refuses it. The emulator profile generates the link, as the official emulator does (it always reports email links as enabled).
- Both profiles: a password reset or verification code acts on the account that owns its address now, also when another account took the address after the code was issued, as production does (sandbox recording 2026-09-24, `auth-action/address-reuse`) and as the official emulator does. The emulator profile now answers a code whose address nobody owns with the official `INVALID_OOB_CODE` and spends it, as the official emulator does; it used to apply the code to the account it was issued for.
- Strict profile: a verification or email change applied from the emulator's action page (`/emulator/action`) follows the same production rules as `accounts:update` with the code: earlier sessions are revoked, the replaced address is recorded as `initialEmail`, and its verification codes are void.
- Both profiles: action codes, phone verification sessions and codes, phone proofs, MFA sessions and pending credentials, refresh tokens and TOTP secrets are drawn from the operating system CSPRNG, as the daemon's start-up secrets are, so a daemon run with a fixed `seed` no longer issues credentials that can be predicted from one another. Their shapes do not change; account and factor ids still follow the seed.

### Fixed

- Both profiles: a session snapshot captures the session project's Identity Platform tenants with the project, and a restore rolls them back too: tenant users and credentials added after the capture are gone, a tenant created since is removed, and a tenant deleted since comes back with its users under a new session epoch. It used to restore the project's own users only. The session resource report counts tenant users in `users.count` and reports the number of tenants as `tenants.count`.

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
