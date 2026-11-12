---
title: Configuration schema
description: The JSON Schema of fireemu.toml.
---

`fireemu.toml` is described by a JSON Schema. Download it from this site, or read it in the repository:

- [fireemu.schema.json on this site](../../spec/config/fireemu.schema.json)
- [spec/config/fireemu.schema.json on GitHub](https://github.com/fireemu/fireemu/blob/main/spec/config/fireemu.schema.json), and the same file at a release tag, `https://raw.githubusercontent.com/fireemu/fireemu/v<version>/spec/config/fireemu.schema.json`, which is what `fireemu init` of a released binary writes into a new file (a build from source writes the `main` location)
- `npx fireemu config schema --out fireemu.schema.json` writes the schema bundled in the binary you run: the keys it accepts are the keys it validates with

The same settings can be written as TOML (`fireemu.toml`) or JSON (`fireemu.json`); see [Configuration files](../../guides/configuration/) for which file is loaded. Fireemu validates the file at startup, including rules the schema cannot express, and stops with an error on a value it does not accept. `npx fireemu config show` prints every key with its effective value and source.

## Top-level sections

| Section | What it configures | Guide |
|---|---|---|
| `schemaVersion` | Always `1` | |
| `profile`, `productionExact` | Production or official-emulator behavior | [Profiles and productionExact](../../guides/profiles/) |
| `firebaseJson` | The `firebase.json` to read ports, rules, indexes and Functions from | [Configuration files](../../guides/configuration/) |
| `firestore` | Edition, API mode, indexes, limits, history | [Cloud Firestore](../../products/firestore/) |
| `rules` | Firestore Security Rules source, and the denial log for Firestore and Storage | [Security Rules](../../guides/security-rules/) |
| `auth` | `requireClientApiKey` (default `false`) makes the emulator profile refuse client requests without an API key or Authorization header with the official emulator 403; strict is unchanged. Also configures sign-in methods, password policy, MFA, tenants, providers, tokens, and whether the Firestore, Storage and Realtime Database Security Rules surfaces accept unsigned mock ID tokens (`allowUnsignedIdTokens`) | [Authentication](../../products/auth/) |
| `storage` | Storage Security Rules, object size, buffered-body and stored-byte limits, bucket declaration (`undeclaredBuckets`), bucket CORS (`cors`) and signed URL keys (`signedUrlKeys`) | [Cloud Storage](../../products/storage/) |
| `database` | What a Realtime Database instance without a rules file allows (`defaultAccess`); `auth.allowUnsignedIdTokens` decides, in both profiles, whether its rules accept `@firebase/rules-unit-testing` mock tokens | [Realtime Database](../../products/realtime-database/) |
| `hosting` | Two development defaults of the strict profile: `cacheControl` (`"none"` by default, `"production"` with `productionExact` adds `Cache-Control: max-age=3600` to files) and `clientCountry` (`"honoured"` by default, `"ignored"` with `productionExact`) | [Firebase Hosting](../../products/hosting/#profiles) |
| `functions` | Codebase, runner, application clock, unserved triggers, a fixed list of served functions (`manifest`), and `authBlockingToken` (`"emulated"` by default, `"production"` with `productionExact` under `strict`, delivering a signed token verified by the Python runner using the SDK rules; Node functions receive the same production-shaped token but do not verify it, so they behave as before) | [Cloud Functions](../../products/functions/) |
| `scheduler` | Time zone, catch-up and overlap of scheduled functions | [Time and scheduled functions](../../guides/time/) |
| `pubsub`, `eventarc` | Authentication and delivery settings; `pubsub.restNegativeCache` (`"off"` by default; `"production"` is an explicit opt-in under strict that reproduces the roughly 10 s cached `404` after a real `404` that production showed on a connection; `productionExact` does not select it) | [Pub/Sub and Eventarc](../../products/pubsub-eventarc/) |
| `appCheck` | Apps, debug tokens and enforcement | [App Check](../../products/app-check/) |
| `daemon` | Ports, project, start time, how the clock moves (`clock`) | [Time and scheduled functions](../../guides/time/) |
| `network` | Listening off loopback (`allowNonLoopbackHosts`), and the extra `Host` names the emulators answer (`allowedHosts`, the DNS-rebinding defence) | [CI and containers](../../guides/ci-and-containers/#host-names-the-emulators-answer) |
| `bind` | Accepted, currently no effect: the daemon binds the loopback address, and `emulators.<name>.host` in `firebase.json` sets a host per service | [CI and containers](../../guides/ci-and-containers/) |
| `projects` | Whether only `demo-` project IDs are accepted (`requireDemoPrefix`), and whether a request naming another project is served or refused (`unknownProjects`) | [Profiles and productionExact](../../guides/profiles/) |
| `limits` | Reserved for limit catalogs, warnings, quota accounting and plan overrides. No member changes behavior yet: each is accepted with no effect, or accepts only its empty or default value and refuses any other. Firestore's limits are switched by `firestore.enforceLimits` | |
| `events` | Delivery of function trigger events: `maxAttempts` for functions declared with `retry` (default 4); `delivery` accepts only `exactly-once-test` | [Profiles and productionExact](../../guides/profiles/) |
| `trace` | Accepted, currently no effect | |

A key that is accepted with no effect prints a `note:` line when a run loads it. To fail a CI job on such a setting instead of relying on the log, run `fireemu config lint --deny-ineffective`, which lists them and exits 1 unless an `--allow` entry covers each one (see [`config lint`](../cli/#config-lint)).

## Storage size limits

`storage.maxObjectBytes` sets the maximum size of one object (default 268435456 bytes, maximum 2143289343). The request body cap is this value plus 4194304 bytes. `storage.bufferedBodyBudgetBytes` sets the process-wide budget for buffered Storage request bodies (default 1073741824 bytes, maximum 2147483647). Both values must be positive whole numbers. See [Cloud Storage](../../products/storage/) for the separate stored-byte and resumable-upload limits.
