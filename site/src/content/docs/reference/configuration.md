---
title: Configuration schema
description: The JSON Schema of fireemu.toml.
---

`fireemu.toml` is described by a JSON Schema. Download it from this site, or read it in the repository:

- [fireemu.schema.json on this site](../../spec/config/fireemu.schema.json)
- [spec/config/fireemu.schema.json on GitHub](https://github.com/t-k/fireemu/blob/main/spec/config/fireemu.schema.json)

Fireemu reads both TOML (`fireemu.toml`) and JSON (`fireemu.json`); discovery loads the file in the current directory and refuses to start if both exist, unless you select one with `--config`.

Fireemu validates the file at startup, including rules the schema cannot express, and stops with an error on a value it does not accept.

## Top-level sections

| Section | What it configures | Guide |
|---|---|---|
| `schemaVersion` | Always `1` | |
| `profile`, `productionExact` | Production or official-emulator behavior | [Profiles and productionExact](../../guides/profiles/) |
| `firebaseJson` | The `firebase.json` to read ports, rules, indexes and Functions from | [Configuration files](../../guides/configuration/) |
| `firestore` | Edition, API mode, indexes, limits, history | [Cloud Firestore](../../products/firestore/) |
| `rules` | Firestore Security Rules source, and the denial log for Firestore and Storage | [Security Rules](../../guides/security-rules/) |
| `auth` | Sign-in methods, password policy, MFA, tenants, providers, tokens, and whether the Firestore, Storage and Realtime Database Security Rules surfaces accept unsigned mock ID tokens (`allowUnsignedIdTokens`) | [Authentication](../../products/auth/) |
| `storage` | Storage Security Rules and stored-byte limit | [Cloud Storage](../../products/storage/) |
| `database` | What a Realtime Database instance without a rules file allows (`defaultAccess`); `auth.allowUnsignedIdTokens` decides, in both profiles, whether its rules accept `@firebase/rules-unit-testing` mock tokens | [Realtime Database](../../products/realtime-database/) |
| `functions` | Codebase, runner, application clock, unserved triggers, a fixed list of served functions (`manifest`) | [Cloud Functions](../../products/functions/) |
| `scheduler` | Time zone, catch-up and overlap of scheduled functions | [Time and scheduled functions](../../guides/time/) |
| `pubsub`, `eventarc` | Authentication and delivery settings | [Pub/Sub and Eventarc](../../products/pubsub-eventarc/) |
| `appCheck` | Apps, debug tokens and enforcement | [App Check](../../products/app-check/) |
| `daemon` | Ports, project, start time | [Time and scheduled functions](../../guides/time/) |
| `network` | Listening off loopback | [CI and containers](../../guides/ci-and-containers/) |
