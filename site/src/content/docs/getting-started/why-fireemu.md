---
title: Why Fireemu
description: What Fireemu is for, and how it differs from the Firebase Local Emulator Suite.
---

Fireemu is a local emulator for testing applications built with Firebase. It aims to match production Firebase behavior as closely as possible, so you can test locally and in CI without using a real Firebase project.

## The gap it closes

Passing tests against the official emulator does not always mean your application will behave the same way in production. Some features are not supported by the official emulator, and some execution conditions are difficult to reproduce locally. These gaps can leave you relying on a real Firebase project for part of your testing.

Fireemu is being developed to close these gaps. For example:

- **Validation of configuration required in production.** Fireemu detects issues that the official emulator misses, such as a Firestore query whose composite index is not declared in `firestore.indexes.json`.
- **Features the official emulator does not serve.** TOTP multi-factor authentication, App Check with debug tokens, and, under `strict`, the `beforeEmailSent` blocking function.
- **Control over test execution conditions.** Set an arbitrary start time and move a virtual clock to run scheduled functions without waiting for the real schedule.

## Production first

Where the official emulator and production Firebase disagree, Fireemu follows production under its default `strict` profile, and records the difference. The exceptions are the development defaults described below, which `productionExact` switches to production's behavior. The answers keep production's wording and status codes, so the errors your application handles in tests are the errors it will meet after you deploy.

Each behavior is checked against recordings from real Firebase projects. The [compatibility tables](../../compatibility/) list every area that has been verified this way and how many conditions it covers.

Some production behavior is costly in a test: production needs signed tokens, signing keys, or a feature enabled through an Admin API call. For each of these, Fireemu keeps a development default that works without setup, and one setting, `productionExact`, switches all of them to production's behavior. See [Profiles and productionExact](../../guides/profiles/).

## Built for tests

- **One command for CI.** `fireemu exec -- npm test` starts the emulators, runs your tests with the emulator environment variables set, stops everything and returns the test command's exit status.
- **Reuses your `firebase.json`.** Rules, indexes, Functions codebases and ports are read from it on every start.
- **Explains denials.** Each Security Rules denial is printed with the conditions that were evaluated and their results.
- **Independent test worlds.** The `fireemu/testing` helper starts isolated emulator instances with their own clock, Rules, Functions and data, for parallel integration tests.
- **Small and fast.** Fireemu is a single native binary. See [Performance](../../compatibility/performance/).

## What it is not

Fireemu does not reproduce real quota accounting, billing, IAM, organization policies, regional or network differences, or service rollouts, and local performance does not predict production latency. See [Limitations](../../compatibility/limitations/).

:::tip[Keep a production check]
Fireemu is still in development. For the features and critical workflows your application uses, run the same tests against Fireemu and a dedicated Firebase test project (not your live project), and compare the results before relying on Fireemu alone in CI.
:::
