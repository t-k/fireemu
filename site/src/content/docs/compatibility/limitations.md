---
title: Limitations
description: What Fireemu does not support, and what no local emulator can reproduce.
---

Fireemu does not yet reproduce every feature and behavior of production Firebase. This page lists the main limitations; it is not exhaustive. Check individual APIs in the [capability manifest](../#capability-manifest), or run:

```sh
npx fireemu capabilities
```

## Unsupported products

App Hosting and Data Connect are not currently supported. Firebase Extensions support is not planned. Firebase Hosting is served for one site, without a production parity claim; see [Firebase Hosting](../../products/hosting/#not-supported) for what it does not support.

## Unsupported features

### Cloud Firestore

- The Enterprise Pipeline API supports a limited subset of read operations (see [Enterprise pipelines](../../products/firestore/#enterprise-pipelines)).
- Enterprise text search provides finite local lexical search and explicit build controls. Analysis and ranking are approximations; `productionExact` refuses unobserved search semantics.

### Authentication

- Sign-in flows that talk to external identity providers, hosted authorization-code exchange and live key discovery and rotation are not supported.
- Local configured signed OIDC/SAML verification is supported by the strict signed-assertion path, using `auth.idpSigners` public keys or the SAML provider's configured certificates.
- Finite SAML checks cover present status, destination, issuer, audience and validity fields, and responses to known daemon-issued requests. Absent fields, unparseable times and other unrecorded combinations remain unobserved.

### Cloud Storage

- Verifying the signature of a signed URL or a POST policy (their expiry and conditions are checked).
- Object ACLs other than `allUsers` read, IAM and bucket-level public access.
- Object composition (`compose`) and notification configuration.

### Realtime Database

- Verified against production for its recorded cases only (see [Production verification](../#production-verification)); broader production compatibility is unverified, and there is no parity claim against the official emulator. Comparison is limited to recorded official-emulator cases.
- The listed unsupported syntax and evaluation cases (regular-expression constructs, case mappings and the other differences listed there) are refused when rules load or produce rule errors. `query.endBefore`, `query.isOrderByChild()`, the `OrderByKey`, `OrderByValue` and `OrderByPriority` names, `http.encodeURL()`, method reads without a call and ternary callees load and evaluate as production was recorded doing.
- The eight recorded patterns refused by the official emulator's determinization resource limit are also rejected when Fireemu loads rules, including in unevaluated expression branches. This does not establish complete regular-expression or production equivalence.
- Functions trigger delivery has been observed for a limited set of recorded handlers and writes; broader cases remain unverified.
- Behavior taken from the official emulator where production has not been observed may change.

See [Realtime Database](../../products/realtime-database/#differences-from-the-official-emulator).

### Cloud Functions

- Triggers for products Fireemu does not deliver events for, such as Data Connect (deferred). Remote Config handlers run only through the local injection action, and its production event shape is unobserved.
- Dart codebases, and protobuf CloudEvents ingress other than Firestore events. Firestore events reach the Python SDK as protobuf, and Node 2nd-gen functions as protobuf under `strict`.
- The exact shape of Storage archive events remains unrecorded.
- Python codebases serve HTTP, callable, Firestore, Pub/Sub, Storage, Eventarc, Realtime Database, scheduled, task-queue and Auth blocking functions. They see real time only (no virtual clock), do not reload source changes (Node source changes reload automatically), and run on macOS and Linux only. Their callables' App Check tokens are verified by the Python SDK against the App Check emulator's keys (no limited-use consumption, and an explicit App Check configuration refuses to start). See [Cloud Functions (Python)](../../products/functions-python/).

### Cloud Pub/Sub

- Schemas, BigQuery and Cloud Storage subscription delivery, exactly-once delivery and message transforms.
- `UpdateTopic` supports only the `labels` update mask; `DetachSubscription` is not implemented.

### App Check

- Attestation through Play Integrity, App Attest, DeviceCheck or reCAPTCHA, and replay protection with limited-use tokens. Local testing with debug tokens is supported.

## Local control limitations

Sessions share clocks, rules, Functions and the admission barrier. Snapshots are held in memory for the daemon lifetime; they do not capture outstanding Functions work. `awaitIdle` does not wait for Text Index work or provide causal fences across sessions.

## Differences no local emulator removes

A successful local operation does not guarantee the same result in production. Fireemu does not reproduce real quota accounting, billing, IAM, organization policies, regional or network differences, or service rollouts. Local performance does not predict production latency or throughput.

Security Rules and API behavior are implemented from documentation and from observations of Firebase's actual behavior. Changes in Firebase, or conditions that have not been tested, may introduce differences that have not been recorded yet.

## Local limits

Some limits exist only in Fireemu, to bound memory use: the [Firestore history limits](../../products/firestore/#transactions-and-history) and the optional [Storage stored-byte limit](../../products/storage/#limit-the-stored-bytes).

## Changes between versions

Configuration and behavior may change between releases. See the [CHANGELOG](https://github.com/t-k/fireemu/blob/main/CHANGELOG.md).
