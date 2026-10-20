---
title: Limitations
description: What Fireemu does not support, and what no local emulator can reproduce.
---

Fireemu does not yet reproduce every feature and behavior of production Firebase. This page lists the main limitations; it is not exhaustive. Check individual APIs in the [capability manifest](../#capability-manifest), or run:

```sh
npx fireemu capabilities
```

## Unsupported products

Firebase Hosting, App Hosting and Data Connect are not currently supported. Firebase Extensions support is not planned.

## Unsupported features

| Product | Unsupported features and limitations |
|---|---|
| Cloud Firestore | The Enterprise Pipeline API supports a limited subset of read operations (see [Enterprise pipelines](../../products/firestore/#enterprise-pipelines)). Full-text search validates index definitions, but searches are not executed locally. |
| Authentication | Sign-in flows that talk to external identity providers, authorization-code exchange and SAML XML signature verification. Provider configuration and local sign-in are supported. |
| Cloud Storage | Verifying the signature of a signed URL or a POST policy (their expiry and conditions are checked), object ACLs other than `allUsers` read, IAM and bucket-level public access, object composition (`compose`) and notification configuration. |
| Realtime Database | Security Rules evaluation (a database without rules is open, or locked to the `owner` credential with `database.defaultAccess`), import and export, Functions triggers and a UI view. Behavior taken from the official emulator where production has not been observed may change. |
| Cloud Functions | Triggers for products Fireemu does not deliver events for, such as Realtime Database (an open gap), Remote Config (deferred) and Data Connect (deferred). The exact shape of Storage archive events, which is unrecorded. |
| Cloud Pub/Sub | Schemas, BigQuery and Cloud Storage subscription delivery, and some APIs such as `UpdateTopic`. |
| App Check | Attestation through Play Integrity, App Attest, DeviceCheck or reCAPTCHA, and replay protection with limited-use tokens. Local testing with debug tokens is supported. |

## Differences no local emulator removes

A successful local operation does not guarantee the same result in production. Fireemu does not reproduce real quota accounting, billing, IAM, organization policies, regional or network differences, or service rollouts. Local performance does not predict production latency or throughput.

Security Rules and API behavior are implemented from documentation and from observations of Firebase's actual behavior. Changes in Firebase, or conditions that have not been tested, may introduce differences that have not been recorded yet.

## Local limits

Some limits exist only in Fireemu, to bound memory use: the [Firestore history limits](../../products/firestore/#transactions-and-history) and the optional [Storage stored-byte limit](../../products/storage/#limit-the-stored-bytes).

## Changes between versions

Configuration and behavior may change between releases. See the [CHANGELOG](https://github.com/t-k/fireemu/blob/main/CHANGELOG.md).
