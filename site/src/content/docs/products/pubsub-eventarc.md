---
title: Pub/Sub and Eventarc
description: Cloud Pub/Sub, Eventarc and Cloud Tasks emulators for Functions and server code.
---

## Cloud Pub/Sub

Fireemu serves the `google.pubsub.v1` API over gRPC and REST at `127.0.0.1:8085`. Pub/Sub starts when it is configured: `emulators.pubsub` in `firebase.json`, `daemon.pubsubPort`, `--pubsub-port`, or `--only pubsub`.

Topics, subscriptions, publish, pull and acknowledgement, push delivery, filters, ordering keys, dead-letter topics, StreamingPull, snapshots and seek are supported. Schemas, BigQuery and Cloud Storage subscription delivery, and some APIs such as `UpdateTopic` are not.

`fireemu exec` sets `PUBSUB_EMULATOR_HOST`, which the Google Cloud client libraries read.

### Authentication

Under `strict`, a request without any credential is accepted, so clients that use `PUBSUB_EMULATOR_HOST` without credentials work. A request that presents a credential is checked, and Fireemu cannot verify a real Google OAuth token offline, so such a request is refused with 401. Use a credential-free client against the emulator, for example the Java client with `NoCredentialsProvider`.

For tests that need a credential, set a local fixture bearer token. The endpoint then accepts only `Authorization: Bearer <token>` with that exact value, and refuses requests without a credential as production does:

```json
{ "schemaVersion": 1, "pubsub": { "authentication": { "localBearerToken": "fixture-token" } } }
```

Use a made-up value; never reuse a production credential. The published configuration schema does not list `pubsub.authentication` yet, so an editor that validates against it flags this key; Fireemu accepts it.

## Eventarc

When a Functions codebase is loaded, Fireemu starts an Eventarc listener at `127.0.0.1:9299` and sets `CLOUD_EVENTARC_EMULATOR_HOST`. Functions declared with `onCustomEventPublished` receive the events published to their channel.

The Admin SDK always asks its credential for an access token before publishing, and CI has no Google credential. Give the app a fake credential:

```js
import { initializeApp } from 'firebase-admin/app';
import { getEventarc } from 'firebase-admin/eventarc';

const app = initializeApp({
  projectId: 'demo-app',
  credential: { getAccessToken: async () => ({ access_token: 'owner', expires_in: 3600 }) },
});
await getEventarc(app).channel('locations/us-central1/channels/firebase').publish({
  type: 'com.example.thing.done',
  source: 'https://example.com/things',
  data: { id: 'e1' },
});
```

By default the listener does not check the credential (`eventarc.authentication: "permissive"`), as the official emulator does not. With `"production"` (or `productionExact`), a missing, malformed or JWT-shaped bearer is refused with production's 401.

## Cloud Tasks

When a Functions codebase is loaded, Fireemu starts a Cloud Tasks emulator at `127.0.0.1:9499` and sets `CLOUD_TASKS_EMULATOR_HOST`. Task queue functions (`onTaskDispatched`) receive the tasks enqueued for them, with their rate limits and retry configuration. Task scheduling can follow the virtual clock; see [Time and scheduled functions](../../guides/time/).
