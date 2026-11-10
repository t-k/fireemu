---
title: Connect your app
description: Point the Firebase client and Admin SDKs at the Fireemu emulators.
---

Fireemu serves the same protocols and default ports as the Local Emulator Suite, so you connect to it the same way.

## Server code and the Admin SDK

The Firebase Admin SDK and the Google Cloud client libraries read the emulator environment variables. `fireemu exec` sets them for the command it runs:

```sh
npx fireemu exec -- node ./scripts/seed.mjs
```

| Variable | Value |
|---|---|
| `FIRESTORE_EMULATOR_HOST` | Firestore `host:port` |
| `FIREBASE_AUTH_EMULATOR_HOST` | Authentication `host:port` |
| `FIREBASE_STORAGE_EMULATOR_HOST`, `STORAGE_EMULATOR_HOST` | Storage `host:port` and `http://host:port` |
| `GCLOUD_PROJECT`, `GOOGLE_CLOUD_PROJECT` | The project ID |
| `FIREEMU_CONTROL_URL`, `FIREEMU_CONTROL_TOKEN` | Fireemu's control API, used by `fireemu/testing` |

Variables for the other emulators (Realtime Database, Pub/Sub, Eventarc, Cloud Tasks, App Check, the Hub) are listed with the conditions in [Environment variables](../../reference/environment-variables/). Variables for emulators that are not selected are left as your environment had them.

```js
import { initializeApp } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

// Under `fireemu exec`, the Admin SDK finds the emulators from the environment.
initializeApp({ projectId: process.env.GCLOUD_PROJECT });
await getFirestore().doc('notes/n1').set({ text: 'hello' });
```

## Client SDKs

Client SDKs are connected in code, as with the Local Emulator Suite. Use the project ID Fireemu runs with: the `.firebaserc` default, else `daemon.authProject` in `fireemu.toml`, else `demo-app`.

```js
import { initializeApp } from 'firebase/app';
import { getAuth, connectAuthEmulator } from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore';
import { getStorage, connectStorageEmulator } from 'firebase/storage';
import { getFunctions, connectFunctionsEmulator } from 'firebase/functions';

const app = initializeApp({
  projectId: 'demo-app',
  apiKey: 'fake-api-key',
  storageBucket: 'demo-app.appspot.com',
});

connectAuthEmulator(getAuth(app), 'http://127.0.0.1:9099');
connectFirestoreEmulator(getFirestore(app), '127.0.0.1', 8080);
connectStorageEmulator(getStorage(app), '127.0.0.1', 9199);
connectFunctionsEmulator(getFunctions(app), '127.0.0.1', 5001);
```

The default ports are listed in [Install and run](../install/#default-ports). The Realtime Database client needs its own `databaseURL`; see [Realtime Database](../../products/realtime-database/#connect). Hosting is plain HTTP and needs no SDK setup ([Firebase Hosting](../../products/hosting/)).

## Security Rules unit tests

`@firebase/rules-unit-testing` works with Fireemu. Its unsigned mock ID tokens (`authenticatedContext()`) are accepted by default, also under the `strict` profile, and the routes it calls to load Firestore and Storage rules and to clear Firestore (`testEnv.clearFirestore()`) are served. So is `withFunctionTriggersDisabled`: the Hub accepts `PUT /functions/disableBackgroundTriggers` and `enableBackgroundTriggers` without a token from a client that sends no browser metadata (`Origin`, `Sec-Fetch-Site`). See [Security Rules](../../guides/security-rules/).

## The project ID

Fireemu takes the project ID from, in order:

1. `--project` (`-P`) on the command line, as an ID or a `.firebaserc` alias;
2. the default project of the `.firebaserc` next to the loaded `firebase.json`;
3. `daemon.authProject` in `fireemu.toml`;
4. `demo-app`.
