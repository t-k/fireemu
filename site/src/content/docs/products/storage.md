---
title: Cloud Storage
description: Cloud Storage for Firebase locally, with both the Firebase and Cloud Storage JSON APIs and Storage Security Rules.
---

Fireemu serves Cloud Storage for Firebase at `127.0.0.1:9199`, with both API dialects:

- the Firebase Storage protocol the client SDKs use, including resumable uploads and download tokens;
- the Cloud Storage JSON API the Admin SDK and the Google Cloud client libraries use, including copy and rewrite.

Both dialects share one store, so an object uploaded through one is visible through the other.

## Production behavior

Under `strict`, generation and metageneration preconditions and declared checksums are honored as production honors them. The official emulator verifies no checksum.

Storage Security Rules are read from the `storage.rules` file named in `firebase.json`, or `storage.rules` in `fireemu.json`. A Storage rule can read Firestore documents with `firestore.get()` and `firestore.exists()`. Under `strict`, a project without rules refuses every end-user request with production's 400 "bucket has not been set up" answer. See [Security Rules](../../guides/security-rules/).

## Limit the stored bytes

The Storage emulator keeps every object in memory, and by default nothing bounds how much. To cap it, set `storage.maxStoredBytes`. This limit is local to Fireemu; production has none:

```json
{
  "schemaVersion": 1,
  "storage": { "maxStoredBytes": 1073741824 }
}
```

- An upload, a resumable upload's final request or a copy that would grow the total past the limit is refused with HTTP 402 and the message `storage.maxStoredBytes limit exceeded`. The Firebase client SDKs report it at once as `storage/quota-exceeded`.
- A write that does not grow the total, such as an equal or smaller replacement, always passes.
- A refused write changes nothing. A resumable upload stays open, so you can send the same final chunk again after making room.

`fireemu doctor --connect <control URL>` reports the stored bytes against this limit.

## Not supported

Object versioning, signed URLs, ACL-based access control, object composition (`compose`) and notification configuration are not supported.

:::caution[Keep the Storage port on localhost]
Like the official emulator, the Storage port reflects the requested object name in the HTML body of its 404 for a missing media read. A web page opened on your machine could run script on that origin. Keep the emulator bound to localhost, the default, and do not expose the Storage port to other hosts or networks.
:::
