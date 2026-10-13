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

Under `strict` the Storage emulator also refuses what production refuses and the official emulator accepts:

- **A bucket nobody created.** An object operation on a bucket that does not exist (upload, read, list, delete, copy, rewrite, ACL) is refused with production's 404 `The specified bucket does not exist.` The official emulator creates a bucket on first use. Your project's two default buckets (`<project>.appspot.com` and `<project>.firebasestorage.app`), the buckets of `firebase.json` storage targets, the buckets a deployed Storage trigger names, and any bucket that holds imported data exist. Declare any other bucket in `storage.buckets`.
- **A public URL for a private object.** `GET /{bucket}/{object}`, which is what `file.publicUrl()` builds, answers 403 `AccessDenied` unless the request carries an `Authorization` header, is a signed URL that has not expired, or the object's ACL grants `allUsers` read. `file.makePublic()` and `predefinedAcl=publicRead` on an upload grant it, for that generation of the object only: an overwrite is private again. Firebase download-token URLs are not affected.
- **An expired signed URL.** A V4 or V2 signed URL past its lifetime answers 400 `ExpiredToken`, and a V4 lifetime over seven days or an unreadable `X-Goog-Date` answers 400. The signature itself is not verified, because that needs the signing service account's key; any signature is accepted.
- **A form upload without a signed policy.** `POST /{bucket}` with a multipart form needs a `policy` and a signature field. The policy's expiry and conditions (`bucket`, `eq`, `starts-with`, `content-length-range`) are enforced; the signature is not verified.
- **A Firebase ID token as an OAuth bearer** on the JSON API: 401 `Invalid Credentials`. Any other credential, or none, is served as the owner, because a local run cannot judge an access token.
- **An ACL entry Cloud Storage does not know** (400). Only `allUsers` with role `READER` has an effect.
- **A bucket name Cloud Storage never accepts** (for example `ab` or `Has-Upper`): 400 `Invalid bucket name` on the JSON API.

The `emulator` profile keeps the official emulator's behavior for all of these.

### Declare extra buckets

```json
{
  "schemaVersion": 1,
  "storage": { "buckets": ["uploads-bucket", "exports.example.com"] }
}
```

Each name must be one Cloud Storage accepts. The key is ignored by the `emulator` profile, which creates a bucket on first use.

### Which default bucket exists

A production project has one default bucket: `<project>.firebasestorage.app` if Storage was set up after 2024-10-30, `<project>.appspot.com` before. A local run cannot know which, so both exist by default. To refuse the one your project does not have, such as an app configuration copied from an older project, set `storage.defaultBucket`:

```json
{
  "schemaVersion": 1,
  "storage": { "defaultBucket": "firebasestorage.app" }
}
```

The values are `"both"` (the default), `"firebasestorage.app"` and `"appspot.com"`.

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

Verifying the signature of a signed URL or a POST policy, object ACLs other than `allUsers` read, IAM and bucket-level public access, object composition (`compose`) and notification configuration are not supported. Object versioning is served on the JSON API: `PATCH /storage/v1/b/{bucket}` with `{"versioning":{"enabled":true}}` turns it on, as in production.

:::caution[Keep the Storage port on localhost]
Like the official emulator, the Storage port reflects the requested object name in the HTML body of its 404 for a missing media read. A web page opened on your machine could run script on that origin. Keep the emulator bound to localhost, the default, and do not expose the Storage port to other hosts or networks.
:::
