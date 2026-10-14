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

Storage Security Rules are read from the `storage.rules` file named in `firebase.json`, or `storage.rules` in `fireemu.toml`. A Storage rule can read Firestore documents with `firestore.get()` and `firestore.exists()`. Under `strict`, a project without rules refuses every end-user request with production's 400 "bucket has not been set up" answer. See [Security Rules](../../guides/security-rules/).

Under `strict` the Storage emulator also refuses what production refuses and the official emulator accepts (a bucket that does not exist is the exception, see below):

- **A public URL for a private object.** `GET /{bucket}/{object}`, which is what `file.publicUrl()` builds, answers 403 `AccessDenied` unless the request carries a non-empty `Bearer` `Authorization` header, comes from a Google client library (these send `x-goog-api-client`, and the Go library, so the Firebase Admin Go SDK, reads through this URL with no credential while `STORAGE_EMULATOR_HOST` is set; the Python, Java and Node libraries read through the JSON API and are never refused), is a signed URL that has not expired, or the object is public. An object is public when application code made it so (`file.makePublic()`, `predefinedAcl=publicRead` on an upload, patch, copy (`destinationPredefinedAcl`) or rewrite, an `allUsers` `READER` entry in the `acl` of an uploaded or patched resource, or `POST .../acl`), for that generation of the object only: an overwrite is private again. `file.makePrivate()` (`predefinedAcl=private`), a patched `acl` without that entry and `DELETE .../acl/allUsers` end it. An `acl` in the metadata that starts a resumable upload is not read. A bucket whose IAM grants `allUsers` the object viewer role, which production sets in the console, is listed in `storage.publicBuckets`. The 403 names both ways. Firebase download-token URLs are not affected.
- **An expired signed URL.** A V4 or V2 signed URL past its lifetime answers 400 `ExpiredToken`, and a V4 lifetime over seven days or an unreadable `X-Goog-Date` answers 400. The signature itself is not verified, because that needs the signing service account's key; any signature is accepted.
- **A form upload without a signed policy.** `POST /{bucket}` with a multipart form needs a `policy` and a signature field. The policy's expiry and conditions (`bucket`, `eq`, `starts-with`, `content-length-range`) are enforced; the signature is not verified.
- **A Firebase ID token as an OAuth bearer** on the JSON API: 401 `Invalid Credentials`. Any other credential, or none, is served as the owner, because a local run cannot judge an access token.
- **An ACL entry Cloud Storage does not know** (400). Only `allUsers` with role `READER` has an effect.
- **A bucket name Cloud Storage never accepts** (for example `ab`, `goog-x` or `1.2.3.4`): 400 `Invalid bucket name` on the JSON API, 400 `InvalidBucketName` on the XML routes and 404 on the Firebase routes, unless a bucket of that name exists (imported or declared).

The `emulator` profile keeps the official emulator's behavior for all of these.

### Buckets that do not exist

Production answers 404 `The specified bucket does not exist.` for an object operation on a bucket nobody created. The Storage emulator serves it instead, and creates the bucket on the first write, so a test needs no setup. Under `strict` it prints one `note:` line on standard error the first time an object is written to a bucket that is not a default bucket of the project (`<project>.appspot.com` or `<project>.firebasestorage.app`), a `firebase.json` storage target, imported data, a bucket a deployed Storage trigger names, or listed in the configuration. A typo in a bucket name is visible that way. To silence the note for a bucket that exists in production, list it:

```toml
schemaVersion = 1

[storage]
buckets = ["uploads-bucket", "exports.example.com"]
publicBuckets = ["public-assets.example.com"]
```

JSON also works: existing `fireemu.json` files and `--config <path>.json` remain supported.

Each name must be one Cloud Storage accepts. `storage.publicBuckets` lists buckets whose objects the public URL serves without a credential, and also counts as declaring them. `storage.buckets` and `storage.publicBuckets` are ignored by the `emulator` profile.

A production project has one default bucket: `<project>.firebasestorage.app` if Storage was set up after 2024-10-30, `<project>.appspot.com` before. A local run cannot know which, so both exist by default. To catch an app configuration copied from the other kind of project, set `storage.defaultBucket` to `"firebasestorage.app"` or `"appspot.com"` (default `"both"`): the other name then counts as an undeclared bucket, so its first write prints the note and `GET /storage/v1/b/{bucket}` answers 404.

## Limit the stored bytes

The Storage emulator keeps every object in memory, and by default nothing bounds how much. To cap it, set `storage.maxStoredBytes`. This limit is local to Fireemu; production has none:

```toml
schemaVersion = 1

[storage]
maxStoredBytes = 1073741824
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
