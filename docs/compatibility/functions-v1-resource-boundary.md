# Functions v1 resource names: namespace-safe discovery

This change is local to Node discovery. It does not assert native trigger dispatch,
real SDK acceptance, or new production observations.

## Contract

Both supported v1 metadata representations go through `describeV1Event`:

* `__endpoint.platform = "gcfv1"` with `eventTrigger.eventFilters.resource`.
* Legacy `__trigger.eventTrigger.resource`.

Firestore resources are parsed as
`projects/{project}/databases/{database}/documents/{document-pattern}`. Labels
occupy fixed positions: a project or database named `documents` or `databases`
is data, not another separator. The document-pattern suffix is preserved verbatim,
including wildcard braces, Unicode, and percent-like literal characters. Its
actual matching/validation remains the native pattern layer's responsibility.
The parser does not URL-decode the pattern or impose extra ID/field/size quotas.

Storage resources are parsed as `projects/{project}/buckets/{bucket}`. The normal
v1 SDK uses `_` as the project placeholder. The runner also accepts other nonempty
project segments as before, but no longer mistakes a project named `buckets` for
the bucket selector. A bucket is exactly one nonempty final path segment.

A resource whose fixed prefix/structure cannot be identified is reported as a
named `ignored` export (`scope: unsupported`, trigger type `firestore`/`storage`).
No partial selector, guessed default database, or all-bucket trigger is produced.
Other valid exports in the same codebase remain discoverable and invokable.
This is a local rejection policy, not a claim that Firebase deploy/emulator reports
these malformed metadata objects in the same manner. An alternate
`documents@namespace` shape is not converted to the default namespace.

V2's explicit database/document/bucket filters, event type mappings, v1 callback
data/context, retry flags, export ordering and source declaration are unchanged.
No new dependency, worker, quota or authority is introduced. Nothing changes
native schemas or grants access to an additional project/database/bucket.

## Why substring parsing was wrong

For `projects/documents/databases/(default)/documents/orders/{id}`, the old
`indexOf("/documents/")` selected the project segment and emitted
`databases/(default)/documents/orders/{id}` as the document pattern. A database
named `documents` caused the same confusion. Searching for `/databases/` selected
a project named `databases` instead of the database. The analogous first-match
Storage parsing could select the project or silently omit the bucket filter.

## Primary reference, pinned and read-only

The v1 SDK builds the above Firestore resource, optionally with its namespace
suffix, in `NamespaceBuilder.document`. Storage's `resourceGetter` explicitly
resolves a bucket and builds `projects/_/buckets/${bucketName}`; a missing bucket
raises an error instead of requesting all buckets.

* https://github.com/firebase/firebase-functions/blob/v7.3.2/src/v1/providers/firestore.ts
* https://github.com/firebase/firebase-functions/blob/v7.3.2/src/v1/providers/storage.ts

Only the source was read; no Firebase SDK package was installed or executed.

## Local regression

```sh
node --test tools/runner-node/event-resource-runner.test.mjs
node --test --test-concurrency=1 tools/runner-node/*.test.mjs
```

The resource regression launches the actual `index.mjs`, reads its real framed
hello, and invokes actual fixture callbacks over IPC. It covers both v1 metadata
forms, namespace-marker names in project/database/path positions, event kinds,
Unicode/literal suffix preservation, malformed/unserved resource shapes, healthy
siblings, unchanged v1 callback arguments and unchanged v2 explicit filters.
The metadata is SDK-shaped test data, not a real SDK execution. Native Rust
routing and real Firestore/Storage writes triggering Functions still need their
own locked-SDK/native integration run. No old observation receipt, source digest,
manifest or production permission is rewritten by this change.
