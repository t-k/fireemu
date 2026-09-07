# Production gap follow-up: 2026-09-07

These focused observations supplement the historical production matrices; they do not regenerate their evidence identities or claim a fresh full-matrix run. Requests used the authorized `fireemu-35fe6` project. Firestore probes used unique collection names and deleted only their own documents. The PartitionQuery and transaction probe deleted all 1,001 documents it created.

## Authentication unknown method

Production returned HTTP 404 with `text/html; charset=UTF-8` for `accounts:definitelyNotAMethod`. The Auth HTTP adapter now emits a static HTML 404 for its unknown-route envelope. Genuine API 404 responses remain JSON. The HTML document is not intended to reproduce Google's presentation byte for byte.

## Cross-project reads

The recorded `other-project` read compares a production OAuth principal with the local emulator's privileged `Bearer owner`. These credentials do not have equivalent authority: local owner intentionally spans emulated projects. The existing user-token path separately checks project audience. The recorded 403/404 remains an observation, but it does not establish that every foreign-project resource should be globally refused. Scoped OAuth/IAM emulation remains an open compatibility requirement.

## PartitionQuery

The collection-group query ordered by `__name__` ascending, with page size 10, produced these split-point counts:

| Documents | Requested 1 | Requested 2 | Requested 10 |
| --- | --- | --- | --- |
| 5 | 0 | 0 | 0 |
| 100 | 1 | 1 | 1 |
| 1,000 | 1 | 2 | 8 |

This is one run, with larger datasets built incrementally. It does not establish stable thresholds or an algorithm. Production may return fewer split points than requested under the [PartitionQuery contract](https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/partitionQuery). Fireemu's deterministic evenly spaced points remain different; no arbitrary document-count threshold was introduced. The follow-up below verifies full partition-range reconstruction, not physical split-point equality.

### Index, authentication, and partition implementation follow-up

The focused Auth probe in [FIRESTORE-AUTH-FOCUSED.md](FIRESTORE-AUTH-FOCUSED.md) obtains real Identity Toolkit anonymous-user ID tokens on both targets and keeps privileged setup credentials separate. A production own-project request returned 403 PERMISSION_DENIED under the existing rules; the exact temporary Auth account was deleted. No independently confirmed active second project was supplied, so cross-project ID-token parity remains unverified. The original foreign-project 403 also contains an API-activation precondition, which must not be mistaken for an audience rejection.

`firestore-probe/partition-reconstruction.mjs` fetches every partition page and runs the original query and adjacent ranges at one explicit readTime. A new live production run reconstructed 100 documents using 2 ranges and 1 page, and 1,000 documents using 9 ranges and 3 pages (10 requested split points, page size 3). Both reconstructions matched full document values with no omissions or duplicates. All 1,000 probe documents were deleted. Reference sorting compares path segments, including parent IDs such as `a` and `a-`. The core splitter now makes two ordered passes and retains only selected cut points rather than all document references.

Writes and imports now account for automatic and configured composite index entries before atomic publication: 40,000 entries, 7,680 bytes per entry, and 8,388,608 bytes in total. Live production accepted arrays with 19,998 and 19,999 distinct integers and rejected 20,000 with INDEX_ENTRIES_COUNT_LIMIT_EXCEEDED. Automatic membership accounting includes both document-name directions plus whole-array ordered entries. Duplicate array values do not create duplicate membership entries. Composite indexes include only documents with all required fields, and allow at most one array field and 100 fields.

Single-field overrides now preserve enabled modes and collection scope, inherit into map descendants, support explicit child re-enabling and wildcard defaults, and distinguish the wildcard from a literal quoted star field. Query planning rejects membership-only indexes for scalar queries and vice versa. Project-specific catalogs apply to write admission and import validation; replacement takes effect on subsequent writes. Configuration loading enforces the supported billing-disabled 200-index and 200-single-field-configuration limits. Billing-enabled profiles remain unsupported. Indexed-value truncation is used for size accounting; exact production query behavior for truncated values and physical index split selection are not claimed.

## Phantom writes

The historical sequential probe waits for an external writer before releasing the transaction whose query blocks that writer. A timeout is therefore not a server rejection. Evidence classification now keeps status-zero transport failures unverified.

A focused concurrent production probe queried an empty matching range in a read-write transaction, started a matching external write, and rolled back the holder after two seconds. The writer returned HTTP 200 after 2,961ms. The current daemon already has bounded contention waiting; a REST regression now exercises query-range contention followed by holder completion. The core store's immediate contention error is an internal retry signal, not the daemon's full HTTP behavior.

## Limits

Document-name length and collection depth already had runtime validation and boundary tests; their catalog and capability entries now reflect that enforcement. Stored field-name validation now descends into maps and maps inside arrays, and rejects `__name__` as a stored field while retaining its query meaning. Production rejected both nested `__name__` and `__reserved__` with HTTP 400 INVALID_ARGUMENT.

Production accepted string payload lengths 1,048,486 and 1,048,487 bytes, and rejected 1,048,488 bytes with HTTP 400 INVALID_ARGUMENT. The runtime now checks string and bytes payloads recursively at that boundary. Storage-size accounting's extra string byte is not part of this payload limit. Aggregate field-value accounting is still unverified, so the whole field-value catalog entry remains unsupported with an explicit partial-implementation note.

Database management limits, index generation/count/size/truncation, Export/Import management quotas, and billing quota observation remain outstanding. They require their corresponding management, index and usage-accounting surfaces; this change does not label them implemented. The [official limits](https://firebase.google.com/docs/firestore/quotas) distinguish hard limits from free usage allowances.
