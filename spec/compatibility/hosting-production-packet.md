# Hosting production observation (packet v1 outline)

Status: unsent. This document grants no sending authority; the owner and the coordinator approve an exact frozen packet. No credential, project number or API key belongs here or in any file of the repository.

## What is observed

Ten site versions, each deployed to its own disposable preview channel (24 hour TTL) of the default Hosting site of the Identity Platform sandbox project, through the Hosting REST API (never the firebase CLI, whose channel commands rewrite the project's authorized domains) and never to the live channel. Each version's requests are sent to its channel host with a client that keeps the request target literal, follows no redirect, decompresses nothing and never retries. The same requests are sent to fireemu (strict and emulator profiles) by `conformance/src/hosting-production/local.mjs`, and the shaped rows are compared by `compare.mjs`.

| Version | Site configuration | Observes |
| --- | --- | --- |
| v01 | redirects, rewrites, headers, 404.html, content-type files, compressible files | static files, redirects (including 39 capture-encoding edges), rewrites, headers and caching, 404 handling, conditional and range requests, methods, reserved paths, content types, compression and Vary |
| v02 | `cleanUrls`, `appAssociation: AUTO` | cleanUrls path selection, `/.well-known` association files |
| v03, v04 | `trailingSlash` true / false | trailing-slash canonicalization |
| v05, v06 | `cleanUrls` with `trailingSlash` true / false | the combinations |
| v07, v08 | `i18n` (alone, and with cleanUrls and trailingSlash) | language and country selection by header and by cookie |
| v09 | catch-all redirect | reserved initialization paths before a configured redirect |
| v10 | sixteen header rules, one per glob pattern, and a catch-all rewrite | which patterns match which paths |

The corpus is `conformance/src/hosting-production/corpus.mjs`; its pinned form is `corpus.manifest.json`. There are 201 requests (three of them information only). Function and Cloud Run rewrites are out of scope for this parent (owner ledger 2435), and `ignore` is a deploy-tool rule that the REST API cannot observe: both are recorded as NOT_COMPARED in the closure record.

## Budget of one attempt

| Kind | Cap | Expected |
| --- | ---: | ---: |
| token refreshes | 3 | 1 |
| control (Hosting, Service Usage and Identity Toolkit reads and writes) | 90 | 65 |
| cleanup (deletes, listings and the read-backs) | 45 | 23 |
| uploads | 20 | 14 |
| edge (requests to preview channel hosts, readiness probes included) | 330 | 210 |

A request that would exceed its kind is not sent. Every request, failed or not, counts. Two independent recordings are planned (the recorder is run twice on fresh channels). Cost: stored well under 100 KB, transferred about 2 MB per recording; at the published Hosting prices (10 GB storage and 10 GB transfer free, US$0.026/GB and US$0.15/GB beyond; the allowance is project-wide) the cost is zero inside the allowance and below US$0.01 otherwise. The first readiness probe waits 30 s after the release and every probe has its own query (`?fireemu-ready=<run>-<n>`, because the CDN caches a negative answer per URL); a version whose release is not served yet is probed up to 12 times, 10 s apart (about 110 s); a version still dark afterwards keeps its last answer and whether the channel still holds the release, and is not released again. The ledger reserves US$1 per attempt; attempts are counted per envelope (`FIREEMU_HOSTING_ENVELOPE`; the launch names its number in `FIREEMU_HOSTING_ATTEMPT`, which must be the count) and the parent's reservation over all envelopes is at most US$6.00.

## Unknown answers

A 3xx, 5xx, status below 200, timeout, abort or unreadable body of an API write is unknown. A create with an unknown answer is probed once with a read; an unconfirmed channel or version create stops the run (`needs-recovery`) and is settled only by a later read, never by a 404 during the run. A delete with an unknown answer is never re-sent, and a delete that answers 404 for a resource the run saw created settles nothing in the run (only a later read does). A 409 after an unknown request settles nothing. Edge answers of 429 or 5xx, timeouts and resets are unknown rows, never retried; a request whose header depends on an earlier answer (an ETag) that did not arrive is not sent.

## Cleanup

Each version's channel and version are deleted right after its requests. At the end the channel list must hold no channel of the run, the version list (at most three pages) must hold no version labelled with the run that is not DELETED, and the project's authorized domains must equal their value before. A recovery run only deletes what is listed under the run's prefix and label, records each delete answer and reads back; it never closes the run. An unknown create settles only on an own 2xx read that shows the resource (then it is deleted and read back); a 404 or an empty list never settles it, and the coordinator alone closes the run after its own read-back at least 10 minutes later. The site's version list must fit the read-back's three pages: the precheck refuses to start when it already runs past two. The Hosting API's `fileCount` is a string and counts the reserved `/__/firebase/init.js` and `init.json`; the recorder stores it as returned and lists the returned file paths separately.

## Masking

The reserved initialization bodies hold a web API key and the project number. Rows keep their byte count and line count and, for the JSON, the key order and the type and byte length of each value; no value is retained. Any other value found in a row that equals a private value stops that row (it becomes an unknown row) and the run is flagged for review.

## Judge

`judge.mjs` compares status, a fixed set of headers, body size and digest (the decoded body when either side is content-encoded) and the layout of the initialization JSON. ETag and Last-Modified are compared by form. Edge headers that differ on every request (date, age, via, x-cache and similar) are recorded and never compared. Any other header that appears and is neither compared nor volatile is listed as unclassified; the review has to name each before the closure.

References: [Hosting REST API, sites.versions](https://firebase.google.com/docs/reference/hosting/rest/v1beta1/sites.versions), [Hosting usage and pricing](https://firebase.google.com/docs/hosting/usage-quotas-pricing).
