# Auth refresh and ListCollectionIds campaign

This is a prepared offline campaign based on `aad1a41de926fae244b42ac1bd2baa57bf2bcdde`. It stops before production and admits only a fixed loopback Auth and Firestore entry. A fresh 32 character hexadecimal nonce names every owned resource.

The five cases are `changed-refresh@0`, `reference-refresh`, root `ListCollectionIds`, a missing document parent with a subcollection, and `pageSize=1` over two child collection IDs. The paged case consumes exactly one continuation token. The Auth sequences reuse the recorded `auth-session-v2` and `auth-session-continuity` logical sequences, with dedicated accounts, runtime UID and token binding, and post-run account absence checks.

The shared budget is one serialized worker, 16 observation requests, 16 recovery requests over six logical owned targets, a 300 second wall limit, a 240 second recovery reserve, and USD0.008 maximum request allocation. The production flag remains false and owner, permission, window, and nonce inputs remain unset.

Each row records the operation, principal, resource, source, observer, configuration, and token or page-token provenance. Recording, state/readback, cleanup, and compatibility are evaluated independently. Either side may be a mismatch or indeterminate; a shared wrong operation remains a mismatch when both sides record it.

Refusal, token/source mismatch, page-token substitution/reuse/wrong parent, state/readback/cleanup failure, timeout/budget exhaustion, malformed or non-JSON responses, and same-wrong-operation behavior are covered by the campaign tests. The local shadow must be run with the fixed local entry and its owned process tree must be absent before the campaign is handed off.
