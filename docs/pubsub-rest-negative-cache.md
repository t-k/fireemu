# Pub/Sub REST negative cache

What production does, what two recordings settle, and what fireemu reproduces (`pubsub.restNegativeCache`).

## Source

Two recordings of the observation packet `PUBSUB-NEGCACHE` on a disposable Pub/Sub project, 189 requests each, one request in flight at a time, cleaned up afterwards. The masked requests are `conformance/pubsub-negcache/recordings/run-1.json` and `run-2.json`; `combined-runs.json` is the recorder's judgement of the two runs. `crates/fireemu-adapter-pubsub/tests/negative_cache_recordings.rs` replays both through the model.

## Settled by both runs

| Rule | Cells |
|---|---|
| The entry belongs to one connection. 16 of 16 reads on a fresh connection after the arming 404 were forwarded; every read on the arming keep-alive connection was served. | N2a, N2b |
| A 404 of `GET` or `PATCH` of the plain subscription URL arms. A failed create (missing topic), `:pull`, `:getIamPolicy`, `:seek` and every snapshot request do not. | A1, A3, A4, A5, A6, A7, A9, D1, D2, N2a |
| An armed entry answers `GET`, `PATCH` and `DELETE` of the plain URL with the cached 404; the patch is not applied and the delete does not run. `:getIamPolicy` and `:pull` reach the backend. | V1 to V4 |
| A hit does not re-arm. | V4 |
| A query string and a snapshot of the same id are separate keys. | K1 |
| A create whose body `name` equals the URL name does not clear the entry. | N4 |
| The entry serves for at least 10.2 s from the start of the arming request. | N2a |

## Not linked to `productionExact`

The link (owner line 2482) waits for a follow-up observation that settles the open questions below; until then `pubsub.restNegativeCache = "production"` is an explicit opt-in and `productionExact` leaves it off.

## Documented choices (not recorded)

- The window edge lies in (10.20 s, 10.50 s]: 11 of 12 reads at 10.50 s or later were forwarded, one `DELETE`-armed entry still answered at 10.50 s. fireemu uses 10.35 s.
- A `DELETE` that answers 404 does not arm (the recordings disagree on its second read).
- A `GET` that answered 200 within the window keeps a later 404 from arming (no subscription cell recorded this).
- A never-created name: production missed at 3.0 s in both runs and then hit at 6.0 s; fireemu arms on any 404, so it answers the 3.0 s read from the entry.
- A create whose body `name` differs from its URL is not recorded; fireemu clears nothing.
- The existing-name failed create answers 409 in production, which does not arm.
