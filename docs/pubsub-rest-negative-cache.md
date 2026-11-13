# Pub/Sub REST negative cache

What production does, what four recordings settle, and what fireemu reproduces (`pubsub.restNegativeCache`).

## Source

Two recordings of the observation packet `PUBSUB-NEGCACHE` on a disposable Pub/Sub project, 189 requests each, one request in flight at a time, cleaned up afterwards. The masked requests are `conformance/pubsub-negcache/recordings/run-1.json` and `run-2.json`; `combined-runs.json` is the recorder's judgement of the two runs. The v5 follow-ups, runs `903d638614a1` and `70602e8b29e0`, are `run-3.json` and `run-4.json`. `crates/fireemu-adapter-pubsub/tests/negative_cache_recordings.rs` replays all four through the model.

## Recorded rules

| Rule | Cells |
|---|---|
| The entry belongs to one connection. 16 of 16 reads on a fresh connection after the arming 404 were forwarded; every read on the arming keep-alive connection was served. | N2a, N2b |
| A 404 of `GET` or `PATCH` of the plain subscription URL arms. A failed create (missing topic), `:pull`, `:getIamPolicy`, `:seek` and every snapshot request do not. | A1, A3, A4, A5, A6, A7, A9, D1, D2, N2a |
| An armed entry answers `GET`, `PATCH` and `DELETE` of the plain URL with the cached 404; the patch is not applied and the delete does not run. `:getIamPolicy` and `:pull` reach the backend. | V1 to V4 |
| A hit does not re-arm. | V4 |
| A query string and a snapshot of the same id are separate keys. | K1 |
| A create whose body `name` equals the URL name does not clear the entry. | N4 |
| The entry serves for at least 10.2 s from the start of the arming request (v4 hits up to 10.20 s; the edge after that varies, see below). | N2a |
| A `GET` 200 seven seconds before the 404 exempted it from arming in both v5 runs. | E200-7a, E200-7b |

Expiry uses the daemon’s logical clock. If the clock is frozen, advance it past the 10.35-second window, use another connection, or disable the cache to recover from a cached 404.

## Not linked to `productionExact`

The link (owner line 2482) waits for a follow-up observation that settles the open questions below; until then `pubsub.restNegativeCache = "production"` is an explicit opt-in and `productionExact` leaves it off.

## Known difference and open questions

- The window edge varies between runs, from before 10.25 s (run 4: every read from 10.25 s missed) to after 10.50 s (run 3: a hit at 10.50 s); the v4 runs hit up to 10.20 s. Production is nondeterministic inside this band. The model uses a deterministic 10.35 s, a known difference.
- DELETE 404 arming remains open: the DA cells were mixed. The model does not arm.
- Recent-200 exemption at four and 13 seconds remains open: the results were mixed. The model exempts a `GET` 200 within its window.
- Activation for a never-created name remains open: the N1 cells were mixed. The model arms on any 404.
- A create whose body `name` differs from its URL is not recorded; fireemu clears nothing.
- The existing-name failed create answers 409 in production, which does not arm.
