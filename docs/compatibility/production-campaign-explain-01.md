# Production Query Explain campaign 01

This package prepares one bounded production comparison for six Firestore Standard REST Query Explain recipes: `runQuery` and `runAggregationQuery`, each in plan-only, analyze and empty-analyze forms. Every recipe uses exactly two fresh-namespace documents. The lifecycle is absence preflight, conditional setup, typed observation, final state readback, journaled conditional cleanup and post-state absence verification.

The fixed manifest is [prod-campaign-explain-01.json](../../spec/compatibility/broad-runs/prod-campaign-explain-01.json). It uses the existing `batch_adapter`, shared gate, ownership journal, metadata projection `database-settings-v2`, credential verification and production comparator. Metadata and credential operations are included in the shared request budget: 18 observation requests, 12 recovery requests and 30 total requests, serialized at concurrency one. The 10,000 micro-USD ceiling is below USD 0.01. The planning formula reserves 100 micro-USD for each request plus a 1,000 micro-USD fixed reserve; the ceiling includes headroom and is checked against the official [Firestore pricing](https://firebase.google.com/docs/firestore/pricing) and [Query Explain](https://firebase.google.com/docs/firestore/query-data/query-explain) references during owner preflight.

The checked-in package contains no production nonce and makes no Google or Firebase call. The owner authorization records the current-session bounded window and the permission reference `conversation-2026-09-14-autonomous-production-under-usd10`; it does not itself constitute executable permission. Production admission additionally requires a clean frozen checkout, current project/database/Auth/API-key metadata, the projection digest, verified credential expiry, a fresh generated 32-hex nonce and a separately supplied permission record.

Run the offline shadow through the real Adapter and Gate with:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 python tools/compat-broad/campaign_explain_shadow.py --output /absolute/private/campaign-explain-shadow
```

The shadow writes private artifact, input, process and cleanup hashes to `shadow-hashes.json`. It uses a fixture wire boundary and never sets a production nonce. The comparator retains complete response mismatches and returns `indeterminate` for incomplete recording, preflight drift or cleanup evidence.
