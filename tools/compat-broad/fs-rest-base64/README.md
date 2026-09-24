# Firestore REST Base64 saved-production comparison

This lane compares only `firestore:errors/rest-shapes#write-bad-base64`. It binds the historical Firestore production matrix and program/step digests, then checks the current local HTTP receipt and its source/artifact provenance. It does not contact production and does not change the legacy broad comparator or historical artifacts.

The available fresh local run is under `docs.local/runs/rest-base64-current-http` and records source commit `ff90876b9f6b3e468b1da9e25e95d6384cbecc6b`. Once this comparator is integrated into that checkout, compare that condition with:

```sh
RUN=docs.local/runs/rest-base64-current-http
uv run --project tools/compat-inventory --locked --python 3.12 python tools/compat-broad/fs-rest-base64/comparator.py \
  --manifest "$RUN/manifest.json" \
  --cases "$RUN/cases.json" \
  --expected-source-commit ff90876b9f6b3e468b1da9e25e95d6384cbecc6b
```

For another run, pass its independently verified `executionCommit`; never substitute the current checkout HEAD if it differs from the commit that built the executed artifact.

The comparator returns `match`, `mismatch`, or `indeterminate` as JSON. Exit codes are 0, 1, and 2 respectively. A missing, malformed, incomplete, unbound, or inapplicable artifact is indeterminate. A mismatch is emitted only when the full receipt and provenance are valid; status, canonical error code, and exact message are compared.

For a future fresh run, the existing broad local HTTP collector can produce the inputs, but it executes a wider suite:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/compat-broad/second_cases.py --output "$RUN"
```

Run that collector only when separately scheduled for the checkout and environment. The comparator does not launch it, and this lane did not run it. A comparator `match` by itself is not condition acceptance; the current run still requires the campaign's independent review and source-bound local regression checks.
