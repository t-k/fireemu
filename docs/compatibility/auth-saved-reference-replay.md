# Auth saved-reference replay

This bounded local replay evaluates four immutable Auth production receipts against one current local artifact: `auth-basic-v2`, `auth-profile`, `auth-display-name` and `auth-password`, with twelve semantic cases each.

The production receipts are read-only inputs. Their original hashes, case order, cleanup evidence and configuration projections are bound by `spec/compatibility/broad-runs/auth-saved-reference-replay-v2.json`. The replay does not rewrite receipts, run production, or infer compatibility from local results alone.

The existing owned probes are reused. `run_replay.py` builds one artifact, runs each probe against that copied artifact, and requires source and artifact binding together with process and listener cleanup. The evaluator compares typed case projections and exact cleanup evidence. Boolean, integer and floating-point values remain distinct. Local strict-runner configuration and production configuration projections remain separate evidence because they are different contracts.

The current-head replay at source commit `78b1da35071f93504c872b21dd9f92858d3e1fd3` produced artifact SHA-256 `ec5a7934c1f5c92fde933ccaca814528f2ff1f7229bd988b7ad9636de2286f12` and comparison digest `9a2a77091fb2fea11718ff8592df62df7b9154e96f0e415b1f52e5f0d3fc0232`. All four corpora matched 12/12 rows, for 48/48 saved-reference matches. The checked-in candidate result is [`78b1da35-auth-saved-reference-replay.json`](../../spec/compatibility/broad-runs/78b1da35-auth-saved-reference-replay.json).

This replay reduces only the final-artifact replay condition for the four declared account/profile/password corpora. It does not promote `AUTH-ACCOUNT` or establish provider lifecycle, alternate hash formats, configured policy parity, MFA, OOB, tenant, blocking, token-signature or SDK compatibility. The original production receipts and their limitations remain immutable.

To reproduce the local-only run, check out the clean committed source `78b1da35071f93504c872b21dd9f92858d3e1fd3`. That source already contains the replay tools and binding spec. The run manifest binds the runtime commit used by the owned probes:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/auth-saved-reference-replay/run_replay.py \
  --output-root /tmp/auth-saved-reference-replay

uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/auth-saved-reference-replay/replay.py \
  --local-root /tmp/auth-saved-reference-replay \
  --output /tmp/auth-saved-reference-replay/comparison.json \
  --source-commit 78b1da35071f93504c872b21dd9f92858d3e1fd3
```

## Current feature replay (`577eaad5`)

The same immutable production receipts were replayed through the current feature source `577eaad53c7e914f141405a715b246248dcd6ae8`. One freshly built local artifact (`95ffc5825108db895c0e298d10865c288ffe423038eee8d6cef74f0a6ba774e6`) completed all four owned corpora with 48/48 `MATCH` rows. The generated run manifest is bound by `5cb9484c8b16f5dac23e22e26e07ff84459ecea77b2bd8b8dae78d67b595cdbb`, and the comparison digest is `ef054f4ee9ef0daea008042466b6081dc693be3cfb023e3b649cbc9a1ba7aaff`. The candidate result is [`577eaad5-auth-saved-reference-replay.json`](../../spec/compatibility/broad-runs/577eaad5-auth-saved-reference-replay.json).

This is a saved-production-reference comparison only. It does not add production traffic or promote `AUTH-ACCOUNT`; provider lifecycle, alternate hash formats, policy boundaries, MFA, OOB, tenant, blocking, token-signature and SDK conditions remain separately declared.
