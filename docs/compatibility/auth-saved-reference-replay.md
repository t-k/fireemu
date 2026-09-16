# Auth saved-reference replay

This bounded local replay evaluates four immutable Auth production receipts against one current local artifact: `auth-basic-v2`, `auth-profile`, `auth-display-name` and `auth-password`, with twelve semantic cases each.

The production receipts are read-only inputs. Their original hashes, case order, cleanup evidence and configuration projections are bound by `spec/compatibility/broad-runs/auth-saved-reference-replay-v2.json`. The replay does not rewrite receipts, run production, or infer compatibility from local results alone.

The existing owned probes are reused. `run_replay.py` builds one artifact, runs each probe against that copied artifact, and requires source and artifact binding together with process and listener cleanup. The evaluator compares typed case projections and exact cleanup evidence. Boolean, integer and floating-point values remain distinct. Local strict-runner configuration and production configuration projections remain separate evidence because they are different contracts.

The current-head replay at source commit `628d9c59a1c3816c67df3e4791c1a567a7ae1d15` produced artifact SHA-256 `73a2c0607368d3e2bfa7438c3043ced5cd66ae5561fa88511b5eb6ba53770c6d` and comparison digest `d50ff00649f98008e43c7a47931eaa7d9aeb21ecc7cd27b95f2bd2351350ffe0`. All four corpora matched 12/12 rows, for 48/48 saved-reference matches. The checked-in candidate result is [`628d9c59-auth-saved-reference-replay.json`](../../spec/compatibility/broad-runs/628d9c59-auth-saved-reference-replay.json).

This replay reduces only the final-artifact replay condition for the four declared account/profile/password corpora. It does not promote `AUTH-ACCOUNT` or establish provider lifecycle, alternate hash formats, configured policy parity, MFA, OOB, tenant, blocking, token-signature or SDK compatibility. The original production receipts and their limitations remain immutable.

To reproduce the local-only run, check out the fixed runtime source `628d9c59a1c3816c67df3e4791c1a567a7ae1d15`, then materialize the replay tools and binding spec from the later feature commit that contains this result. Keep the runtime source commit passed to the evaluator fixed at `628d9c59`; the replay tool and binding spec are separate evidence inputs:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/auth-saved-reference-replay/run_replay.py \
  --output-root /tmp/auth-saved-reference-replay

uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/auth-saved-reference-replay/replay.py \
  --local-root /tmp/auth-saved-reference-replay \
  --output /tmp/auth-saved-reference-replay/comparison.json \
  --source-commit 628d9c59a1c3816c67df3e4791c1a567a7ae1d15
```
