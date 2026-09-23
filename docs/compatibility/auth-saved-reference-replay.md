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

## Retained current-source checkpoint (2026-09-17)

Source `cce4a4f9b7369938c89bd32a5106e8d3cab59f83` replayed all four immutable corpora against one newly retained artifact, SHA-256 `be2771b9f2093cced55e8158d8d5a72ed35e6ac5e32edddb068daa45511e12ae`. All 48 cases matched. The materialized comparison and its hash-bound provenance summary are retained as `spec/compatibility/broad-runs/cce4a4f9b-auth-saved-reference-replay.json` and the adjacent `-binding.json`. Independent evidence review verified source, artifact, collector/comparator, reference bindings and cleanup. Owned accounts were absent, listeners closed and processes stopped.

This is a new saved-reference comparison, not new production traffic or an amendment to historical v9/source-9830 preparation. Configuration projections remain separate evidence; provider, hash-format and configured-policy gaps are not discharged by these 48 cases. No Auth parent was promoted.

## Receipt-scoped finite acceptance (2026-09-23)

Four independent reviews accept only the following 40 receipt-scoped finite observations from the current saved replay. The receipt case IDs below identify rows in their respective corpora; they are not all canonical condition IDs. Any canonical relation described by an individual review remains a relation only, not promotion of the receipt row into a broader condition.

| Corpus | Accepted receipt cases | Saved receipt SHA-256 |
|---|---|---|
| `auth-basic-v2` (9) | `signup-token-lookup`, `signup-token-refresh`, `signup-refreshed-lookup`, `lookup`, `unchanged-state`, `refresh`, `refreshed-lookup`, `delete`, `deleted-account-absent` | `0fb1648416ad615a7f18bcb79b2abad7c26b7ced6e202276cdb3a2eeb409304a` |
| `auth-password` (11) | `signup`, `baseline-signin`, `change-password`, `changed-token-lookup`, `unchanged-state`, `new-password-signin`, `new-password-lookup`, `changed-token-refresh`, `refreshed-lookup`, `delete`, `deleted-account-absent` | `2054ac0ede30d54e91e59f3e6c5454714e97118dc6845fd22a34f86e70255d2f` |
| `auth-profile` (10) | `signup`, `initial-lookup`, `set-photo`, `set-photo-lookup`, `invalid-token-update`, `unchanged-state`, `delete-photo`, `deleted-photo-lookup`, `delete`, `deleted-account-absent` | `75a58259e1dc8e26665e955bcea1b32bc008acc2bdb50e42430f9563500c7f87` |
| `auth-display-name` (10) | `signup`, `initial-lookup`, `set-name`, `set-name-lookup`, `replace-name`, `replace-name-lookup`, `invalid-token-update`, `unchanged-state`, `delete`, `deleted-account-absent` | `1c1a1aba0bd2cadc0cba6f80e5fbd1266163f73242c9d90ce652b6e0cce02f47` |

These reviews are limited to typed, redacted semantic projections and the stated cleanup observations, not raw response equality. They exclude the other corpus rows, and do not establish full account-state invariance, independent token-signature or expiry enforcement, or broader profile/password behavior. The saved replay result is SHA-256 `cefc33acf95eaac590a05343d1e88e301abaa5c7c9f458c8173f56ade218be69`; it records source commit `818065185d66debdb8afd414b68f6c04e7482e1c` and 12/12 MATCH for each corpus (48/48 overall). This corpus-wide comparator context does not expand the 40-case acceptance. Production and local configuration projections remain `SEPARATE_EVIDENCE`, not equivalent configuration. The recorded local cleanup confirms the owned email and UID absent for all four corpora, with listeners closed and owned processes stopped at exit code 0. No new production request was made for these reviews. Credentials, tokens, UIDs, emails, and raw profile values are not included.

The bounded security reviews for the basic and profile predicates found no Must Fix within their assigned scope; they likewise retain the finite-observation limits above. This evidence does not promote `AUTH-ACCOUNT`, any parent Auth feature, or the broad Auth surface.
