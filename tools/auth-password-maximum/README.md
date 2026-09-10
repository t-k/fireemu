# Maximum password boundary

An independent 21-case candidate for a 4096-character URL-safe ASCII update, exact-final-character and 4095-prefix signin rejection, and 4097-character update refusal with fixed credential/state checks. It uses the recorded schema 1 ENFORCE min 6/max 4096 policy and a dedicated random account. Original update-response refresh bytes are used before and after oversize; the post-attempt lookup uses fixed maximum-signin ID. No password bytes, hashes or raw messages are public.

Oversize error classification is observed separately from policy refusal checks. Unknown errors stay unclassified; authentication/rate-limit failures do not prove a policy refusal. A failed flow remains a private incomplete diagnostic; cleanup uses persisted verified UID regardless of working password. No old evidence is rewritten.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-maximum/maximum_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-maximum/maximum_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-maximum/maximum_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-maximum.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-maximum.py --check
AUTH_PASSWORD_MAXIMUM_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password-maximum -q
```

The owned runner builds/copies strict artifacts, uses OS-assigned ports, verifies process identity, hashes, exit and listener closure. Production is fixed to fireemu-35fe6 / 592603257417 with auth and policy readbacks. Admin APIs establish ownership and cleanup only. UID/email absence is checked separately from DELETE success. This is not every 4096-character string, Unicode counting, all prefixes, SDK/Rules, elapsed expiry, revocation propagation or fault-injected recovery. New subject remains unapproved.

## Runtime correction and evidence history

The first production acquisition completed all 21 cases and returned HTTP 400 / `PASSWORD_DOES_NOT_MEET_REQUIREMENTS` for the 4097-character update. The original local run accepted that update and subsequently failed signin with the former 4096-character password. That incomplete local diagnostic remains in private working logs, with UID/email absence and process shutdown recorded; it is not relabeled as a successful observation.

Runtime commit `de0c389` adds the upper-bound check to end-user updates before any state mutation. Authenticated Admin routing, not a user-supplied `localId`, determines the administrative exemption. A separate local regression rejects unauthenticated and other-user attempts to select an account by `localId`; this security regression is not counted as an additional production-observed case. Existing Admin fixtures now use the authenticated Admin route. Signup, import and reset upper-bound behavior is not changed or claimed by this slice. Unicode scalar counting follows the existing minimum-length implementation convention, but the ASCII observations do not establish Firebase's Unicode counting rule.

The published candidate pairs the unchanged initial production acquisition with a new owned local acquisition after the runtime correction. Earlier approved receipts are checked at their immutable source anchors, including the [later password/session anchor](../compat-history/PASSWORD-HISTORY.md). Historical test results do not establish regression coverage on the new runtime. The old receipts, source reviews and human approvals are not rewritten.
