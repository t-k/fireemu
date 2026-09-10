# Maximum password boundary

An independent21-case candidate for a4096-character URL-safe ASCII update, exact-final-character and4095-prefix signin rejection, and4097-character update refusal with fixed credential/state checks. It uses the recorded schema1 ENFORCE min6/max4096 policy and a dedicated random account. Original update-response refresh bytes are used before and after oversize; the post-attempt lookup uses fixed maximum-signin ID. No password bytes, hashes or raw messages are public.

Oversize error classification is observed separately from policy refusal checks. Unknown errors stay unclassified; authentication/rate-limit failures do not prove a policy refusal. A failed flow remains a private incomplete diagnostic; cleanup uses persisted verified UID regardless of working password. No old evidence is rewritten.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-maximum/maximum_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-maximum/maximum_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-maximum/maximum_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-maximum.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-maximum.py --check
AUTH_PASSWORD_MAXIMUM_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password-maximum -q
```

The owned runner builds/copies strict artifacts, uses OS-assigned ports, verifies process identity, hashes, exit and listener closure. Production is fixed to fireemu-35fe6 /592603257417 with auth and policy readbacks. Admin APIs establish ownership and cleanup only. UID/email absence is checked separately from DELETE success. This is not every4096string, Unicode counting, all prefixes, SDK/Rules, elapsed expiry, revocation propagation or fault-injected recovery. New subject remains unapproved.
