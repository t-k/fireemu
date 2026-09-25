# No-password-change REST session continuity control

This independent revision complements the approved password-change observation with a short no-password-change control. Two separated signin credential sets A/B are frozen and proven usable before a bounded 0/10/30-second observation schedule. After a three-second gap, A's original refresh token is exchanged and its returned ID token used for lookup. Completion of that reference operation starts the observation clock.

There is no accounts:update, password reset, disablement or explicit revocation. Final signin uses the original password. Setup, deletion, signin metadata and token exchange still involve server state; this is not an entirely read-only workload. The end-user client has an explicit lifecycle/read route allowlist. Reference refresh bytes may equal A's original refresh bytes, so the reference lanes do not establish an independent third session or device.

All six scheduled primary lanes must be accepted, including successful lookup with every refresh-issued ID token. Matching rejections are inconclusive, not continuity success. Transport failures, missing observations and timing overruns remain distinct. No new primary/dependent request starts at the 45-second deadline, and the schedule never extends until success. HTTP socket/processing budgets are not hard real-time cancellation; workers drain before cleanup.

The corpus has 34 top-level records including baseline/repeated original refresh use, reference exchange, 18 timed lanes, final original-password signin/lookup, two fixed invalid-input controls and deletion/dual absence. JWT timing metadata is decoded without signature verification. The public projection excludes credentials, token digests, private identities and raw responses. Exact token reuse and identity comparisons remain recorder testimony.

Use new private output directories:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-continuity/continuity_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-continuity/continuity_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-continuity/continuity_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-session-continuity.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-session-continuity.py --check
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-session-continuity -q
AUTH_SESSION_CONTINUITY_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-session-continuity -q
```

The owned runner builds/copies the strict artifact, proves instance identity and checks exit/listener closure. Production remains fixed to the authorized fireemu-35fe6 / 592603257417 project and recorded policy settings. Private journal precedes signup; verified UID is persisted before cleanup; deletion requires exact owner confirmation and UID/email absence. Normal cleanup does not establish fault-injected recovery.

The source review reuses prior official snapshots without changing their acquisition dates. This is a new candidate, not inherited approval. It does not establish one-hour expiry, permanent validity, whole rotated-session lineage, SDK checkRevoked, Rules or a simultaneous randomized comparison with the earlier password-change run. Older records/approvals remain immutable; their historical checks are separate from current-runtime regression checks.
