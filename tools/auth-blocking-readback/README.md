# Hook-applied disable: readback timing

One flow deploys the disabling `beforeSignIn` function from `tools/auth-blocking-disable` for the run and reads the disabled flag back through privileged lookup on a time axis: for claimed account X before the refused sign-in, immediately after it, five and thirty seconds after it; for claimed account Y only after thirty seconds with no earlier read; control Z signs in first and last. Readback rows record the flag as seen with the seconds since the refusal; the corpus is complete only when the first sign-ins were refused and the waits were honored. No MFA, phone or SMS configuration is touched; the trigger registration is restored with a digest comparison. The owned local runner reuses the local fixture from `tools/auth-blocking-disable`.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-readback/readback_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-readback/readback_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-blocking-readback -q
```

On the local artifact (2026-09-12) the flag reads true at every point after the refusal for both accounts. The production run is the observation planned for GAP-AUTH-001.
