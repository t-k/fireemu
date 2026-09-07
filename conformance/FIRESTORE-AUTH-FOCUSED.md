# Focused cross-project Auth observation

Run `node conformance/src/firestore-probe/auth-focused.mjs` with the variables below. The command creates one temporary anonymous Auth user, sends only Firestore GetDocument requests, and deletes exactly that Auth user in a finally block. It never clears the database, lists documents, changes rules, or emits tokens, project IDs, document data or server error messages.

- `FIRESTORE_AUTH_PROBE_TARGET`: `production` or `local`.
- `FIRESTORE_AUTH_PROBE_PROJECT`: the project owning the Auth API key.
- `FIRESTORE_AUTH_PROBE_API_KEY` or `FIRESTORE_AUTH_PROBE_API_KEY_FILE`: the Identity Toolkit key, or a file containing only that key.
- Local runs require `FIRESTORE_AUTH_PROBE_FIRESTORE_BASE` and `FIRESTORE_AUTH_PROBE_AUTH_BASE`. Use loopback HTTP endpoints; the Auth base includes `/identitytoolkit.googleapis.com`.
- Production defaults to the official HTTPS APIs.
- Optional `FIRESTORE_AUTH_PROBE_FOREIGN_PROJECT`: a separately authorized second project. Set `FIRESTORE_AUTH_PROBE_FOREIGN_PROJECT_ACTIVE=1` only after independently confirming that its Firestore API and default database are active.

Both targets obtain a real ID token through Identity Toolkit anonymous sign-up. Anonymous sign-up must already be enabled. The token audience is checked against the own project before Firestore access.

Without a known active second project, the report is explicitly unverified. A 403 caused by API activation is also unverified and never establishes audience-status equivalence. Even an observed result is a single-target measurement, not an automatic parity claim. Compare sanitized local and production observations only when the credential class and project activation preconditions match.

A failure produces no report. Check exact-user cleanup if execution is interrupted or Identity Toolkit is unavailable during deletion. The command does not start an emulator; the caller owns the local process lifecycle.
