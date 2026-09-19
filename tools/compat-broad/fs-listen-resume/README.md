# O6 Listen/SDK reconnect preparation

This directory contains an offline preparation contract for the existing `FS-LISTEN-SDK-002` campaign. It does not contact Firebase, start an emulator, read credentials, or execute a production run.

`manifest.py` compiles a deterministic plan for a fresh 128-bit hexadecimal nonce. The plan owns exactly `one` and `two` in `o6_resume_{nonce}`, pins the SDK and local shadow versions, and freezes the operation, snapshot, concurrency, time, and cost budgets. The nonce is retained only through its SHA-256 digest in a receipt.

`shadow.py` emits only an expected logical event sequence for the finite initial-listen, update, interruption, reconnect, and unsubscribe preparation. It does not claim that any transport, collector, bounds, cleanup, or production event occurred.

`comparator.py` accepts preparation receipts only and always returns `PREPARATION_ONLY` with no rows and `promotionReady=false`. It rejects production markers and observation-shaped fields. The declared source and transport bindings identify inputs needed by a future acquisition run; they are not measured evidence.

This version never determines whether the production oracle matches the local shadow. A future measurement version must bind path-specific SHA-256 digests for the source, runner, collector, comparator, and lockfiles; resolved SDK and artifact identities; timestamped transport connect, disconnect, and reconnect events; collector-owned operation, snapshot, and deadline counts; unsubscribe, callback quieting, process termination; and owned conditional deletion with typed final absence. Raw resume tokens must be represented by digests and acquisition boundaries. Logical SDK resume and raw gRPC RESET/token behavior require separate cases.

Run the focused checks with:

```text
uv run --project tools/compat-inventory --locked pytest -q tools/compat-broad/fs-listen-resume
```

## Production campaign preparation

A second, separate layer prepares a bounded production campaign for the same
inventory row. It does not execute one, and the row stays `WAITING_ORACLE`.

- `cases.py` declares twelve Observation Cases: six observations, each with a
  control or negative counterpart, covering document and query event order,
  `hasPendingWrites`, resume after a forced stream break, unsubscribe and auth
  switching on a Rules-protected document.
- `campaign.py` freezes the manifest: resolved SDK identities with npm
  integrity digests, the budget, the permission envelope and the owner
  preconditions. A compiled campaign is `BLOCKED_OWNER` until a campaign-scoped
  permission is supplied, and then only `PREPARED`.
- `listen_collector.mjs` is the bounded step machine, budget, invariant checker
  and cleanup contract. It imports no Firebase code; `listen_sdk_adapter.mjs`
  supplies the real SDK and refuses production mode.
- `observation.py` compares a local receipt against a production receipt. It
  reaches `MATCH` only on acquisition evidence and reports the paths it could
  not observe in every result.
- `export_spec.py` publishes the catalog and budget the Node side reads, under
  `spec/compatibility/`.

The full narrative, including the campaign cost, the owner preconditions and the
browser and mobile paths that remain unobserved, is in
`docs/compatibility/fs-listen-sdk-campaign-preparation.md`.

Run the Node checks with:

```text
node --test tools/compat-broad/fs-listen-resume/*.test.mjs
```
