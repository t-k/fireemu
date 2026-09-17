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
