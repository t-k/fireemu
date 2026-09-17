# O6 Listen/SDK reconnect preparation

This directory contains an offline preparation contract for the existing `FS-LISTEN-SDK-002` campaign. It does not contact Firebase, start an emulator, read credentials, or execute a production run.

`manifest.py` compiles a deterministic plan for a fresh 128-bit hexadecimal nonce. The plan owns exactly `one` and `two` in `o6_resume_{nonce}`, pins the SDK and local shadow versions, and freezes the operation, snapshot, concurrency, time, and cost budgets. The nonce is retained only through its SHA-256 digest in a receipt.

`shadow.py` emits a pure local receipt for the finite initial-listen, update, transport interruption, reconnect, negative-token, unsubscribe, and cleanup sequence. It is a semantic control and is not evidence of production behavior.

`comparator.py` compares the normalized logical event ledger. It excludes read times and raw resume-token bytes, requires plan and owned-resource binding, and reports incomplete collection, missing transport evidence, or cleanup drift as `INDETERMINATE`. A complete bound ledger difference is `SEMANTIC_MISMATCH`; acquisition and promotion remain false.

Run the focused checks with:

```text
uv run --project tools/compat-inventory --locked pytest -q tools/compat-broad/fs-listen-resume
```

