# Firestore write limits local artifact shadow — 2026-09-17

Evidence class: local artifact shadow. This is not a production observation, saved-production comparison, or parent promotion.

- Fixed source: `59f0d77fa18d7df46cefe6e7ff7887156780e22c`.
- Artifact SHA-256: `e6eedc0bc5e0448f7ccb5eee6b8f2e4bd5602a21d5fa0dbc77100d2eb96db721`.
- Target: an owned local strict-profile Standard/Native instance, `demo-firestore-probe`, default database.
- Execution: `tools/compat-broad/fs-write-limits/shadow.py` through the existing `broad.run` artifact builder and process supervisor.

The exact 1,048,576-logical-byte document and depth-20 map were accepted and read back unchanged. The corresponding one-byte-over and depth-21 requests returned typed `400 INVALID_ARGUMENT`; both targets remained absent. Both accepted controls retained their typed fields and creation versions after each negative request.

The collector completed all 16 observation operations and 12 declared recovery stages. The Gate accounted for 26 Firestore data-plane HTTP requests (owned-instance control checks and supervisor probes are separate): the Gate skipped two conditional deletes after their ownership reads proved absence. All four resource paths were absent after recovery. The supervisor independently confirmed the owned process stopped and all listeners closed. The subdirectory source binding matched before, during, and after execution.

`recordingComplete`, `stateValidation`, and `cleanupComplete` were true. There were no local semantic discrepancies or infrastructure failures in this run. Immutable full receipts remain in the private execution directory; this public record contains no raw nonce or credentials.

Preparation conditions completed by this slice are bounded large-body local transport and the successful real-artifact boundary/cleanup shadow. This does not complete failure injection/recovery rehearsals, production collector/comparator binding, environment preflight budgets, frozen O7 admission, or production observation. Production-unobserved parent closure conditions reduced: **0**. `FS-DATA-WRITE` is not `COMPAT_VERIFIED`. Historical campaign manifests and production receipts were not modified.

## Reviewed binding follow-up

Independent review identified that the initial Python-only source closure omitted the compiler's limit catalog. The initial run above remains unchanged and is not the final binding evidence. The follow-up binds `spec/limits/firestore-standard-2026-08-25.json` alongside the collector inputs in the parent, child, and post-run maps. It also verifies the full ordered cleanup journal and repeats body-cap validation inside the transport worker.

A new run at source `a9ab812de51fb1f9a7b824ab52246474f13ebeba`, artifact SHA-256 `565ec3bbeac612ae867083858a0cc6c070b2549d7a8f6ad4301002f641a42e0c`, completed the same 16 observations and 12 recovery stages with 26 Gate-accounted Firestore requests. Catalog-inclusive binding and the independent receipt validator passed. There were no local semantic discrepancies or infrastructure failures. The supervisor confirmed process termination and listener closure. The new receipt is separate from the initial run.

Validation after remediation: compiler/shadow 48 passed; actual-loopback transport 10 passed; Ruff and type checks passed. The oversized direct-worker regression failed before the fix and passes with zero received requests afterward. Catalog-only mutation and missing/reordered/altered cleanup records are rejected. These checks remain local evidence and do not reduce production-unobserved conditions.
