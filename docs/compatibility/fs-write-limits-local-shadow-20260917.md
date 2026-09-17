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
