# ADR-011: Reset is an epoch swap

- Status: accepted (2026-08-29)

## Decision

A session reset does not delete data synchronously. It bumps a monotonic epoch, publishes new
state, and every asynchronous work item checks its captured epoch immediately before mutating
state (`Session::check_work_epoch`). Stale work is discarded without side effects
(INV-EPOCH-001). `fireemu-core-session` owns this invariant; `SessionEpoch.qnt` and the Loom
scenarios `stale_epoch_never_mutates_new_state` / `reset_races_with_commit` verify it.
