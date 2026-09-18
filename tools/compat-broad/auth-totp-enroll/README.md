# AUTH-MFA preparation

Two packages live here, both `productionExecuted=false`.

`AUTH-MFA-AGE-TOTP-01` is the prepared successor campaign for the AUTH-MFA row: pending-credential age causality with fresh same-account controls at 300, 450 and 600 seconds, a TOTP enrollment, sign-in and withdrawal matrix computed from locally derived RFC 6238 codes, an enrollment-session age family, and an interaction matrix. `mfa_cases.py` holds the thirty observation cases with their expected local results, `mfa_manifest.py` the frozen manifest with enforced limits, the permission envelope and the owner preconditions, `mfa_collector.py` the bounded resumable state machine, `mfa_provenance.py` the recomputed source binding, `mfa_comparator.py` the comparison contract and `mfa_local_shadow.py` the owned local run. The design, the budget and the limits of the campaign are in [the campaign document](../../../docs/compatibility/auth-mfa-next-campaign-preparation.md); the frozen manifest is checked in at `spec/compatibility/broad-runs/o2-mfa-next-campaign-manifest.json` and the local ledger at `spec/compatibility/broad-runs/o2-mfa-local-shadow.json`.

The collector never sleeps. A step that must wait returns the instant it becomes due, and a checkpoint file carries the run across processes. Budgets are enforced: an exceeded request or wall-clock budget latches an abort, and an aborted run still has to prove its cleanup. Observations carrying secret or credential material are refused before storage.

The provenance binding is recomputed from the worktree rather than read from the receipt, which is the gap the earlier review named. A receipt is accepted only when its binding equals what the comparator just computed from the checked-out files, and agreement additionally requires a production side that says it was executed. No preparation receipt can reach `MATCH`.

`AUTH-MFA-TOTP-ENROLL-RETRY-01` remains the earlier non-executable preparation. Status: `PREPARATION`. It has no production transport, no observed production receipt and no parity claim; its manifest is a logical sequence rather than an executable request plan, its proposed limits are not enforced, and its comparator returns `INDETERMINATE` for every supplied pair because caller-provided hashes cannot establish provenance. Its one distinct obligation, whether a wrong TOTP code leaves the same enrollment session usable for one correct retry and whether replay after success is refused, is carried forward as cases in the campaign above. Related controls in `conformance/fixtures/auth/mfa-error-shapes.json`, `conformance/fixtures/auth/mfa-enrollment-eligibility.json` and `conformance/src/auth-probe/programs.mjs` do not discharge it.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 pytest -q tools/compat-broad/auth-totp-enroll
uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/compat-broad/auth-totp-enroll/mfa_local_shadow.py --output /absolute/private/o2-mfa-shadow
```

The local run owns one strict Auth artifact on OS-assigned ports, ages by advancing that instance's virtual clock, deletes every account it created, confirms absence, and reaps the child process. It contacts nothing but loopback and reads no ambient Google credentials.
