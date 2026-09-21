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

- `cases.py` declares eighteen Observation Cases: nine observations, each with a
  control or negative counterpart, covering document and query event order,
  `hasPendingWrites`, resume after a forced stream break, unsubscribe, auth
  switching on a Rules-protected document, default-mode subscription, a second
  principal's private document (cross-identity) and session revocation while a
  listener is attached.
- `campaign.py` freezes the manifest: resolved SDK identities with npm
  integrity digests, the budget, the permission envelope and the owner
  preconditions. A compiled campaign is `BLOCKED_OWNER` until a campaign-scoped
  permission is supplied, and then only `PREPARED`.
- `listen_collector.mjs` is the bounded step machine, budget, invariant checker
  and cleanup contract. It imports no Firebase code; `listen_sdk_adapter.mjs`
  supplies the real SDK and refuses production mode.
- `listen_browser_adapter.mjs` runs the same catalog through the browser build
  of the SDK (WebChannel transport) in a headless Chromium it owns, once with
  forced long polling and once with a streamed backchannel. The collector is
  served to the page byte-identical, so the event rows have the Node receipt's
  shape; the receipt adds the page's WebChannel request log and the digests of
  the SDK bundles the browser executed. Playwright lives in its own package,
  `tools/sdk-smoke-browser/` (see its README for the run command).
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

## Local expectation checker

`node tools/compat-broad/fs-listen-resume/local_shadow_check.mjs receipt.json`
checks the entire catalog, per-case failures/invariants, cleanup passes, budgets,
and the current lifecycle receipt. Exit 0 means that this **local projection**
passed these checks; it does not verify the current binary, SDK or production.
Exit 1 means incomplete/different evidence, and exit 2 means invalid input/usage.

An old immutable receipt without `lifecycle` requires the explicit
`--legacy-lifecycle` option. The JSON result marks that limited scope. Do not add
synthetic lifecycle evidence to old receipts, change old source hashes, or treat
this diagnostic checker as replacement for `observation.py`'s source binding.

## Local process watchdog and responsibility journal

The optional `local_supervisor.py --output <fresh-directory>` runs the fixed SDK
adapter inside an existing owned `fireemu exec`. It requires a demo project and
numeric loopback endpoints, excludes cloud credentials/Node injection variables,
and generates fresh unapproved local inputs. It does not start/stop the emulator
or authorize production. See the supervised execution section of
`docs/compatibility/fs-listen-sdk-campaign-preparation.md` for prerequisites and
limits.

Node resolution: `FIREEMU_NODE` (an executable file) wins. Otherwise the first
`node` on `PATH` is used, resolved through symlinks; when that resolves to a
`volta-shim` the launcher substitutes the pinned image from
`$VOLTA_HOME/tools/image/node/<version>/bin/node` (`tools/user/platform.json`
first, then the newest image) and refuses with `volta-shim-refused` when none
exists. The shim is never executed: with the private empty `HOME` the child
gets, it would try to install a default Node and can spawn itself recursively.

The private pre-spawn launch record and synchronous adapter checkpoints retain
recovery responsibility if a Promise stalls or the process is killed. Process
termination is not resource cleanup. The wrapper does not retry, refresh budgets,
perform recovery from saved identifiers, or grant deletion permission. A new
native/SDK shadow is still required for the changed source binding.
