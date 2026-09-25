# PR #1 offline integration (2026-09-19)

This preparation builds on source `64806be161703b4a2c967b185120f851a40cd523`.
It does not authorize production observation, adopt a live configuration, reuse a
consumed permission, or promote a parent group to `COMPAT_VERIFIED`.

## BatchWrite ownership

For a recognized BatchWrite operation, an item with an exact `exists: false`
conditional create, an integer `ALREADY_EXISTS` (6) status and an empty typed
WriteResult is a settled refusal. It grants **no creation or deletion authority**
for that document. Successful siblings retain their own creation proofs. A
transient error, malformed result, or a refusal accompanied by a write version
remains uncertain. An independently uncertain earlier create remains uncertain.

The local shared-scenario fixture returns a typed `400 INVALID_ARGUMENT` for its
unsupported transaction member. A bare HTTP status and an empty object are not
substituted for a typed refusal.

## MFA process cleanup

A missing process identity (including an empty or unreadable `/proc` entry) is
not proof of child termination. The local reaper now reports `stopped` only after
waiting for the owned child confirms its exit; otherwise it refuses to signal
an unbound identity and retains the cleanup failure. Identity capture retries a
transient missing identity within its existing deadline, and never adopts the
parent's pre-exec identity at timeout. The parent reserves a fresh output
directory before launch and requires a successful child exit plus complete
recording and typed recovery. A stale ledger, timeout or unsuccessful child
cannot turn into a successful shadow run.

The historical `o2-mfa-local-shadow.json` is byte-pinned and remains unchanged.
Its old recorder digest intentionally does not match the repaired recorder. The
current comparator therefore keeps it `INDETERMINATE` instead of replacing its
provenance with a new hash and pretending the new local artifact was executed.
A fresh owned-artifact MFA rehearsal is still required.

## Bounded stdlib workers and test fixtures

The credential worker now starts with `-I -S -B`: it uses only the standard
library and explicit repository paths and must not execute site hooks. The
existing end-to-end deadline and no-retry checks remain unchanged. An additional
real-loopback regression verifies the isolated command and one completed request.
Pure-stdlib supervisor test children use the same isolation so interpreter site
startup cannot consume their entire 0.5/0.7-second fixture deadline. Their recorded
process identities retain the actual interpreter flags. A benchmark positive
fixture now uses its declared profile, with a separate wrong-profile refusal test.

## Current Explain preparation

The current generated preparation is
[`prod-campaign-explain-01-v9.json`](../../spec/compatibility/broad-runs/prod-campaign-explain-01-v9.json),
with its separate
[comparison binding](../../spec/compatibility/broad-runs/prod-campaign-explain-01-v9-binding.json).
The v7 and v8 files remain immutable historical preparations. Their digests are
not current execution permissions or proof of a current local artifact run.

The v9 preparation declares `authorizesProduction: false`,
`productionExecuted: false` and `requiresFreshPermissionBinding: true`. The
existing `productionExecutable` field describes the implementation's capability,
not authorization. Owner authorization, frozen artifact and source, current
credential/preflight, complete recovery, and independent review remain separate
requirements. Existing configuration and historical owner-reference fields have
not been re-approved or changed into current consent.

Regenerate the current pair only after changing the observer or its tests, then
verify it against the complete repository. This command performs no network I/O:

```sh
PYTHONPATH=tools/compat-broad python - <<'PY'
import json
from pathlib import Path
from campaign_explain import manifest, binding

root = Path('spec/compatibility/broad-runs')
for name, value in (
    ('prod-campaign-explain-01-v9.json', manifest()),
    ('prod-campaign-explain-01-v9-binding.json', binding()),
):
    (root / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
PY
```

## Validation boundaries

The source archive preserves the complete source tree but not historical Git
objects, Rust and Node dependencies, toolchains, or private artifact bundles.
A source archive's lack of these inputs is not evidence that their tests passed.
Reconstructing a source commit or making an offline validation snapshot does not
create historical executions or independent-review evidence.

Run the real modules in the locked environment, with the full historical Git
objects required by `tools/compat-history`. Keep failed acquisition, missing
dependencies, setup errors, intentionally skipped tests and successfully run
tests distinct. Do not clear dirty-source guards, fabricate artifacts or replace
missing history with the current file merely to make a test pass.

The native Reference-size repair still requires Rust 1.94.0 build/test and the
final artifact must run the declared SDK, Rules, Listen, replay, resource and
formal gates. An injected-transport O8 lifecycle test establishes only that
local integration path, never a production CLI run or production compatibility.
The [parent acceptance table](ip-fs-production-compatibility.md) remains the goal.
