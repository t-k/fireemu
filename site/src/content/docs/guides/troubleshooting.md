---
title: Troubleshooting
description: Diagnose installation and startup problems, and report issues.
---

## Check the installation

```sh
npx fireemu doctor
```

`doctor` reports the Fireemu binary, UI, Functions runner and Node.js it finds, and suggests a remedy for each problem.

To also report what a running suite says, such as the Firestore history and Storage bytes it holds, pass its control URL, which is printed at startup:

```sh
npx fireemu doctor --connect http://127.0.0.1:<port>
```

## Common problems

| Symptom | What to check |
|---|---|
| Startup fails with `bind 127.0.0.1:9000: Address already in use` | Your `firebase.json` has `emulators.database`, so the Realtime Database starts on 9000, which another process (PHP-FPM by default) holds. Use `--database-port`, or leave it out with `--only`. |
| Your `firebase.json` or `fireemu.toml` is not used | The `config:` line of the startup output names the files that were loaded. See [Which files are loaded](../configuration/#which-files-are-loaded), and the ownership rule if you run in a container or with `sudo`. |
| Every Firestore or Storage request is denied | Under `strict`, a project without Security Rules refuses client requests, as production does. Check the `firestore rules:` and `storage rules:` startup lines. See [Security Rules](../security-rules/). |
| A request is denied and you do not know why | Read the `note: firestore: Security Rules denied ...` line on standard error, or the Rules page of the UI. |
| A query works locally but fails in production | Under `emulator`, a missing index does not refuse the query, but suggestions are printed on standard error; switch to `strict` to enforce it. OR queries can need an index per branch; all missing branch definitions are listed on standard error. If `firestore.missingIndexes` is `"report"`, look for the missing-index report on standard error, or read it from `GET /v1/firestore/missingIndexes` on the control API (see [Cloud Firestore](../../products/firestore/#fail-a-ci-job-on-a-missing-index)). |
| Export fails because of permissions | Run `fireemu doctor --export-dir <dir>`. It inspects the complete existing ancestor chain without modifying it; a private child under a shared parent is insufficient. See [export destinations](../data/#where-to-export). |
| Tests fail while copying an unrelated global repository | From v0.27.0 a Functions world clears ambient `NODE_PATH`; on an older version, snapshots copied it. Upgrade, or pass an empty `NODE_PATH` for local-only dependencies, or explicitly narrow the required roots. See [dependency snapshots](../test-worlds/#dependency-snapshots-and-global-node_path). |
| Test-world snapshot preparation times out | Narrow unused dependencies or raise `snapshotTimeoutMs` (default 60,000 ms, at most 2,147,483,647). `startupTimeoutMs` only covers daemon readiness after preparation. See [independent test worlds](../test-worlds/#snapshots-and-timeouts). |
| Functions reload reports snapshot ACL validation failure on Windows | Use a private temporary directory without junctions or other reparse points. Its permissions must restrict access to your account and trusted system accounts, and its ancestors must not allow other accounts to modify it. Ensure Windows PowerShell is available under `SystemRoot`, then retry the source change. See [source reload](../../products/functions/#source-reload). |
| The UI does not open | `up` starts without the UI when port 4000 is busy. Use `--ui-port`. `exec` starts the UI only with `--ui`. |
| A scheduled function never runs | Schedules follow the virtual clock. With `daemon.clockStart` pinned (or `daemon.clock = "frozen"`) the clock stands still, so move it or run the function from the UI; without a pinned start it follows real time. See [Time and scheduled functions](../time/). |

For more detail, start with `--log-verbosity debug`, which also prints the resolved configuration.

## Report an issue

[Open an issue on GitHub](https://github.com/t-k/fireemu/issues) with:

- the Fireemu and Firebase SDK versions, the profile, and the Firebase product involved;
- a minimal reproduction;
- for a compatibility issue, whether you compared against production Firebase or the official emulator, and the expected and actual results.

Remove credentials and personal information before sharing configuration files or logs.
