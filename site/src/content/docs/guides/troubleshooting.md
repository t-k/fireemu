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
| A query works locally but fails in production | Under `emulator`, a missing index does not refuse the query, but suggestions are printed on standard error; switch to `strict` to enforce it. OR queries can need multiple branch indexes; v0.26.0 reports all missing definitions in supplementary diagnostics. If `firestore.missingIndexes` is `"report"`, look for the missing-index report on standard error, or read it from `GET /v1/firestore/missingIndexes` on the control API (see [Cloud Firestore](../../products/firestore/#fail-a-ci-job-on-a-missing-index)). |
| Export fails because of permissions | Run `fireemu doctor --export-dir <dir>`. It inspects the complete existing ancestor chain without modifying it; a private child under a shared parent is insufficient. See [export destinations](../data/#where-to-export). |
| Tests fail while copying an unrelated global repository | Functions worlds in v0.25.0/v0.26.0 snapshot inherited `NODE_PATH`. Use an empty path for local-only dependencies, or explicitly narrow required roots. See [dependency snapshots](../time/#dependency-snapshots-and-global-node_path). |
| The UI does not open | `up` starts without the UI when port 4000 is busy. Use `--ui-port`. `exec` starts the UI only with `--ui`. |
| A scheduled function never runs | Schedules follow the virtual clock, not real time. Move the clock or run the function from the UI. See [Time and scheduled functions](../time/). |

For more detail, start with `--log-verbosity debug`, which also prints the resolved configuration.

## Report an issue

[Open an issue on GitHub](https://github.com/t-k/fireemu/issues) with:

- the Fireemu and Firebase SDK versions, the profile, and the Firebase product involved;
- a minimal reproduction;
- for a compatibility issue, whether you compared against production Firebase or the official emulator, and the expected and actual results.

Remove credentials and personal information before sharing configuration files or logs.
