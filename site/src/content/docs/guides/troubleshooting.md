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
| Your `firebase.json` or `fireemu.json` is not used | The `config:` line of the startup output names the files that were loaded. See [Which files are loaded](../configuration/#which-files-are-loaded), and the ownership rule if you run in a container or with `sudo`. |
| Every Firestore or Storage request is denied | Under `strict`, a project without Security Rules refuses client requests, as production does. Check the `firestore rules:` and `storage rules:` startup lines. See [Security Rules](../security-rules/). |
| A request is denied and you do not know why | Read the `note: firestore: Security Rules denied ...` line on standard error, or the Rules page of the UI. |
| A query works locally but fails in production | Under `emulator` a missing index is not checked; switch to `strict`, which refuses the query as production does. If `firestore.missingIndexes` is `"report"`, look for the missing-index report on standard error. |
| The UI does not open | `up` starts without the UI when port 4000 is busy. Use `--ui-port`. `exec` starts the UI only with `--ui`. |
| A scheduled function never runs | Schedules follow the virtual clock, not real time. Move the clock or run the function from the UI. See [Time and scheduled functions](../time/). |

For more detail, start with `--log-verbosity debug`, which also prints the resolved configuration.

## Report an issue

[Open an issue on GitHub](https://github.com/t-k/fireemu/issues) with:

- the Fireemu and Firebase SDK versions, the profile, and the Firebase product involved;
- a minimal reproduction;
- for a compatibility issue, whether you compared against production Firebase or the official emulator, and the expected and actual results.

Remove credentials and personal information before sharing configuration files or logs.
