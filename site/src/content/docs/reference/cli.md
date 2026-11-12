---
title: CLI
description: Commands and options of the fireemu command.
---

This reference lists common fireemu commands and options. Run `npx fireemu --help`, or `npx fireemu help <command>`, for the help of the version you have installed. The blocks below are the help text of the current release; `exec` and `capabilities` accept every option of `up`, which is listed once under [up](#up).

| Command | What it does |
|---|---|
| [`init`](#init) | Create `fireemu.toml` in the current directory |
| [`up`](#up) | Start the emulators and keep them running until `Ctrl+C` (alias: `emulators:start`) |
| [`exec`](#exec) | Start the emulators, run a command, stop them (alias: `emulators:exec`) |
| [`emulators:export`](#emulatorsexport) | Export the state of a running suite to a directory |
| [`doctor`](#doctor) | Check the installation: binary, UI, Functions runner, Node.js |
| [`capabilities`](#capabilities) | Print the capability manifest of the resolved profile as JSON |
| [`config show`](#config-show) | Print every configuration key with its effective value and source |
| [`config lint`](#config-lint) | List the settings a configuration sets that are accepted but have no effect; fail on them in CI |
| `--version` (also `-V`, `version`) | Print the version and exit |
| `help [command]` (also `--help`, `-h`) | Print the command list, or the help of one command |

## init

```text
fireemu init - create fireemu.toml in the current directory

usage:
  fireemu init [options]

Creates fireemu.toml in the current directory and prints the command to start with it. It never overwrites an existing file unless --force is given. An existing fireemu.json must be removed before creating fireemu.toml.

options:
  --reference
        Also write fireemu.reference.toml, which fireemu does not load. With an existing fireemu.toml or fireemu.json and no --profile or --firebase-json, write only the reference. Copying a key into fireemu.toml makes it explicit and stops productionExact from switching it.
  --profile strict|emulator
        Compatibility profile. strict follows production Firebase and is recommended, including when migrating from the official emulator; emulator is only for checking alignment with the pinned official emulator and is not needed when migrating. Default: strict (asked interactively).
  --firebase-json <file>
        Reference this firebase.json from fireemu.toml, so rules, indexes, Functions and ports are read from it on every start. Default: ./firebase.json when it exists (asked interactively).
  --interactive
        Ask for the missing choices. Default: only when stdin and stdout are terminals.
  --yes, --no-interactive
        Never ask; use the defaults for what is not given.
  --force
        Replace existing output files. Default: an existing file is an error.
  -h, --help
        Print this help and exit.
```

## up

```text
fireemu up - start the emulators and keep them running until Ctrl-C (alias: emulators:start)

usage:
  fireemu up [options]
  fireemu up --plan [--json] [options]
  fireemu emulators:start [options]

Serves the selected emulators (Firestore, Auth, Storage and App Check; Functions when a codebase is configured, and with it Eventarc and Cloud Tasks; Pub/Sub when configured; the Realtime Database when configured) plus the control API, the Emulator Hub and the UI on loopback until Ctrl-C.

options:
  --config <file>
        Configuration file: TOML (.toml) or JSON (any other extension), with schemaVersion 1, or a firebase.json. Default: ./fireemu.toml or ./fireemu.json when neither --config nor --firebase-json is given (both present is an error; remove one), else the nearest firebase.json (see --no-config-discovery), else the built-in defaults.
  --firebase-json <file>
        Read ports, rules, indexes and Functions codebases from this firebase.json. Takes precedence over one referenced by --config. Default: the one ./fireemu.toml or ./fireemu.json names, else, without either, the nearest firebase.json in the current directory or a parent.
  --no-config-discovery
        Do not search for ./fireemu.toml, ./fireemu.json or the nearest firebase.json when neither --config nor --firebase-json is given; use the built-in defaults. Also silences the warning for a discovered file that was skipped because of its owner or permissions. Default: the search is on.
  -P, --project <id|alias>
        Project ID, or an alias from the .firebaserc next to the firebase.json (else the current directory). Default: the .firebaserc default, else daemon.authProject from --config, else demo-app.
  --only <list>
        Comma-separated services to start: auth, firestore, storage, functions (or functions:<codebase>), eventarc, tasks, pubsub, database, appcheck, hosting. Default: Firestore, Auth, Storage and App Check; Functions when a codebase is configured (firebase.json or --functions), and with it Eventarc and Cloud Tasks; Pub/Sub when configured (emulators.pubsub, daemon.pubsubPort or --pubsub-port); the Realtime Database when configured (emulators.database, daemon.databasePort or --database-port); Hosting when firebase.json has hosting.public.
  --firestore-port <n>
        Firestore port. Default: 8080 (0 picks a free port).
  --http-port <n>
        Auth (Identity Toolkit) port. Default: 9099 (0 picks a free port).
  --storage-port <n>
        Storage port. Default: 9199 (0 picks a free port).
  --functions-port <n>
        Functions port, used when a codebase is loaded. Default: 5001 (0 picks a free port).
  --hosting-port <n>
        Hosting port, used when firebase.json has hosting.public. Default: 5000 (0 picks a free port).
  --eventarc-port <n>
        Eventarc port. Eventarc starts exactly when a Functions backend is loaded; this option only sets the port. Default: 9299.
  --tasks-port <n>
        Cloud Tasks port. Cloud Tasks starts exactly when a Functions backend is loaded; this option only sets the port. Default: 9499.
  --pubsub-port <n>
        Pub/Sub port. Without --only, giving it also starts Pub/Sub; with --only, Pub/Sub starts only when the list names pubsub. Default: 8085.
  --database-port <n>
        Realtime Database port. Without --only, giving it also starts the Realtime Database; with --only, it starts only when the list names database. Default: 9000.
  --functions <dir>
        Load exactly one Functions codebase from this directory, whatever firebase.json declares. Default: the codebases firebase.json declares.
  --ui-port <n|auto>
        UI port; auto assigns an available port, 0 disables the UI. Default: 4000 for up (the UI is skipped if that port is busy), off for exec.
  --hub-port <n|auto>
        Emulator Hub port; auto assigns an available port, 0 disables it. Default: 4400.
  --logging-port <n>
        Logging emulator port; 0 disables it. Default: 4500.
  --inspect-functions [port]
        Run the Functions runner under the Node inspector on this port (1024-65535); without a port, or with `true`, a free port. Refused when functions.runner is not node. Default: off.
  --log-verbosity quiet|silent|info|debug
        quiet and silent print errors only; info adds the banner and notices; debug also prints the resolved configuration. Case-insensitive. Default: info.
  --import <dir>
        Import an export directory (from --export-on-exit or emulators:export) at start; it must exist. Default: start empty.
  --export-on-exit [dir]
        Export all state to this directory when the emulators stop; without a directory, the --import directory. Refused for the working directory or a parent of it, and unavailable on Windows. Default: no export.
  --plan
        Resolve the run exactly as start-up does, print what it would do and start nothing: the project ID and where it came from, the command-line overrides, each service with its address (or why it is off), the environment variables the run sets and the inherited ones that remain, the absolute path of every rules, index and source file with the directory a relative path is resolved against, the Node or Python each Functions codebase would run on with its SDK versions, the active development defaults and the settings that have no effect. It runs `node --version` and a Python codebase's own interpreter, probes no port, and exits 1 when the run would fail for a reason it can see (a codebase that cannot start, a variable --deny-inherited-emulator-env refuses). For up and exec; capabilities accepts and ignores it. Default: off.
  --json
        With --plan: print the plan as JSON (planVersion 1) instead of text. Requires --plan. Default: text.
  --deny-inherited-emulator-env
        Refuse to start (exit 1, before anything starts) when the environment carries an emulator variable (FIRESTORE_EMULATOR_HOST, PUBSUB_EMULATOR_HOST, ...) for a service this run does not start: the command, or a Functions runner that inherits the environment, would reach whatever listens there, for example another worktree's suite. Variables of services this run starts are replaced by its own values and never refused. For up and exec; capabilities accepts and ignores it. Default: warn and keep the variable, as the official emulators:exec does.
  --allow-inherited-emulator-env <NAME>
        Keep this inherited emulator variable on purpose (for example PUBSUB_EMULATOR_HOST when one suite deliberately uses another's Pub/Sub): no warning and no refusal for it. May be repeated. A name that is no emulator variable is a usage error. Default: none.
  --ready-file <file>
        Publish endpoint discovery, including a control capability, to this private file once every listener is bound, and remove it on graceful shutdown. For tooling such as fireemu/testing. Default: none.
  --owner-stdin
        Shut down when standard input is closed. For tooling such as fireemu/testing. Default: off.
  -h, --help
        Print this help and exit.
```

## exec

```text
fireemu exec - start the emulators, run a command, stop them (alias: emulators:exec)

usage:
  fireemu exec [options] "shell script"
  fireemu exec [options] -- <command...>
  fireemu exec --plan [--json] [options] -- <command...>
  fireemu emulators:exec [options] "shell script"
  fireemu emulators:exec [options] -- <command...>

Starts the same emulators as `up`, runs the command with the emulator host environment variables (FIRESTORE_EMULATOR_HOST, FIREBASE_AUTH_EMULATOR_HOST, and so on) once every listener is bound, stops everything when the command exits, and exits with the command's status. On Unix, a command ended by signal n gives 128 + n, and SIGINT and SIGTERM are forwarded to it.

Like the official emulators:exec, the command inherits the parent environment, and this run's values replace the variables of the services it starts. An emulator variable for a service it does not start stays as it is (and is warned about); --deny-inherited-emulator-env refuses such a run instead, and --allow-inherited-emulator-env keeps a variable on purpose. --plan shows the environment without starting anything.

With "shell script" (the official form) the script is run by the system shell. With `--` the command is run as exactly that program and argv, without a shell. Everything after `--` belongs to the command, including --help; a `--help` inside the script text is script text.

options: every option of `up` (listed under up above), and:
  --ui
        Start the UI while the command runs (exec does not start it otherwise, as in `firebase emulators:exec`). --ui-port overrides.
  -h, --help
        Print this help and exit.
```

### Plan a run

`--plan` on `up` or `exec` resolves the run exactly as start-up does, prints what it would do, and starts nothing. `--json` prints the same plan as JSON (`planVersion` 1). Put it in front of a CI job to see what a command line and a configuration add up to:

```sh
npx fireemu exec --plan -- npm test
npx fireemu up --plan --json --only firestore,auth --project demo-ci
```

The plan lists:

- The project ID and the rule that chose it (`--project`, an alias in `.firebaserc`, the `.firebaserc` default, `daemon.authProject`, or the built-in default), the configuration files that were loaded, and the command-line overrides that were applied. [`config show`](#config-show) reads the files only, so it does not include the overrides.
- Every service with its address, or the reason it does not start (`--only`, no Functions codebase, Pub/Sub not configured). It does not probe a port; the run binds its ports when it starts.
- The environment: the variables the run sets for its services, and the emulator variables the parent environment carries that remain (see [Inherited emulator variables](#inherited-emulator-variables)). A credential in an inherited endpoint is replaced by `***`.
- Each rules, index, text-index and source file as the run opens it: the absolute path, the path as written, and the directory a relative path is resolved against. Paths in the canonical configuration resolve against the working directory and paths in `firebase.json` against its directory ([Relative paths](../../guides/configuration/#relative-paths)); the plan warns when the canonical configuration lives in another directory than the working directory, because the same file run from its own directory would read other files.
- For each Functions codebase, the Node or Python executable and version the run would use, chosen by the code start-up uses (so `FIREEMU_NODE`, `PATH`, `VOLTA_HOME`, `engines.node`, and the codebase's `venv` all count), and the installed `firebase-functions` and `firebase-admin` versions. The plan runs `node --version` and a Python codebase's interpreter to find out.
- The development defaults in effect, with the ones [`productionExact`](../../guides/profiles/) would switch marked `relaxed`, and the settings the configuration sets that have [no effect](#config-lint).

The command exits 1, with the plan still printed, when the run would fail for a reason the plan can see: a Functions codebase that cannot start (no usable Node, a missing `venv`), or an inherited variable that `--deny-inherited-emulator-env` refuses. A configuration the daemon refuses fails with the same message and exit code as `up`.

### Inherited emulator variables

`exec` gives its command your environment with the variables of the services it starts replaced, as `firebase emulators:exec` does. A variable for a service this run does not start keeps its value, so a missing emulator never sends an SDK to production, but it also means that a variable left in your shell by another suite (a second checkout or a parallel job) points your tests at that suite. Fireemu therefore reports it:

- By default it prints a `warning:` for each such variable, keeps it, and runs.
- `--deny-inherited-emulator-env` refuses the run before anything starts (exit code 1) when the environment carries an emulator variable for a service the run does not start. The variables of services the run starts are replaced by its own values and are never refused. It applies to `up` too, where the variables belong to the shell that starts it and to a Functions runner under the `emulator` profile.
- `--allow-inherited-emulator-env <NAME>` keeps one on purpose, for example `PUBSUB_EMULATOR_HOST` when one suite deliberately uses another's Pub/Sub. It silences the warning and the refusal for that variable, can be repeated, and refuses a name that is no emulator variable. [`--plan`](#plan-a-run) lists each inherited variable and what happens to it.

The check recognizes every emulator host variable the Firebase and Google Cloud SDKs read, including `DATA_CONNECT_EMULATOR_HOST` and `FIREBASE_DATA_CONNECT_EMULATOR_HOST` for a service Fireemu does not serve, which is never started. The Hub and the Logging emulator are best effort (a busy default port only disables them): the pre-start check treats them as started, and once the listeners are bound the check runs again against the ones that really bound, before any Functions runner or command starts. A `functions.runner` override is shown with its arguments replaced by `[redacted]`, because they can carry credentials.

## emulators:export

```text
fireemu emulators:export - export the state of a running suite to a directory

usage:
  fireemu emulators:export <dir> [options]

Asks the suite that is already running for the project (found through its Emulator Hub locator file) to write its state to <dir>, in the format --import reads. Not available on Windows.

options:
  -P, --project <id>
        Project of the running suite. Default: the .firebaserc default in the current directory, else demo-app.
  -f, --force
        Overwrite a non-empty destination. Default: refused.
  -h, --help
        Print this help and exit.
```

## doctor

```text
fireemu doctor - check the installation: binary, UI, Functions runner, Node.js

usage:
  fireemu doctor [--connect <control url> | --export-dir <path>]

Reports the Fireemu binary, UI, Functions runner and the Node.js that Functions would run on (FIREEMU_NODE, else the first node on PATH or in VOLTA_HOME, chosen by the code Functions start-up uses, not the node a shell finds), and suggests a remedy for each problem. A codebase's runtime or engines.node can select another installed Node; `fireemu up --plan` shows the one each codebase gets.

options:
  --export-dir path
        Inspect an export destination and its ancestors without starting a daemon or changing files. Export checks again when it writes. Cannot be combined with --connect.
  --connect http://127.0.0.1:<port>
        Also report what a running suite says, through its control URL (the control port is printed at startup). Default: only the offline report.
  -h, --help
        Print this help and exit.
```

## capabilities

```text
fireemu capabilities - print the capability manifest of the resolved profile as JSON

usage:
  fireemu capabilities [options]

Prints the capability manifest for the profile the options resolve to. It accepts the same options as `up` and validates them the same way, but only --config (the profile it names) changes the result.

options: every option of `up` (listed under up above); only --config and --firebase-json change the result.
  -h, --help
        Print this help and exit.
```

`capabilities` resolves the configured profile and overrides without starting a daemon. A missing virtual-clock start is reported on standard error while standard output remains capability JSON; startup still requires that clock value.

## config show

`fireemu config show` prints every configuration key in schema order with its effective value and source, using the same configuration discovery as `fireemu up`, but without the command-line overrides of `up` (`--project`, `--only` and the port flags) and without starting the emulators. To see the result of the files and the overrides together, use [`fireemu up --plan`](#plan-a-run). Use `--config <path>` or `--firebase-json <path>` to select files, and `--json` for records containing `key`, `value`, `source`, and the schema description.

- Sources distinguish explicit values, defaults, `productionExact`, derived values, and unset keys.
- When the runtime does not expose a value, the command uses its explicit file value, its schema default (marked `default (schema)`), or `(unset)` (`null` with source `unset` in JSON).
- A key the configuration accepts but the daemon does not read (for example `bind`, `limits.catalog`, `firestore.textSearch.*`, `rules.staticLimitChecks`, `auth.enabled` and `trace.*`) has the source `accepted, no effect`: its value is shown as written, or `(unset)`, never as if it were in effect, and a configuration that sets one prints a `note:` line at start-up.
- `firebaseJson` shows the Firebase configuration file actually selected, including one chosen with `--firebase-json`.

## config lint

```text
fireemu config lint [--config <path>] [--firebase-json <path>] [--json] [--deny-ineffective] [--allow <key>]... [--allow-file <path>]
```

`fireemu config lint` loads the configuration exactly as `fireemu config show` does (a configuration the daemon refuses fails with the same message and exit code 1) and lists the settings it sets that Fireemu accepts but does not read. Each line carries the same text as the `note:` line that `fireemu up` prints at start-up, and both come from one list of keys, so a key that starts to take effect leaves the lint and the note together. A configuration that sets none prints `no ineffective settings`.

By default the report is informational and the exit code is 0. Add `--deny-ineffective` to a CI job to make it a check: the command exits 1, naming each setting, when the configuration sets one that no allow-list entry covers.

```sh
fireemu config lint --deny-ineffective --allow bind --allow 'firestore.textSearch.*'
```

- `--allow <key>` names a setting that may be present although it has no effect, for example a key you keep for a later release. `prefix.*` covers every key below `prefix`. The option can be repeated. Allowed settings are still listed, marked `allowed`, and do not fail the check.
- `--allow-file <path>` reads allow-list entries from a file, one per line. The file must be UTF-8; a byte order mark and CRLF line endings are accepted, and any other encoding is a usage error (exit code 2). Blank lines and `#` comments (whole-line or trailing) are ignored. Use it when the list is long or should be reviewed in version control.
- An entry that names no configuration key (a typo, or a table such as `trace` instead of `trace.*`) is a usage error with exit code 2, so a misspelt entry cannot silently allow nothing.
- `--json` prints `config` (the file checked, or `null`), `ineffective` (each setting with `key`, `note` and `allowed`) and `denied` (the keys that fail under `--deny-ineffective`).
- Only the canonical configuration (`fireemu.toml` or `fireemu.json`) is checked. When none is found, the command says so and exits 0.
