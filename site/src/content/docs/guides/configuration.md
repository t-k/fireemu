---
title: Configuration files
description: How Fireemu finds fireemu.json and firebase.json, and what each one holds.
---

Fireemu reads two kinds of files:

- **`fireemu.json`** holds Fireemu's own settings, such as the [profile](../profiles/), Authentication project configuration and the clock. It contains `"schemaVersion": 1`. See the [configuration schema](../../reference/configuration/).
- **`firebase.json`** is the file the Firebase CLI uses. Fireemu reads ports, Security Rules, indexes and Functions codebases from it, every time it starts.

Keep Fireemu-specific settings in `fireemu.json` rather than in `firebase.json`. To use both, name the `firebase.json` in `fireemu.json`:

```json
{
  "$schema": "https://fireemu.dev/spec/config/fireemu.schema.json",
  "schemaVersion": 1,
  "profile": "strict",
  "firebaseJson": "firebase.json"
}
```

`npx fireemu init --firebase-json firebase.json` writes this for you.

## Which files are loaded

`up`, `exec`, `emulators:start` and `emulators:exec` choose their configuration files as follows.

1. `--config <file>` and `--firebase-json <file>` load exactly the files they name, and nothing is searched for.
2. Otherwise, `fireemu.json` in the current directory is loaded. Its `firebaseJson` entry, resolved relative to `fireemu.json`, names the `firebase.json` to load. A `firebase.json` beside a `fireemu.json` without a `firebaseJson` entry is not loaded, and the startup output says so. A `fireemu.json` in a parent directory is not used.
3. Otherwise, the nearest `firebase.json` is loaded: the one in the current directory, else the first one found in a parent directory, as the Firebase CLI finds it. The `.firebaserc` beside it is read too.
4. Otherwise, the built-in defaults apply, and no Security Rules are loaded.

`--no-config-discovery` skips steps 2 and 3. The `config:` line of the startup output names the files that were loaded.

## File ownership checks

A discovered file can name Functions code to run and the rules to enforce, so on Unix the search checks who owns what it finds, as git checks repository ownership. The Firebase CLI does not check this. The trusted owners are you, root, and, when you run as root through `sudo`, the user in `SUDO_UID`.

- A `fireemu.json` or `firebase.json` whose owner is not trusted, or that any user can write, is skipped with a warning. Group write is allowed.
- The search stops before a parent directory whose owner is not trusted or that any user can write, such as `/tmp`.
- A current directory that any user can write is not searched at all.
- A discovered file larger than 16 MiB is refused.

To load a skipped file anyway, name it with `--config` or `--firebase-json`. To silence the warning, pass `--no-config-discovery`. On Windows, ownership is not checked.

Two common setups run into this rule:

- **A root container with a bind-mounted checkout**, such as a GitHub Actions `container:` job, or `docker run -v "$PWD":/app` as root. The files are owned by a host user the container's root does not trust. Use the explicit flags, or `chown` the checkout. Rootless Podman maps your user to the container's root, so it is not affected.
- **`sudo`.** Files owned by the user in `SUDO_UID` are trusted.

## Validate your configuration

`fireemu.json` is validated at startup, and a value Fireemu does not accept stops it with an error. The [configuration schema](../../reference/configuration/) is a JSON Schema you can also use in your editor.

`fireemu capabilities` prints the capability manifest for the profile your configuration resolves to.
