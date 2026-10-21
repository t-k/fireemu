---
title: Export and import data
description: Save emulator data, load it at startup, and keep it between runs.
---

## Export from a running emulator

Run this in another terminal while `fireemu up` is running:

```sh
npx fireemu emulators:export ./emulator-data
```

`--force` overwrites a non-empty destination.

## Import at startup and export on exit

`--import <dir>` loads an export at startup. `--export-on-exit` without a directory writes the state back to the same directory when the run ends:

```sh
npx fireemu exec --import ./emulator-data --export-on-exit -- npm test
```

- An empty `--import` directory starts with no data, so the first run needs no separate command. A missing directory is refused, so a mistyped path cannot start an empty suite, unless it is also where `--export-on-exit` writes.
- A directory that holds files but no `firebase-export-metadata.json` is refused.
- A failed `--export-on-exit` is printed as an `error:` line, and the run exits 1 when the command succeeded. The official CLI only warns and exits 0; Fireemu differs so that a CI job that depends on the saved data cannot pass without it.
- The export directory may be a volume mount point, such as a container volume mounted at `/data`.

## Where to export

Before starting a persistent run, inspect the destination without creating directories or changing permissions:

```sh
npx fireemu doctor --export-dir "$HOME/.local/share/fireemu/emulator-data"
```

On Unix-like systems, the destination and every existing ancestor are checked for ownership and permissions, including the home directory. Use a dedicated, non-shared directory rather than `/tmp`; a 0700 child under a shared ancestor is insufficient. `--export-on-exit` checks before the daemon or child command starts and validates again when exporting, since permissions can change. A volume mount destination needs to be writable even when its parent need not be.

- **macOS:** a parent directory with an ACL that allows anyone but the owner, root or you is refused, and the message names the entry. Exporting under your home directory or `$TMPDIR` works. A destination on exFAT or FAT, or on a volume that ignores ownership, is refused; use a directory on an APFS volume.
- **Windows:** `emulators:export` and `--export-on-exit` are not currently available. Import and the rest of the emulators work.

## Export independent test worlds

Since v0.26.0, `hub: true` enables a private Hub for the world's existing CLI export command. Use an absolute caller-owned export path outside `world.directory`:

```js
import { resolve } from 'node:path';
import { createTestWorld } from 'fireemu/testing';

const exportPath = resolve('./emulator-data');
const services = ['auth', 'firestore', 'storage'];
const world = await createTestWorld({ services, hub: true });
try {
  await world.run('fireemu', [
    'emulators:export', exportPath, '--project', world.projectId,
  ]);
} finally {
  await world.dispose();
}
const restored = await createTestWorld({ services, import: exportPath });
try {
  // Connect fresh SDK clients through restored.endpoints or restored.run(...).
} finally {
  await restored.dispose();
}
```

Pass `--project` explicitly. The helper owns the Hub's OS-assigned port and private locator; same-project worlds stay independent. For a development binary, use its absolute path for both `binaryPath` and the export command.

Exports preserve Auth users and password credentials, Firestore documents, Storage bytes and metadata, and Realtime Database data. They do not preserve App Check state, virtual clocks, Functions process memory or the validity of previously issued tokens. Imports are snapshotted at creation, so later edits to the original export do not affect reset. Exports outside the world directory remain caller-owned after disposal. See the [full export and import guide](https://github.com/t-k/fireemu/blob/main/docs/test-worlds.md#export-and-import-test-data).
