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

On Unix-like systems, the destination and its parent directories are checked for ownership and permissions. Use a dedicated, non-shared directory rather than `/tmp` or a shared directory.

- **macOS:** a parent directory with an ACL that allows anyone but the owner, root or you is refused, and the message names the entry. Exporting under your home directory or `$TMPDIR` works. A destination on exFAT or FAT, or on a volume that ignores ownership, is refused; use a directory on an APFS volume.
- **Windows:** `emulators:export` and `--export-on-exit` are not currently available. Import and the rest of the emulators work.
