---
title: Time and scheduled functions
description: Start at a chosen time, move a virtual clock, and run scheduled functions without waiting.
---

Fireemu has a clock of its own. Set where it starts and move it, and every service sees the new time: scheduled functions come due, tokens expire, and Security Rules see the new `request.time`.

## Set the start time

```json
{
  "schemaVersion": 1,
  "daemon": { "clockStart": "2026-01-31T23:59:00Z" }
}
```

Configure the time zone, catch-up and overlap behavior of scheduled functions in the `scheduler` section.

## Run scheduled functions

A schedule is driven by the virtual clock alone: real time passing runs nothing. Move the clock from the Runtime page of the [Emulator UI](../ui/), or with the control API (`clock:advance`, `clock:advanceTo`, `clock:set`). Each move makes every occurrence in `(previous time, new time]` due.

- `scheduler.catchUp` decides what runs when a move passes several occurrences: `all` runs each one (at most `scheduler.maxCatchUpRuns` per job and move), `latest` runs the newest, and `none` runs none.
- `scheduler.overlap` (`allow`, `skip`, `queue`, `reject`, `skip-in-flight`) decides what happens when a run comes due while the previous one is still running. Under `strict` the default is `skip-in-flight`, as production's Cloud Scheduler behaves; under `emulator` it is `allow`.

The Functions page of the UI can also run a scheduled function immediately, or advance the clock to its next occurrence. A manual run does not consume the next occurrence.

## Move the clock backwards

The clock can move backwards (`clock:set` with `"allowBackwards": true`, or **Allow moving backwards** on the Runtime page). A rewind never replays occurrences that already ran.

Under `strict`, Authentication, Firestore and Storage refuse an ID token issued after the new time until the clock reaches its issue time again. In both profiles an expired token is still refused. If a rewind leaves tokens unusable, move the clock forward again or reset the session.

## Application time in Functions

By default your function code sees real time. To make `Date.now()`, timers and Cloud Tasks follow the virtual clock too, set `functions.clock` together with a pinned `daemon.clockStart`:

```json
{
  "schemaVersion": 1,
  "daemon": { "clockStart": "2026-01-31T23:59:00Z" },
  "functions": {
    "source": "./functions",
    "clock": { "date": "virtual", "timers": "real", "tasks": "virtual" }
  }
}
```

Each mode accepts `real` or `virtual`. Virtual timers require virtual `date`.

## Independent test worlds

A session inside one daemon shares the daemon's clock, Rules and Functions. For parallel tests that change any of them, the `fireemu/testing` helper starts independent worlds, each with its own daemon, ports, clock and data, even with the same project ID:

```js
import { withTestWorld } from 'fireemu/testing';

await withTestWorld(
  {
    projectId: 'demo-parallel',
    clockStart: '2026-01-31T23:59:00Z',
    functionsSource: './functions',
    services: ['auth', 'firestore', 'storage', 'functions'],
  },
  async (world) => {
    await world.clock.advance(59999); // milliseconds: one millisecond before midnight
    await world.run(process.execPath, ['./trial-before-expiry.mjs']);
    await world.clock.advance(1);
    await world.run(process.execPath, ['./trial-expired.mjs']);
  },
);
```

`world.run` launches a command with the world's project and emulator hosts. `world.reset()` starts the world again from its creation snapshot, and `world.dispose()` stops it and removes its files; `withTestWorld` disposes it for you, also when the callback throws.
