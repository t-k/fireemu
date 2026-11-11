---
title: Test worlds
description: Start independent Fireemu worlds with their own clock, ports and data for parallel integration tests, with the fireemu/testing helper.
---

A session inside one daemon shares the daemon's clock, Rules and Functions. For parallel tests that change any of them, the `fireemu/testing` helper starts independent worlds, each with its own daemon, ports, clock and data, even with the same project ID. A world pins its clock start, so its clock stands still and a test moves it by hand (see [Time and scheduled functions](../time/)).

## Clock scope and reset: read this first

### What a clock move reaches

`world.clock` moves the daemon's clock. It does not move the clock of your test process or of anything you start.

| Surface | Moved by `world.clock`? |
| --- | --- |
| Functions `Date`, `Date.now()`, `new Date()` | Yes, by default in a world (`functions.clock.date` is `virtual`). |
| Security Rules `request.time`, Auth, Storage and App Check timestamps | Yes. |
| Cloud Tasks schedule times, retry backoff and rate refill | Yes, by default in a world (`functions.clock.tasks` is `virtual`). |
| Scheduled Functions | Yes. |
| Functions JavaScript timers (`setTimeout`, `setInterval`) | No by default (`functions.clock.timers` is `real`). With `timers: 'virtual'` a move makes them due and `world.clock.runDue()` runs them. |
| The test process: `Date.now()`, `performance.now()`, its timers | No. Pass explicit instants to your own helpers. |
| Commands started with `world.run()`: their `Date.now()` and `performance.now()` | No. They only receive routing to the world. |
| External services and anything else outside the daemon | No. |

### What `reset()` invalidates

`world.reset()` stops the daemon and starts a new one, a new *generation*, from the snapshot taken when the world was created.

- Everything you read from the old generation is stale: `world.endpoints`, `world.environment`, `world.uiUrl`, SDK instances and clients built from them, and control clients created from the old control URL and token. Read the getters again and reconnect after `reset()` resolves.
- `world.control()`, `world.clock.*` and `world.run()` always use the current generation. A client made with `createControlClient({ env: world.environment })` or with an explicit origin and token keeps the old generation's endpoint and credential: create it again after `reset()`.
- Commands started with `world.run()` in the old generation are terminated.
- `reset()` returns to the *creation snapshot*, not to your current sources. Edits made to Functions code, Rules, indexes or configuration after the world was created are not picked up. Create a new world to use them.

## Start a world

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

Several worlds in one test: with `Promise.all`, give each its own `withTestWorld()` so every world is disposed even when a sibling fails. Worlds that must coexist inside one test are created with `Promise.allSettled` and disposed in `finally`; `Promise.all([createTestWorld(), ...])` followed by `try/finally` leaks the worlds that started when one creation fails (see the [test worlds guide](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md#create-parallel-worlds)).

Separate worlds isolate their clocks, Rules, Functions and service state. The `fireemu/control` client also works in `fireemu exec` commands and shares URL resolution and authentication with `world.control()`, so callers do not need to concatenate control URLs (see the [test worlds guide](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md)).

- `world.run` launches a command with the world's project and emulator hosts.
- `world.reset()` starts the world again from its creation snapshot.
- `world.dispose()` stops the world and removes its files. `withTestWorld` disposes it for you, also when the callback throws.

## Advance the clock and wait for work

`world.clock.advanceAndSettle(duration, { scope, timeoutSeconds, runTimers })` advances the clock, runs due virtual timers and waits for the daemon to be idle, in that order. The default scope is `runnable`, which does not wait for work scheduled beyond the move. It rejects when the move fails or the wait times out.

```js
const { clock, timers, idle } = await world.clock.advanceAndSettle({ seconds: 60 });
```

A concurrent `awaitIdle` and clock move also work, because a pending `awaitIdle` does not hold up later clock calls on the same world:

```js
await Promise.all([
  world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 20 }),
  world.clock.advance({ seconds: 60 }),
]);
```

`reset()` and `dispose()` cancel a pending wait instead of waiting for its budget. The ordering rules are in the [test worlds guide](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md#advance-the-clock-and-wait-for-work).

## Fixtures for Vitest and Playwright

Create the world in a fixture, give each test its own named Admin SDK app, and delete the app at teardown. After `reset()`, delete the app, read `world.endpoints` again and create a new app. The default Admin app is cached process-wide and cannot be redirected to a world.

```ts
// Vitest: test/world.ts
import { test as base } from 'vitest';
import { createTestWorld, type TestWorld } from 'fireemu/testing';
import { initializeApp, deleteApp, type App } from 'firebase-admin/app';
import { getFirestore, type Firestore } from 'firebase-admin/firestore';

export const test = base.extend<{ world: TestWorld; admin: { db: () => Firestore; reset: () => Promise<Firestore> } }>({
  world: async ({}, use) => {
    const world = await createTestWorld({ services: ['auth', 'firestore'] });
    try {
      await use(world);
    } finally {
      await world.dispose();
    }
  },
  admin: async ({ world }, use) => {
    let app: App | undefined;
    let db: Firestore;
    const connect = () => {
      const { host, port } = world.endpoints.firestore!;
      app = initializeApp({ projectId: world.projectId }, `world-${world.id}-${world.generation}`);
      db = getFirestore(app);
      db.settings({ host: `${host}:${port}`, ssl: false });
      return db;
    };
    connect();
    try {
      await use({
        db: () => db,
        reset: async () => {
          await deleteApp(app!);
          app = undefined;
          await world.reset();
          return connect();
        },
      });
    } finally {
      if (app) await deleteApp(app);
    }
  },
});
```

```ts
// Playwright: one world per worker, a clean generation and a new Admin app per test
import { test as base } from '@playwright/test';
import { createTestWorld, type TestWorld } from 'fireemu/testing';
import { initializeApp, deleteApp } from 'firebase-admin/app';
import { getFirestore, type Firestore } from 'firebase-admin/firestore';

export const test = base.extend<{ db: Firestore }, { world: TestWorld }>({
  world: [
    async ({}, use) => {
      const world = await createTestWorld({ services: ['auth', 'firestore'] });
      try {
        await use(world);
      } finally {
        await world.dispose();
      }
    },
    { scope: 'worker' },
  ],
  db: async ({ world }, use, testInfo) => {
    await world.reset(); // endpoints below are read after the reset
    const { host, port } = world.endpoints.firestore!;
    const app = initializeApp({ projectId: world.projectId }, `test-${testInfo.testId}-${world.generation}`);
    const db = getFirestore(app);
    db.settings({ host: `${host}:${port}`, ssl: false });
    try {
      await use(db);
    } finally {
      await deleteApp(app);
    }
  },
});
```

Clients that read their emulator host from the environment, such as Admin Auth, cannot be pointed at a world through a named app: run that code with `world.run()`, which passes `world.environment` to the child process.

## Inspect a world in the UI

To inspect the same world in the debug UI, pass `ui: true` to `createTestWorld()` and open `world.uiUrl`. The UI is disabled by default. Each enabled world receives its own loopback port and shares its live Firestore, Auth, Storage and Functions state. Keep the world alive while inspecting it; `dispose()` also stops its UI. After `reset()`, read `world.uiUrl` again and reopen the page. See [test worlds](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md#inspect-a-world-in-the-ui) for an interactive example.

## Export and import

Enable `hub: true` to export a test world and import its data into a fresh one; see [Export independent test worlds](../data/#export-independent-test-worlds).

## Snapshot cost

A world copies Functions sources, dependency links and `NODE_PATH` roots only when it loads Functions: `services` omitted (the default selection includes Functions when the configuration names a source or manifest), or listing `functions` or `functions:<codebase>`. A selection such as `['auth', 'firestore']` skips all of it and removes the Functions section from the snapshotted configuration. Auth blocking functions and event-triggered functions run in the Functions service, so select `functions` to use them.

`world.snapshotStats` reports what each copy cost: `initial` is the one-time copy of your inputs and each `generations` entry is the copy that started a generation (creation and every `reset()`), each with `files`, `directories`, `symlinks`, `bytes`, `method` (`copy`, `clone` or `mixed`) and `elapsedMs`. Set `FIREEMU_TEST_WORLD_STATS=1` to print one line per copy to stderr.

```js
const { initial, generations } = world.snapshotStats;
console.log(initial.functions, initial.files, initial.elapsedMs, generations.at(-1).method);
```

Generation copies use copy-on-write where the platform supports it (macOS `cp -c` on APFS; reflinks on Linux file systems that allow them) and a plain copy otherwise; each generation owns its bytes either way. See [what a snapshot copies](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md#what-a-snapshot-copies-and-what-it-costs).

## Snapshots and timeouts

`snapshotTimeoutMs` bounds the initial input snapshot and first generation preparation together, and each reset preparation separately. Its default is 60,000 ms; it accepts integers from 1 through 2,147,483,647. `startupTimeoutMs` separately defaults to 60,000 ms for daemon readiness after preparation.

- Timeout or cancellation stops file copying, waits for active copies to settle and cleans up partial snapshots, including read-only copied directories.
- Configuration files must resolve to regular files. Copied trees can contain directories, regular files and supported dependency links, but other filesystem types are refused.
- If preparation times out, narrow unused dependencies or raise `snapshotTimeoutMs`; raising the readiness timeout does not help.
- Reset retires the previous generation first, so a failed preparation does not keep the old daemon running.

### Dependency snapshots and global NODE_PATH

Functions worlds snapshot local sources and dependencies so caller edits do not affect reset. Ambient `NODE_PATH` is cleared by default (since v0.27.0), while ordinary parent environment variables stay inherited. Local sources and ancestor `node_modules` are still snapshotted.

- To retain globals, pass `env: { ...process.env }`, or supply a narrowed `env.NODE_PATH` with only the directories you need. An environment object containing `NODE_PATH` is an opt-in even when constructed with a spread.
- `nodePathExcludes` omits exact unused package names, including scoped names, before following their links. Required dependency failures are still errors.
- Before v0.27.0, worlds also copied inherited `NODE_PATH` directories, including linked global development repositories, so an unused linked repository could slow startup or fail copying before tests began. On those versions, pass `env: { ...process.env, NODE_PATH: '' }` for local-only dependencies.

See [dependency snapshot limits](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md#create-parallel-worlds).

## Wait for runnable work

`POST /v1/sessions/default:awaitIdle` accepts `{ "scope": "runnable" }` (since v0.26.0). In a world:

```js
await world.control('POST', 'sessions/default:awaitIdle', { scope: 'runnable' });
```

This excludes future task schedules and future retry backoff from the wait. The default scope still waits for all work. Due tasks blocked by rate or concurrency limits and active HTTP requests remain pending. Advance the applicable clock or wait for the active work; diagnostics identify the waiting phase and deadline. This does not wait for arbitrary user-created JavaScript timers. See [idle scopes and task clocks](https://github.com/fireemu/fireemu/blob/main/docs/tasks-idle.md).
