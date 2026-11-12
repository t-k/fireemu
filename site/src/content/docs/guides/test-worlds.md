---
title: Test worlds
description: Start independent Fireemu worlds with their own clock, ports and data for parallel integration tests, with the fireemu/testing helper.
---

A session inside one daemon shares the daemon's clock, Rules and Functions. For parallel tests that change any of them, the `fireemu/testing` helper starts independent worlds, each with its own daemon, ports, clock and data, even with the same project ID. A world pins its clock start, so its clock stands still and a test moves it by hand (see [Time and scheduled functions](../time/)).

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

Separate worlds isolate their clocks, Rules, Functions and service state. The `fireemu/control` client also works in `fireemu exec` commands and shares URL resolution and authentication with `world.control()`, so callers do not need to concatenate control URLs (see the [test worlds guide](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md)).

- `world.run` launches a command with the world's project and emulator hosts.
- `world.reset()` starts the world again from its creation snapshot.
- `world.dispose()` stops the world and removes its files. `withTestWorld` disposes it for you, also when the callback throws.

## Inspect a world in the UI

To inspect the same world in the debug UI, pass `ui: true` to `createTestWorld()` and open `world.uiUrl`. The UI is disabled by default. Each enabled world receives its own loopback port and shares its live Firestore, Auth, Storage and Functions state. Keep the world alive while inspecting it; `dispose()` also stops its UI. After `reset()`, read `world.uiUrl` again and reopen the page. See [test worlds](https://github.com/fireemu/fireemu/blob/main/docs/test-worlds.md#inspect-a-world-in-the-ui) for an interactive example.

## Dump diagnostics when a test fails

`world.dump(directory)` writes the world's diagnostics bundle into `directory` as two files: `bundle.json` and `bundle.html`. The bundle holds the Security Rules denials with their source line and column, the missing composite indexes, the Functions events and attempts, and the resources the daemon retains. It also records any ranges that were dropped or truncated, and how many values were redacted. Call it from a test's failure handler:

```js
try {
  await run();
} catch (error) {
  await world.dump(join(tmpdir(), 'fireemu-failure'));
  throw error;
}
```

Two shapes to know about:

- `bundle.json` is the parsed answer of the control endpoint, written back out with `JSON.stringify(…, null, 2)`. It is the same data, not the raw response bytes; the test world's control client does not expose the raw bytes.
- The control endpoint answers the HTML page inside a JSON object, `{"html": "…"}`, because the control client parses only JSON answers. `bundle.html` is that `html` field written as a file.

The bundle contains no secrets: configuration values that carry them are redacted, and the scanner masks credential shapes such as bearer tokens and private-key blocks. The config section of the bundle is filled by the command-line dump (`fireemu dump`, and `fireemu exec --dump-on-failure`) from the configuration files the CLI reads, not from the running daemon; `world.dump` leaves it empty.

## Export and import

Enable `hub: true` to export a test world and import its data into a fresh one; see [Export independent test worlds](../data/#export-independent-test-worlds).

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
