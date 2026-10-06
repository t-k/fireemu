# Test clocks and independent worlds

Test clocks and worlds are explicit local testing extensions. Normal daemon configurations keep native application dates, JavaScript timers and Cloud Tasks time. A session inside one daemon still shares the daemon's clock, Rules and Functions; create separate worlds for parallel tests that change any of them.

## Configure application time

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

Each mode accepts `real` or `virtual`. A virtual mode requires an explicit pinned `daemon.clockStart`. Virtual timers require virtual Date. The bundled Node runner installs the policy before importing user code. Custom runners must advertise the clock protocol capability; startup refuses a virtual Date policy when the runner cannot acknowledge it.

Clock control commands acknowledge the current Functions runner generations before returning success. Date reads after that acknowledgement use the destination instant, including after an `await`, a reload or runner recovery. `new Date(value)`, `Date.parse`, `Date.UTC`, prototypes and subclasses keep their JavaScript meaning. Nanoseconds are converted to whole epoch milliseconds by flooring, including before the Unix epoch. Moves outside JavaScript's Date range are refused without publishing new clock state, including fault delays and fixture ticks.

## What a clock move changes

| Surface | Effect of advancing the world clock |
| --- | --- |
| Scheduled Functions and event retry eligibility | Admit due work according to the configured catch-up and retry policies. |
| Node `Date.now()`, `new Date()` and `Date()` | Read the destination time when `date` is virtual. Explicit Date values keep their normal meaning. |
| Delayed JavaScript timers | When `timers` is virtual, positive clock movement consumes delay and makes callbacks due. Call `world.clock.runDue()` to execute a bounded batch. |
| Cloud Tasks | When `tasks` is virtual, scheduleTime eligibility uses world wall time; rate refill, retry backoff, retry duration and statistics windows use positive elapsed time. |
| Pub/Sub retention and delivery deadlines | Use the world-owned logical clock under the existing service policies. |
| Firestore history and TTL | Existing clock-control compaction and TTL sweep policies apply within this daemon; advancing is not a promise of unconditional immediate TTL deletion. |
| Auth, App Check, Storage timestamps and Rules `request.time` | Subsequent service operations observe the pinned world clock. |
| `setImmediate`, Promise continuations, `nextTick`, networking, `performance.now()` and `process.hrtime()` | Keep native event-loop and monotonic-time behavior. |
| HTTP, function invocation, IPC, output, readiness, await-idle and shutdown timeouts | Keep native deadlines, so a frozen test clock cannot disable lifecycle safeguards. |
| External services, user-created workers and subprocesses | Are not clock-patched. Processes launched with `world.run` receive routing to the world; their own Date remains native. |

Moving the wall clock backwards consumes no timer or Tasks elapsed time and does not resurrect completed work. Timer callbacks see the destination Date. The timer drain yields to Promise and nextTick continuations between callbacks, preserves deadline/registration order and never waits for a callback's returned promise. It returns executed, pending and due counts; it does not move time. The default budget is 1,000 callbacks per runner, and the maximum is 10,000. Call it again to consume a remaining interval backlog. Native timers continue to fire while virtual Date is frozen.

A clock command admits eligible scheduled/task work; it does not establish that asynchronous handlers or networking have completed. Use a service-visible condition or the existing await-idle endpoint where appropriate. User timers are not included in Functions idle counts.

An entry point that awaits a virtual timer during top-level module initialization cannot finish startup before a clock actor exists. Use native timers during initialization, or move that wait into a handler. Timer virtualization supports the global, CommonJS and ESM `node:timers` callback APIs and `node:timers/promises` timeout/interval APIs, including cancellation, refresh, ref/unref and AbortSignal.

## Create parallel worlds

```js
import { createTestWorld, withTestWorld } from 'fireemu/testing';

const settings = {
  projectId: 'demo-parallel',
  clockStart: '2026-01-31T23:59:00Z',
  functionsSource: './functions',
  services: ['auth', 'firestore', 'storage', 'functions'],
  clock: { date: 'virtual', timers: 'real', tasks: 'virtual' },
};

const worlds = await Promise.all([
  createTestWorld(settings), createTestWorld(settings), createTestWorld(settings),
]);
try {
  const [a, b, c] = worlds;
  await Promise.all([a.clock.advance({ seconds: 86400 }), c.reset()]);
  await b.run(process.execPath, ['./integration-test.mjs']);
  // B retains its original clock, Rules, Functions globals and service state.
} finally {
  await Promise.all(worlds.map(world => world.dispose()));
}

await withTestWorld(settings, async world => {
  await world.clock.advance(59999); // milliseconds: one millisecond before midnight
  await world.run(process.execPath, ['./trial-before-expiry.mjs']);
  await world.clock.advance(1);
  await world.run(process.execPath, ['./trial-expired.mjs']);
});
```

Each world owns one daemon, OS-assigned service ports, a control token, private temporary directories and a creation snapshot of configuration, Rules, indexes, Functions sources, dependency links and optional import data. Even the same project ID is independent across worlds. Hub, UI and logging listeners are disabled in this helper. Defaults are a pinned `2026-01-01T00:00:00Z`, seed 1, virtual Date/Tasks and native JavaScript timers.

`config` accepts a configuration object or path; `firebaseJson`, `functionsSource`, `cwd`, `import`, `projectId`, `clockStart`, `seed`, `services` and `clock` select the initial inputs. `binaryPath` can select a development binary. Input files and linked Functions dependencies are copied before readiness; later caller changes do not affect reset. This has an upfront disk/time cost for large dependency graphs. Do not put a world's temporary directory inside its Functions source.

Configured Functions also snapshot and relocate `NODE_PATH` search directories. If global dependency roots are unused by the codebase, select `env: { ...process.env, NODE_PATH: '' }` to exclude them from the snapshot. Worlds without configured Functions clear this extra search path. The helper supplies its own `FIREBASE_CONFIG` and emulator routes, including to SDK default-app initialization; inherited configuration and child environment overrides cannot redirect them to another world.

`world.environment` is the immutable environment for SDK children. `world.run(command, argv, options)` launches a tracked child with the world's project and emulator hosts, without changing `process.env` in the test runner. It returns `{code, signal, stdout, stderr}` and rejects on failure, cancellation or retirement of its generation. SDK instances in the parent process must use named apps and explicitly connect to `world.endpoints`; they remain caller-owned. The helper cannot redirect a parent's cached default Admin SDK app.

`world.reset()` stops the old daemon and tracked command trees, discards all generation state and starts from the creation snapshot. It returns after readiness, with new `generation`, `endpoints` and `environment`. Clients using old endpoints must reconnect. Do not cache these getters across reset. A plain session reset has the existing narrower behavior and does not recreate a world.

`world.dispose()` joins process retirement and removes its private files; repeat calls are safe. `withTestWorld` also disposes when the callback throws. Functions process groups on Unix have an independent lifetime guardian, so forced daemon retirement can clean up a runner blocked in synchronous user code. Windows commands and Functions are owned through native Job Objects. Cleanup deadlines remain native. An explicit error reports a process tree that cannot close after escalation.

A retirement error still attempts to stop every owned daemon and retains unresolved cleanup handles for another `dispose()` attempt. User-created detached subprocesses that leave an owned Unix process group require caller supervision; the helper reports a held output pipe instead of silently declaring disposal complete.

The authenticated `--ready-file <path>` daemon option publishes endpoint discovery atomically in a private file without overwriting an existing descriptor. It contains a control capability and is withdrawn on graceful shutdown. The helper keeps it inside the private generation directory and removes the directory after forced retirement.
