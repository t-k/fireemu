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
| Strict scheduled delivery | Gen2 `x-cloudscheduler-scheduletime` uses the occurrence with the Los Angeles offset; Gen1 context timestamps and Pub/Sub publish times use the occurrence, even when virtual Date reads the destination instant. |
| Scheduler retry backoff | Due retries and `maxRetrySeconds` windows use the daemon clock; advancing it can release retries or exhaust their retry window. |
| Node `Date.now()`, `new Date()` and `Date()` | Read the destination time when `date` is virtual. Explicit Date values keep their normal meaning. |
| Delayed JavaScript timers | When `timers` is virtual, positive clock movement consumes delay and makes callbacks due. Call `world.clock.runDue()` to execute a bounded batch. |
| Cloud Tasks | When `tasks` is virtual, scheduleTime eligibility uses world wall time; rate refill, retry backoff, retry duration and statistics windows use positive elapsed time. |
| Pub/Sub retention and delivery deadlines | Use the world-owned logical clock under the existing service policies. |
| Firestore history and TTL | Existing clock-control compaction and TTL sweep policies apply within this daemon; advancing is not a promise of unconditional immediate TTL deletion. |
| Strict Firestore writer lock waits | A contended writer aborts with `ABORTED` after 20 seconds of wall time or an advance of at least 20 seconds from the start of its wait. |
| Strict Eventarc channel and operation times | Use the daemon clock when `daemon.clockStart` is pinned, including in worlds; otherwise use wall time. A frozen clock keeps an operation pending until a clock move reaches its completion time. Recorded channel timestamp offsets still apply. |
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

Each world owns one daemon, OS-assigned service ports, a control token, private temporary directories and a creation snapshot of configuration, Rules, indexes, Functions sources, dependency links and optional import data. Even the same project ID is independent across worlds. Hub and logging listeners are disabled in this helper. The UI is disabled by default and can be enabled explicitly with `ui: true`. Defaults are a pinned `2026-01-01T00:00:00Z`, seed 1, virtual Date/Tasks and native JavaScript timers.

`config` accepts a configuration object or a path to `fireemu.toml`, `fireemu.json` or `firebase.json`. TOML is parsed by the same native loader as the CLI (including case-insensitive `.toml` extensions); keep the npm helper and native binary at the same version. Canonical resource paths remain relative to `cwd`, while `firebaseJson` is relative to the configuration file and its resource paths are relative to that Firebase file. You can reuse `fireemu init` output directly: `createTestWorld({ cwd: process.cwd(), config: 'fireemu.toml' })`. In v0.23.0 the helper accepts only JSON files or objects; when staying on that release, keep JSON as the single configuration source and pass its path explicitly rather than maintaining a TOML copy.

`firebaseJson`, `functionsSource`, `cwd`, `import`, `projectId`, `clockStart`, `seed`, `services` and `clock` select the initial inputs. `binaryPath` can select a development binary. Input files and linked Functions dependencies are copied before readiness; later caller changes do not affect reset. This has an upfront disk/time cost for large dependency graphs. Do not put a world's temporary directory inside its Functions source.

Configured Functions also snapshot and relocate `NODE_PATH` search directories. If global dependency roots are unused by the codebase, select `env: { ...process.env, NODE_PATH: '' }` to exclude them from the snapshot. Worlds without configured Functions clear this extra search path. The helper supplies its own `FIREBASE_CONFIG` and emulator routes, including to SDK default-app initialization; inherited configuration and child environment overrides cannot redirect them to another world.

`world.environment` is the immutable environment for SDK children. `world.run(command, argv, options)` launches a tracked child with the world's project and emulator hosts, without changing `process.env` in the test runner. It returns `{code, signal, stdout, stderr}` and rejects on failure, cancellation or retirement of its generation. SDK instances in the parent process must use named apps and explicitly connect to `world.endpoints`; they remain caller-owned. The helper cannot redirect a parent's cached default Admin SDK app.

`world.reset()` stops the old daemon and tracked command trees, discards all generation state and starts from the creation snapshot. It returns after readiness, with new `generation`, `endpoints`, `uiUrl` and `environment`. Clients using old endpoints must reconnect. Do not cache these getters across reset. A plain session reset has the existing narrower behavior and does not recreate a world.

`world.dispose()` joins process retirement and removes its private files; repeat calls are safe. `withTestWorld` also disposes when the callback throws. Functions process groups on Unix have an independent lifetime guardian, so forced daemon retirement can clean up a runner blocked in synchronous user code. Windows commands and Functions are owned through native Job Objects. Cleanup deadlines remain native. An explicit error reports a process tree that cannot close after escalation.

A retirement error still attempts to stop every owned daemon and retains unresolved cleanup handles for another `dispose()` attempt. User-created detached subprocesses that leave an owned Unix process group require caller supervision; the helper reports a held output pipe instead of silently declaring disposal complete.

The authenticated `--ready-file <path>` daemon option publishes endpoint discovery atomically in a private file without overwriting an existing descriptor. It contains a control capability and is withdrawn on graceful shutdown. The helper keeps it inside the private generation directory and removes the directory after forced retirement.

## Inspect a world in the UI

Pass `ui: true` to expose the same world's Firestore, Auth, Storage and Functions through its bundled UI. `world.uiUrl` is the browser entry URL, or `undefined` when UI is disabled. Each enabled world binds its own OS-assigned loopback port, even when project IDs are identical. Configuration-file UI ports do not override this helper option.

```js
import { createInterface } from 'node:readline/promises';
import { createTestWorld } from 'fireemu/testing';

const world = await createTestWorld({ config: 'fireemu.toml', ui: true });
const terminal = createInterface({ input: process.stdin, output: process.stdout });
try {
  console.log(`Inspect this world: ${world.uiUrl}`);
  // Seed data or reproduce the failing request before pausing here.
  await terminal.question('Press Enter after inspecting the world. ');
} finally {
  terminal.close();
  await world.dispose();
}
```

Keep the world alive while inspecting it: `withTestWorld()` disposes immediately when its callback returns or throws. A separate `fireemu up` instance has independent state and cannot inspect this world. UI mutations affect the owning world's live state. `reset()` stops the old UI with its daemon and starts a fresh generation; read `world.uiUrl` again and reopen the page afterward. `dispose()` closes the UI listener along with the owned services and Functions runner.

The CLI equivalent for an automatically assigned UI port is `--ui-port auto`; `--ui-port 0` continues to disable the UI. The readiness descriptor includes `uiUrl` (a browser entry URL, or `null` when disabled). Keep the helper and native binary at the same version.

## Use the shared control client

`fireemu/control` and `world.control()` share URL resolution, bearer authentication and JSON requests. Use API-relative paths such as `sessions/default:awaitIdle` or existing root-relative paths such as `/v1/sessions/default:awaitIdle`; both address the same route. Root-relative health paths such as `/health/ready` also remain supported.

In a command launched by `fireemu exec`:

```js
import { createControlClient } from 'fireemu/control';

// Reads FIREEMU_CONTROL_URL and FIREEMU_CONTROL_TOKEN once at construction.
const control = createControlClient();
await control.request('POST', 'sessions/default:awaitIdle');
```

In a test world:

```js
// Uses the current generation, including after world.reset().
await world.control('POST', 'sessions/default:awaitIdle');
// Existing calls remain supported.
await world.control('POST', '/v1/sessions/default:awaitIdle');
```

For explicit configuration, call `createControlClient({ origin, token })` or `createControlClient({ apiBaseUrl, token })`. Specify only one endpoint field; explicit endpoints require an explicit token. `createControlClient({ env: world.environment })` instead snapshots that environment. A standalone client captures its endpoint and credential at construction: recreate it after a world reset, or use `world.control()` to follow generations automatically. Neither client construction nor requests modify `process.env`.

The client exposes immutable `origin` and `apiBaseUrl` strings. Test-world endpoints expose the same names while retaining the legacy `url` field:

| Value | Meaning | Example |
| --- | --- | --- |
| `control.origin`, `world.endpoints.control.origin` | Origin | `http://127.0.0.1:9099` |
| `control.apiBaseUrl`, `world.endpoints.control.apiBaseUrl` | Versioned API base | `http://127.0.0.1:9099/v1/` |
| `world.endpoints.control.url`, descriptor `controlUrl` | Legacy origin, unchanged | `http://127.0.0.1:9099` |
| `FIREEMU_CONTROL_URL` | Legacy API base, unchanged | `http://127.0.0.1:9099/v1/` |

`request(method, path, body?, { signal }?)` JSON-encodes a supplied body and returns the parsed JSON response, or `undefined` for an empty response. HTTP failures reject with an error carrying `status` and the daemon's error message. Malformed JSON success responses also reject. The default request timeout is 10 seconds; set `requestTimeoutMs` when constructing the client. A per-request `signal` replaces the default timeout signal, so callers supplying one own its deadline. Full request URLs, network-path references and redirects are refused; requests stay on the configured origin. URL-encode dynamic path segments and query values.

Existing raw URL consumers remain compatible. When using `fetch` directly, resolve paths rather than concatenate strings:

```js
const base = process.env.FIREEMU_CONTROL_URL;
const absolute = new URL('/v1/sessions/default:awaitIdle', base);
const relative = new URL('sessions/default:awaitIdle', base);
// Both resolve to http://host:port/v1/sessions/default:awaitIdle.
```

## TOTP enrollment consumes a code

Successful TOTP enrollment consumes the accepted time step. Reusing that code to sign in in the same step returns `auth/invalid-verification-code`; this can be replay prevention rather than clock skew or an incorrect secret. A step at or below the factor's last accepted step remains unusable even if it is inside the allowed clock-skew window. Advancing time backwards does not make it reusable.

For an enrollment-then-login test, pin the world clock, generate the enrollment code at that instant, advance by the enrolled secret's period (usually 30 seconds), then generate a new code at the new instant. Advancing the daemon alone does not advance the parent test process's `Date.now()`.

```js
const start = Date.parse('2026-01-01T00:00:00Z');
await withTestWorld({ services: ['auth'], clockStart: new Date(start).toISOString() }, async world => {
  // Application test helpers; generateTotp must accept an explicit timestamp.
  const { secret, periodSeconds } = await beginTotpEnrollment(world);
  await finishTotpEnrollment(world, generateTotp(secret, start));
  const stepMillis = periodSeconds * 1000;
  await world.clock.advance(stepMillis);
  await signOutAndBeginMfaSignIn(world);
  await finishTotpSignIn(world, generateTotp(secret, start + stepMillis));
});
```

Use the secret's actual period and matching algorithm/digit count. Keep invalid-code responses generic; this recipe does not add externally visible distinctions between an expired, incorrect or reused code.
