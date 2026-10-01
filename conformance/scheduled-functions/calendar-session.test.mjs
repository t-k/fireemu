import {
  calendarPortctlInvocation,
  createCalendarSignalRelay,
  readOwnCalendarClaims,
} from "./calendar-run-local.mjs";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, writeFile, readFile, rm, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  sessionArguments,
  superviseCalendarProcess,
  prepareCalendarSession,
  calendarOwnedBranches,
} from "./calendar-session.mjs";

const options = {
  configPath: "/private/calendar/fireemu.json",
  fixturePath: "/private/calendar/fixture",
  childPath: "/private/calendar/child.mjs",
  inputPath: "/private/calendar/input.json",
  port: 12345,
};

test("calendar session argv selects only local functions with an exclusively claimed control port", () => {
  const args = sessionArguments(options);
  assert.equal(args[0], "exec");
  assert.equal(args[args.indexOf("--project") + 1], "demo-scheduled-calendar");
  assert.equal(args[args.indexOf("--only") + 1], "functions");
  assert.equal(args[args.indexOf("--http-port") + 1], "12345");
  assert.equal(args[args.indexOf("--config") + 1], options.configPath);
  assert.equal(args[args.indexOf("--functions") + 1], options.fixturePath);
  for (const service of [
    "functions",
    "firestore",
    "storage",
    "eventarc",
    "tasks",
    "pubsub",
    "ui",
    "hub",
    "logging",
  ])
    assert.equal(args[args.indexOf("--" + service + "-port") + 1], "0");
  assert.deepEqual(args.slice(args.indexOf("--") + 1), [
    process.execPath,
    options.childPath,
    "--calendar-child",
    options.inputPath,
  ]);
  assert.ok(!args.some((arg) => /token|googleapis|fireemu-oracle/.test(arg)));
});

test("calendar session refuses missing or unclaimed control-port values before process startup", () => {
  for (const port of [0, -1, 65536, "12345", undefined, NaN])
    assert.throws(() => sessionArguments({ ...options, port }), /claimed.*port/);
});

function lifecycle({ timeout = false, reused = false } = {}) {
  const identity = (pid, ppid, comm = "node") => ({
    pid,
    ppid,
    uid: 501,
    started: "Thu Oct 1 00:00:00 2026",
    comm,
    args: comm + " own-calendar-run",
    pgid: pid,
  });
  const root = identity(100, 50),
    daemon = identity(200, 100, "fireemu"),
    runner = identity(300, 200),
    foreign = identity(900, 50);
  let now = 0,
    done = !timeout,
    survivors = [root, ...(timeout ? [daemon] : []), runner, foreign];
  const signals = [];
  return {
    root,
    ownershipComplete: () => true,
    child: { pid: daemon.pid, state: () => ({ done, code: done ? 0 : null }) },
    initial: [root, daemon, runner, foreign],
    snapshot: async () =>
      survivors.map((value) =>
        reused && value.pid === 300 ? { ...value, args: "foreign session" } : value,
      ),
    signal: async (pid, signal) => {
      signals.push({ pid, signal });
      survivors = survivors.filter((value) => value.pid !== pid);
      if (pid === daemon.pid) done = true;
    },
    sleep: async (ms) => {
      now += ms;
    },
    clock: () => now,
    deadlineMs: 1000,
    graceMs: 100,
    pollMs: 50,
    signals,
  };
}

test("calendar supervisor cleans a retained owned runner after the daemon leader has exited", async () => {
  const f = lifecycle();
  const result = await superviseCalendarProcess(f);
  assert.equal(result.cleanupVerified, true);
  assert.deepEqual(f.signals, [{ pid: 300, signal: "SIGTERM" }]);
});

test("calendar supervisor timeout targets the verified daemon first and preserves foreign processes", async () => {
  const f = lifecycle({ timeout: true });
  const result = await superviseCalendarProcess(f);
  assert.equal(result.timedOut, true);
  assert.equal(result.cleanupVerified, true);
  assert.equal(f.signals[0].pid, 200);
  assert.ok(!f.signals.some((value) => value.pid === 100 || value.pid === 900));
});

test("calendar supervisor does not signal an identity-reused PID", async () => {
  const f = lifecycle({ reused: true });
  const result = await superviseCalendarProcess(f);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.groupDebt, true);
  assert.deepEqual(f.signals, []);
});

test("calendar supervisor escalates only an owned TERM-ignoring survivor after bounded grace", async () => {
  const f = lifecycle(),
    originalSignal = f.signal;
  f.signal = async (pid, signal) => {
    if (signal === "SIGTERM") f.signals.push({ pid, signal });
    else await originalSignal(pid, signal);
  };
  const result = await superviseCalendarProcess(f);
  assert.equal(result.cleanupVerified, true);
  assert.deepEqual(f.signals, [
    { pid: 300, signal: "SIGTERM" },
    { pid: 300, signal: "SIGKILL" },
  ]);
});

test("calendar supervisor cancellation follows the daemon-first cleanup path", async () => {
  const f = lifecycle({ timeout: true });
  const result = await superviseCalendarProcess({ ...f, stopping: () => true });
  assert.equal(result.cancelled, true);
  assert.equal(result.timedOut, false);
  assert.equal(result.cleanupVerified, true);
  assert.equal(f.signals[0].pid, 200);
});

test("calendar supervisor retries a transient inventory failure and never claims unreadable cleanup", async () => {
  const f = lifecycle({ timeout: true }),
    originalSnapshot = f.snapshot;
  let reads = 0;
  f.snapshot = async () => {
    if (++reads === 1) throw new Error("fake inventory failure");
    return originalSnapshot();
  };
  let result;
  await assert.doesNotReject(async () => {
    result = await superviseCalendarProcess(f);
  });
  assert.equal(result.inventoryFailures, 1);
  assert.equal(result.cleanupVerified, true);
  assert.equal(f.signals[0].pid, 200);
  const unreadable = lifecycle({ timeout: true });
  unreadable.snapshot = async () => {
    throw new Error("fake inventory failure");
  };
  await assert.doesNotReject(async () => {
    result = await superviseCalendarProcess(unreadable);
  });
  assert.equal(result.cleanupVerified, false);
  assert.deepEqual(unreadable.signals, []);
});

test("calendar session preparation pins binary/runner and exact virtual anchor in a private shared receipt fixture", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "calendar-local-prepare-"));
  t.after(() => rm(root, { recursive: true }));
  for (const [name, version] of [
    ["firebase-functions", "7.3.2"],
    ["firebase-tools", "15.28.2"],
  ]) {
    const path = join(root, "conformance/node_modules", name);
    await mkdir(path, { recursive: true });
    await writeFile(join(path, "package.json"), JSON.stringify({ version }));
  }
  const binary = join(root, "fireemu"),
    runner = join(root, "runner.mjs");
  await writeFile(binary, "fake binary");
  await writeFile(runner, "fake runner");
  const sha = (value) => createHash("sha256").update(value).digest("hex");
  const config = {
    root,
    binary,
    runner,
    binarySha256: sha("fake binary"),
    runnerSha256: sha("fake runner"),
    sourceCommit: "a".repeat(40),
    anchor: "2026-09-30T09:00:01.123456789Z",
    input: {
      caseId: "c01",
      schedule: "* * * * *",
      timeZone: "UTC",
      scheduleTime: "2026-09-30T09:01:00Z",
    },
    childPath: "/private/calendar/child.mjs",
  };
  const prepared = await prepareCalendarSession(config);
  assert.ok(prepared.directory.startsWith(join(root, "conformance/.runs") + "/"));
  assert.equal((await lstat(prepared.directory)).mode & 0o077, 0);
  const runtime = JSON.parse(await readFile(prepared.configPath, "utf8"));
  assert.equal(runtime.schemaVersion, 1);
  assert.equal(runtime.profile, "strict");
  assert.equal(runtime.daemon.clockStart, config.anchor);
  const fixture = await readFile(join(prepared.fixturePath, "index.cjs"), "utf8");
  assert.ok(fixture.includes("exports.calendarProbe"));
  assert.ok(fixture.includes("exports.calendarReceipt"));
  assert.equal(prepared.identity.binarySha256, config.binarySha256);
  assert.equal(prepared.identity.runnerSha256, config.runnerSha256);
  await assert.rejects(
    prepareCalendarSession({ ...config, binarySha256: "f".repeat(64) }),
    /binary.*binding/,
  );
});

test("post-spawn observation failure is retried inside guarded supervision with no initial inventory", async () => {
  const f = lifecycle({ timeout: true }),
    snapshot = f.snapshot;
  let reads = 0;
  delete f.initial;
  f.snapshot = async () => {
    if (++reads === 1) throw new Error("first post-spawn snapshot failed");
    return snapshot();
  };
  let result;
  await assert.doesNotReject(async () => {
    result = await superviseCalendarProcess(f);
  });
  assert.equal(result.inventoryFailures, 1);
  assert.equal(result.cleanupVerified, true);
  assert.equal(f.signals[0].pid, 200);
});

test("calendar supervisor never adopts an unrelated subprocess of its caller", async () => {
  const f = lifecycle(),
    original = f.snapshot;
  const sibling = { ...f.root, pid: 950, ppid: f.root.pid, args: "unrelated caller subprocess" };
  f.initial.push(sibling);
  f.snapshot = async () => [...(await original()), sibling];
  const result = await superviseCalendarProcess(f);
  assert.equal(result.cleanupVerified, true);
  assert.ok(!result.ownedProcesses.some((row) => row.pid === 950));
  assert.ok(!f.signals.some((row) => row.pid === 950));
});
test("calendar supervisor retains acquisition debt for an exited never-observed leader", async () => {
  const f = lifecycle();
  delete f.initial;
  const result = await superviseCalendarProcess(f);
  assert.equal(result.childAcquired, false);
  assert.equal(result.cleanupVerified, false);
  assert.ok(!f.signals.some((row) => row.pid === 300));
});

test("own claim query reads one exact service without probing or mutating foreign entries", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "calendar-claim-read-"));
  t.after(() => rm(directory, { recursive: true }));
  const database = join(directory, "registry.sqlite3"),
    script = join(directory, "portctl.py");
  await writeFile(
    script,
    "def list_rows(*args, **kwargs): raise Exception('foreign endpoint probing forbidden')\n",
  );
  execFileSync("python3", [
    "-c",
    "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE reservations (service TEXT, host TEXT, port INTEGER, pid INTEGER, token TEXT)'); c.executemany('INSERT INTO reservations VALUES (?,?,?,?,?)',[('own-service','127.0.0.1',12001,201,'fake-own-token'),('foreign-service','production.invalid',443,999,'fake-foreign-token')]); c.commit(); c.close()",
    database,
  ]);
  const before = await readFile(database);
  const result = await readOwnCalendarClaims({
    script,
    cwd: directory,
    service: "own-service",
    database,
  });
  assert.equal(result.claims.length, 1);
  assert.equal(result.claims[0].service, "own-service");
  assert.ok(!JSON.stringify(result).includes("foreign"));
  assert.deepEqual(await readFile(database), before);
});

test("missing complete acquisition coverage retains debt even after the immediate child was observed", async () => {
  const f = lifecycle();
  f.ownershipComplete = () => false;
  const result = await superviseCalendarProcess(f);
  assert.equal(result.childAcquired, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.trackedAbsenceVerified, true);
});
test("undefined child PID is not absence proof without an explicit terminal spawn failure", async () => {
  const f = lifecycle();
  f.child = { pid: undefined, state: () => ({ done: true, code: -1 }) };
  const result = await superviseCalendarProcess(f);
  assert.equal(result.cleanupVerified, false);
});

test("calendar observation handshake requires the standalone exec child, not its argv inside the daemon", () => {
  const plan = {
    runner: "/private/runner.mjs",
    fixturePath: "/private/fixture",
    childPath: "/private/calendar-child.mjs",
    inputPath: "/private/input.json",
    node: "/private/node",
  };
  const daemon = {
      pid: 200,
      args: "/private/fireemu exec -- /private/node /private/calendar-child.mjs --calendar-child /private/input.json",
    },
    runner = {
      pid: 300,
      args: "/private/node /private/runner.mjs --source /private/fixture --codebase default",
    };
  assert.equal(calendarOwnedBranches([daemon, runner], plan).child, undefined);
  const child = {
    pid: 400,
    args: "/private/node /private/calendar-child.mjs --calendar-child /private/input.json",
  };
  assert.equal(calendarOwnedBranches([daemon, runner, child], plan).child.pid, 400);
});

test("an exited unacquired child PID cannot be acquired from a later caller subprocess", async () => {
  const f = lifecycle();
  delete f.initial;
  const replacement = {
    ...f.root,
    pid: 200,
    ppid: 100,
    args: "foreign replacement",
    started: "Thu Oct 1 00:00:05 2026",
  };
  f.snapshot = async () => [f.root, replacement];
  const result = await superviseCalendarProcess(f);
  assert.equal(result.childAcquired, false);
  assert.equal(result.cleanupVerified, false);
  assert.deepEqual(f.signals, []);
});

test("calendar cancellation relay verifies the original inner identity before signaling", async () => {
  const wrapper = { ...lifecycle().root, pid: 200 },
    inner = {
      ...wrapper,
      pid: 300,
      ppid: 200,
      args: "node launcher.mjs --calendar-supervisor input.json",
    };
  for (const change of [
    null,
    { uid: 999 },
    { started: "Thu Oct 1 00:00:05 2026" },
    { comm: "foreign" },
    { args: inner.args + " extra" },
  ]) {
    const signals = [],
      relay = createCalendarSignalRelay({
        wrapperPid: wrapper.pid,
        innerArgs: inner.args,
        snapshot: async () => [wrapper, { ...inner, ...change }],
        kill: (pid, kind) => signals.push({ pid, kind }),
      });
    relay.observe([wrapper, inner]);
    if (change) {
      await assert.rejects(relay.signal(wrapper.pid, "SIGTERM"), /identity/);
      assert.deepEqual(signals, []);
      assert.equal(relay.debt(), true);
    } else {
      await relay.signal(wrapper.pid, "SIGTERM");
      assert.deepEqual(signals, [{ pid: inner.pid, kind: "SIGTERM" }]);
      assert.equal(relay.debt(), false);
    }
  }
});

test("calendar cancellation relay refuses an inner identity that was never acquired", async () => {
  const signals = [],
    relay = createCalendarSignalRelay({
      wrapperPid: 200,
      innerArgs: "node launcher.mjs --calendar-supervisor input.json",
      snapshot: async () => [
        { pid: 300, ppid: 200, args: "node launcher.mjs --calendar-supervisor input.json" },
      ],
      kill: (pid, kind) => signals.push({ pid, kind }),
    });
  await assert.rejects(relay.signal(200, "SIGTERM"), /identity/);
  assert.deepEqual(signals, []);
  assert.equal(relay.debt(), true);
});

test("calendar cancellation relay retains identity debt when fresh inventory is unreadable", async () => {
  const inner = { ...lifecycle().root, pid: 300, ppid: 200 },
    signals = [],
    relay = createCalendarSignalRelay({
      wrapperPid: 200,
      innerArgs: inner.args,
      snapshot: async () => {
        throw new Error("unreadable identity inventory");
      },
      kill: (pid, kind) => signals.push({ pid, kind }),
    });
  relay.observe([inner]);
  await assert.rejects(relay.signal(200, "SIGTERM"), /inventory/);
  assert.equal(relay.debt(), true);
  assert.deepEqual(signals, []);
});

test("calendar port acquisition and own query require one explicit private database", async () => {
  const prepared = { directory: "/private/calendar/unique-session" },
    invocation = calendarPortctlInvocation({
      prepared,
      script: "/private/portctl.py",
      cwd: "/private/conformance",
      service: "lane8-calendar-unique",
      launcherPath: "/private/calendar/unique-session/launcher.json",
    });
  assert.equal(invocation.database, prepared.directory + "/ports.sqlite3");
  assert.equal(invocation.args[invocation.args.indexOf("--db") + 1], invocation.database);
  assert.ok(invocation.args.indexOf("--db") < invocation.args.indexOf("run"));
  await assert.rejects(
    readOwnCalendarClaims({ service: "lane8-calendar-unique" }),
    /private database/,
  );
});
