import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { constants, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const launcher =
  process.env.FIREEMU_TEST_LAUNCHER ??
  fileURLToPath(new URL("../fireemu/bin/fireemu.mjs", import.meta.url));
const unix = process.platform !== "win32";
const timeout = 10_000;

// Polling is intentionally sequential: each observation determines whether to wait again.
/* eslint-disable no-await-in-loop */
async function until(predicate, label) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await delay(20);
  }
  assert.fail(`timed out waiting for ${label}`);
}

/* eslint-enable no-await-in-loop */

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
}

// Only signal a PID after matching both its executable identity and unique arguments.
async function stopOwned(pid, token) {
  if (!pid || !alive(pid)) return;
  const result = spawnSync("ps", ["-p", String(pid), "-o", "comm=", "-o", "args="], {
    encoding: "utf8",
  });
  if (result.status !== 0) return;
  assert.match(result.stdout, /node|fireemu/);
  assert.ok(result.stdout.includes(token), `refusing to stop unowned PID ${pid}`);
  process.kill(pid, "SIGTERM");
  await delay(100);
  if (alive(pid)) {
    const current = spawnSync("ps", ["-p", String(pid), "-o", "comm=", "-o", "args="], {
      encoding: "utf8",
    });
    assert.ok(current.stdout.includes(token) && /node|fireemu/.test(current.stdout));
    process.kill(pid, "SIGKILL");
  }
}

function start(t, args, env = {}, cwd) {
  const child = spawn(process.execPath, [launcher, ...args], {
    env: { ...process.env, ...env },
    cwd,
    detached: unix,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let result;
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      result = { code, signal };
      resolve(result);
    });
  });
  t.after(async () => {
    if (!result) {
      child.stdin.end("finish\n");
      child.kill("SIGTERM");
      await delay(100);
      if (!result) {
        if (unix) await stopOwned(child.pid, launcher);
        else child.kill("SIGKILL");
      }
    }
    await exited;
    child.stdin.destroy();
    child.stdout.destroy();
    child.stderr.destroy();
  });
  return { child, exited, stdout: () => stdout, stderr: () => stderr, result: () => result };
}

for (const signal of ["SIGTERM", "SIGINT"]) {
  for (const target of ["launcher", "process group"]) {
    test(
      `${signal} to ${target} waits for the owned child's cleanup`,
      { skip: !unix },
      async (t) => {
        const token = `fireemu-signal-${process.pid}-${signal}-${target}`;
        // Run a real Node executable through the supported binary override. Its stdin handshake
        // prevents shutdown completion until the test explicitly releases it.
        const script = `
        process.on('SIGTERM', () => console.log('received:SIGTERM'));
        process.on('SIGINT', () => console.log('received:SIGINT'));
        process.stdin.resume();
        process.stdin.on('data', () => process.exit(7));
        console.log('ready:' + process.pid);
      `;
        const run = start(t, ["-e", script, token], { FIREEMU_BINARY_PATH: process.execPath });
        let nativePid;
        t.after(async () => {
          await stopOwned(nativePid, token);
          if (nativePid) await until(() => !alive(nativePid), "owned child cleanup");
        });
        const ready = await until(() => /ready:(\d+)/.exec(run.stdout()), "child readiness");
        nativePid = Number(ready[1]);
        const pid = target === "launcher" ? run.child.pid : -run.child.pid;
        process.kill(pid, signal);
        await until(
          () => run.stdout().includes(`received:${signal}`) || run.result(),
          "signal delivery",
        );
        assert.ok(run.stdout().includes(`received:${signal}`), "child must receive the signal");
        assert.equal(run.result(), undefined, "launcher must wait for child cleanup");
        // A second signal must not restore Node's default termination while the child is busy.
        process.kill(pid, signal);
        await delay(100);
        assert.equal(run.result(), undefined, "launcher must also wait after repeated signals");
        assert.ok(alive(nativePid));
        run.child.stdin.end("finish\n");
        await until(() => run.result(), "launcher exit");
        assert.deepEqual(await run.exited, { code: 7, signal: null });
        assert.equal(alive(nativePid), false);
      },
    );
  }
}

test("the launcher preserves arguments, environment, streams and normal exit status", async (t) => {
  const run = start(
    t,
    [
      "-e",
      `
    process.stdin.on('data', data => {
      console.log(JSON.stringify([process.argv[1], process.env.FIREEMU_TEST_VALUE, data.toString()]));
      console.error('child stderr');
      process.exit(3);
    });
  `,
      "argument with spaces",
    ],
    { FIREEMU_BINARY_PATH: process.execPath, FIREEMU_TEST_VALUE: "value" },
  );
  run.child.stdin.end("input");
  await until(() => run.result(), "normal exit");
  assert.deepEqual(await run.exited, { code: 3, signal: null });
  await until(
    () => run.stdout().includes("input") && run.stderr().includes("child stderr"),
    "streams",
  );
  assert.deepEqual(JSON.parse(run.stdout()), ["argument with spaces", "value", "input"]);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  test(`native ${signal} death preserves shell-style status`, { skip: !unix }, async (t) => {
    const run = start(t, ["-e", `process.kill(process.pid, '${signal}')`], {
      FIREEMU_BINARY_PATH: process.execPath,
    });
    await until(() => run.result(), "signal exit");
    assert.deepEqual(await run.exited, { code: 128 + constants.signals[signal], signal: null });
  });
}

test("a missing executable keeps the actionable startup error", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "fireemu-missing-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const missing = join(dir, "missing");
  const run = start(t, [], { FIREEMU_BINARY_PATH: missing });
  await until(() => run.result(), "startup failure");
  assert.deepEqual(await run.exited, { code: 1, signal: null });
  await until(
    () => run.stderr().includes("does not exist (from FIREEMU_BINARY_PATH)"),
    "startup diagnostic",
  );
});

test("a non-executable path reports a startup failure without hanging", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "fireemu-not-executable-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const run = start(t, [], { FIREEMU_BINARY_PATH: dir });
  await until(() => run.result(), "non-executable startup failure");
  assert.deepEqual(await run.exited, { code: 1, signal: null });
  await until(
    () => run.stderr().includes("fireemu could not start the daemon:"),
    "startup diagnostic",
  );
  assert.ok(run.stderr().includes(dir));
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  test(
    `installed native emulator stops serving after launcher ${signal}`,
    {
      skip: !unix || !process.env.FIREEMU_TEST_LAUNCHER,
    },
    async (t) => {
      const dir = mkdtempSync(join(tmpdir(), "fireemu-native-signal-"));
      const project = `demo-npm-signal-${process.pid}-${signal.toLowerCase()}`;
      const exported = join(dir, "export");
      const args = ["up", "--only", "auth", "--project", project, "--export-on-exit", exported];
      for (const name of [
        "http",
        "firestore",
        "storage",
        "functions",
        "hub",
        "ui",
        "logging",
        "eventarc",
        "tasks",
        "pubsub",
      ]) {
        args.push(`--${name}-port`, "0");
      }
      const run = start(t, args, { FIREEMU_BINARY_PATH: "" }, dir);
      let nativePid;
      t.after(async () => {
        await stopOwned(nativePid, project);
        if (nativePid) await until(() => !alive(nativePid), "native cleanup");
        rmSync(dir, { recursive: true, force: true });
      });
      nativePid = await until(() => {
        const census = spawnSync("ps", ["-axo", "pid=,ppid=,comm=,args="], { encoding: "utf8" });
        const line = census.stdout.split("\n").find((entry) => {
          const fields = entry.trim().split(/\s+/);
          return (
            Number(fields[1]) === run.child.pid &&
            entry.includes(project) &&
            entry.includes("fireemu")
          );
        });
        return line && Number(line.trim().split(/\s+/)[0]);
      }, "native PID");
      const address = await until(() => {
        assert.equal(run.result(), undefined, `native startup failed: ${run.stderr()}`);
        return /FIREBASE_AUTH_EMULATOR_HOST=([^\s]+)/.exec(run.stdout());
      }, "Auth listener");
      const url = `http://${address[1]}/`;
      await until(async () => {
        try {
          return (await fetch(url, { signal: AbortSignal.timeout(500) })).status === 200;
        } catch {
          return false;
        }
      }, "Hub readiness");
      run.child.kill(signal);
      await until(() => run.result(), "launcher shutdown");
      assert.deepEqual(await run.exited, { code: 0, signal: null });
      assert.equal(alive(nativePid), false, "native PID must not survive launcher shutdown");
      assert.ok(
        existsSync(join(exported, "firebase-export-metadata.json")),
        "export completes before launcher exit",
      );
      await assert.rejects(fetch(url, { signal: AbortSignal.timeout(500) }));
    },
  );
}
