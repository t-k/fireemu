import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";

import { spawnSdk } from "./auth-fs-cross/sdk-client.mjs";

/** A fake driver process: the test reads its stdin and writes its stdout. */
function fakeSpawn() {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = [];
  child.kill = (signal) => {
    child.killed.push(signal);
    child.emit("close", null, signal);
  };
  const commands = [];
  child.stdin.on("data", (chunk) => {
    for (const line of String(chunk).split("\n").filter(Boolean)) commands.push(JSON.parse(line));
  });
  const say = (event) => child.stdout.write(`${JSON.stringify(event)}\n`);
  return { spawnImpl: () => child, child, commands, say };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

test("a command resolves with its own result, events are kept in order", async () => {
  const fake = fakeSpawn();
  const sdk = spawnSdk({ mode: "local" }, { spawnImpl: fake.spawnImpl, timeoutMs: 1_000 });
  fake.say({ event: "ready" });
  await sdk.ready();
  const pending = sdk.send("signIn", { email: "a@example.com", password: "p" });
  await tick();
  assert.deepEqual(fake.commands[0], {
    email: "a@example.com",
    password: "p",
    id: "c1",
    op: "signIn",
  });
  fake.say({ event: "auth", uid: "u1" });
  fake.say({ event: "result", id: "other", ok: true });
  fake.say({ event: "result", id: "c1", ok: true, uid: "u1" });
  assert.deepEqual(await pending, { event: "result", id: "c1", ok: true, uid: "u1" });
  assert.deepEqual(
    sdk.events.map(({ event }) => event),
    ["ready", "auth", "result", "result"],
  );
});

test("a wait sees an event that already arrived after its mark, and times out otherwise", async () => {
  const fake = fakeSpawn();
  const sdk = spawnSdk({}, { spawnImpl: fake.spawnImpl, timeoutMs: 1_000 });
  fake.say({ event: "snapshot", name: "l1", docs: [] });
  await tick();
  assert.equal((await sdk.waitFor((e) => e.event === "snapshot")).name, "l1");
  await assert.rejects(
    sdk.waitFor((e) => e.event === "snapshot", { from: 1, timeout: 20 }),
    /timed out/,
  );
});

test("an exit fails every wait, and close kills a driver that does not stop", async () => {
  const fake = fakeSpawn();
  const sdk = spawnSdk({}, { spawnImpl: fake.spawnImpl, timeoutMs: 1_000 });
  const waiting = sdk.waitFor((e) => e.event === "never");
  fake.child.emit("close", 1, null);
  await assert.rejects(waiting, /exited/);

  const stuck = fakeSpawn();
  const other = spawnSdk({}, { spawnImpl: stuck.spawnImpl, timeoutMs: 50 });
  await other.close();
  assert.deepEqual(stuck.child.killed, ["SIGKILL"]);
});

test("a client runs the Node driver unless told to run the browser driver", async () => {
  const { DRIVERS } = await import("./auth-fs-cross/sdk-client.mjs");
  const seen = [];
  const spawnImpl = (command, args, options) => {
    seen.push([args[0], JSON.parse(options.env.AFC_SDK_CONFIG)]);
    return fakeSpawn().spawnImpl();
  };
  spawnSdk({ mode: "local" }, { spawnImpl });
  spawnSdk({ mode: "local", wireCap: 7 }, { spawnImpl, driver: DRIVERS.browser });
  assert.deepEqual(
    seen.map(([driver, config]) => [driver.split("/").at(-1), config.wireCap ?? null]),
    [
      ["sdk-driver.mjs", null],
      ["browser-driver.mjs", 7],
    ],
  );
});

test("the Node driver ends when its parent's pipe closes", async () => {
  const { spawn } = await import("node:child_process");
  const { DRIVERS } = await import("./auth-fs-cross/sdk-client.mjs");
  const config = {
    mode: "local",
    web: { apiKey: "fake-api-key", projectId: "demo-afc", authDomain: "localhost" },
    authEmulator: "http://127.0.0.1:9",
    firestoreEmulator: { host: "127.0.0.1", port: 9 },
    wireCap: 5,
  };
  const child = spawn(process.execPath, [DRIVERS["node-sdk"]], {
    env: { ...process.env, AFC_SDK_CONFIG: JSON.stringify(config) },
    stdio: ["pipe", "pipe", "ignore"],
  });
  await new Promise((resolve) => child.stdout.once("data", resolve));
  // A listener on an unreachable emulator keeps retrying: only the pipe's close ends the driver.
  child.stdin.write(
    `${JSON.stringify({ id: "l", op: "listen", name: "d", path: "afc2-owned/x" })}\n`,
  );
  await new Promise((resolve) => setTimeout(resolve, 500));
  const exited = new Promise((resolve) => child.once("exit", (code) => resolve(code)));
  child.stdin.end();
  const code = await Promise.race([
    exited,
    new Promise((r) => setTimeout(() => r("timeout"), 10_000)),
  ]);
  if (code === "timeout") child.kill("SIGKILL");
  assert.equal(code, 0);
});
