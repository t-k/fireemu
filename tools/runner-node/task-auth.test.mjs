import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { TASK_IDENTITY_HEADER, takeTaskIdentityMarker, installTaskAuthEnvironment, runWithTaskAuth } from "./task-auth.mjs";

const target = () => ({ env: { FUNCTIONS_EMULATOR: "true", OTHER: "1" } });

test("takes only the exact marker and removes all raw copies", () => {
  for (const value of ["1", "true", "1, 1", "", undefined]) {
    const req = { headers: { [TASK_IDENTITY_HEADER]: value }, rawHeaders: ["Other", "x", "X-Fireemu-Task-Identity", "1", TASK_IDENTITY_HEADER, "1"] };
    assert.equal(takeTaskIdentityMarker(req), value === "1");
    assert.equal(TASK_IDENTITY_HEADER in req.headers, false);
    assert.deepEqual(req.rawHeaders, ["Other", "x"]);
  }
  for (const rawHeaders of [undefined, null, "bad"]) {
    assert.equal(takeTaskIdentityMarker({ headers: {}, rawHeaders }), false);
  }
});

test("only the first get is hidden, including across awaits and timers", async () => {
  const fake = target();
  installTaskAuthEnvironment(fake);
  assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
  await runWithTaskAuth(async () => {
    assert.equal("FUNCTIONS_EMULATOR" in fake.env, true);
    assert.ok(Object.keys(fake.env).includes("FUNCTIONS_EMULATOR"));
    assert.equal(Object.getOwnPropertyDescriptor(fake.env, "FUNCTIONS_EMULATOR").value, "true");
    assert.equal(fake.env.OTHER, "1");
    assert.equal(fake.env[Symbol.toStringTag], undefined);
    assert.equal(fake.env.FUNCTIONS_EMULATOR, undefined);
    assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
    await Promise.resolve();
    assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
    const timer = await new Promise(resolve => setTimeout(() => resolve(fake.env.FUNCTIONS_EMULATOR), 1));
    assert.equal(timer, "true");
  });
  assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
});

test("concurrent scopes consume independent reads while a sibling sees the flag", async () => {
  const fake = target();
  installTaskAuthEnvironment(fake);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const run = () => runWithTaskAuth(async () => {
    await gate;
    return [fake.env.FUNCTIONS_EMULATOR, fake.env.FUNCTIONS_EMULATOR];
  });
  const a = run(), b = run();
  assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
  release();
  assert.deepEqual(await Promise.all([a, b]), [[undefined, "true"], [undefined, "true"]]);
  assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
});

test("writes and deletes go to the real environment, and installing twice changes nothing", () => {
  const fake = target();
  const real = fake.env;
  installTaskAuthEnvironment(fake);
  const view = fake.env;
  installTaskAuthEnvironment(fake);
  assert.equal(fake.env, view);
  fake.env.NEW = "x";
  assert.equal(real.NEW, "x");
  delete fake.env.NEW;
  assert.equal("NEW" in real, false);
  fake.env.FUNCTIONS_EMULATOR = "false";
  assert.equal(real.FUNCTIONS_EMULATOR, "false");
});

test("on the real process.env writes, deletes and children still work, and the flag is hidden only in a scope", () => {
  const script = `
    import("${new URL("./task-auth.mjs", import.meta.url).href}").then(async (m) => {
      process.env.FUNCTIONS_EMULATOR = "true";
      m.installTaskAuthEnvironment();
      process.env.FUNCTION_TARGET = "t";
      process.env.K_SERVICE = "s";
      delete process.env.FUNCTION_TARGET;
      Object.defineProperty(process.env, "VIA_DEFINE", { value: "d", enumerable: true, configurable: true, writable: true });
      const outside = process.env.FUNCTIONS_EMULATOR;
      const inside = await m.runWithTaskAuth(async () => process.env.FUNCTIONS_EMULATOR);
      const child = (await import("node:child_process")).spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.env.K_SERVICE) + process.env.VIA_DEFINE)"], { encoding: "utf8" });
      console.log(JSON.stringify({ outside, inside: inside ?? null, target: process.env.FUNCTION_TARGET ?? null, child: child.stdout }));
    });`;
  const run = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { outside: "true", inside: null, target: null, child: "sd" });
});
