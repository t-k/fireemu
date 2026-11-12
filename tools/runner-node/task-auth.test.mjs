import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  hasTaskIdentityToken,
  inTaskAuthScope,
  installTaskAuthEnvironment,
  runWithTaskAuth,
} from "./task-auth.mjs";

const target = () => ({ env: { FUNCTIONS_EMULATOR: "true", OTHER: "1" } });

test("only a Bearer of three segments is an identity token", () => {
  assert.equal(hasTaskIdentityToken({ authorization: "Bearer a.b.c" }), true);
  assert.equal(hasTaskIdentityToken({ authorization: "Bearer a.b." }), true, "an unsigned token has an empty third segment");
  for (const authorization of ["Bearer a.b", "Bearer a.b.c.d", "bearer a.b.c", "Basic a.b.c", "Bearer .b.c", "Bearer a..c", "Bearer a.b.c d", "a.b.c", ""]) {
    assert.equal(hasTaskIdentityToken({ authorization }), false, authorization);
  }
  assert.equal(hasTaskIdentityToken({}), false);
  assert.equal(hasTaskIdentityToken(undefined), false);
  assert.equal(hasTaskIdentityToken({ authorization: ["Bearer a.b.c"] }), false);
});

test("the emulator flag is hidden only inside a task auth scope", async () => {
  const fake = target();
  installTaskAuthEnvironment(fake);
  assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
  assert.equal(inTaskAuthScope(), false);
  const inside = await runWithTaskAuth(async () => {
    await new Promise((resolve) => setTimeout(resolve, 1));
    return {
      value: fake.env.FUNCTIONS_EMULATOR,
      has: "FUNCTIONS_EMULATOR" in fake.env,
      keys: Object.keys(fake.env),
      other: fake.env.OTHER,
      scoped: inTaskAuthScope(),
    };
  });
  assert.deepEqual(inside, { value: undefined, has: false, keys: ["OTHER"], other: "1", scoped: true });
  assert.equal(fake.env.FUNCTIONS_EMULATOR, "true");
  assert.ok("FUNCTIONS_EMULATOR" in fake.env);
});

test("another function in the same process still sees the flag while a task dispatch runs", async () => {
  const fake = target();
  installTaskAuthEnvironment(fake);
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const task = runWithTaskAuth(async () => {
    await gate;
    return fake.env.FUNCTIONS_EMULATOR;
  });
  const sibling = await (async () => {
    await new Promise((resolve) => setTimeout(resolve, 1));
    return fake.env.FUNCTIONS_EMULATOR;
  })();
  release();
  assert.equal(sibling, "true");
  assert.equal(await task, undefined);
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
