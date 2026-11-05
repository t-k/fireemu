import { test } from "node:test";
import assert from "node:assert/strict";
import { createSdk } from "./breadth-sdk.mjs";

test("signs in once and sends each requested write once", async () => {
  const calls = [];
  const page = {
    evaluate: async (_fn, arg) => {
      calls.push(arg);
      return { outcome: "ok" };
    },
  };
  const sdk = createSdk({
    page,
    config: {},
    email: "user@example.test",
    password: "password",
    uid: "uid",
    nonce: "nonce",
  });
  await sdk.signIn();
  for (const id of ["w10", "w11", "w12"]) assert.equal((await sdk.write(id)).outcome, "ok");
  assert.deepEqual(
    calls.map((x) => x.action),
    ["signIn", "w10", "w11", "w12"],
  );
});

test("a rejected write stops the client without retry", async () => {
  const calls = [];
  const page = {
    evaluate: async (_fn, arg) => {
      calls.push(arg.action);
      if (arg.action === "w11") throw Error("rejected");
      return { outcome: "ok" };
    },
  };
  const sdk = createSdk({
    page,
    config: {},
    email: "user@example.test",
    password: "password",
    uid: "uid",
    nonce: "nonce",
  });
  await sdk.signIn();
  await sdk.write("w10");
  await assert.rejects(sdk.write("w11"));
  await assert.rejects(sdk.write("w12"));
  assert.deepEqual(calls, ["signIn", "w10", "w11"]);
});

test("page guards the app and current user before every write", async () => {
  const { readFile } = await import("node:fs/promises");
  const vm = await import("node:vm");
  let source = await readFile(new URL("./breadth-sdk-page.js", import.meta.url), "utf8");
  source = source.replace(/^import [\s\S]*?;\n/gm, "");
  const app = {},
    auth = { app, currentUser: { uid: "owned" } },
    db = { app },
    writes = [];
  const context = {
    window: {},
    initializeApp: () => app,
    getAuth: () => auth,
    signInWithEmailAndPassword: async () => ({ user: { uid: "owned" } }),
    forceWebSockets: () => {},
    getDatabase: () => db,
    ref: () => ({}),
    set: async () => writes.push("set"),
    update: async () => writes.push("update"),
    remove: async () => writes.push("remove"),
  };
  vm.runInNewContext(source, context);
  await context.window.__breadth({ action: "signIn", config: {}, uid: "owned" });
  await context.window.__breadth({ action: "w10", nonce: "n" });
  auth.currentUser = null;
  await assert.rejects(context.window.__breadth({ action: "w11" }));
  auth.currentUser = { uid: "owned" };
  db.app = {};
  await assert.rejects(context.window.__breadth({ action: "w12" }));
  assert.deepEqual(writes, ["set"]);
});

test("opens lazily with current credentials and closes the runner", async () => {
  const { openSdk } = await import("./breadth-sdk.mjs");
  const events = [];
  let credentials = { uid: "before" };
  const sdk = openSdk(
    async (config, actual, observe) => {
      events.push([config, actual]);
      await observe({ write: async (id) => ({ id }) });
      events.push("closed");
    },
    { projectId: "project" },
    () => credentials,
  );
  assert.deepEqual(events, []);
  credentials = { uid: "after" };
  assert.deepEqual(await sdk.write("w10"), { id: "w10" });
  await sdk.close();
  assert.deepEqual(events, [[{ projectId: "project" }, credentials], "closed"]);
});

test("runner failure rejects current and later writes without retry", async () => {
  const { openSdk } = await import("./breadth-sdk.mjs");
  let calls = 0;
  const sdk = openSdk(
    async () => {
      calls++;
      throw Error("runner failed");
    },
    {},
    () => ({}),
  );
  await assert.rejects(sdk.write("w10"), /runner failed/);
  await assert.rejects(sdk.write("w11"), /runner failed/);
  await assert.rejects(sdk.close(), /runner failed/);
  assert.equal(calls, 1);
});

test("closing an unused SDK does not start the runner", async () => {
  const { openSdk } = await import("./breadth-sdk.mjs");
  const sdk = openSdk(
    () => {
      throw Error("started");
    },
    {},
    () => ({}),
  );
  await sdk.close();
});

test("runner failure after handover rejects pending and later writes", async () => {
  const { openSdk } = await import("./breadth-sdk.mjs");
  let fail;
  const sdk = openSdk(
    async (_config, _credentials, observe) => {
      void observe({ write: () => new Promise(() => {}) });
      await new Promise((_resolve, reject) => {
        fail = reject;
      });
    },
    {},
    () => ({}),
  );
  const pending = sdk.write("w10");
  await new Promise((resolve) => setImmediate(resolve));
  fail(Error("runner crashed"));
  await assert.rejects(pending, /runner crashed/);
  await assert.rejects(sdk.write("w11"), /runner crashed/);
  await assert.rejects(sdk.close(), /runner crashed/);
});
