import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { createSdk } from "./breadth-sdk.mjs";
import { KINDS_SCENARIO } from "./kinds-scenario.mjs";

async function loadPage() {
  let source = await readFile(KINDS_SCENARIO.sdk.pageFile, "utf8");
  source = source.replace(/^import [\s\S]*?;\n/gm, "");
  const app = {};
  const auth = { app, currentUser: { uid: "owned" } };
  const db = { app };
  const log = [];
  const context = {
    window: {},
    initializeApp: () => app,
    getAuth: () => auth,
    signInWithEmailAndPassword: async () => ({ user: { uid: "owned" } }),
    forceLongPolling: () => log.push(["forceLongPolling"]),
    forceWebSockets: () => log.push(["forceWebSockets"]),
    getDatabase: () => db,
    ref: (_db, path) => ({ path }),
    set: async (r, value) => log.push(["set", r.path, value]),
    runTransaction: async (r, update) => {
      // the first attempt sees no data, the server refuses it, the retry sees the stored node
      const first = update(null);
      const second = update({ value: 1, run: "n" });
      log.push(["transaction", r.path, first, second]);
      return { committed: true };
    },
    onDisconnect: (r) => ({
      remove: async () => log.push(["onDisconnect.remove", r.path]),
      set: async (value) => log.push(["onDisconnect.set", r.path, value]),
    }),
    goOffline: () => log.push(["goOffline"]),
  };
  vm.runInNewContext(source, context);
  return { context, auth, db, log };
}

test("the page forces long polling and never WebSockets", async () => {
  const { context, log } = await loadPage();
  await context.window.__breadth({ action: "signIn", config: {}, uid: "owned" });
  assert.deepEqual(log, [["forceLongPolling"]]);
});

test("each planned write is one SDK operation on the planned path", async () => {
  const { context, log } = await loadPage();
  await context.window.__breadth({ action: "signIn", config: {}, uid: "owned" });
  log.length = 0;
  for (const id of KINDS_SCENARIO.sdk.ids)
    assert.equal((await context.window.__breadth({ action: id, nonce: "n" })).outcome, "ok");
  // objects made in the page's realm are compared by value
  assert.deepEqual(JSON.parse(JSON.stringify(log)), [
    ["set", "k9-rtdb/gs/items/s1", { value: 1, run: "n" }],
    ["transaction", "k9-rtdb/gs/items/s1", { value: 2, run: "n" }, { value: 2, run: "n" }],
    ["transaction", "k9-rtdb/gs/items/s2", { value: 1, run: "n" }, { value: 1, run: "n" }],
    ["onDisconnect.remove", "k9-rtdb/gs/items/s1"],
    ["onDisconnect.set", "k9-rtdb/gs/items/s3", { value: 3, run: "n" }],
    ["goOffline"],
  ]);
});

test("the page guards the app and the current user before every write", async () => {
  const { context, auth, db, log } = await loadPage();
  await context.window.__breadth({ action: "signIn", config: {}, uid: "owned" });
  log.length = 0;
  auth.currentUser = null;
  await assert.rejects(context.window.__breadth({ action: "k18", nonce: "n" }));
  auth.currentUser = { uid: "other" };
  await assert.rejects(context.window.__breadth({ action: "k18", nonce: "n" }));
  auth.currentUser = { uid: "owned" };
  db.app = {};
  await assert.rejects(context.window.__breadth({ action: "k18", nonce: "n" }));
  assert.deepEqual(log, []);
  await assert.rejects(context.window.__breadth({ action: "k99", nonce: "n" }));
});

test("sign-in refuses another user than the owned one and a second initialisation", async () => {
  const { context } = await loadPage();
  await assert.rejects(context.window.__breadth({ action: "signIn", config: {}, uid: "someone" }));
  const second = await loadPage();
  await second.context.window.__breadth({ action: "signIn", config: {}, uid: "owned" });
  await assert.rejects(
    second.context.window.__breadth({ action: "signIn", config: {}, uid: "owned" }),
    /already initialized/,
  );
});

test("the SDK client of the scenario accepts only the four planned ids, once each", async () => {
  const calls = [];
  const page = {
    evaluate: async (_fn, arg) => (calls.push(arg.action), { outcome: "ok" }),
  };
  const sdk = createSdk({
    page,
    config: {},
    email: "e",
    password: "p",
    uid: "owned",
    nonce: "n",
    ids: KINDS_SCENARIO.sdk.ids,
  });
  await sdk.signIn();
  await assert.rejects(sdk.write("w10"));
  for (const id of KINDS_SCENARIO.sdk.ids) await sdk.write(id);
  await assert.rejects(sdk.write("k18"));
  assert.deepEqual(calls, ["signIn", "k18", "k19", "k20", "k21"]);
});

test("the runner's request caps are the scenario's, the breadth ones by default", async () => {
  const { browserRunner } = await import("./breadth-sdk.mjs");
  const path = await import("node:path");
  const take = async (caps) => {
    const handlers = {};
    const page = {
      route: async (_pattern, handler) => (handlers.route = handler),
      on: () => {},
      goto: async () => {},
      waitForFunction: async () => {},
      evaluate: async () => ({ outcome: "ok" }),
    };
    const deps = {
      path,
      LAUNCH: {},
      createSdk,
      createRequire: () => () => ({
        chromium: {
          launch: async () => ({
            newContext: async () => ({ newPage: async () => page }),
            close: async () => {},
          }),
        },
      }),
      createServer: () => ({
        listen: (_p, _h, cb) => cb(),
        address: () => ({ port: 1 }),
        close: (cb) => cb(),
      }),
    };
    const runner = new Function(
      ...Object.keys(deps),
      `return (${browserRunner.toString().replaceAll("import.meta.url", JSON.stringify(import.meta.url))});`,
    )(...Object.values(deps))({ modules: ".", allowHost: () => true, ...(caps ? { caps } : {}) });
    const outcomes = [];
    await runner({}, {}, async () => {
      for (let i = 0; i < 90; i++) {
        let continued = false;
        await handlers.route({
          request: () => ({ url: () => "https://x.firebaseio.com/.lp" }),
          continue: () => (continued = true),
          abort: () => {},
          fulfill: () => {},
        });
        outcomes.push(continued);
      }
    });
    return outcomes.filter(Boolean).length;
  };
  assert.equal(await take(undefined), 40);
  assert.equal(await take({ http: 80, ws: 4 }), 80);
});
