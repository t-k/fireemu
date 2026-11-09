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

async function runnerWith(options, observe) {
  const { browserRunner } = await import("./breadth-sdk.mjs");
  const path = await import("node:path");
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const handlers = {};
  const seen = { pageClosed: 0, serve: null };
  const page = {
    route: async () => {},
    on: (name, cb) => (handlers[name] = cb),
    goto: async () => {},
    waitForFunction: async () => {},
    evaluate: async () => ({ outcome: "ok" }),
    close: async () => {
      seen.pageClosed++;
    },
  };
  const deps = {
    path,
    LAUNCH: {},
    createSdk,
    readFileSync,
    fileURLToPath,
    createRequire: () => () => ({
      chromium: {
        launch: async () => ({
          newContext: async () => ({ newPage: async () => page }),
          close: async () => {},
        }),
      },
    }),
    createServer: (handler) => {
      seen.serve = (url) => {
        let body;
        handler({ url }, { writeHead() {}, end: (text) => (body = text) });
        return body;
      };
      return { listen: (_p, _h, cb) => cb(), address: () => ({ port: 1 }), close: (cb) => cb() };
    },
  };
  const runner = new Function(
    ...Object.keys(deps),
    `return (${browserRunner.toString().replaceAll("import.meta.url", JSON.stringify(new URL("./breadth-sdk.mjs", import.meta.url).href))});`,
  )(...Object.values(deps))({ modules: ".", allowHost: () => true, ...options });
  const result = await runner({}, {}, (api) => observe(api, handlers, seen));
  return { ...result, seen };
}

test("the runner's WebSocket cap is the scenario's", async () => {
  const closedAfter = async (caps, sockets) => {
    const { seen } = await runnerWith({ caps }, async (_api, handlers) => {
      for (let i = 0; i < sockets; i++)
        handlers.websocket({ url: () => "wss://s-gke.firebaseio.com/.ws" });
    });
    return seen.pageClosed;
  };
  assert.equal(await closedAfter({ http: 80, ws: 6 }, 6), 0);
  assert.equal(await closedAfter({ http: 80, ws: 6 }, 7), 1);
  assert.equal(await closedAfter({ http: 80, ws: 2 }, 3), 1);
});

test("the page the runner serves is the scenario's, the breadth page by default", async () => {
  const { readFile } = await import("node:fs/promises");
  const served = async (options) => {
    let body;
    await runnerWith(options, async (_api, _handlers, seen) => {
      body = seen.serve("/page.js");
      assert.match(seen.serve("/"), /<script type="module" src="\/page.js">/);
    });
    return body.toString();
  };
  const kinds = await readFile(KINDS_SCENARIO.sdk.pageFile, "utf8");
  const breadth = await readFile(new URL("./breadth-sdk-page.js", import.meta.url), "utf8");
  assert.notEqual(kinds, breadth);
  assert.equal(await served({ pageFile: KINDS_SCENARIO.sdk.pageFile }), kinds);
  assert.equal(await served({}), breadth);
});

test("the runner hands the scenario's ids to the SDK client", async () => {
  const outcomes = [];
  await runnerWith({ ids: ["k18"] }, async ({ write }) => {
    outcomes.push((await write("k18")).outcome);
    await assert.rejects(write("w10"), /write unavailable/);
  });
  assert.deepEqual(outcomes, ["ok"]);
  // without ids the breadth ids are the allowed ones
  await runnerWith({}, async ({ write }) => {
    assert.equal((await write("w10")).outcome, "ok");
    await assert.rejects(write("k18"), /write unavailable/);
  });
});

test("a rejected write keeps the page's error text, masked and bounded, and never a secret", async () => {
  const email = "breadth-abc@example.com";
  const uid = "uid1234567890";
  const nonce = "0123456789abcdef";
  const make = (evaluate) => {
    const sdk = createSdk({
      page: { evaluate },
      config: {},
      email,
      password: "pw-secret",
      uid,
      nonce,
      ids: KINDS_SCENARIO.sdk.ids,
    });
    return sdk;
  };
  const failing = (message) => async (_fn, arg) => {
    if (arg.action === "signIn") return { outcome: "ok" };
    throw Error(message);
  };
  const reject = async (message) => {
    const sdk = make(failing(message));
    await sdk.signIn();
    return sdk.write("k19").then(
      () => assert.fail("resolved"),
      (error) => error.message,
    );
  };
  assert.equal(
    await reject("page.evaluate: Error: permission_denied\n    at transaction (page.js:1)"),
    "write rejected: Error: permission_denied",
  );
  assert.equal(await reject("maxretry"), "write rejected: maxretry");
  const masked = await reject(
    `page.evaluate: Error: ${email} ${uid} ${nonce} pw-secret eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.${"A".repeat(300)}`,
  );
  for (const secret of [email, uid, nonce, "pw-secret", "eyJhbGci", "AAAAAAAA"])
    assert.ok(!masked.includes(secret), `${secret} in ${masked}`);
  assert.match(masked, /^write rejected: Error: <email> <uid> <nonce> <password> <masked>/);
  // bounded: a long text of short words (long runs of letters would be masked as tokens instead)
  const bounded = await reject("word ".repeat(2000));
  assert.equal(bounded.length, "write rejected: ".length + 159); // 160 characters, the last a space that is trimmed
  assert.ok(bounded.startsWith("write rejected: word word word"));
  assert.equal(await reject("bad\u0000\u001b[31m text​"), "write rejected: bad??[31m text?");
  // a page that returns a non-ok outcome instead of throwing is described the same way
  const returning = make(async (_fn, arg) =>
    arg.action === "signIn" ? { outcome: "ok" } : { outcome: "error", error: "permission_denied" },
  );
  await returning.signIn();
  await assert.rejects(returning.write("k19"), /^Error: write rejected: error permission_denied$/);
  const silent = make(async (_fn, arg) => (arg.action === "signIn" ? { outcome: "ok" } : {}));
  await silent.signIn();
  await assert.rejects(silent.write("k19"), /^Error: write rejected$/);
});

test("the page throws when a transaction is not committed", async () => {
  const { context } = await loadPage();
  await context.window.__breadth({ action: "signIn", config: {}, uid: "owned" });
  context.runTransaction = async () => ({ committed: false });
  await assert.rejects(context.window.__breadth({ action: "k19", nonce: "n" }), /not committed/);
  await assert.rejects(context.window.__breadth({ action: "k20", nonce: "n" }), /not committed/);
});
