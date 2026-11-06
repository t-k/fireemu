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

test("a successful SDK write cannot be sent twice", async () => {
  const calls = [];
  const sdk = createSdk({
    page: {
      evaluate: async (_fn, arg) => {
        calls.push(arg.action);
        return { outcome: "ok" };
      },
    },
    config: {},
    email: "user@example.test",
    password: "password",
    uid: "uid",
    nonce: "nonce",
  });
  await sdk.signIn();
  await sdk.write("w10");
  await assert.rejects(sdk.write("w10"), /write unavailable/);
  assert.deepEqual(calls, ["signIn", "w10"]);
});

test("closing releases a handed-over runner promptly", async () => {
  const { openSdk } = await import("./breadth-sdk.mjs");
  const sdk = openSdk(
    async (_config, _credentials, observe) => {
      await observe({ write: async () => ({ outcome: "ok" }) });
    },
    {},
    () => ({}),
  );
  await sdk.write("w10");
  let timer;
  try {
    await Promise.race([
      sdk.close(),
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(Error("close timed out")), 200);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
});

test("a hung SDK write becomes unknown after sixty seconds and closes without retry", async (t) => {
  const { openSdk } = await import("./breadth-sdk.mjs");
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let writes = 0,
    closed = false;
  const sdk = openSdk(
    async (_config, _credentials, observe) => {
      try {
        await observe({
          write: () => {
            writes++;
            return new Promise(() => {});
          },
        });
      } finally {
        closed = true;
      }
    },
    {},
    () => ({}),
  );
  const pending = sdk.write("w10");
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(59999);
  let settled = false;
  pending.then(() => {
    settled = true;
  });
  await Promise.resolve();
  assert.equal(settled, false);
  t.mock.timers.tick(1);
  assert.deepEqual(await pending, { outcome: "unknown" });
  await assert.rejects(sdk.write("w11"), /stopped/);
  await sdk.close();
  assert.equal(writes, 1);
  assert.equal(closed, true);
});

test("WebSocket observer counts allowed reconnects and closes on host count or budget refusal", async () => {
  const { browserRunner } = await import("./breadth-sdk.mjs");
  const path = await import("node:path");
  for (const mode of ["allowed", "host", "count", "budget"]) {
    const handlers = {},
      counts = [],
      stop = {};
    let pageClosed = 0,
      browserClosed = 0,
      serverClosed = 0;
    const page = {
      route: async () => {},
      on: (name, cb) => {
        handlers[name] = cb;
      },
      goto: async () => {},
      waitForFunction: async () => {},
      evaluate: async () => ({ outcome: "ok" }),
      close: async () => {
        pageClosed++;
      },
    };
    const deps = {
      createRequire: () => () => ({
        chromium: {
          launch: async () => ({
            newContext: async () => ({ newPage: async () => page }),
            close: async () => {
              browserClosed++;
            },
          }),
        },
      }),
      path,
      LAUNCH: {},
      createSdk,
      createServer: () => ({
        listen: (_port, _host, cb) => cb(),
        address: () => ({ port: 12345 }),
        close: (cb) => {
          serverClosed++;
          cb();
        },
      }),
    };
    const runnerFactory = new Function(
      ...Object.keys(deps),
      `return (${browserRunner.toString().replaceAll("import.meta.url", JSON.stringify(import.meta.url))});`,
    )(...Object.values(deps));
    const runner = runnerFactory({
      modules: ".",
      stop,
      allowHost: (host) => host.endsWith(".firebaseio.com"),
      budget: {
        take: (kind) => {
          counts.push(kind);
          if (mode === "budget") throw Error("limit");
        },
      },
    });
    const result = await runner({}, {}, async ({ write }) => {
      const socket = () => ({
        url: () =>
          mode === "host"
            ? "wss://foreign.test/.ws"
            : "wss://s-gke-usc1-nssi2-1.firebaseio.com/.ws",
      });
      for (let i = 0; i < (mode === "count" ? 5 : 1); i++) handlers.websocket(socket());
      if (mode === "allowed") assert.equal((await write("w10")).outcome, "ok");
      else await assert.rejects(write("w10"), /stopped/);
      assert.equal(typeof stop.closeBrowser, "function");
    });
    assert.equal(result.counts.ws, mode === "host" ? 0 : mode === "count" ? 5 : 1);
    assert.equal(counts.length, mode === "host" ? 0 : mode === "count" ? 4 : 1);
    assert.equal(pageClosed, mode === "allowed" ? 0 : 1);
    assert.equal(browserClosed, 1);
    assert.equal(serverClosed, 1);
    assert.equal(stop.closeBrowser, undefined);
  }
});

test("browser close failure still closes the SDK HTTP server", async () => {
  const { browserRunner } = await import("./breadth-sdk.mjs");
  const path = await import("node:path");
  let serverClosed = false;
  const page = {
    route: async () => {},
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
          close: async () => {
            throw Error("browser already failed");
          },
        }),
      },
    }),
    createServer: () => ({
      listen: (_port, _host, cb) => cb(),
      address: () => ({ port: 12345 }),
      close: (cb) => {
        serverClosed = true;
        cb();
      },
    }),
  };
  const factory = new Function(
    ...Object.keys(deps),
    `return (${browserRunner.toString().replaceAll("import.meta.url", JSON.stringify(import.meta.url))});`,
  )(...Object.values(deps));
  await assert.rejects(
    factory({ modules: ".", allowHost: () => true })({}, {}, async () => {}),
    /browser already failed/,
  );
  assert.equal(serverClosed, true);
});
