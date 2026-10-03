import test from "node:test";
import assert from "node:assert/strict";
import { createWireBudget } from "./wire_budget.mjs";

const module = await import("./wire_transport.mjs").catch(() => null);

test("Node guard claims gRPC streams and Auth fetches before transport calls", async () => {
  assert.equal(typeof module?.installNodeWireGuard, "function", "Node wire guard is required");
  const sent = [];
  const session = {
    request: (headers) => {
      sent.push(["grpc", headers]);
      return "stream";
    },
  };
  const originalRequest = session.request;
  const http2 = { connect: () => session };
  const globals = {
    fetch: async (url) => {
      sent.push(["auth", url]);
      return "response";
    },
  };
  const originalConnect = http2.connect;
  const originalFetch = globals.fetch;
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  let phase = "observation";
  const guard = module.installNodeWireGuard({ http2, globals, budget, phase: () => phase });
  try {
    const active = http2.connect("http://127.0.0.1:1");
    assert.equal(active.request({ ":path": "/Listen" }), "stream");
    assert.equal(await globals.fetch("http://127.0.0.1:2/auth"), "response");
    assert.throws(() => active.request({ ":path": "/Listen" }), /wire request budget exhausted/);
    assert.equal(sent.length, 2);
    budget.beginCleanup();
    phase = "cleanup";
    assert.equal(await globals.fetch("http://127.0.0.1:2/cleanup"), "response");
    assert.deepEqual(budget.snapshot().transports, { grpc: 1, auth: 2 });
  } finally {
    guard.close();
  }
  assert.equal(http2.connect, originalConnect);
  assert.equal(globals.fetch, originalFetch);
  assert.equal(session.request, originalRequest);
});

test("Node guard rejects unknown destinations before any wire claim", async () => {
  assert.equal(typeof module?.installNodeWireGuard, "function", "Node wire guard is required");
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const http2 = { connect: () => ({ request: () => "stream" }) };
  const globals = { fetch: async () => "response" };
  const guard = module.installNodeWireGuard({
    http2,
    globals,
    budget,
    phase: () => "observation",
    allowUrl: (url) => url.startsWith("http://127.0.0.1:"),
  });
  try {
    assert.throws(() => http2.connect("https://example.com"), /wire destination/);
    await assert.rejects(globals.fetch("https://example.com/auth"), /wire destination/);
    assert.equal(budget.snapshot().total, 0);
  } finally {
    guard.close();
  }
});

const harness = (options = {}) => {
  const sent = { connects: 0, grpc: 0, auth: 0 };
  const budget = createWireBudget({ maxRequests: 8, cleanupReserve: 2 });
  let requestPhase = "observation";
  const session = {
    request(...args) {
      sent.grpc++;
      return options.request?.apply(this, args) ?? "stream";
    },
  };
  const http2 = {
    connect(...args) {
      sent.connects++;
      options.connect?.apply(this, args);
      return session;
    },
  };
  const globals = {
    fetch(...args) {
      sent.auth++;
      return options.fetch ? options.fetch.apply(this, args) : Promise.resolve("response");
    },
  };
  const originals = { connect: http2.connect, request: session.request, fetch: globals.fetch };
  const guard = module.installNodeWireGuard({
    http2,
    globals,
    budget,
    phase: () => requestPhase,
    ...options.guardInputs,
  });
  return {
    sent,
    budget,
    session,
    http2,
    globals,
    originals,
    guard,
    cleanup() {
      budget.beginCleanup();
      requestPhase = "cleanup";
    },
  };
};

test("default destinations are parsed and refused before any underlying call", async () => {
  const h = harness();
  try {
    for (const url of [
      "http://127.0.0.1:65536",
      "http://127.0.0.1:0",
      "http://127.0.0.1:-1",
      "http://127.0.0.1:1.evil",
      "http://127.0.0.1.evil:1",
      "http://127.0.0.1:1@evil:2",
      "http://user:password@127.0.0.1:1",
      "https://127.0.0.1:1",
      "ftp://127.0.0.1:1",
      "file:///tmp/local",
      "http://192.168.0.1:1",
      "not a url",
      "",
      null,
      {},
    ]) {
      assert.throws(() => h.http2.connect(url), /destination/, String(url));
      await assert.rejects(h.globals.fetch(url), /destination/, String(url));
    }
    assert.deepEqual(h.sent, { connects: 0, grpc: 0, auth: 0 });
    assert.equal(h.budget.snapshot().total, 0);
    assert.equal(h.guard.snapshot().failures.destination, 30);
  } finally {
    h.guard.close();
  }
});

test("loopback URL and Request shaped inputs preserve receivers and arguments", async () => {
  const seen = [];
  const h = harness({
    connect(...args) {
      seen.push([this, args]);
    },
    request(...args) {
      seen.push([this, args]);
      return "custom-stream";
    },
    fetch(...args) {
      seen.push([this, args]);
      return Promise.resolve("custom-response");
    },
  });
  try {
    const options = { settings: {} };
    const url = new URL("http://[::1]:65535");
    assert.equal(h.http2.connect(url, options), h.session);
    const headers = { ":path": "/Listen" };
    assert.equal(h.session.request(headers, options), "custom-stream");
    const input = { url: "http://localhost:80/auth" };
    assert.equal(await h.globals.fetch(input, options), "custom-response");
    assert.deepEqual(seen, [
      [h.http2, [url, options]],
      [h.session, [headers, options]],
      [h.globals, [input, options]],
    ]);
    assert.deepEqual(h.budget.snapshot().transports, { grpc: 1, auth: 1 });
  } finally {
    h.guard.close();
  }
});

test("each RPC and fetch attempt is claimed before success, throw or rejection", async () => {
  for (const mode of ["success", "throw", "reject"]) {
    const error = new Error(`underlying-${mode}`);
    let h;
    const effect = (kind) => {
      assert.equal(h.budget.snapshot().total, h.sent.grpc + h.sent.auth);
      assert.equal(
        h.budget.snapshot().transports[kind],
        kind === "grpc" ? h.sent.grpc : h.sent.auth,
      );
      if (mode === "throw") throw error;
      if (mode === "reject") return Promise.reject(error);
      return "value";
    };
    h = harness({ request: () => effect("grpc"), fetch: () => effect("auth") });
    try {
      h.http2.connect("http://127.0.0.1:2");
      assert.equal(h.budget.snapshot().total, 0, "connect is not an RPC claim");
      for (let i = 0; i < 3; i++) {
        if (mode === "throw")
          assert.throws(
            () => h.session.request(),
            (e) => e === error,
          );
        else if (mode === "reject") await assert.rejects(h.session.request(), (e) => e === error);
        else assert.equal(h.session.request(), "value");
        if (mode === "throw")
          assert.throws(
            () => h.globals.fetch("http://127.0.0.1:2/auth"),
            (e) => e === error,
          );
        else if (mode === "reject")
          await assert.rejects(h.globals.fetch("http://127.0.0.1:2/auth"), (e) => e === error);
        else assert.equal(h.globals.fetch("http://127.0.0.1:2/auth"), "value");
      }
      assert.throws(() => h.session.request(), /exhausted/);
      await assert.rejects(h.globals.fetch("http://127.0.0.1:2/auth"), /exhausted/);
      assert.deepEqual(h.sent, { connects: 1, grpc: 3, auth: 3 });
      h.cleanup();
      if (mode === "throw")
        assert.throws(
          () => h.session.request(),
          (e) => e === error,
        );
      else if (mode === "reject") await assert.rejects(h.session.request(), (e) => e === error);
      else h.session.request();
      assert.equal(h.budget.snapshot().cleanup, 1);
    } finally {
      h.guard.close();
    }
  }
});

test("close restores all owned hooks and captured wrappers refuse further effects", async () => {
  const h = harness();
  const connect = h.http2.connect;
  const fetch = h.globals.fetch;
  h.http2.connect("http://127.0.0.1:1");
  const request = h.session.request;
  assert.equal(h.http2.connect("http://127.0.0.1:1"), h.session);
  assert.equal(h.session.request, request, "same session is wrapped only once");
  request();
  h.guard.close();
  h.guard.close();
  assert.equal(h.http2.connect, h.originals.connect);
  assert.equal(h.globals.fetch, h.originals.fetch);
  assert.equal(h.session.request, h.originals.request);
  assert.throws(() => connect("http://127.0.0.1:1"), /closed/);
  assert.throws(() => request(), /closed/);
  await assert.rejects(fetch("http://127.0.0.1:1"), /closed/);
  assert.deepEqual(h.sent, { connects: 2, grpc: 1, auth: 0 });
  assert.equal(h.budget.snapshot().total, 1);
  const snapshot = h.guard.snapshot();
  assert.equal(snapshot.closed, true);
  assert.deepEqual(snapshot.failures, { closed: 3, destination: 0, claim: 0, ownership: 0 });
  snapshot.failures.closed = 100;
  assert.equal(h.guard.snapshot().failures.closed, 3);
});

test("concurrent install refuses shared owners and permits a fresh isolated run after close", () => {
  const h = harness();
  const guardedConnect = h.http2.connect;
  const guardedFetch = h.globals.fetch;
  const freshBudget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const inputs = {
    http2: h.http2,
    globals: h.globals,
    budget: freshBudget,
    phase: () => "observation",
  };
  try {
    assert.throws(() => module.installNodeWireGuard(inputs), /ownership/);
    assert.throws(
      () => module.installNodeWireGuard({ ...inputs, globals: { fetch() {} } }),
      /ownership/,
    );
    assert.throws(
      () => module.installNodeWireGuard({ ...inputs, http2: { connect() {} } }),
      /ownership/,
    );
    assert.equal(h.http2.connect, guardedConnect);
    assert.equal(h.globals.fetch, guardedFetch);
    h.http2.connect("http://127.0.0.1:1").request();
    h.cleanup();
  } finally {
    h.guard.close();
  }
  const fresh = module.installNodeWireGuard(inputs);
  try {
    h.http2.connect("http://127.0.0.1:1").request();
    assert.equal(freshBudget.snapshot().observation, 1);
    assert.equal(freshBudget.snapshot().phase, "observation");
    assert.equal(h.budget.snapshot().total, 1);
  } finally {
    fresh.close();
  }
});

test("foreign replacements survive teardown and ownership drift stays visible", async () => {
  const h = harness();
  h.http2.connect("http://127.0.0.1:1");
  const captured = [h.http2.connect, h.session.request, h.globals.fetch];
  const foreign = { connect() {}, request() {}, fetch() {} };
  h.http2.connect = foreign.connect;
  h.session.request = foreign.request;
  h.globals.fetch = foreign.fetch;
  assert.throws(() => captured[0]("http://127.0.0.1:1"), /ownership/);
  assert.throws(() => captured[1](), /ownership/);
  await assert.rejects(captured[2]("http://127.0.0.1:1"), /ownership/);
  h.guard.close();
  assert.equal(h.http2.connect, foreign.connect);
  assert.equal(h.session.request, foreign.request);
  assert.equal(h.globals.fetch, foreign.fetch);
  assert.equal(h.guard.snapshot().failures.ownership, 6);
  assert.equal(h.budget.snapshot().total, 0);
  assert.deepEqual(h.sent, { connects: 1, grpc: 0, auth: 0 });
});

test("partial installation failure restores earlier hooks and releases ownership", () => {
  const error = new Error("fake fetch setter refusal");
  const http2 = {
    connect() {
      return { request() {} };
    },
  };
  const originalConnect = http2.connect;
  const originalFetch = () => Promise.resolve("response");
  let currentFetch = originalFetch;
  const globals = {};
  Object.defineProperty(globals, "fetch", {
    configurable: true,
    get: () => currentFetch,
    set(value) {
      if (value !== originalFetch) throw error;
      currentFetch = value;
    },
  });
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const inputs = { http2, globals, budget, phase: () => "observation" };
  assert.throws(
    () => module.installNodeWireGuard(inputs),
    (e) => e === error,
  );
  assert.equal(http2.connect, originalConnect);
  assert.equal(globals.fetch, originalFetch);
  Object.defineProperty(globals, "fetch", {
    configurable: true,
    writable: true,
    value: originalFetch,
  });
  const guard = module.installNodeWireGuard(inputs);
  guard.close();
  assert.equal(http2.connect, originalConnect);
  assert.equal(globals.fetch, originalFetch);
});

test("session hook failure and invalid hook objects refuse RPC effects", () => {
  for (const session of [
    { request: null },
    Object.freeze({
      request() {
        assert.fail("must not send");
      },
    }),
  ]) {
    const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
    const http2 = { connect: () => session };
    const globals = { fetch: async () => "response" };
    const guard = module.installNodeWireGuard({
      http2,
      globals,
      budget,
      phase: () => "observation",
    });
    try {
      assert.throws(() => http2.connect("http://127.0.0.1:1"));
      assert.equal(budget.snapshot().total, 0);
      assert.equal(guard.snapshot().failures.ownership, 1);
    } finally {
      guard.close();
    }
  }
});

test("guard failures preserve claim error identity and detached refusal provenance", async () => {
  const error = new Error("phase provider failure");
  const h = harness({
    guardInputs: {
      phase: () => {
        throw error;
      },
    },
  });
  try {
    h.http2.connect("http://127.0.0.1:1");
    assert.throws(
      () => h.session.request(),
      (e) => e === error,
    );
    await assert.rejects(h.globals.fetch("http://127.0.0.1:1"), (e) => e === error);
    assert.equal(h.guard.snapshot().failures.claim, 2);
    assert.equal(h.budget.snapshot().exhausted, false);
    assert.deepEqual(h.sent, { connects: 1, grpc: 0, auth: 0 });
  } finally {
    h.guard.close();
  }
});

test("mutating then throwing hook setters roll back immediately and revoke captured wrappers", async () => {
  for (const key of ["fetch", "request"]) {
    const h = { http2: {}, globals: {}, session: {} };
    const error = new Error(`setter-${key}`);
    const original = () => "original";
    const target = key === "fetch" ? h.globals : h.session;
    let value = original;
    let captured;
    Object.defineProperty(target, key, {
      configurable: true,
      get: () => value,
      set(next) {
        value = next;
        if (next !== original) {
          captured = next;
          throw error;
        }
      },
    });
    h.http2.connect = () => h.session;
    if (key === "fetch") h.session.request = original;
    else h.globals.fetch = original;
    const originalConnect = h.http2.connect;
    const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
    const inputs = { http2: h.http2, globals: h.globals, budget, phase: () => "observation" };
    if (key === "fetch") {
      assert.throws(
        () => module.installNodeWireGuard(inputs),
        (e) => e === error,
      );
      assert.equal(h.http2.connect, originalConnect);
      await assert.rejects(captured("http://127.0.0.1:1"), /closed/);
    } else {
      const guard = module.installNodeWireGuard(inputs);
      try {
        assert.throws(
          () => h.http2.connect("http://127.0.0.1:1"),
          (e) => e === error,
        );
        assert.equal(target[key], original, "failed session hook rolls back before close");
        assert.throws(() => captured(), /ownership/);
      } finally {
        guard.close();
      }
    }
    assert.equal(target[key], original);
    assert.equal(budget.snapshot().total, 0);
  }
});

test("installation refuses a hook changed by another owner during the first assignment", () => {
  const originalConnect = () => ({ request() {} });
  const originalFetch = () => Promise.resolve("original");
  const foreignFetch = () => Promise.resolve("foreign");
  let currentConnect = originalConnect;
  const globals = { fetch: originalFetch };
  const http2 = {};
  Object.defineProperty(http2, "connect", {
    get: () => currentConnect,
    set(value) {
      currentConnect = value;
      if (value !== originalConnect) globals.fetch = foreignFetch;
    },
  });
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  assert.throws(
    () => module.installNodeWireGuard({ http2, globals, budget, phase: () => "observation" }),
    /ownership/,
  );
  assert.equal(http2.connect, originalConnect);
  assert.equal(globals.fetch, foreignFetch);
});

test("teardown errors stay visible while other hooks are restored and released", () => {
  const h = harness();
  h.http2.connect("http://127.0.0.1:1");
  Object.defineProperty(h.session, "request", { value: h.session.request, writable: false });
  assert.throws(() => h.guard.close(), /restoration failed/);
  h.guard.close();
  assert.equal(h.guard.snapshot().closed, true);
  assert.equal(h.guard.snapshot().failures.ownership, 1);
  assert.equal(h.http2.connect, h.originals.connect);
  assert.equal(h.globals.fetch, h.originals.fetch);
  assert.throws(() => h.session.request(), /closed/);
  assert.equal(h.budget.snapshot().total, 0);
});

test("inherited hooks are restored without adding permanent own properties", () => {
  const session = Object.create({ request() {} });
  const http2 = Object.create({ connect: () => session });
  const globals = Object.create({ fetch() {} });
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const guard = module.installNodeWireGuard({ http2, globals, budget, phase: () => "observation" });
  http2.connect("http://127.0.0.1:1");
  guard.close();
  assert.equal(Object.hasOwn(http2, "connect"), false);
  assert.equal(Object.hasOwn(globals, "fetch"), false);
  assert.equal(Object.hasOwn(session, "request"), false);
});

test("invalid guard inputs and permissive allowUrl cannot bypass malformed destinations", async () => {
  const base = {
    http2: {
      connect() {
        assert.fail("must not connect");
      },
    },
    globals: {
      fetch() {
        assert.fail("must not fetch");
      },
    },
    budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
    phase: () => "observation",
  };
  for (const [key, value] of [
    ["http2", null],
    ["globals", {}],
    ["budget", {}],
    ["phase", null],
    ["allowUrl", 1],
  ]) {
    assert.throws(() => module.installNodeWireGuard({ ...base, [key]: value }), /inputs/);
  }
  const guard = module.installNodeWireGuard({ ...base, allowUrl: () => true });
  try {
    for (const url of [
      "http://127.0.0.1:65536",
      "http://127.0.0.1:0",
      "ftp://127.0.0.1:1",
      "http://u:p@127.0.0.1:1",
    ]) {
      assert.throws(() => base.http2.connect(url), /destination/);
      await assert.rejects(base.globals.fetch(url), /destination/);
    }
    assert.equal(base.budget.snapshot().total, 0);
  } finally {
    guard.close();
  }
});

test("hook setters that silently reject installation or restoration fail visibly", () => {
  const originalFetch = () => "original";
  const originalConnect = () => ({ request() {} });
  const http2 = { connect: originalConnect };
  const globals = {};
  Object.defineProperty(globals, "fetch", {
    configurable: true,
    get: () => originalFetch,
    set() {},
  });
  const inputs = {
    http2,
    globals,
    budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
    phase: () => "observation",
  };
  assert.throws(() => module.installNodeWireGuard(inputs), /installation refused/);
  assert.equal(http2.connect, originalConnect);
  let currentFetch = originalFetch;
  Object.defineProperty(globals, "fetch", {
    configurable: true,
    get: () => currentFetch,
    set(value) {
      if (value !== originalFetch) currentFetch = value;
    },
  });
  const guard = module.installNodeWireGuard(inputs);
  assert.throws(() => guard.close(), /restoration failed/);
  assert.equal(guard.snapshot().failures.ownership, 1);
  assert.equal(http2.connect, originalConnect);
});

test("generated guarded operations match independent admitted effect sets", async () => {
  let seed = 0x9c03;
  const next = (n) => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return seed % n;
  };
  for (let run = 0; run < 40; run++) {
    const h = harness();
    const connect = h.http2.connect;
    const fetch = h.globals.fetch;
    connect("http://127.0.0.1:1");
    const request = h.session.request;
    const admitted = [];
    let closed = false;
    let cleaning = false;
    let destinations = 0;
    let closedCalls = 0;
    let refusedClaims = 0;
    try {
      for (let step = 0; step < 50; step++) {
        const action = next(10);
        if (action === 0) {
          h.guard.close();
          closed = true;
        } else if (action === 1 && !cleaning) {
          h.cleanup();
          cleaning = true;
        } else {
          const isFetch = action % 2 === 0;
          const invalidUrl = isFetch && action === 2;
          const currentPhase = cleaning ? "cleanup" : "observation";
          const admittedInPhase = admitted.filter((x) => x.phase === currentPhase).length;
          const limit = cleaning ? 2 : 6;
          let refused;
          if (closed) {
            refused = /closed/;
            closedCalls++;
          } else if (invalidUrl) {
            refused = /destination/;
            destinations++;
          } else if (admittedInPhase >= limit) {
            refused = /exhausted/;
            refusedClaims++;
          } else admitted.push({ phase: currentPhase, transport: isFetch ? "auth" : "grpc" });
          const send = () =>
            isFetch
              ? fetch(invalidUrl ? "http://external.invalid:1" : "http://127.0.0.1:1")
              : request();
          if (refused && isFetch) await assert.rejects(send(), refused);
          else if (refused) assert.throws(send, refused);
          else await send();
        }
        assert.equal(h.sent.grpc, admitted.filter((x) => x.transport === "grpc").length);
        assert.equal(h.sent.auth, admitted.filter((x) => x.transport === "auth").length);
        assert.equal(h.sent.connects, 1);
        assert.equal(h.budget.snapshot().total, admitted.length);
        assert.deepEqual(
          h.guard.snapshot(),
          {
            closed,
            failures: {
              closed: closedCalls,
              destination: destinations,
              claim: refusedClaims,
              ownership: 0,
            },
          },
          `run ${run}, step ${step}`,
        );
      }
    } finally {
      h.guard.close();
    }
  }
});

test("two distinct guards cannot own the same session request hook", () => {
  const h = harness();
  h.http2.connect("http://127.0.0.1:1");
  const secondBudget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const secondHttp2 = { connect: () => h.session };
  const secondGlobals = { fetch: () => Promise.resolve("response") };
  const second = module.installNodeWireGuard({
    http2: secondHttp2,
    globals: secondGlobals,
    budget: secondBudget,
    phase: () => "observation",
  });
  try {
    assert.throws(() => secondHttp2.connect("http://127.0.0.1:1"), /ownership/);
    assert.equal(second.snapshot().failures.ownership, 1);
    assert.equal(secondBudget.snapshot().total, 0);
    h.session.request();
    assert.equal(h.budget.snapshot().total, 1);
  } finally {
    second.close();
    h.guard.close();
  }
});

test("reentrant callbacks cannot send after closing or replacing the active owner", async () => {
  for (const boundary of ["phase-request", "phase-fetch", "allow-connect", "allow-fetch"]) {
    for (const action of ["close", "foreign", "fresh"]) {
      let h;
      let fresh;
      const callback = () => {
        if (action === "foreign") {
          if (boundary.endsWith("request")) h.session.request = () => "foreign";
          else if (boundary.endsWith("connect")) h.http2.connect = () => h.session;
          else h.globals.fetch = () => "foreign";
        } else {
          h.guard.close();
          if (action === "fresh")
            fresh = module.installNodeWireGuard({
              http2: h.http2,
              globals: h.globals,
              budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
              phase: () => "observation",
            });
        }
        return boundary.startsWith("phase") ? "observation" : true;
      };
      h = harness({
        guardInputs: boundary.startsWith("phase") ? { phase: callback } : { allowUrl: callback },
      });
      try {
        if (boundary.endsWith("request")) h.http2.connect("http://127.0.0.1:1");
        const send = () =>
          boundary.endsWith("request")
            ? h.session.request()
            : boundary.endsWith("connect")
              ? h.http2.connect("http://127.0.0.1:1")
              : h.globals.fetch("http://127.0.0.1:1");
        if (boundary.endsWith("fetch"))
          await assert.rejects(send(), /closed|ownership/, `${boundary}/${action}`);
        else assert.throws(send, /closed|ownership/, `${boundary}/${action}`);
        assert.equal(h.sent.grpc + h.sent.auth, 0);
        if (boundary.startsWith("allow")) assert.equal(h.budget.snapshot().total, 0);
        assert.equal(h.sent.connects, boundary.endsWith("request") ? 1 : 0);
        const failure = action === "foreign" ? "ownership" : "closed";
        assert.equal(h.guard.snapshot().failures[failure], 1);
        if (fresh) {
          assert.equal(fresh.snapshot().closed, false);
          assert.equal(h.http2.connect("http://127.0.0.1:1").request(), "stream");
          assert.equal(fresh.snapshot().failures.ownership, 0);
        }
      } finally {
        h.guard.close();
        fresh?.close();
      }
    }
  }
});

test("native connect and hook setter reentrancy cannot install hooks after close", () => {
  for (const boundary of ["connect", "request-setter"]) {
    let guard;
    let requests = 0;
    let connects = 0;
    const originalRequest = () => {
      requests++;
    };
    let value = originalRequest;
    const session = {};
    Object.defineProperty(session, "request", {
      configurable: true,
      get: () => value,
      set(next) {
        value = next;
        if (boundary === "request-setter" && next !== originalRequest) guard.close();
      },
    });
    const http2 = {
      connect() {
        connects++;
        if (boundary === "connect") guard.close();
        return session;
      },
    };
    const originalConnect = http2.connect;
    const globals = { fetch() {} };
    const originalFetch = globals.fetch;
    guard = module.installNodeWireGuard({
      http2,
      globals,
      budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
      phase: () => "observation",
    });
    assert.throws(() => http2.connect("http://127.0.0.1:1"), /closed/);
    guard.close();
    assert.equal(connects, 1);
    assert.equal(requests, 0);
    assert.equal(session.request, originalRequest);
    assert.equal(http2.connect, originalConnect);
    assert.equal(globals.fetch, originalFetch);
    assert.equal(guard.snapshot().closed, true);
  }
});

test("inherited reversible accessors restore backing functions and preserve foreign replacements", () => {
  for (const key of ["connect", "fetch", "request"]) {
    for (const action of ["close", "foreign", "throw"]) {
      const session = { request() {} };
      const http2 = { connect: () => session };
      const globals = { fetch() {} };
      const target = key === "connect" ? http2 : key === "fetch" ? globals : session;
      const original = target[key];
      const foreign = () => "foreign";
      let value = original;
      delete target[key];
      const prototype = {};
      const setterError = new Error("inherited setter refusal");
      Object.defineProperty(prototype, key, {
        configurable: true,
        get: () => value,
        set(next) {
          value = next;
          if (action === "throw" && next !== original) throw setterError;
        },
      });
      Object.setPrototypeOf(target, prototype);
      const inputs = {
        http2,
        globals,
        budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
        phase: () => "observation",
      };
      if (action === "throw" && key !== "request")
        assert.throws(
          () => module.installNodeWireGuard(inputs),
          (e) => e === setterError,
        );
      else {
        const guard = module.installNodeWireGuard(inputs);
        if (action === "throw")
          assert.throws(
            () => http2.connect("http://127.0.0.1:1"),
            (e) => e === setterError,
          );
        else if (key === "request") http2.connect("http://127.0.0.1:1");
        if (action === "foreign") target[key] = foreign;
        guard.close();
        if (action === "foreign") assert.equal(guard.snapshot().failures.ownership, 1);
        const snapshot = guard.snapshot();
        snapshot.failures.ownership = 100;
        assert.notEqual(guard.snapshot().failures.ownership, 100);
      }
      assert.equal(target[key], action === "foreign" ? foreign : original, `${key}/${action}`);
      assert.equal(Object.hasOwn(target, key), false);
    }
  }
});

test("inherited accessor prototype drift is retained without invoking a foreign setter", () => {
  const original = () => "original";
  let value = original;
  let foreignSets = 0;
  const prototype = {};
  Object.defineProperty(prototype, "fetch", {
    configurable: true,
    get: () => value,
    set(next) {
      value = next;
    },
  });
  const globals = Object.create(Object.create(prototype));
  const http2 = { connect: () => ({ request() {} }) };
  const guard = module.installNodeWireGuard({
    http2,
    globals,
    budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
    phase: () => "observation",
  });
  const captured = globals.fetch;
  Object.defineProperty(prototype, "fetch", {
    configurable: true,
    get: () => value,
    set() {
      foreignSets++;
    },
  });
  guard.close();
  assert.equal(foreignSets, 0);
  assert.equal(globals.fetch, captured);
  assert.equal(Object.hasOwn(globals, "fetch"), false);
  assert.equal(guard.snapshot().failures.ownership, 1);
});

test("a reentrant hook getter cannot complete installation after closing the guard", () => {
  let guard;
  const original = () => "original";
  let value = original;
  let armed = false;
  const session = {};
  Object.defineProperty(session, "request", {
    get() {
      const read = value;
      if (armed && read !== original) guard.close();
      return read;
    },
    set(next) {
      value = next;
    },
  });
  const http2 = { connect: () => session };
  const globals = { fetch() {} };
  guard = module.installNodeWireGuard({
    http2,
    globals,
    budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
    phase: () => "observation",
  });
  armed = true;
  assert.throws(() => http2.connect("http://127.0.0.1:1"), /closed/);
  guard.close();
  assert.equal(session.request, original);
  assert.equal(guard.snapshot().failures.closed, 1);
});

test("generated callback lifecycle transitions retain an empty refused effect set", async () => {
  let seed = 0xa02;
  const next = (n) => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % n;
  };
  for (let run = 0; run < 100; run++) {
    const transport = ["grpc", "auth"][next(2)];
    const transition = ["close", "replace"][next(2)];
    const boundary = transport === "grpc" ? "phase" : ["phase", "allowUrl"][next(2)];
    let h;
    const transitionOwner = () => {
      if (transition === "close") h.guard.close();
      else if (transport === "grpc") h.session.request = () => "foreign";
      else h.globals.fetch = () => "foreign";
      return boundary === "phase" ? "observation" : true;
    };
    h = harness({ guardInputs: { [boundary]: transitionOwner } });
    try {
      if (transport === "grpc") {
        h.http2.connect("http://127.0.0.1:1");
        assert.throws(() => h.session.request(), /closed|ownership/);
      } else await assert.rejects(h.globals.fetch("http://127.0.0.1:1"), /closed|ownership/);
      assert.equal(h.sent.grpc + h.sent.auth, 0, `run ${run}`);
      assert.equal(h.guard.snapshot().failures[transition === "close" ? "closed" : "ownership"], 1);
      assert.ok(
        h.budget.snapshot().total <= 1,
        "an admitted attempt may remain, but no effect is sent",
      );
    } finally {
      h.guard.close();
    }
  }
});

test("session getters closing before installation cannot trigger even a temporary hook write", () => {
  let guard;
  let reads = 0;
  let writes = 0;
  const original = () => "original";
  let value = original;
  const session = {};
  Object.defineProperty(session, "request", {
    get() {
      if (++reads === 3) guard.close();
      return value;
    },
    set(next) {
      writes++;
      value = next;
    },
  });
  const http2 = { connect: () => session };
  const globals = { fetch() {} };
  guard = module.installNodeWireGuard({
    http2,
    globals,
    budget: createWireBudget({ maxRequests: 3, cleanupReserve: 1 }),
    phase: () => "observation",
  });
  assert.throws(() => http2.connect("http://127.0.0.1:1"), /closed/);
  assert.equal(writes, 0);
  assert.equal(session.request, original);
});

test("getter lifecycle changes immediately before send retain closed refusal provenance", async () => {
  let guard;
  let sends = 0;
  let armed = false;
  const original = () => {
    sends++;
  };
  let value = original;
  const globals = {};
  Object.defineProperty(globals, "fetch", {
    get() {
      const read = value;
      if (armed) guard.close();
      return read;
    },
    set(next) {
      value = next;
    },
  });
  const http2 = { connect: () => ({ request() {} }) };
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  guard = module.installNodeWireGuard({ http2, globals, budget, phase: () => "observation" });
  const captured = globals.fetch;
  armed = true;
  await assert.rejects(captured("http://127.0.0.1:1"), /closed/);
  assert.equal(sends, 0);
  assert.equal(budget.snapshot().total, 0);
  assert.equal(guard.snapshot().failures.closed, 1);
  assert.equal(guard.snapshot().failures.ownership, 0);
});

test("native connect ownership drift refuses late session hooks", () => {
  const originalRequest = () => "stream";
  const session = { request: originalRequest };
  const foreignConnect = () => session;
  const http2 = {
    connect() {
      http2.connect = foreignConnect;
      return session;
    },
  };
  const globals = { fetch() {} };
  const budget = createWireBudget({ maxRequests: 3, cleanupReserve: 1 });
  const guard = module.installNodeWireGuard({ http2, globals, budget, phase: () => "observation" });
  assert.throws(() => http2.connect("http://127.0.0.1:1"), /ownership/);
  assert.equal(session.request, originalRequest);
  assert.equal(budget.snapshot().total, 0);
  assert.equal(guard.snapshot().failures.ownership, 1);
  guard.close();
  assert.equal(http2.connect, foreignConnect);
});
