import assert from "node:assert/strict";
import test from "node:test";
const module = await import("./storage-object/wire-transport-core.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const make = (changes = {}) => {
  assert.equal(typeof module.createWireTransportCore, "function", "shared wire core is missing");
  return module.createWireTransportCore({
    limits: {
      maxRequestBytes: 100000,
      maxResponseBytes: 100000,
      maxPerResponseWireBytes: 20000,
      responseReadUnitBytes: 8192,
    },
    onByteReserve: async () => {},
    serializeRequest: () => {
      throw new Error("NEW_SERIALIZER_SECRET");
    },
    createCapture: () => {
      throw new Error("capture must not run");
    },
    tlsConnectionOptions: () => {
      throw new Error("TLS must not run");
    },
    timeoutMs: 30000,
    ...changes,
  });
};

test("a serializer rejection creates no reservation, capture, TLS connection or raw error", async () => {
  const calls = [];
  const core = make({
    onByteReserve: async () => calls.push("reserve"),
    createCapture: () => calls.push("capture"),
    tlsConnectionOptions: () => calls.push("TLS"),
  });
  try {
    await assert.rejects(
      core.fetch("https://unlisted.example/path", { accountingPhase: "subject" }),
      /^Error: WIRE_PREDISPATCH_OR_CAPTURE_FAILED$/,
    );
    assert.deepEqual(calls, []);
    assert.equal(core.snapshot().attempts, 0);
  } finally {
    await core.close();
  }
});

test("shared core requires all factory policies and bounded timeouts before any dispatch", () => {
  for (const changes of [
    { serializeRequest: null },
    { createCapture: null },
    { tlsConnectionOptions: null },
    { onByteReserve: null },
    { timeoutMs: 0 },
    { timeoutMs: 30001 },
  ])
    assert.throws(() => make(changes), /^Error: invalid wire transport core configuration$/);
});

test("closed core and unknown phases cannot create transport attempts", async () => {
  const core = make();
  await assert.rejects(
    core.fetch("https://unlisted.example/path", { accountingPhase: "unknown" }),
    /WIRE_INVALID_PHASE/,
  );
  await core.close();
  await assert.rejects(
    core.fetch("https://unlisted.example/path", { accountingPhase: "subject" }),
    /WIRE_CLOSED/,
  );
  assert.equal(core.snapshot().attempts, 0);
});

test("throwable message accessors and descriptor traps cannot escape failure sanitization", async () => {
  let messageGetterCalls = 0;
  for (const error of [
    Object.defineProperty({}, "message", {
      get() {
        messageGetterCalls++;
        throw new Error("NEW_MESSAGE_GETTER_SECRET");
      },
    }),
    new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          throw new Error("NEW_DESCRIPTOR_TRAP_SECRET");
        },
      },
    ),
  ]) {
    const core = make({
      serializeRequest: () => {
        throw error;
      },
    });
    try {
      await assert.rejects(
        core.fetch("https://unlisted.example/path", { accountingPhase: "subject" }),
        /^Error: WIRE_PREDISPATCH_OR_CAPTURE_FAILED$/,
      );
      assert.equal(messageGetterCalls, 0);
    } finally {
      await core.close();
    }
  }
});

test("an asynchronous capture result cannot reach credential verification or a socket", async () => {
  const calls = [];
  let release;
  const core = make({
    serializeRequest: () => ({
      url: new URL("http://127.0.0.1:9999/path"),
      method: "GET",
      headers: [],
      body: Buffer.alloc(0),
      wire: Buffer.from("GET /path HTTP/1.1\r\n\r\n"),
    }),
    onByteReserve: async () => calls.push("reserve"),
    createCapture: () => {
      calls.push("capture");
      return new Promise((resolve) => {
        release = resolve;
      });
    },
  });
  try {
    await assert.rejects(
      core.fetch("http://127.0.0.1:9999/path", {
        operationId: "fixture",
        accountingPhase: "subject",
        verifyBeforeDispatch: () => {
          calls.push("verify");
          throw new Error("VERIFY_MUST_NOT_RUN");
        },
      }),
      /^Error: WIRE_CAPTURE_FAILED$/,
    );
    assert.deepEqual(calls, ["reserve", "capture"]);
    assert.equal(core.snapshot().busy, false);
  } finally {
    release?.(Object.freeze({ appendResponse() {}, finish() {} }));
    await core.close();
  }
});

test("capture completion failures cannot replace a sanitized rejection with raw factory text", async () => {
  const core = make({
    serializeRequest: () => ({
      url: new URL("http://127.0.0.1:9999/path"),
      method: "GET",
      headers: [],
      body: Buffer.alloc(0),
      wire: Buffer.from("GET /path HTTP/1.1\r\n\r\n"),
    }),
    createCapture: () =>
      Object.freeze({
        appendResponse() {},
        finish() {
          throw new Error("NEW_CAPTURE_FINISH_SECRET");
        },
      }),
  });
  try {
    await assert.rejects(
      core.fetch("http://127.0.0.1:9999/path", {
        operationId: "fixture",
        accountingPhase: "subject",
        verifyBeforeDispatch: () => {
          throw new Error("VERIFY_MUST_STOP_BEFORE_SOCKET");
        },
      }),
      /^Error: WIRE_CAPTURE_FAILED$/,
    );
    assert.equal(core.snapshot().busy, false);
  } finally {
    await core.close();
  }
});

test("a rejected async capture is consumed without an unhandled rejection or socket", async () => {
  const core = make({
    serializeRequest: () => ({
      url: new URL("http://127.0.0.1:9999/path"),
      method: "GET",
      headers: [],
      body: Buffer.alloc(0),
      wire: Buffer.from("GET /path HTTP/1.1\r\n\r\n"),
    }),
    createCapture: () => Promise.reject(new Error("NEW_ASYNC_CAPTURE_SECRET")),
  });
  try {
    await assert.rejects(
      core.fetch("http://127.0.0.1:9999/path", {
        operationId: "fixture",
        accountingPhase: "subject",
        verifyBeforeDispatch: () => {
          throw new Error("VERIFY_MUST_STOP_BEFORE_SOCKET");
        },
      }),
      /^Error: WIRE_CAPTURE_FAILED$/,
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(core.snapshot().busy, false);
  } finally {
    await core.close();
  }
});

test("a regular capture method returning a rejected Promise is consumed and fails closed", async () => {
  const core = make({
    serializeRequest: () => ({
      url: new URL("http://127.0.0.1:9999/path"),
      method: "GET",
      headers: [],
      body: Buffer.alloc(0),
      wire: Buffer.from("GET /path HTTP/1.1\r\n\r\n"),
    }),
    createCapture: () =>
      Object.freeze({
        appendResponse() {},
        finish() {
          return Promise.reject(new Error("NEW_FINISH_RETURN_PROMISE_SECRET"));
        },
      }),
  });
  try {
    await assert.rejects(
      core.fetch("http://127.0.0.1:9999/path", {
        operationId: "fixture",
        accountingPhase: "subject",
        verifyBeforeDispatch: () => {
          throw new Error("VERIFY_MUST_STOP_BEFORE_SOCKET");
        },
      }),
      /^Error: WIRE_CAPTURE_FAILED$/,
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(core.snapshot().busy, false);
  } finally {
    await core.close();
  }
});

test("capture methods must return undefined synchronously, without inspecting unknown thenables", async () => {
  for (const returned of [
    false,
    Promise.resolve(),
    // oxlint-disable-next-line unicorn/no-thenable -- This adversarial return value must be rejected without inspecting then.
    Object.defineProperty({}, "then", {
      get() {
        throw new Error("NEW_THENABLE_GETTER_SECRET");
      },
    }),
  ]) {
    const core = make({
      serializeRequest: () => ({
        url: new URL("http://127.0.0.1:9999/path"),
        method: "GET",
        headers: [],
        body: Buffer.alloc(0),
        wire: Buffer.from("GET /path HTTP/1.1\r\n\r\n"),
      }),
      createCapture: () =>
        Object.freeze({
          appendResponse() {},
          finish() {
            return returned;
          },
        }),
    });
    try {
      await assert.rejects(
        core.fetch("http://127.0.0.1:9999/path", {
          operationId: "fixture",
          accountingPhase: "subject",
          verifyBeforeDispatch: () => {
            throw new Error("VERIFY_MUST_STOP_BEFORE_SOCKET");
          },
        }),
        /^Error: WIRE_CAPTURE_FAILED$/,
      );
      assert.equal(core.snapshot().busy, false);
    } finally {
      await core.close();
    }
  }
});
