import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

const secret = "private-transport-secret";
const input = (overrides = {}) => ({
  url: `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${secret}`,
  method: "POST",
  headers: { "content-type": "application/json" },
  body: Buffer.from("{}"),
  ...overrides,
});

async function setup({
  status = 200,
  rawHeaders = ["X-Test", "one", "x-test", "two"],
  chunks = [Buffer.from([0, 255, 1]), Buffer.from("bytes")],
  complete = true,
  behavior,
} = {}) {
  const module = await import("./storage-rules/http-transport.mjs").catch((error) => {
    if (error.code === "ERR_MODULE_NOT_FOUND") return {};
    throw error;
  });
  assert.equal(typeof module.createSingleAttemptHttpsTransport, "function");
  const requests = [];
  const requestImpl = (url, options, callback) => {
    const request = new EventEmitter();
    const response = new EventEmitter();
    response.statusCode = status;
    response.rawHeaders = rawHeaders;
    response.complete = false;
    response.destroyed = false;
    response.destroy = () => {
      response.destroyed = true;
    };
    request.destroyed = false;
    request.destroy = () => {
      request.destroyed = true;
    };
    request.end = (body) => {
      requests.push({ url: String(url), options, body, request, response });
      queueMicrotask(() => {
        if (behavior) return behavior({ request, response, callback });
        callback(response);
        for (const chunk of chunks) response.emit("data", chunk);
        response.complete = complete;
        response.emit("end");
        response.emit("close");
        request.emit("close");
      });
    };
    return request;
  };
  const transport = module.createSingleAttemptHttpsTransport({ requestImpl });
  return { transport, requests, module };
}

test("one complete response retains raw header duplicates and binary chunks", async () => {
  const ctx = await setup();
  const response = await ctx.transport.send(input());
  assert.equal(response.status, 200);
  assert.deepEqual(response.rawHeaders, ["X-Test", "one", "x-test", "two"]);
  assert.deepEqual(response.bytes, Buffer.concat([Buffer.from([0, 255, 1]), Buffer.from("bytes")]));
  assert.ok(response.startedAtMs <= response.finishedAtMs);
  assert.equal(ctx.requests.length, 1);
  const { options, body } = ctx.requests[0];
  assert.equal(options.agent, false);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.method, "POST");
  assert.equal(options.headers["content-length"], "2");
  assert.equal(options.headers["accept-encoding"], "identity");
  assert.deepEqual(body, Buffer.from("{}"));
});

for (const status of [302, 403, 429, 500]) {
  test(`HTTP ${status} is captured once without redirect or retry`, async () => {
    const ctx = await setup({ status, rawHeaders: ["Location", `https://example.com/${secret}`] });
    const response = await ctx.transport.send(input());
    assert.equal(response.status, status);
    assert.equal(ctx.requests.length, 1);
  });
}

for (const url of [
  "http://identitytoolkit.googleapis.com/",
  "https://example.com/",
  "https://identitytoolkit.googleapis.com.evil.test/",
  "https://identitytoolkit.googleapis.com:444/",
  `https://${secret}@identitytoolkit.googleapis.com/`,
  "https://identitytoolkit.googleapis.com/#fragment",
  "https://www.googleapis.com/anything-else",
]) {
  test(`an unapproved transport destination is refused before a request`, async () => {
    const ctx = await setup();
    await assert.rejects(
      ctx.transport.send(input({ url })),
      (error) =>
        error.message === "invalid HTTP transport input" && !error.message.includes(secret),
    );
    assert.equal(ctx.requests.length, 0);
  });
}

for (const overrides of [
  { method: "CONNECT" },
  { method: "GET" },
  { body: "private-body" },
  { body: Buffer.alloc(256 * 1024 + 1) },
  { headers: { host: "other.test" } },
  { headers: { "content-length": "10" } },
  { headers: { "transfer-encoding": "chunked" } },
  { headers: { authorization: `${secret}\r\nother: injected` } },
  { headers: { Authorization: secret } },
]) {
  test("unreviewed method, body or header input cannot reach the transport", async () => {
    const ctx = await setup();
    await assert.rejects(ctx.transport.send(input(overrides)), /invalid HTTP transport input/);
    assert.equal(ctx.requests.length, 0);
  });
}

test("an accessor cannot acquire secrets or start a request", async () => {
  const ctx = await setup();
  const spec = input();
  let reads = 0;
  Object.defineProperty(spec, "url", {
    enumerable: true,
    get() {
      reads++;
      return secret;
    },
  });
  await assert.rejects(ctx.transport.send(spec), /invalid HTTP transport input/);
  assert.equal(reads, 0);
  assert.equal(ctx.requests.length, 0);
});

test("a header accessor is rejected without invoking it", async () => {
  const ctx = await setup();
  let reads = 0;
  const headers = {};
  Object.defineProperty(headers, "authorization", {
    enumerable: true,
    get() {
      reads++;
      return secret;
    },
  });
  await assert.rejects(ctx.transport.send(input({ headers })), /invalid HTTP transport input/);
  assert.equal(reads, 0);
  assert.equal(ctx.requests.length, 0);
});

for (const throws of [false, true]) {
  test(`a Buffer length accessor is refused without reading it${throws ? " or leaking its thrown secret" : ""}`, async () => {
    const ctx = await setup();
    let reads = 0;
    const body = Buffer.from("{}");
    Object.defineProperty(body, "length", {
      get() {
        reads++;
        if (throws) throw new Error(secret);
        return 2;
      },
    });
    await assert.rejects(
      ctx.transport.send(input({ body })),
      (error) => error.message === "invalid HTTP transport input",
    );
    assert.equal(reads, 0);
    assert.equal(ctx.requests.length, 0);
  });
}

test("hidden Buffer metadata cannot carry unreviewed private behavior", async () => {
  const ctx = await setup();
  const body = Buffer.from("{}");
  Object.defineProperty(body, "constructor", {
    get() {
      assert.fail("Buffer constructor accessor forbidden");
      return undefined;
    },
  });
  await assert.rejects(ctx.transport.send(input({ body })), /invalid HTTP transport input/);
  assert.equal(ctx.requests.length, 0);
});

test("a forged Buffer prototype is rejected without exposing its lower-level exception", async () => {
  const ctx = await setup();
  await assert.rejects(
    ctx.transport.send(input({ body: Object.create(Buffer.prototype) })),
    (error) => error.message === "invalid HTTP transport input",
  );
  assert.equal(ctx.requests.length, 0);
});

test("the fixed Firebase certificate path permits a bodyless GET", async () => {
  const ctx = await setup();
  await ctx.transport.send(
    input({
      url: "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
      method: "GET",
      headers: {},
      body: null,
    }),
  );
  assert.equal(ctx.requests[0].options.headers["content-length"], undefined);
});

for (const event of ["error", "close"]) {
  test(`a request ${event} before its response stops after one attempt with a fixed error`, async () => {
    const ctx = await setup({ behavior: ({ request }) => request.emit(event, new Error(secret)) });
    await assert.rejects(
      ctx.transport.send(input()),
      (error) => error.message === "HTTP transport failed",
    );
    assert.equal(ctx.requests.length, 1);
    assert.equal(ctx.requests[0].request.destroyed, true);
  });
}

for (const event of ["error", "aborted", "close"]) {
  test(`a partial response ${event} cannot return a successful capture`, async () => {
    const ctx = await setup({
      behavior: ({ response, callback }) => {
        callback(response);
        response.emit("data", Buffer.from(secret));
        response.emit(event, new Error(secret));
      },
    });
    await assert.rejects(
      ctx.transport.send(input()),
      (error) => error.message === "HTTP transport failed",
    );
    assert.equal(ctx.requests.length, 1);
    assert.equal(ctx.requests[0].request.destroyed, true);
    assert.equal(ctx.requests[0].response.destroyed, true);
  });
}

test("a premature end with an incomplete HTTP message is refused", async () => {
  const ctx = await setup({ complete: false });
  await assert.rejects(ctx.transport.send(input()), /HTTP transport failed/);
});

test("the response byte cap is enforced during streaming and closes both sides", async () => {
  const ctx = await setup({ chunks: [Buffer.alloc(2 * 1024 * 1024), Buffer.from("overflow")] });
  await assert.rejects(
    ctx.transport.send(input()),
    (error) => error.message === "HTTP response exceeds bound",
  );
  assert.equal(ctx.requests[0].response.destroyed, true);
  assert.equal(ctx.requests[0].request.destroyed, true);
});

test("the exact request and response byte bounds remain accepted", async () => {
  const ctx = await setup({ chunks: [Buffer.alloc(2 * 1024 * 1024)] });
  const response = await ctx.transport.send(input({ body: Buffer.alloc(256 * 1024) }));
  assert.equal(ctx.requests[0].body.length, 256 * 1024);
  assert.equal(response.bytes.length, 2 * 1024 * 1024);
});

test("the outgoing header bound includes generated transport headers", async () => {
  const ctx = await setup();
  await assert.rejects(
    ctx.transport.send(input({ headers: { "x-limit": "x".repeat(32 * 1024 - 11) } })),
    /invalid HTTP transport input/,
  );
  assert.equal(ctx.requests.length, 0);
});

test("an oversized incoming header set stops before body capture", async () => {
  const ctx = await setup({ rawHeaders: ["X-Limit", "x".repeat(32 * 1024)] });
  await assert.rejects(ctx.transport.send(input()), /HTTP transport failed/);
  assert.equal(ctx.requests[0].response.destroyed, true);
});

for (const beforeHeaders of [true, false]) {
  test(`the total deadline closes a stalled request ${beforeHeaders ? "before" : "after"} response headers`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const ctx = await setup({
      behavior: ({ response, callback }) => {
        if (!beforeHeaders) callback(response);
      },
    });
    const sending = ctx.transport.send(input());
    await Promise.resolve();
    const rejected = assert.rejects(
      sending,
      (error) => error.message === "HTTP transport timed out",
    );
    t.mock.timers.tick(30000);
    await rejected;
    assert.equal(ctx.requests[0].request.destroyed, true);
    if (!beforeHeaders) assert.equal(ctx.requests[0].response.destroyed, true);
    assert.equal(ctx.requests.length, 1);
  });
}

test("a synchronous request factory error is masked and never retried", async () => {
  const ctx = await setup();
  let attempts = 0;
  const transport = ctx.module.createSingleAttemptHttpsTransport({
    requestImpl: () => {
      attempts++;
      throw new Error(secret);
    },
  });
  await assert.rejects(
    transport.send(input()),
    (error) => error.message === "HTTP transport failed",
  );
  assert.equal(attempts, 1);
});
