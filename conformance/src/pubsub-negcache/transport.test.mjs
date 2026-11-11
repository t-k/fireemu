import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createTransport, DEFAULT_ENDPOINT, grpcCodeName } from "./transport.mjs";

test("HTTP responses, connections, errors and timeout", async (t) => {
  let connections = 0;
  const headers = [];
  const server = http.createServer((req, res) => {
    headers.push(req.headers);
    if (req.url === "/reset") return req.socket.destroy();
    if (req.url === "/timeout") return;
    if (req.url === "/large") return res.end(Buffer.alloc(1024 * 1024 + 1));
    res.writeHead(201);
    res.end('{"ok":true}');
  });
  server.on("connection", () => connections++);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  let tick = 0;
  const transport = createTransport({
    getToken: () => "test-authorization-value",
    clock: { now: () => ++tick },
    protocol: "http",
    host: "127.0.0.1",
    port: server.address().port,
  });
  t.after(() => transport.close());
  const send = (path, connPolicy = "dedicated", timeoutMs = 5000) =>
    transport.send({ method: "GET", path }, { conn: "cell", connPolicy, timeoutMs });
  const first = await send("/");
  assert.equal(first.status, 201);
  assert.equal(first.bodyText, '{"ok":true}');
  assert.ok(first.startedAt < first.headersAt && first.headersAt < first.completedAt);
  await send("/");
  assert.equal(connections, 1);
  await send("/", "fresh");
  await send("/", "fresh");
  assert.equal(connections, 3);
  assert.equal(headers[0].authorization, "Bearer test-authorization-value");
  assert.equal(headers.at(-1).connection, "close");
  assert.equal((await send("/large")).failure, "body-too-large");
  assert.equal((await send("/timeout", "dedicated", 100)).failure, "timeout");
  const reset = await send("/reset");
  assert.equal(reset.failure, "ECONNRESET");
  assert.ok(!JSON.stringify([first, reset]).includes("test-authorization-value"));
});

test("gRPC status mapping", async () => {
  let code;
  const clock = { now: () => 1 };
  const transport = createTransport({
    getToken: () => "unused",
    clock,
    protocol: "http",
    host: "127.0.0.1",
    port: 1,
    grpcCall: async () => ({ code, message: "message" }),
  });
  for (const [value, status] of Object.entries({
    OK: 200,
    NOT_FOUND: 404,
    PERMISSION_DENIED: 403,
    UNAUTHENTICATED: 401,
    ALREADY_EXISTS: 409,
    INVALID_ARGUMENT: 400,
  })) {
    code = value;
    const result = await transport.send(
      { grpc: true, path: "projects/p/subscriptions/s" },
      { timeoutMs: 10 },
    );
    assert.equal(result.status, status);
    assert.deepEqual(
      JSON.parse(result.bodyText),
      status === 200
        ? { name: "projects/p/subscriptions/s" }
        : { error: { code: status, message: "message", status: code } },
    );
  }
  for (code of ["UNAVAILABLE", "DEADLINE_EXCEEDED", "UNKNOWN", "INTERNAL", "CANCELLED", "OTHER"]) {
    assert.equal(
      (await transport.send({ grpc: true, path: "x" }, { timeoutMs: 10 })).failure,
      `grpc:${code}`,
    );
  }
  transport.close();
});

test("the default endpoint is the production Pub/Sub host and an unsupported protocol is refused", () => {
  assert.deepEqual(
    { ...DEFAULT_ENDPOINT },
    { protocol: "https", host: "pubsub.googleapis.com", port: 443 },
  );
  const clock = { now: () => 0 };
  assert.throws(
    () => createTransport({ getToken: () => "t", clock, protocol: "ftp", host: "127.0.0.1" }),
    /unsupported protocol/,
  );
  for (const host of ["127.0.0.1", "::1", "localhost"])
    createTransport({ getToken: () => "t", clock, protocol: "http", host, port: 1 }).close();
});

test("pooled requests share a connection; a body brings a content type and a bodyless request does not", async (t) => {
  let connections = 0;
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({
      method: req.method,
      type: req.headers["content-type"],
      accept: req.headers.accept,
    });
    res.end(Buffer.alloc(req.url === "/exact" ? 1024 * 1024 : 2));
  });
  server.on("connection", () => connections++);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  let tick = 0;
  const transport = createTransport({
    getToken: () => "t",
    clock: { now: () => ++tick },
    protocol: "http",
    host: "127.0.0.1",
    port: server.address().port,
  });
  t.after(() => transport.close());
  const meta = { conn: "pool:x", connPolicy: "pool", timeoutMs: 1000 };
  await transport.send({ method: "GET", path: "/" }, meta);
  await transport.send({ method: "PUT", path: "/", body: { a: 1 } }, meta);
  assert.equal(connections, 1);
  assert.equal(seen[0].type, undefined);
  assert.equal(seen[1].type, "application/json");
  assert.ok(seen.every((s) => s.accept === "application/json"));
  const exact = await transport.send({ method: "GET", path: "/exact" }, meta);
  assert.equal(exact.status, 200);
  assert.equal(exact.bodyText.length, 1024 * 1024);
  assert.equal(exact.failure, undefined);
});

test("each dedicated key keeps its own connection", async (t) => {
  let connections = 0;
  const server = http.createServer((req, res) => res.end("{}"));
  server.on("connection", () => connections++);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  let tick = 0;
  const transport = createTransport({
    getToken: () => "t",
    clock: { now: () => ++tick },
    protocol: "http",
    host: "127.0.0.1",
    port: server.address().port,
  });
  t.after(() => transport.close());
  for (const conn of ["dedicated:a", "dedicated:b", "dedicated:a", "dedicated:b"])
    await transport.send(
      { method: "GET", path: "/" },
      { conn, connPolicy: "dedicated", timeoutMs: 1000 },
    );
  assert.equal(connections, 2);
});

test("gRPC status names", () => {
  assert.equal(grpcCodeName(5), "NOT_FOUND");
  assert.equal(grpcCodeName(0), "OK");
  assert.equal(grpcCodeName(14), "UNAVAILABLE");
  assert.equal(grpcCodeName(99), "UNKNOWN");
});

test("requestedAt: a new connection is ready after the start, a reused one at the start", async (t) => {
  const server = http.createServer((req, res) => res.end("{}"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  let tick = 0;
  const transport = createTransport({
    getToken: () => "t",
    clock: { now: () => ++tick },
    protocol: "http",
    host: "127.0.0.1",
    port: server.address().port,
  });
  t.after(() => transport.close());
  const meta = { conn: "d", connPolicy: "dedicated", timeoutMs: 5000 };
  const first = await transport.send({ method: "GET", path: "/" }, meta);
  assert.ok(
    first.startedAt < first.requestedAt && first.requestedAt < first.headersAt,
    "the connect event comes between the start and the answer",
  );
  const second = await transport.send({ method: "GET", path: "/" }, meta);
  assert.equal(second.requestedAt, second.startedAt, "a reused socket has no connection setup");
  const fresh = await transport.send(
    { method: "GET", path: "/" },
    { ...meta, connPolicy: "fresh" },
  );
  assert.ok(fresh.startedAt < fresh.requestedAt);
});

test("S2: the gRPC channel is warmed before the timed call, and an injected call is not warmed", async () => {
  const order = [];
  let tick = 0;
  const clock = { now: () => (order.push("clock"), ++tick) };
  const transport = createTransport({
    getToken: () => "t",
    clock,
    protocol: "http",
    host: "127.0.0.1",
    port: 1,
    grpcWarm: async (deadlineMs) => order.push(`warm:${deadlineMs}`),
  });
  const result = await transport
    .send({ grpc: true, path: "projects/p/subscriptions/s" }, { timeoutMs: 4000 })
    .catch((e) => e);
  // The default call runs against a closed port and fails on its own; what matters is the order.
  assert.equal(order[0], "warm:4000");
  assert.ok(order.indexOf("clock") > 0, "the clock is first read after the warm-up");
  assert.ok(result.failure !== undefined || result.status !== undefined);
  transport.close();
  order.length = 0;
  const injected = createTransport({
    getToken: () => "t",
    clock,
    protocol: "http",
    host: "127.0.0.1",
    port: 1,
    grpcWarm: async () => order.push("warm"),
    grpcCall: async () => ({ code: "OK" }),
  });
  await injected.send({ grpc: true, path: "projects/p/subscriptions/s" }, { timeoutMs: 4000 });
  assert.ok(!order.includes("warm"));
  const capped = [];
  const long = createTransport({
    getToken: () => "t",
    clock,
    protocol: "http",
    host: "127.0.0.1",
    port: 1,
    grpcWarm: async (ms) => capped.push(ms),
    grpcCall: undefined,
  });
  await long.send({ grpc: true, path: "projects/p/subscriptions/s" }, { timeoutMs: 60000 });
  assert.deepEqual(capped, [10000], "the warm-up never waits longer than 10 s");
  long.close();
});
