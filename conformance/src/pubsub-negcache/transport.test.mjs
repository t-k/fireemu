import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createTransport } from "./transport.mjs";

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
  const send = (path, connPolicy = "dedicated") =>
    transport.send({ method: "GET", path }, { conn: "cell", connPolicy, timeoutMs: 100 });
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
  assert.equal((await send("/timeout")).failure, "timeout");
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
