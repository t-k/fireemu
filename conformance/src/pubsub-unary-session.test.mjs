import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-corpus/unary-session.mjs", import.meta.url);
const topic = "projects/demo-pubsub/topics/fireemu-owned-topic";
const step = {
  id: "topic-create",
  method: "CreateTopic",
  request: { name: topic, labels: { owner: "lane7" } },
};
async function session(sessionOptions) {
  assert.ok(existsSync(target), "raw unary recorder is missing");
  const { createUnarySession } = await import(target.href);
  return createUnarySession(sessionOptions);
}
function options(extra = {}) {
  return {
    target: { kind: "local", restEndpoint: "http://127.0.0.1:1234" },
    maxRequests: 2,
    maxResponseBytes: 1024,
    wallMs: 1000,
    requestMs: 1000,
    persist: async () => {},
    ...extra,
  };
}
test("REST request is durably reserved before one transport call, and raw bytes precede the returned result", async () => {
  const rows = [];
  let dispatched = 0;
  const s = await session(
    options({
      persist: async (row) => rows.push(row),
      sendRest: async (request) => {
        dispatched++;
        assert.equal(rows.at(-1).state, "before-send");
        assert.equal(rows.at(-1).id, step.id);
        assert.equal(request.redirect, "manual");
        return new Response(Uint8Array.from([0, 255, 13, 10]), {
          status: 201,
          headers: { "content-type": "application/octet-stream" },
        });
      },
    }),
  );
  const result = await s.rest(step);
  assert.equal(dispatched, 1);
  assert.deepEqual(s.counts(), { attempted: 1, completed: 1, unknown: 0 });
  assert.equal(rows.at(-1).state, "response-persisted");
  assert.equal(result.status, 201);
  assert.equal(result.bodyBase64, "AP8NCg==");
  assert.equal(result.bodyBytes, 4);
  assert.match(result.bodySha256, /^[a-f0-9]{64}$/);
});
test("native gRPC uses explicit message types and preserves binary/status/trailers rather than SDK projections", async () => {
  const rows = [],
    serializations = [];
  const s = await session(
    options({
      persist: async (row) => rows.push(row),
      codec: {
        serialize(type, input) {
          serializations.push([type, input]);
          return Buffer.from([8, 1]);
        },
      },
      sendGrpc: async (request) => {
        assert.equal(rows.at(-1).state, "before-send");
        assert.equal(request.path, "/google.pubsub.v1.Publisher/CreateTopic");
        assert.deepEqual(request.requestBytes, Buffer.from([8, 1]));
        assert.equal(
          request.metadata["x-goog-request-params"],
          `name=${encodeURIComponent(topic)}`,
        );
        return {
          responseBytes: Buffer.from([18, 0]),
          statusOrigin: "successful-response",
          status: {
            code: 0,
            details: "",
            metadata: { "grpc-status-details-bin": [Buffer.from([1, 2])] },
          },
        };
      },
    }),
  );
  const result = await s.grpc(step);
  assert.deepEqual(serializations, [["Topic", step.request]]);
  assert.equal(result.responseType, "Topic");
  assert.equal(result.bodyBase64, "EgA=");
  assert.equal(result.grpcStatus.code, 0);
  assert.deepEqual(result.grpcStatus.metadata["grpc-status-details-bin"], [{ base64: "AQI=" }]);
  assert.equal(rows.at(-1).state, "response-persisted");
});
test("production guard is mandatory, runs before sends, and the credential is never part of receipts", async () => {
  const rows = [];
  let guarded = 0;
  await assert.rejects(
    session(
      options({
        target: {
          kind: "production",
          restEndpoint: "https://pubsub.googleapis.com",
          accessToken: "secret",
          quotaProject: "demo-pubsub",
        },
      }),
    ),
  );
  const s = await session(
    options({
      target: {
        kind: "production",
        restEndpoint: "https://pubsub.googleapis.com",
        accessToken: "secret-token",
        quotaProject: "demo-pubsub",
      },
      guard: async () => {
        guarded++;
      },
      persist: async (r) => rows.push(r),
      sendRest: async (request) => {
        assert.ok(guarded > 0);
        assert.equal(request.headers.authorization, "Bearer secret-token");
        return new Response("{}");
      },
    }),
  );
  await s.rest(step);
  assert.ok(!JSON.stringify(rows).includes("secret-token"));
});
test("transport errors consume one slot without retries or persisting secret-bearing exceptions", async () => {
  const rows = [];
  let calls = 0;
  const s = await session(
    options({
      persist: async (r) => rows.push(r),
      sendRest: async () => {
        calls++;
        throw new Error("secret-token");
      },
    }),
  );
  const result = await s.rest(step);
  assert.equal(result.outcome, "transport-uncertain");
  assert.equal(calls, 1);
  assert.equal(s.counts().unknown, 1);
  assert.equal(rows.at(-1).state, "transport-uncertain");
  assert.ok(!JSON.stringify(rows).includes("secret-token"));
});
test("persistence, request cap, duplicate identity and wall exhaustion stop transport dispatch", async () => {
  let calls = 0;
  const sendRest = async () => {
    calls++;
    return new Response("{}");
  };
  const failed = await session(
    options({
      persist: async () => {
        throw new Error("secret");
      },
      sendRest,
    }),
  );
  await assert.rejects(failed.rest(step));
  assert.equal(calls, 0);
  const bounded = await session(options({ maxRequests: 1, sendRest }));
  await bounded.rest(step);
  await assert.rejects(bounded.rest({ ...step, id: "second" }));
  await assert.rejects(bounded.rest(step));
  assert.equal(calls, 1);
  let time = 0;
  const expired = await session(options({ clock: () => time, sendRest }));
  time = 1001;
  await assert.rejects(expired.rest(step));
  assert.equal(calls, 1);
});
test("response overflow is uncertain and reflected credentials are refused before durable response storage", async () => {
  for (const mode of ["overflow", "reflection"]) {
    const rows = [];
    const s = await session(
      options({
        maxResponseBytes: mode === "overflow" ? 3 : 1024,
        target: {
          kind: "production",
          restEndpoint: "https://pubsub.googleapis.com",
          accessToken: "secret-token",
          quotaProject: "demo-pubsub",
        },
        guard: async () => {},
        persist: async (r) => rows.push(r),
        sendRest: async () => new Response(mode === "overflow" ? "xxxx" : "secret-token"),
      }),
    );
    const result = await s.rest(step);
    assert.equal(result.outcome, "transport-uncertain");
    assert.ok(!JSON.stringify(rows).includes("secret-token"));
    assert.equal(s.counts().completed, 0);
  }
});

test("concurrent invocations cannot race past the request reservation cap", async () => {
  let unblock;
  const gate = new Promise((resolve) => {
    unblock = resolve;
  });
  let calls = 0;
  const s = await session(
    options({
      maxRequests: 1,
      persist: async (row) => {
        if (row.state === "before-send") await gate;
      },
      sendRest: async () => {
        calls++;
        return new Response("{}");
      },
    }),
  );
  const first = s.rest(step);
  const second = s.rest({ ...step, id: "concurrent" });
  const rejected = assert.rejects(second);
  unblock();
  await first;
  await rejected;
  assert.equal(calls, 1);
  assert.equal(s.counts().attempted, 1);
});

test("an uncertain send halts the recorder and never continues remaining observation writes", async () => {
  let calls = 0;
  const s = await session(
    options({
      sendRest: async () => {
        calls++;
        throw new Error("secret-token");
      },
    }),
  );
  await s.rest(step);
  await assert.rejects(s.rest({ ...step, id: "must-not-follow" }));
  assert.equal(calls, 1);
  assert.equal(s.counts().unknown, 1);
});

test("a failed reservation persistence halts even before dispatch", async () => {
  let persistCalls = 0,
    calls = 0;
  const s = await session(
    options({
      persist: async () => {
        if (persistCalls++ === 0) throw new Error("secret-token");
      },
      sendRest: async () => {
        calls++;
        return new Response("{}");
      },
    }),
  );
  await assert.rejects(s.rest(step));
  await assert.rejects(s.rest({ ...step, id: "must-not-follow" }));
  assert.equal(calls, 0);
});

test("caller mutation during durable reservation cannot change admission identity or escape re-admission", async () => {
  const rows = [];
  let calls = 0,
    owned = "projects/demo/topics/old";
  const input = { ...step, id: "stable-id", request: { name: owned } };
  const s = await session(
    options({
      target: {
        kind: "production",
        restEndpoint: "https://pubsub.googleapis.com",
        accessToken: "secret-token",
      },
      guard: async (captured) => {
        assert.equal(captured.request.name, owned);
      },
      persist: async (row) => {
        rows.push(row);
        if (row.state === "before-send") {
          owned = "projects/demo/topics/new";
          input.request.name = owned;
          input.id = "mutated-id";
        }
      },
      sendRest: async () => {
        calls++;
        return new Response("{}");
      },
    }),
  );
  const result = await s.rest(input);
  assert.equal(result.outcome, "transport-uncertain");
  assert.equal(calls, 0);
  assert.deepEqual(
    rows.map((row) => row.id),
    ["stable-id", "stable-id"],
  );
});

test("unverified native terminal is durably raw, consumes an unknown slot and halts", async () => {
  const rows = [];
  let calls = 0;
  const s = await session(
    options({
      codec: { serialize: () => Buffer.from([8, 1]) },
      persist: async (row) => rows.push(row),
      sendGrpc: async () => {
        calls++;
        return {
          responseBytes: Buffer.alloc(0),
          statusOrigin: "unverified",
          status: { code: 5, details: "missing", metadata: { key: ["first", "second"] } },
        };
      },
    }),
  );
  const result = await s.grpc(step);
  assert.equal(result.outcome, "transport-uncertain");
  assert.equal(result.grpcStatus.code, 5);
  assert.equal(result.statusOrigin, "unverified");
  assert.equal(rows.at(-1).state, "transport-uncertain");
  assert.deepEqual(rows.at(-1).grpcStatus.metadata.key, ["first", "second"]);
  assert.deepEqual(s.counts(), { attempted: 1, completed: 0, unknown: 1 });
  await assert.rejects(s.grpc({ ...step, id: "must-not-follow" }));
  assert.equal(calls, 1);
});
test("a bare native error status cannot manufacture peer provenance", async () => {
  const s = await session(
    options({
      codec: { serialize: () => Buffer.alloc(0) },
      sendGrpc: async () => ({
        status: { code: 4, details: "Deadline exceeded", metadata: {} },
        responseBytes: Buffer.alloc(0),
      }),
    }),
  );
  const result = await s.grpc(step);
  assert.equal(result.outcome, "transport-uncertain");
  assert.equal(result.statusOrigin, "unverified");
});

test("local target cannot bypass production admission with a remote endpoint", async () => {
  await assert.rejects(
    session(options({ target: { kind: "local", restEndpoint: "https://pubsub.googleapis.com" } })),
  );
  await assert.rejects(
    session(
      options({
        target: {
          kind: "production",
          restEndpoint: "https://unowned.invalid",
          accessToken: "secret",
        },
        guard: async () => {},
      }),
    ),
  );
});
test("native operation and target snapshots are immutable before the first admission await", async () => {
  const raw = Buffer.from([1, 2]);
  const input = {
    ...step,
    request: { name: topic, labels: { owner: "lane7" }, data: raw.toString("base64") },
  };
  const t = {
    kind: "production",
    restEndpoint: "https://pubsub.googleapis.com",
    accessToken: "original-token",
  };
  let checked = 0;
  const s = await session(
    options({
      target: t,
      guard: async (captured) => {
        checked++;
        assert.ok(Object.isFrozen(captured));
        assert.ok(Object.isFrozen(captured.request.labels));
        input.request.labels.owner = "changed";
        raw[0] = 99;
        t.accessToken = "changed-token";
      },
      codec: {
        serialize(type, capturedInput) {
          assert.equal(capturedInput.data, "AQI=");
          assert.equal(capturedInput.labels.owner, "lane7");
          return Buffer.from([8, 1]);
        },
      },
      sendGrpc: async (request) => {
        assert.equal(request.metadata.authorization, "Bearer original-token");
        return {
          statusOrigin: "successful-response",
          responseBytes: Buffer.alloc(0),
          status: { code: 0, metadata: {} },
        };
      },
    }),
  );
  assert.equal((await s.grpc(input)).outcome, "recorded");
  assert.equal(checked, 2);
});

test("unavailable native response bytes are not invented as a captured empty protobuf message", async () => {
  for (const available of [false, true]) {
    const rows = [];
    const s = await session(
      options({
        codec: { serialize: () => Buffer.alloc(0) },
        persist: async (row) => rows.push(row),
        sendGrpc: async () => ({
          statusOrigin: "unverified",
          status: { code: 5, details: "missing", metadata: {} },
          ...(available ? { responseBytes: Buffer.alloc(0) } : {}),
        }),
      }),
    );
    const result = await s.grpc(step);
    assert.equal(result.outcome, "transport-uncertain");
    assert.equal(rows.at(-1).responseBytesAvailable, available);
    assert.equal(Object.hasOwn(rows.at(-1), "bodyBase64"), available);
    if (available) assert.equal(result.bodyBase64, "");
  }
});

test("field-unaware snapshots cannot coerce binary attributes into accepted strings", async () => {
  let sent = 0;
  const s = await session(
    options({
      codec: { serialize: () => Buffer.alloc(0) },
      sendGrpc: async () => {
        sent++;
        return {
          statusOrigin: "successful-response",
          responseBytes: Buffer.alloc(0),
          status: { code: 0, metadata: {} },
        };
      },
    }),
  );
  await assert.rejects(
    s.grpc({
      id: "wrong-attribute",
      method: "Publish",
      request: { topic, messages: [{ data: "AQ==", attributes: { region: Buffer.from("A") } }] },
    }),
  );
  assert.equal(sent, 0);
});
test("direct peer refusal wire fields are durable before a confirmed native error result", async () => {
  const rows = [];
  const wire = {
    headers: [":status", "200", "content-type", "application/grpc"],
    trailers: ["grpc-status", "5"],
    dataBase64: "",
  };
  const s = await session(
    options({
      codec: { serialize: () => Buffer.alloc(0) },
      persist: async (r) => rows.push(r),
      sendGrpc: async () => ({
        statusOrigin: "peer-trailers",
        status: { code: 5, details: "missing", metadata: {} },
        wire,
      }),
    }),
  );
  const r = await s.grpc(step);
  assert.equal(r.outcome, "recorded");
  assert.equal(r.grpcStatus.code, 5);
  assert.deepEqual(rows.at(-1).nativeWire.headers, wire.headers);
  assert.deepEqual(rows.at(-1).nativeWire.trailers, wire.trailers);
  assert.equal(r.responseBytesAvailable, false);
  assert.equal(rows.at(-1).nativeWire.data.bodyBytes, 0);
  assert.equal(s.counts().completed, 1);
});
test("missing native terminal preserves bounded wire evidence as uncertain without inventing grpc status", async () => {
  const rows = [];
  const s = await session(
    options({
      codec: { serialize: () => Buffer.alloc(0) },
      persist: async (r) => rows.push(r),
      sendGrpc: async () => ({
        statusOrigin: "unverified",
        reason: "stream-error",
        wire: { headers: [":status", "200"], trailers: [], dataBase64: "AAA=" },
      }),
    }),
  );
  const r = await s.grpc(step);
  assert.equal(r.outcome, "transport-uncertain");
  assert.equal(rows.at(-1).nativeReason, "stream-error");
  assert.equal(rows.at(-1).nativeWire.data.bodyBase64, "AAA=");
  assert.ok(!Object.hasOwn(rows.at(-1), "grpcStatus"));
});
test("wire bounds and credential reflections cannot enter durable native response receipts", async () => {
  for (const mode of [
    "body",
    "headers",
    "reflection",
    "binary-reflection",
    "additional-headers",
    "additional-reflection",
  ]) {
    const rows = [];
    const wire = {
      headers: [":status", "200"],
      trailers: [],
      dataBase64: Buffer.from([1]).toString("base64"),
    };
    if (mode === "body") wire.dataBase64 = Buffer.alloc(1030).toString("base64");
    if (mode === "headers") wire.headers = ["key", "x".repeat(1100)];
    if (mode === "additional-headers") wire.additionalHeaders = [["key", "x".repeat(1100)]];
    if (mode === "additional-reflection")
      wire.additionalHeaders = [["key-bin", Buffer.from("secret-token").toString("base64")]];
    if (mode === "reflection") wire.dataBase64 = Buffer.from("secret-token").toString("base64");
    if (mode === "binary-reflection")
      wire.headers = ["key-bin", Buffer.from("secret-token").toString("base64")];
    const s = await session(
      options({
        target: {
          kind: "production",
          restEndpoint: "https://pubsub.googleapis.com",
          accessToken: "secret-token",
        },
        guard: async () => {},
        codec: { serialize: () => Buffer.alloc(0) },
        persist: async (r) => rows.push(r),
        sendGrpc: async () => ({
          statusOrigin: "peer-trailers",
          status: { code: 5, metadata: {} },
          wire,
        }),
      }),
    );
    assert.equal((await s.grpc(step)).outcome, "transport-uncertain");
    assert.ok(!Object.hasOwn(rows.at(-1), "nativeWire"));
    assert.equal(s.counts().completed, 0);
  }
});
test("additional native header blocks stay raw under uncertainty and halt the receipt session", async () => {
  const { EventEmitter } = await import("node:events");
  const { createPeerGrpcTransport } = await import("../pubsub-corpus/peer-grpc-transport.mjs");
  const client = new EventEmitter(),
    stream = new EventEmitter();
  stream.close = () => stream.emit("close");
  client.destroy = () => {};
  client.request = () => stream;
  const raw = [":status", "103", "hint", "small"];
  stream.end = () => queueMicrotask(() => stream.emit("headers", { ":status": 103 }, 0, raw));
  const transport = createPeerGrpcTransport(client, {
      authority: "http://127.0.0.1:1234",
      maxResponseBytes: 1024,
      maxHeaderBytes: 128,
    }),
    rows = [];
  try {
    const s = await session(
      options({
        codec: { serialize: () => Buffer.alloc(0) },
        sendGrpc: transport.send,
        persist: async (row) => rows.push(row),
      }),
    );
    const r = await s.grpc(step);
    assert.equal(r.outcome, "transport-uncertain");
    assert.equal(rows.at(-1).nativeReason, "extra-headers");
    assert.deepEqual(rows.at(-1).nativeWire.additionalHeaders, [raw]);
    assert.equal(s.counts().unknown, 1);
    await assert.rejects(s.grpc({ ...step, id: "must-not-follow" }));
  } finally {
    transport.close();
  }
});
