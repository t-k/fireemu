import assert from "node:assert/strict";
import test from "node:test";
import { protos } from "@google-cloud/pubsub";
import grpc from "@grpc/grpc-js";
import { createBudget, createCapture } from "./pubsub-production/capture.mjs";
import {
  SERVICES,
  createGrpc,
  durationFromWire,
  durationToWire,
  requestToWire,
  responseFromWire,
  timestampFromWire,
  timestampToWire,
} from "./pubsub-production/grpc.mjs";

const v1 = protos.google.pubsub.v1;
const TOKEN = "ya29.a0AfH6SMBsecretsecretsecretsecretsecret";
const HANG = Symbol("hang");
const typeOf = (name) => (name === "Empty" ? protos.google.protobuf.Empty : v1[name]);

/** A server that answers each method of the Publisher and Subscriber services with `handlers[method]`. */
async function server(handlers) {
  const calls = [];
  const instance = new grpc.Server();
  for (const [service, { path, methods }] of Object.entries(SERVICES)) {
    const definition = {};
    const implementation = {};
    for (const [method, [requestName, responseName]] of Object.entries(methods)) {
      const Request = typeOf(requestName);
      const Response = typeOf(responseName);
      definition[method] = {
        path: `${path}/${method}`,
        requestStream: false,
        responseStream: false,
        requestSerialize: (value) =>
          Buffer.from(Request.encode(Request.fromObject(value)).finish()),
        requestDeserialize: (buffer) =>
          Request.toObject(Request.decode(buffer), { longs: String, enums: String, bytes: String }),
        responseSerialize: (value) =>
          Buffer.from(Response.encode(Response.fromObject(value)).finish()),
        responseDeserialize: (buffer) => Response.decode(buffer),
      };
      implementation[method] = (call, callback) => {
        calls.push({ service, method, request: call.request, metadata: call.metadata.getMap() });
        const handler = handlers[method];
        if (!handler) return callback({ code: grpc.status.UNIMPLEMENTED, details: "no handler" });
        const result = handler(call.request, call);
        if (result === HANG) return;
        if (result?.error) return callback(result.error);
        callback(null, result ?? {});
      };
    }
    instance.addService(definition, implementation);
  }
  const port = await new Promise((resolve, reject) =>
    instance.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (error, bound) =>
      error ? reject(error) : resolve(bound),
    ),
  );
  return { target: `127.0.0.1:${port}`, calls, close: () => instance.forceShutdown() };
}
const setup = (target, extra = {}) => {
  const lines = [];
  const budget = createBudget(extra.max ?? 10);
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  const transport = createGrpc({ target, secure: false, budget, capture, ...extra });
  return { transport, lines, budget };
};

test("durations and times convert between the REST text and the wire object, and back", () => {
  assert.deepEqual(durationToWire("600s"), { seconds: "600", nanos: 0 });
  assert.deepEqual(durationToWire("1.5s"), { seconds: "1", nanos: 500_000_000 });
  assert.deepEqual(durationToWire("0.000000001s"), { seconds: "0", nanos: 1 });
  assert.deepEqual(durationToWire("-2s"), { seconds: "-2", nanos: 0 });
  assert.deepEqual(durationToWire("-0.5s"), { seconds: "-0", nanos: -500_000_000 });
  for (const bad of ["600", "s", "1.s", "1.0000000001s", "abc", 5, ""])
    assert.throws(() => durationToWire(bad), /not a duration/, String(bad));
  assert.equal(durationFromWire({ seconds: "600" }), "600s");
  assert.equal(durationFromWire({ seconds: "1", nanos: 500_000_000 }), "1.500s");
  assert.equal(durationFromWire({ seconds: "1", nanos: 1_000 }), "1.000001s");
  assert.equal(durationFromWire({ seconds: "1", nanos: 1 }), "1.000000001s");
  assert.equal(durationFromWire({ seconds: "-2" }), "-2s");
  assert.equal(durationFromWire({ seconds: "0", nanos: -500_000_000 }), "-0.500s");
  assert.equal(durationFromWire({}), "0s");
  assert.deepEqual(timestampToWire("2026-10-05T01:02:03Z"), {
    seconds: String(Date.UTC(2026, 9, 5, 1, 2, 3) / 1000),
    nanos: 0,
  });
  assert.deepEqual(timestampToWire("2026-10-05T01:02:03.250Z").nanos, 250_000_000);
  for (const bad of ["2026-10-05", "2026-10-05T01:02:03", "x", 5])
    assert.throws(() => timestampToWire(bad), /not a time/, String(bad));
  assert.equal(
    timestampFromWire(timestampToWire("2026-10-05T01:02:03.250Z")),
    "2026-10-05T01:02:03.250Z",
  );
  assert.equal(
    timestampFromWire({ seconds: String(Date.UTC(2026, 9, 5) / 1000) }),
    "2026-10-05T00:00:00Z",
  );
  assert.equal(
    timestampFromWire({ seconds: "0", nanos: 123_456_789 }),
    "1970-01-01T00:00:00.123456789Z",
  );
});

test("a request is converted in its duration and time fields, wherever they are, and a response back", () => {
  assert.deepEqual(
    requestToWire({
      name: "n",
      messageRetentionDuration: "600s",
      expirationPolicy: { ttl: "86400s" },
      retryPolicy: { minimumBackoff: "1s", maximumBackoff: "2s" },
      time: "2026-10-05T00:00:00Z",
      labels: { ttl: "keep" },
      list: [{ ttl: "3s" }],
    }),
    {
      name: "n",
      messageRetentionDuration: { seconds: "600", nanos: 0 },
      expirationPolicy: { ttl: { seconds: "86400", nanos: 0 } },
      retryPolicy: {
        minimumBackoff: { seconds: "1", nanos: 0 },
        maximumBackoff: { seconds: "2", nanos: 0 },
      },
      time: { seconds: String(Date.UTC(2026, 9, 5) / 1000), nanos: 0 },
      labels: { ttl: "keep" },
      list: [{ ttl: { seconds: "3", nanos: 0 } }],
    },
  );
  assert.deepEqual(
    responseFromWire({
      messageRetentionDuration: { seconds: "604800" },
      expirationPolicy: { ttl: { seconds: "2678400" } },
      messages: [{ publishTime: { seconds: "0", nanos: 5_000_000 } }],
      ttl: "stays",
    }),
    {
      messageRetentionDuration: "604800s",
      expirationPolicy: { ttl: "2678400s" },
      messages: [{ publishTime: "1970-01-01T00:00:00.005Z" }],
      ttl: "stays",
    },
  );
});

test("a call is converted, sent with the credentials, converted back and captured, and the token stays out of the capture", async (t) => {
  const s = await server({
    CreateSubscription: (request) => ({
      ...request,
      state: "ACTIVE",
      messageRetentionDuration: { seconds: "604800" },
      pushConfig: {},
    }),
    Pull: () => ({
      receivedMessages: [
        {
          ackId: "a1",
          message: { data: Buffer.from("hi"), messageId: "m1", publishTime: { seconds: "0" } },
        },
      ],
    }),
  });
  t.after(s.close);
  const { transport, lines, budget } = setup(s.target, {
    getToken: async () => TOKEN,
    quotaProject: "demo-project",
  });
  const created = await transport.call({
    label: { case: "c", step: "s1" },
    op: "createSubscription",
    service: "Subscriber",
    method: "CreateSubscription",
    request: {
      name: "projects/p/subscriptions/s",
      topic: "projects/p/topics/t",
      ackDeadlineSeconds: 30,
      expirationPolicy: { ttl: "86400s" },
    },
  });
  assert.equal(created.code, "OK");
  assert.equal(created.body.ackDeadlineSeconds, 30);
  assert.equal(created.body.state, "ACTIVE");
  assert.equal(created.body.messageRetentionDuration, "604800s");
  assert.equal(created.body.expirationPolicy.ttl, "86400s");
  assert.deepEqual(s.calls[0].request.expirationPolicy, { ttl: { seconds: "86400", nanos: 0 } });
  assert.equal(s.calls[0].metadata.authorization, `Bearer ${TOKEN}`);
  assert.equal(s.calls[0].metadata["x-goog-user-project"], "demo-project");
  const pulled = await transport.call({
    label: { case: "c" },
    op: "pull",
    service: "Subscriber",
    method: "Pull",
    request: { subscription: "projects/p/subscriptions/s", maxMessages: 1 },
  });
  assert.equal(pulled.body.receivedMessages[0].message.data, Buffer.from("hi").toString("base64"));
  assert.equal(pulled.body.receivedMessages[0].message.publishTime, "1970-01-01T00:00:00Z");
  assert.equal(budget.used(), 2);
  assert.equal(lines[0].transport, "grpc");
  assert.equal(lines[0].request.rpc, "Subscriber/CreateSubscription");
  assert.deepEqual(lines[0].request.body.expirationPolicy, { ttl: "86400s" });
  assert.equal(lines[0].response.code, "OK");
  assert.equal(JSON.stringify(lines).includes(TOKEN), false);
  transport.close();
});

test("an update mask is sent as snake_case paths, and the token choices change only the credentials", async (t) => {
  const s = await server({
    UpdateSubscription: (request) => ({
      name: request.subscription.name,
      topic: "t",
      ackDeadlineSeconds: request.subscription.ackDeadlineSeconds,
    }),
  });
  t.after(s.close);
  const { transport } = setup(s.target, {
    getToken: async () => TOKEN,
    quotaProject: "demo-project",
  });
  await transport.call({
    label: {},
    op: "update",
    service: "Subscriber",
    method: "UpdateSubscription",
    request: {
      subscription: { name: "projects/p/subscriptions/s", ackDeadlineSeconds: 20 },
      updateMask: "ackDeadlineSeconds,pushConfig.pushEndpoint",
    },
  });
  assert.deepEqual(s.calls[0].request.updateMask, {
    paths: ["ack_deadline_seconds", "push_config.push_endpoint"],
  });
  await transport.call({
    label: {},
    op: "x",
    service: "Subscriber",
    method: "GetSnapshot",
    request: { snapshot: "projects/p/snapshots/n" },
    token: "none",
  });
  await transport.call({
    label: {},
    op: "x",
    service: "Subscriber",
    method: "GetSnapshot",
    request: { snapshot: "projects/p/snapshots/n" },
    token: "invalid",
  });
  assert.equal(s.calls[1].metadata.authorization, undefined);
  assert.equal(s.calls[1].metadata["x-goog-user-project"], undefined);
  assert.equal(s.calls[2].metadata.authorization, "Bearer invalid-token-for-the-recording");
  transport.close();
});

test("an error status is captured with its name and message, and only the unsure ones are unknown answers", async (t) => {
  const s = await server({
    GetTopic: () => ({
      error: { code: grpc.status.NOT_FOUND, details: "Resource not found (resource=t)." },
    }),
    DeleteTopic: () => ({ error: { code: grpc.status.UNAVAILABLE, details: "try later" } }),
    GetSnapshot: () => ({ error: { code: grpc.status.INTERNAL, details: "boom" } }),
    ListSnapshots: () => ({ error: { code: grpc.status.INVALID_ARGUMENT, details: "bad" } }),
  });
  t.after(s.close);
  const { transport, lines } = setup(s.target);
  const call = (service, method, request) =>
    transport.call({ label: {}, op: "x", service, method, request });
  const missing = await call("Publisher", "GetTopic", { topic: "projects/p/topics/t" });
  assert.deepEqual(missing, {
    code: "NOT_FOUND",
    message: "Resource not found (resource=t).",
    body: undefined,
    unknown: false,
  });
  assert.equal(
    (await call("Publisher", "DeleteTopic", { topic: "projects/p/topics/t" })).unknown,
    true,
  );
  assert.equal(
    (await call("Subscriber", "GetSnapshot", { snapshot: "projects/p/snapshots/n" })).unknown,
    true,
  );
  assert.equal(
    (await call("Subscriber", "ListSnapshots", { project: "projects/p" })).unknown,
    false,
  );
  assert.deepEqual(
    lines.map((line) => line.response.code),
    ["NOT_FOUND", "UNAVAILABLE", "INTERNAL", "INVALID_ARGUMENT"],
  );
  assert.equal(lines[0].unknown, undefined);
  assert.equal(lines[1].unknown, true);
  transport.close();
});

test("a deadline is an unknown answer, a call over the budget is refused unsent, and the arguments are checked", async (t) => {
  const s = await server({ Pull: () => HANG });
  t.after(s.close);
  const { transport, lines, budget } = setup(s.target, { max: 1 });
  const pulled = await transport.call({
    label: {},
    op: "pull",
    service: "Subscriber",
    method: "Pull",
    request: { subscription: "projects/p/subscriptions/s", maxMessages: 1 },
    timeoutMs: 150,
  });
  assert.equal(pulled.code, "DEADLINE_EXCEEDED");
  assert.equal(pulled.unknown, true);
  assert.equal(lines[0].unknown, true);
  assert.equal(budget.used(), 1);
  await assert.rejects(
    transport.call({ label: {}, op: "x", service: "Subscriber", method: "Pull", request: {} }),
    /budget of 1 is spent/,
  );
  assert.equal(s.calls.length, 1);
  await assert.rejects(
    transport.call({ label: {}, op: "x", service: "Publisher", method: "Nope", request: {} }),
    /unknown method Publisher\/Nope/,
  );
  await assert.rejects(
    transport.call({ label: {}, op: "x", service: "Nope", method: "Pull", request: {} }),
    /unknown method/,
  );
  for (const bad of ["", "localhost", "host:port", undefined, 5])
    assert.throws(
      () => createGrpc({ target: bad, secure: false, budget, capture: { record() {} } }),
      /host:port/,
      String(bad),
    );
  transport.close();
});
