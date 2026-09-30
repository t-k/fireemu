import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-corpus/grpc-transport.mjs", import.meta.url);
async function adapter(client) {
  assert.ok(existsSync(target), "raw native gRPC adapter is missing");
  const { createRawGrpcTransport } = await import(target.href);
  return createRawGrpcTransport(client, () => ({ set() {} }));
}
const request = () => ({
  path: "/google.pubsub.v1.Publisher/GetTopic",
  requestBytes: Buffer.from([10, 0]),
  metadata: { "x-goog-request-params": "topic=owned" },
  deadline: new Date(Date.now() + 1000),
  signal: AbortSignal.timeout(1000),
});
function fakeClient(reply) {
  const call = new EventEmitter();
  call.cancel = () => {
    call.cancels = (call.cancels ?? 0) + 1;
  };
  let closed = 0;
  return {
    call,
    get closed() {
      return closed;
    },
    close() {
      closed++;
    },
    makeUnaryRequest(path, serialize, deserialize, input, metadata, options, callback) {
      assert.equal(path, request().path);
      assert.deepEqual(serialize(input), Buffer.from([10, 0]));
      assert.deepEqual(deserialize(Buffer.from([18, 0])), Buffer.from([18, 0]));
      assert.ok(options.deadline instanceof Date);
      queueMicrotask(() => reply(call, callback));
      return call;
    },
  };
}
test("callback and status order both preserve raw response bytes and final trailers", async () => {
  for (const order of ["callback-first", "status-first"]) {
    const client = fakeClient((call, callback) => {
      const status = { code: 0, details: "", metadata: { getMap: () => ({ key: "value" }) } };
      if (order === "callback-first") {
        callback(null, Buffer.from([18, 0]));
        call.emit("status", status);
      } else {
        call.emit("status", status);
        callback(null, Buffer.from([18, 0]));
      }
    });
    const transport = await adapter(client);
    const result = await transport.send(request());
    assert.equal(result.responseBytes.toString("base64"), "EgA=");
    assert.equal(result.status.code, 0);
    assert.deepEqual(result.status.metadata, { key: ["value"] });
    transport.close();
    assert.equal(client.closed, 1);
  }
});
test("native non-OK terminals retain public status and details without converting exception messages", async () => {
  const client = fakeClient((call, callback) => {
    callback(Object.assign(new Error("secret-token"), { code: 5, details: "resource missing" }));
    call.emit("status", { code: 5, details: "resource missing", metadata: { getMap: () => ({}) } });
  });
  const transport = await adapter(client);
  const result = await transport.send(request());
  assert.equal(result.status.code, 5);
  assert.equal(result.status.details, "resource missing");
  assert.equal(result.responseBytes, undefined);
  assert.ok(!JSON.stringify(result).includes("secret-token"));
  transport.close();
});
test("abort cancels only the owned call and settles even if the callback never arrives", async () => {
  const client = fakeClient(() => {});
  const transport = await adapter(client);
  const controller = new AbortController();
  const promise = transport.send({ ...request(), signal: controller.signal });
  controller.abort();
  await assert.rejects(promise);
  assert.equal(client.call.cancels, 1);
  transport.close();
  assert.equal(client.closed, 1);
});
test("close cancels pending calls, closes once and refuses later requests", async () => {
  const client = fakeClient(() => {});
  const transport = await adapter(client);
  const pending = transport.send(request());
  transport.close();
  await assert.rejects(pending);
  transport.close();
  assert.equal(client.closed, 1);
  assert.equal(client.call.cancels, 1);
  await assert.rejects(transport.send(request()));
});
test("duplicate metadata values are preserved rather than collapsed to getMap first values", async () => {
  const metadata = {
    getMap: () => ({ key: "first", "binary-bin": Buffer.from([1]) }),
    get: (key) => (key === "key" ? ["first", "second"] : [Buffer.from([1]), Buffer.from([2])]),
  };
  const client = fakeClient((call, callback) => {
    call.emit("status", { code: 0, details: "", metadata });
    callback(null, Buffer.alloc(0));
  });
  const transport = await adapter(client);
  const result = await transport.send(request());
  assert.deepEqual(result.status.metadata.key, ["first", "second"]);
  assert.deepEqual(result.status.metadata["binary-bin"], [Buffer.from([1]), Buffer.from([2])]);
  transport.close();
});

test(
  "absolute deadline settles and cancels an unresponsive owned call without relying on grpc callbacks",
  { timeout: 1000 },
  async () => {
    const client = fakeClient(() => {});
    const transport = await adapter(client);
    const result = transport.send({
      ...request(),
      deadline: new Date(Date.now() + 100),
      signal: undefined,
    });
    await assert.rejects(result);
    assert.equal(client.call.cancels, 1);
    transport.close();
  },
);

test("synchronous cancel status cannot turn local interruption into a service refusal record", async () => {
  const client = fakeClient(() => {});
  const original = client.makeUnaryRequest.bind(client);
  let callback;
  client.makeUnaryRequest = (...args) => {
    callback = args.at(-1);
    return original(...args);
  };
  client.call.cancel = () => {
    client.call.cancels = (client.call.cancels ?? 0) + 1;
    callback(Object.assign(new Error("cancelled"), { code: 1 }));
    client.call.emit("status", {
      code: 1,
      details: "local cancelled",
      metadata: { getMap: () => ({}) },
    });
  };
  const transport = await adapter(client);
  const controller = new AbortController();
  const pending = transport.send({ ...request(), signal: controller.signal });
  controller.abort();
  await assert.rejects(pending);
  assert.equal(client.call.cancels, 1);
  transport.close();
});

for (const order of ["adapter-first", "client-first"]) {
  test(`deadline terminal ordering ${order} never confirms a peer refusal`, async (t) => {
    let now = 10000,
      mono = 0,
      timer,
      callback;
    t.mock.method(Date, "now", () => now);
    t.mock.method(performance, "now", () => mono);
    t.mock.method(globalThis, "setTimeout", (fn) => {
      timer = fn;
      return { owned: true };
    });
    t.mock.method(globalThis, "clearTimeout", () => {});
    const client = fakeClient(() => {}),
      original = client.makeUnaryRequest.bind(client);
    client.makeUnaryRequest = (...args) => {
      callback = args.at(-1);
      return original(...args);
    };
    const transport = await adapter(client);
    try {
      const pending = transport.send({
        ...request(),
        deadline: new Date(now + 1000),
        signal: undefined,
      });
      now += 1001;
      mono += 1001;
      const terminal = () => {
        callback(Object.assign(new Error("secret-token"), { code: 4 }));
        client.call.emit("status", {
          code: 4,
          details: "Deadline exceeded",
          metadata: { getMap: () => ({ "raw-key": "value" }) },
        });
      };
      if (order === "adapter-first") {
        const rejected = assert.rejects(pending);
        timer();
        await rejected;
        terminal();
        assert.equal(client.call.cancels, 1);
      } else {
        terminal();
        const result = await pending;
        assert.equal(result.statusOrigin, "unverified");
        assert.equal(result.interruption, "deadline");
        assert.equal(result.status.code, 4);
        assert.deepEqual(result.status.metadata, { "raw-key": ["value"] });
        timer();
        assert.equal(client.call.cancels ?? 0, 0);
      }
    } finally {
      transport.close();
      t.mock.restoreAll();
    }
  });
}

test("trailers-only refusals preserve public fields but do not claim confirmed peer origin", async () => {
  const client = fakeClient((call, callback) => {
    callback(Object.assign(new Error("secret-token"), { code: 5 }));
    call.emit("status", {
      code: 5,
      details: "resource missing",
      metadata: { getMap: () => ({ "peer-key": "value" }) },
    });
  });
  const transport = await adapter(client);
  const result = await transport.send(request());
  assert.equal(result.statusOrigin, "unverified");
  assert.equal(result.status.details, "resource missing");
  assert.deepEqual(result.status.metadata, { "peer-key": ["value"] });
  transport.close();
});
test("status zero with a failed unary callback is uncertain while genuine Empty bytes are successful", async () => {
  for (const empty of [false, true]) {
    const client = fakeClient((call, callback) => {
      if (empty) callback(null, Buffer.alloc(0));
      else callback(Object.assign(new Error("No message received"), { code: 13 }));
      call.emit("status", { code: 0, details: "", metadata: { getMap: () => ({}) } });
    });
    const transport = await adapter(client);
    const result = await transport.send(request());
    assert.equal(result.statusOrigin, empty ? "successful-response" : "unverified");
    if (!empty) assert.equal(result.callbackCode, 13);
    transport.close();
  }
});

test("an already expired deadline refuses dispatch before calling the native client", async () => {
  let calls = 0;
  const client = fakeClient(() => {}),
    original = client.makeUnaryRequest.bind(client);
  client.makeUnaryRequest = (...args) => {
    calls++;
    return original(...args);
  };
  const transport = await adapter(client);
  await assert.rejects(
    transport.send({ ...request(), deadline: new Date(Date.now() - 1), signal: undefined }),
  );
  assert.equal(calls, 0);
  transport.close();
});
