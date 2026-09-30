import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-corpus/peer-grpc-transport.mjs", import.meta.url);
const frame = (bytes) => Buffer.concat([Buffer.from([0, 0, 0, 0, bytes.length]), bytes]);
function fakeSession() {
  const stream = new EventEmitter();
  stream.sent = [];
  stream.close = (code) => {
    stream.cancels = (stream.cancels ?? 0) + 1;
    stream.cancelCode = code;
    stream.emit("close");
  };
  stream.end = (bytes) => stream.sent.push(bytes);
  let requests = 0,
    destroyed = 0;
  const session = new EventEmitter();
  session.request = (requestHeaders) => {
    requests++;
    session.headers = requestHeaders;
    return stream;
  };
  session.destroy = () => {
    destroyed++;
    session.emit("close");
  };
  return {
    session,
    stream,
    get requests() {
      return requests;
    },
    get destroyed() {
      return destroyed;
    },
  };
}
async function adapter(fake, extra = {}) {
  assert.ok(existsSync(target), "peer-trailer recorder is missing");
  const { createPeerGrpcTransport } = await import(target.href);
  return createPeerGrpcTransport(fake.session, {
    authority: "http://127.0.0.1:1234",
    maxResponseBytes: 1024,
    maxHeaderBytes: 1024,
    ...extra,
  });
}
const request = () => ({
  path: "/google.pubsub.v1.Publisher/GetTopic",
  requestBytes: Buffer.from([10, 1, 65]),
  metadata: { "x-goog-request-params": "topic=owned" },
  deadline: new Date(Date.now() + 1000),
});
function headers(stream, extra = {}) {
  const h = { ":status": 200, "content-type": "application/grpc", ...extra };
  stream.emit(
    "response",
    h,
    0,
    Object.entries(h).flatMap(([k, v]) => [k, String(v)]),
  );
}
function trailers(stream, code = "0", extra = {}) {
  const h = { "grpc-status": code, ...extra };
  stream.emit(
    "trailers",
    h,
    0,
    Object.entries(h).flatMap(([k, v]) => [k, String(v)]),
  );
}
test("exact unary HTTP2 frame and peer trailers preserve bytes, raw header order and binary metadata", async () => {
  const f = fakeSession(),
    t = await adapter(f);
  try {
    const p = t.send(request());
    assert.equal(f.requests, 1);
    assert.equal(f.session.headers[":method"], "POST");
    assert.equal(f.session.headers[":path"], request().path);
    assert.equal(f.session.headers.te, "trailers");
    assert.equal(f.session.headers["grpc-accept-encoding"], "identity");
    assert.deepEqual(f.stream.sent, [Buffer.from([0, 0, 0, 0, 3, 10, 1, 65])]);
    headers(f.stream);
    f.stream.emit("data", Buffer.from([0, 0]));
    f.stream.emit("data", Buffer.from([0, 0, 2, 18, 0]));
    trailers(f.stream, "0", {
      "grpc-message": "hello%20world",
      key: "first,second",
      "details-bin": "AQI=",
    });
    f.stream.emit("end");
    const r = await p;
    assert.equal(r.statusOrigin, "peer-trailers");
    assert.deepEqual(r.responseBytes, Buffer.from([18, 0]));
    assert.equal(r.status.details, "hello world");
    assert.deepEqual(r.status.metadata["details-bin"], [Buffer.from([1, 2])]);
    assert.deepEqual(r.wire.trailers, [
      "grpc-status",
      "0",
      "grpc-message",
      "hello%20world",
      "key",
      "first,second",
      "details-bin",
      "AQI=",
    ]);
    assert.equal(r.wire.dataBase64, "AAAAAAISAA==");
  } finally {
    t.close();
  }
});
test("trailers-only peer refusal is recorded without inventing a unary response message", async () => {
  const f = fakeSession(),
    t = await adapter(f);
  try {
    const p = t.send(request());
    const h = {
      ":status": 200,
      "content-type": "application/grpc",
      "grpc-status": "5",
      "grpc-message": "missing",
    };
    f.stream.emit(
      "response",
      h,
      1,
      Object.entries(h).flatMap(([k, v]) => [k, String(v)]),
    );
    f.stream.emit("end");
    const r = await p;
    assert.equal(r.statusOrigin, "peer-trailers");
    assert.equal(r.status.code, 5);
    assert.equal(r.responseBytes, undefined);
    assert.equal(r.wire.dataBase64, "");
  } finally {
    t.close();
  }
});
test("defined zero-byte Empty message differs from missing message under peer status zero", async () => {
  for (const available of [true, false]) {
    const f = fakeSession(),
      t = await adapter(f);
    try {
      const p = t.send(request());
      headers(f.stream);
      if (available) f.stream.emit("data", Buffer.from([0, 0, 0, 0, 0]));
      trailers(f.stream);
      f.stream.emit("end");
      const r = await p;
      assert.equal(r.statusOrigin, available ? "peer-trailers" : "unverified");
      if (available) assert.equal(r.responseBytes.length, 0);
      else assert.equal(r.responseBytes, undefined);
    } finally {
      t.close();
    }
  }
});
test("malformed compressed duplicate or truncated unary frames never become a confirmed service result", async () => {
  for (const body of [
    Buffer.from([1, 0, 0, 0, 0]),
    Buffer.concat([frame(Buffer.from([1])), frame(Buffer.from([2]))]),
    Buffer.from([0, 0, 0, 0, 2, 1]),
    Buffer.from([0, 0, 0]),
  ]) {
    const f = fakeSession(),
      t = await adapter(f);
    try {
      const p = t.send(request());
      headers(f.stream);
      f.stream.emit("data", body);
      trailers(f.stream);
      f.stream.emit("end");
      const r = await p;
      assert.equal(r.statusOrigin, "unverified");
      assert.equal(r.wire.dataBase64, body.toString("base64"));
    } finally {
      t.close();
    }
  }
});
test("HTTP status invalid grpc-status and missing trailers preserve wire evidence without invented statuses", async () => {
  for (const mode of ["http", "bad-status", "no-trailers", "content-type"]) {
    const f = fakeSession(),
      t = await adapter(f);
    try {
      const p = t.send(request());
      headers(
        f.stream,
        mode === "http"
          ? { ":status": 503 }
          : mode === "content-type"
            ? { "content-type": "text/html" }
            : {},
      );
      f.stream.emit("data", frame(Buffer.from([1])));
      if (mode !== "no-trailers") trailers(f.stream, mode === "bad-status" ? "bogus" : "0");
      f.stream.emit("end");
      const r = await p;
      assert.equal(r.statusOrigin, "unverified");
      assert.ok(r.wire.dataBase64);
      if (mode === "bad-status" || mode === "no-trailers") assert.equal(r.status, undefined);
    } finally {
      t.close();
    }
  }
});
test("reset after observed headers/data remains uncertain and never waits for nonexistent trailers", async () => {
  const f = fakeSession(),
    t = await adapter(f);
  try {
    const p = t.send(request());
    headers(f.stream);
    f.stream.emit("data", Buffer.from([0, 0]));
    f.stream.emit("error", new Error("secret-token"));
    const r = await p;
    assert.equal(r.statusOrigin, "unverified");
    assert.equal(r.reason, "stream-error");
    assert.equal(r.wire.dataBase64, "AAA=");
    assert.ok(!JSON.stringify(r).includes("secret-token"));
  } finally {
    t.close();
  }
});
test("response and header overflow stop only the owned stream and preserve explicit truncation", async () => {
  for (const mode of ["body", "headers"]) {
    const f = fakeSession(),
      t = await adapter(f, mode === "body" ? { maxResponseBytes: 3 } : { maxHeaderBytes: 3 });
    try {
      const p = t.send(request());
      headers(f.stream);
      if (mode === "body") f.stream.emit("data", Buffer.from([0, 0, 0, 0, 0]));
      const r = await p;
      assert.equal(r.statusOrigin, "unverified");
      assert.equal(r.wire.truncated, true);
      assert.equal(f.stream.cancels, 1);
      if (mode === "body") assert.equal(Buffer.from(r.wire.dataBase64, "base64").length, 3);
    } finally {
      t.close();
    }
  }
});
test("deterministic timeout and abort preserve observed peer fields under uncertainty and cancel exactly once", async (ctx) => {
  let timer;
  ctx.mock.method(globalThis, "setTimeout", (fn) => {
    timer = fn;
    return { owned: true };
  });
  ctx.mock.method(globalThis, "clearTimeout", () => {});
  for (const mode of ["deadline", "abort"]) {
    const f = fakeSession(),
      t = await adapter(f),
      controller = new AbortController();
    try {
      const p = t.send({ ...request(), signal: controller.signal });
      headers(f.stream);
      if (mode === "deadline") timer();
      else controller.abort();
      const r = await p;
      assert.equal(r.statusOrigin, "unverified");
      assert.equal(r.reason, mode);
      assert.equal(f.stream.cancels, 1);
    } finally {
      t.close();
    }
  }
});
test("close owns only the supplied session and stream, is idempotent and refuses later dispatch", async () => {
  const f = fakeSession(),
    t = await adapter(f),
    p = t.send(request());
  t.close();
  const r = await p;
  assert.equal(r.statusOrigin, "unverified");
  assert.equal(f.destroyed, 1);
  assert.equal(f.stream.cancels, 1);
  t.close();
  assert.equal(f.destroyed, 1);
  await assert.rejects(t.send(request()));
  assert.equal(f.requests, 1);
});
test("expired deadlines and overriding protocol pseudoheaders never reach session.request", async () => {
  for (const extra of [
    { deadline: new Date(Date.now() - 1) },
    { metadata: { ":authority": "unowned" } },
    { metadata: { "grpc-timeout": "999999H" } },
  ]) {
    const f = fakeSession(),
      t = await adapter(f);
    try {
      await assert.rejects(t.send({ ...request(), ...extra }));
      assert.equal(f.requests, 0);
    } finally {
      t.close();
    }
  }
});
test("session goaway halts pending and future attempts without retrying another stream", async () => {
  const f = fakeSession(),
    t = await adapter(f);
  try {
    const p = t.send(request());
    f.session.emit("goaway", 0, 0, Buffer.alloc(0));
    assert.equal((await p).statusOrigin, "unverified");
    await assert.rejects(t.send(request()));
    assert.equal(f.requests, 1);
  } finally {
    t.close();
  }
});
test("request payload and response capture have independent explicit byte bounds", async () => {
  const f = fakeSession(),
    t = await adapter(f, { maxResponseBytes: 1, maxRequestBytes: 8 });
  try {
    const p = t.send(request());
    assert.equal(f.requests, 1);
    const h = { ":status": 200, "content-type": "application/grpc", "grpc-status": "3" };
    f.stream.emit(
      "response",
      h,
      1,
      Object.entries(h).flatMap(([k, v]) => [k, String(v)]),
    );
    f.stream.emit("end");
    assert.equal((await p).statusOrigin, "peer-trailers");
    await assert.rejects(t.send({ ...request(), requestBytes: Buffer.alloc(9) }));
    assert.equal(f.requests, 1);
  } finally {
    t.close();
  }
});
test("duplicate peer trailer pairs and binary values remain distinct in raw and decoded metadata", async () => {
  const f = fakeSession(),
    t = await adapter(f);
  try {
    const p = t.send(request());
    headers(f.stream);
    f.stream.emit("data", frame(Buffer.from([1])));
    const raw = [
      "grpc-status",
      "0",
      "key",
      "first",
      "key",
      "second",
      "value-bin",
      "AQ==",
      "value-bin",
      "Ag==",
    ];
    f.stream.emit("trailers", { "grpc-status": "0" }, 0, raw);
    f.stream.emit("end");
    const r = await p;
    assert.deepEqual(r.wire.trailers, raw);
    assert.deepEqual(r.status.metadata.key, ["first", "second"]);
    assert.deepEqual(r.status.metadata["value-bin"], [Buffer.from([1]), Buffer.from([2])]);
  } finally {
    t.close();
  }
});
test("every additional peer header block is bounded and preserved or explicitly truncated under uncertainty", async () => {
  for (const oversized of [false, true]) {
    const f = fakeSession(),
      t = await adapter(f, { maxHeaderBytes: 128 });
    try {
      const p = t.send(request());
      const raw = [":status", "103", "hint", oversized ? "x".repeat(4096) : "small"];
      f.stream.emit("headers", { ":status": 103 }, 0, raw);
      const r = await p;
      assert.equal(r.statusOrigin, "unverified");
      assert.equal(r.reason, oversized ? "header-bound" : "extra-headers");
      assert.equal(f.stream.cancels, 1);
      if (oversized) assert.equal(r.wire.truncated, true);
      else assert.deepEqual(r.wire.additionalHeaders, [raw]);
    } finally {
      t.close();
    }
  }
});
