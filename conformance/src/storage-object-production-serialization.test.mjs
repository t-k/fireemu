import assert from "node:assert/strict";
import test from "node:test";
import { PRODUCTION_WIRE_ORIGINS } from "./storage-object/production-tls.mjs";
const module = await import("./storage-object/production-serialization.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const serialize = (route, init) => {
  assert.equal(
    typeof module.serializeProductionHttpRequest,
    "function",
    "production framing is missing",
  );
  return module.serializeProductionHttpRequest(route, init);
};

test("production framing uses explicit HTTP1.1 headers and counts the original body for each closed origin", () => {
  for (const origin of PRODUCTION_WIRE_ORIGINS) {
    const body = Buffer.from([0, 1, 255]);
    const serialized = serialize(
      Object.freeze({ method: "POST", url: origin + "/path?key=NEW_FIXTURE_KEY" }),
      {
        headers: {
          authorization: "Bearer NEW_FIXTURE_ACCESS_TOKEN",
          "content-type": "application/octet-stream",
        },
        body,
      },
    );
    const expected = Buffer.concat([
      Buffer.from(
        `POST /path?key=NEW_FIXTURE_KEY HTTP/1.1\r\nHost: ${new URL(origin).host}\r\nConnection: close\r\nContent-Length: 3\r\nAccept-Encoding: identity\r\nauthorization: Bearer NEW_FIXTURE_ACCESS_TOKEN\r\ncontent-type: application/octet-stream\r\n\r\n`,
      ),
      body,
    ]);
    assert.deepEqual(serialized.wire, expected);
    assert.deepEqual(serialized.body, body);
    body.fill(7);
    assert.deepEqual(serialized.body, Buffer.from([0, 1, 255]));
  }
});

test("unlisted origin, authority, ports and conflicting methods reject without revealing wire values", () => {
  for (const url of [
    "http://storage.googleapis.com/path",
    "https://storage.googleapis.com:444/path",
    "https://storage.googleapis.com.evil.example/path",
    "https://NEW_SECRET@storage.googleapis.com/path",
    "https://storage.googleapis.com/path#NEW_SECRET",
    "http://127.0.0.1:9999/path",
  ])
    assert.throws(
      () => serialize(Object.freeze({ method: "GET", url }), {}),
      /^Error: invalid production wire request$/,
    );
  assert.throws(
    () =>
      serialize(Object.freeze({ method: "GET", url: "https://storage.googleapis.com/path" }), {
        method: "DELETE",
      }),
    /^Error: invalid production wire request$/,
  );
});

test("production headers and options have a closed vocabulary with no framing or provider override", () => {
  const route = Object.freeze({ method: "GET", url: "https://storage.googleapis.com/path" });
  for (const headers of [
    { host: "NEW_SECRET" },
    { connection: "keep-alive" },
    { "transfer-encoding": "chunked" },
    { "x-unknown": "NEW_SECRET" },
    { authorization: "Bearer NEW_SECRET\r\nHost: other" },
    { "content-length": "1" },
    { Authorization: "Bearer NEW_SECRET", authorization: "Bearer OTHER" },
  ])
    assert.throws(() => serialize(route, { headers }), /^Error: invalid production wire request$/);
  for (const change of [
    { ca: "NEW_SECRET" },
    { dispatcher: {} },
    { redirect: "follow" },
    { body: {} },
    { body: Buffer.alloc(2 * 1024 * 1024 + 1) },
  ])
    assert.throws(() => serialize(route, change), /^Error: invalid production wire request$/);
  assert.equal(
    serialize(route, { headers: { "content-length": "0" }, redirect: "manual" }).body.length,
    0,
  );
});

test("accessors in route, options and headers are rejected before invoking them", () => {
  let calls = 0;
  const getter = {
    enumerable: true,
    get() {
      calls++;
      throw new Error("NEW_GETTER_SECRET");
    },
  };
  const route = Object.freeze({ method: "GET", url: "https://storage.googleapis.com/path" });
  for (const [badRoute, init] of [
    [Object.freeze(Object.defineProperty({ method: "GET" }, "url", getter)), {}],
    [route, Object.defineProperty({}, "body", getter)],
    [route, { headers: Object.defineProperty({}, "authorization", getter) }],
  ])
    assert.throws(() => serialize(badRoute, init), /^Error: invalid production wire request$/);
  assert.equal(calls, 0);
});

test("Buffer properties cannot disguise the body cap or change bytes through accessors", () => {
  const route = Object.freeze({ method: "POST", url: "https://storage.googleapis.com/path" });
  const oversized = Object.defineProperty(Buffer.alloc(2 * 1024 * 1024 + 1), "byteLength", {
    value: 0,
  });
  assert.throws(
    () => serialize(route, { body: oversized }),
    /^Error: invalid production wire request$/,
  );
  let calls = 0;
  for (const key of ["length", "byteLength", "byteOffset", "buffer"]) {
    const body = Object.defineProperty(Buffer.from([1, 2, 3]), key, {
      get() {
        calls++;
        return 0;
      },
    });
    assert.throws(() => serialize(route, { body }), /^Error: invalid production wire request$/);
  }
  assert.equal(calls, 0);
});

test("only ordinary Buffer views are accepted, preserving offsets and the exact cap", () => {
  const route = Object.freeze({ method: "POST", url: "https://storage.googleapis.com/path" });
  const backing = Buffer.from([9, 1, 2, 3, 8]);
  assert.deepEqual(serialize(route, { body: backing.subarray(1, 4) }).body, Buffer.from([1, 2, 3]));
  const full = Buffer.alloc(2 * 1024 * 1024, 7);
  assert.deepEqual(serialize(route, { body: full }).body, full);
  assert.equal(serialize(route, { body: "a".repeat(2 * 1024 * 1024) }).body.length, full.length);
  assert.throws(
    () => serialize(route, { body: "a".repeat(full.length + 1) }),
    /^Error: invalid production wire request$/,
  );
  const unusual = Buffer.from([1, 2, 3]);
  Object.setPrototypeOf(unusual, Object.create(Buffer.prototype));
  assert.throws(
    () => serialize(route, { body: unusual }),
    /^Error: invalid production wire request$/,
  );
  let calls = 0;
  const proxy = new Proxy(Buffer.from([1, 2, 3]), {
    get() {
      calls++;
      throw new Error("NEW_PROXY_SECRET");
    },
  });
  assert.throws(
    () => serialize(route, { body: proxy }),
    /^Error: invalid production wire request$/,
  );
  assert.equal(calls, 0);
});
