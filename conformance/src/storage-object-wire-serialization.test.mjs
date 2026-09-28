import assert from "node:assert/strict";
import test from "node:test";
import { serializeLocalHttpRequest } from "./storage-object/wire-serialization.mjs";
const origin = "http://127.0.0.1:9999";
const serialize = (path, init = {}) => serializeLocalHttpRequest(origin + path, init, [origin]);

test("explicit framing preserves exact binary body and encoded request target", () => {
  const body = Buffer.from([0, 255, 1]);
  const result = serialize("/storage/name%2Fvalue?key=synthetic%2Fkey", {
    method: "PUT",
    headers: { "x-goog-upload-command": "upload" },
    body,
  });
  assert.equal(
    result.headers.join("|"),
    "Host|127.0.0.1:9999|Connection|close|Content-Length|3|Accept-Encoding|identity|x-goog-upload-command|upload",
  );
  assert.deepEqual(
    result.wire,
    Buffer.concat([
      Buffer.from(
        "PUT /storage/name%2Fvalue?key=synthetic%2Fkey HTTP/1.1\r\nHost: 127.0.0.1:9999\r\nConnection: close\r\nContent-Length: 3\r\nAccept-Encoding: identity\r\nx-goog-upload-command: upload\r\n\r\n",
      ),
      body,
    ]),
  );
});

test("UTF8 JSON Content-Length counts bytes and empty GET explicitly has zero body", () => {
  const json = '{"value":"日本語"}';
  const post = serialize("/auth", { method: "POST", body: json });
  assert.equal(post.headers[5], `${Buffer.byteLength(json)}`);
  const get = serialize("/read");
  assert.equal(get.headers[5], "0");
  assert.equal(get.body.length, 0);
});

for (const header of [
  "Host",
  "Connection",
  "Content-Length",
  "Transfer-Encoding",
  "Accept-Encoding",
  "Upgrade",
  "Expect",
  "Trailer",
]) {
  test(`caller-supplied ${header} cannot change serialization`, () =>
    assert.throws(
      () => serialize("/x", { headers: { [header]: "unsafe" } }),
      /invalid wire request/,
    ));
}

test("control characters, duplicate casing, object bodies and unbounded header/body reject", () => {
  for (const init of [
    { headers: { x: "a\r\nsecret" } },
    { headers: { x: "日本語" } },
    { headers: { X: "1", x: "2" } },
    { headers: { x: ["1"] } },
    { body: { json: {} } },
    { body: Buffer.alloc(2 * 1024 * 1024 + 1) },
    { headers: { x: "a".repeat(16 * 1024) } },
    { method: "CONNECT" },
  ])
    assert.throws(() => serialize("/x", init), /invalid wire request/);
});

test("off-origin and URL authority secrets reject without echoing their values", () => {
  for (const url of [
    "https://example.com/?key=synthetic-secret",
    "http://user:synthetic-secret@127.0.0.1:9999/x",
    origin + "/x#synthetic-secret",
  ]) {
    assert.throws(
      () => serializeLocalHttpRequest(url, {}, [origin]),
      (error) =>
        /invalid wire request/.test(error.message) && !error.message.includes("synthetic-secret"),
    );
  }
});
