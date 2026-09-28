import assert from "node:assert/strict";
import test from "node:test";
import { serializeLocalHttpRequest } from "./storage-object/wire-serialization.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
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

test("canonical GCS resumable chunks, query and cancellation retain exact declared lengths with one framing header", () => {
  const recipe = buildCorpus({
    bucket: "example.appspot.com",
    prefix: "storage-object/run/",
  }).recipes.find((row) => row.id === "storage-object/gcs/resumable-upload");
  const continuations = [...recipe.steps, ...recipe.cleanup].filter(
    (step) => step.sessionUriReference,
  );
  assert.equal(continuations.length, 5);
  for (const step of continuations) {
    const body = step.body ? Buffer.from(step.body.base64, "base64") : undefined;
    const serialized = serialize(
      "/upload/storage/v1/b/example.appspot.com/o?upload_id=synthetic-session",
      {
        method: step.method,
        headers: step.headers,
        body,
      },
    );
    const names = serialized.headers.filter((_, index) => index % 2 === 0);
    assert.equal(names.filter((name) => name.toLowerCase() === "content-length").length, 1);
    assert.equal(serialized.headers[5], step.headers["content-length"]);
    assert.equal(serialized.body.length, Number(step.headers["content-length"]));
    assert.ok(
      serialized.wire
        .subarray(-serialized.body.length || serialized.wire.length)
        .equals(serialized.body),
    );
  }
});

test("declared Content-Length must match actual UTF8 bytes and reject mismatches, duplicate casing and noncanonical forms", () => {
  const body = "日本語";
  assert.equal(
    serialize("/x", { method: "POST", body, headers: { "Content-Length": "9" } }).headers[5],
    "9",
  );
  for (const value of ["3", "8", "10", "09", " 9", "+9", "9 ", "9.0"])
    assert.throws(
      () => serialize("/x", { body, headers: { "content-length": value } }),
      /invalid wire request/,
    );
  assert.throws(
    () => serialize("/x", { body, headers: { "Content-Length": "9", "content-length": "9" } }),
    /invalid wire request/,
  );
  assert.throws(
    () => serialize("/x", { headers: { "content-length": "1" } }),
    /invalid wire request/,
  );
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
