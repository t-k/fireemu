// The rehearsal maps the real hosts the lean wire sends to onto a local fireemu, so a local run can
// go through `lean-wire.mjs` itself. This tests only that mapping; the run is `local-aggregate.mjs`.

import assert from "node:assert/strict";
import test from "node:test";
import { createLocalFetchForLeanWire } from "./storage-object/local-lean-wire.mjs";

const LOCAL = {
  storage: "http://127.0.0.1:9199",
  auth: "http://127.0.0.1:9099",
  control: "http://127.0.0.1:9198",
};
const TOKEN = "rehearsal-owner-token-0000000000";

function harness(respond = () => new Response("{}", { status: 200 })) {
  const calls = [];
  const fetchImpl = createLocalFetchForLeanWire({
    local: LOCAL,
    ownerToken: TOKEN,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return respond(String(url), init);
    },
  });
  return { fetchImpl, calls };
}

test("each real host goes to the local server that stands in for it", async () => {
  const cases = [
    [
      "https://firebasestorage.googleapis.com/v0/b/b/o/x?alt=media",
      `${LOCAL.storage}/v0/b/b/o/x?alt=media`,
    ],
    [
      "https://storage.googleapis.com/storage/v1/b/b/o?prefix=p",
      `${LOCAL.storage}/storage/v1/b/b/o?prefix=p`,
    ],
    [
      "https://storage.googleapis.com/upload/storage/v1/b/b/o?uploadType=media&name=n",
      `${LOCAL.storage}/upload/storage/v1/b/b/o?uploadType=media&name=n`,
    ],
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
      `${LOCAL.auth}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k`,
    ],
    [
      "https://securetoken.googleapis.com/v1/token?key=k",
      `${LOCAL.auth}/securetoken.googleapis.com/v1/token?key=k`,
    ],
  ];
  for (const [real, local] of cases) {
    const h = harness();
    await h.fetchImpl(real, { method: "GET", headers: {} });
    assert.equal(h.calls[0].url, local);
  }
});

test("a host that is not one of the four is refused and nothing goes out", async () => {
  const h = harness();
  for (const url of [
    "https://evil.example/v0/b/b/o/x",
    "http://127.0.0.1:9199/v0/b/b/o/x",
    "https://firebaserules.googleapis.com/v1/projects/p/releases/x",
  ]) {
    await assert.rejects(h.fetchImpl(url, { method: "GET", headers: {} }), url);
  }
  assert.equal(h.calls.length, 0);
});

test("the owner token becomes the local server's owner credential, other credentials are untouched", async () => {
  const h = harness();
  await h.fetchImpl("https://storage.googleapis.com/storage/v1/b/b/o", {
    method: "GET",
    headers: { authorization: `Bearer ${TOKEN}`, "x-goog-user-project": "example-project" },
  });
  await h.fetchImpl("https://firebasestorage.googleapis.com/v0/b/b/o/x", {
    method: "GET",
    headers: { authorization: "Firebase id.token.value" },
  });
  assert.equal(new Headers(h.calls[0].init.headers).get("authorization"), "Bearer owner");
  assert.equal(
    new Headers(h.calls[1].init.headers).get("authorization"),
    "Firebase id.token.value",
  );
});

test("a local URL in a response header is given back as the real host it stands for", async () => {
  const gcs = harness(
    () =>
      new Response("{}", {
        status: 200,
        headers: {
          location: `${LOCAL.storage}/upload/storage/v1/b/b/o?uploadType=resumable&upload_id=1`,
        },
      }),
  );
  const one = await gcs.fetchImpl(
    "https://storage.googleapis.com/upload/storage/v1/b/b/o?uploadType=resumable",
    { method: "POST", headers: {}, body: "{}" },
  );
  assert.equal(
    one.headers.get("location"),
    "https://storage.googleapis.com/upload/storage/v1/b/b/o?uploadType=resumable&upload_id=1",
  );
  const fb = harness(
    () =>
      new Response("{}", {
        status: 200,
        headers: { "x-goog-upload-url": `${LOCAL.storage}/v0/b/b/o?name=n&upload_id=1` },
      }),
  );
  const two = await fb.fetchImpl("https://firebasestorage.googleapis.com/v0/b/b/o?name=n", {
    method: "POST",
    headers: {},
    body: "{}",
  });
  assert.equal(
    two.headers.get("x-goog-upload-url"),
    "https://firebasestorage.googleapis.com/v0/b/b/o?name=n&upload_id=1",
  );
});

test("the status, the body and the other headers pass through", async () => {
  const h = harness(() => new Response("payload", { status: 404, headers: { "x-other": "v" } }));
  const response = await h.fetchImpl("https://storage.googleapis.com/storage/v1/b/b/o/x", {
    method: "GET",
    headers: {},
  });
  assert.equal(response.status, 404);
  assert.equal(await response.text(), "payload");
  assert.equal(response.headers.get("x-other"), "v");
});

test("a 204 keeps no body", async () => {
  const h = harness(() => new Response(null, { status: 204 }));
  const response = await h.fetchImpl("https://storage.googleapis.com/storage/v1/b/b/o/x", {
    method: "DELETE",
    headers: {},
  });
  assert.equal(response.status, 204);
});
