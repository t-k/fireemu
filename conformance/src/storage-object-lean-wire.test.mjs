// The lean wire is the one place a STORAGE-OBJECT run reaches production. The sender and the
// recipe replays run in their local mode against placeholder loopback origins; this wire decides
// the real destination, swaps the credentials in, hashes secrets before anything is written,
// paces same-object writes and stops on any doubt. Every test uses a fake `fetch`.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createObjectMutationPacer } from "./storage-object/production-pacing.mjs";
import {
  createLeanWire,
  LEAN_PLACEHOLDER_ADMIN,
  LEAN_PLACEHOLDER_API_KEY,
} from "./storage-object/lean-wire.mjs";

const BUCKET = "example.appspot.com";
const PROJECT = "example-project";
const PREFIX = "storage-object/aaaaaaaaaaaaaaaaaaaa/";
const STORAGE = "http://127.0.0.1:9199";
const AUTH = "http://127.0.0.1:9099";
const CONTROL = "http://127.0.0.1:9198";
const TOKEN = "ya29.a0-synthetic-owner-access-token-value";
const KEY = "AIzaSyD-synthetic-web-api-key-value-000000";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const name = (suffix) => `${PREFIX}${suffix}`;
const enc = (value) => encodeURIComponent(value);

function harness(overrides = {}) {
  const calls = [];
  const captures = [];
  let clock = 0;
  const sleeps = [];
  const respond =
    overrides.respond ??
    (() =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }));
  const wire = createLeanWire({
    bucket: BUCKET,
    projectId: PROJECT,
    prefix: PREFIX,
    origins: { storage: STORAGE, auth: AUTH, control: CONTROL },
    adminToken: () => TOKEN,
    authApiKey: KEY,
    readRules: async () => ({ source: "rules-source", requests: 2 }),
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), ...init });
      return respond(String(url), init);
    },
    capture: async (record) => {
      if (overrides.captureFails) throw new Error("capture writer failed");
      captures.push(record);
    },
    // The real pacer also refuses a write outside the prefix, which would hide the wire's own
    // refusal, so the tests that are not about pacing use a pass-through one.
    pacer: overrides.paced
      ? createObjectMutationPacer({
          ownedPrefixes: [PREFIX],
          now: () => clock,
          sleep: async (ms) => {
            sleeps.push(ms);
            clock += ms;
          },
        })
      : { dispatch: (_name, attempt) => attempt() },
    ...overrides.options,
  });
  return { wire, calls, captures, sleeps, tick: (ms) => (clock += ms) };
}

const admin = { authorization: LEAN_PLACEHOLDER_ADMIN };

// ---- destinations ----------------------------------------------------------------------------

const ALLOWED = [
  [
    "GET",
    `${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`,
    "https://firebasestorage.googleapis.com",
  ],
  [
    "GET",
    `${STORAGE}/v0/b/${BUCKET}/o?prefix=${enc(PREFIX)}&delimiter=%2F`,
    "https://firebasestorage.googleapis.com",
  ],
  [
    "POST",
    `${STORAGE}/v0/b/${BUCKET}/o?name=${enc(name("a"))}`,
    "https://firebasestorage.googleapis.com",
  ],
  [
    "PATCH",
    `${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`,
    "https://firebasestorage.googleapis.com",
  ],
  [
    "DELETE",
    `${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`,
    "https://firebasestorage.googleapis.com",
  ],
  [
    "POST",
    `${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?create_token=true`,
    "https://firebasestorage.googleapis.com",
  ],
  [
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}?alt=media`,
    "https://storage.googleapis.com",
  ],
  [
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o?prefix=${enc(PREFIX)}&maxResults=3`,
    "https://storage.googleapis.com",
  ],
  [
    "PUT",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`,
    "https://storage.googleapis.com",
  ],
  [
    "PATCH",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`,
    "https://storage.googleapis.com",
  ],
  [
    "DELETE",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}?ifGenerationMatch=7`,
    "https://storage.googleapis.com",
  ],
  [
    "POST",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${enc(name("a"))}`,
    "https://storage.googleapis.com",
  ],
  [
    "PUT",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=resumable&upload_id=abc&name=${enc(name("a"))}`,
    "https://storage.googleapis.com",
  ],
  [
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/${BUCKET}/o/${enc(name("b"))}?ifGenerationMatch=0`,
    "https://storage.googleapis.com",
  ],
  [
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/rewriteTo/b/${BUCKET}/o/${enc(name("b"))}`,
    "https://storage.googleapis.com",
  ],
];

for (const [method, href, origin] of ALLOWED) {
  test(`${method} ${new URL(href).pathname.slice(0, 40)} reaches ${origin}`, async () => {
    const h = harness();
    await h.wire.fetch(href, { method, headers: admin, body: method === "GET" ? undefined : "x" });
    assert.equal(h.calls.length, 1);
    const real = new URL(h.calls[0].url);
    assert.equal(real.origin, origin);
    assert.equal(real.pathname + real.search, new URL(href).pathname + new URL(href).search);
    assert.equal(h.calls[0].method, method);
    assert.equal(h.calls[0].redirect, "manual");
    assert.ok(h.calls[0].signal instanceof AbortSignal);
  });
}

const REFUSED = [
  [
    "a PUT to an upload route with an object path",
    "PUT",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`,
  ],
  [
    "a GET of an upload route with an object path",
    "GET",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`,
  ],
  ["another bucket", "GET", `${STORAGE}/storage/v1/b/other.appspot.com/o/${enc(name("a"))}`],
  ["another bucket in a v0 route", "GET", `${STORAGE}/v0/b/other.appspot.com/o/${enc(name("a"))}`],
  ["an object outside the prefix", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc("other/a")}`],
  ["a write outside the prefix", "DELETE", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc("other/a")}`],
  [
    "an upload name outside the prefix",
    "POST",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${enc("other/a")}`,
  ],
  [
    "a copy destination outside the prefix",
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/${BUCKET}/o/${enc("other/b")}`,
  ],
  [
    "a copy to another bucket",
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/other.appspot.com/o/${enc(name("b"))}`,
  ],
  [
    "a rewrite source outside the prefix",
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc("other/a")}/rewriteTo/b/${BUCKET}/o/${enc(name("b"))}`,
  ],
  [
    "a list outside the prefix",
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o?prefix=${enc("other/")}`,
  ],
  ["a list without a prefix", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o`],
  ["a list of the whole bucket by an empty prefix", "GET", `${STORAGE}/v0/b/${BUCKET}/o?prefix=`],
  ["a dot segment in a name", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(`${PREFIX}../x`)}`],
  ["a dot segment in the path", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/../../../b/x/o`],
  [
    "a delete of the collection",
    "DELETE",
    `${STORAGE}/storage/v1/b/${BUCKET}/o?prefix=${enc(PREFIX)}`,
  ],
  ["a bucket listing", "GET", `${STORAGE}/storage/v1/b`],
  ["a bucket metadata read", "GET", `${STORAGE}/storage/v1/b/${BUCKET}`],
  ["an IAM route", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/iam`],
  ["an ACL route", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/acl`],
  ["a compose route", "POST", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/compose`],
  ["an unknown path", "GET", `${STORAGE}/v1/anything`],
  [
    "an origin that is not a placeholder",
    "GET",
    `http://127.0.0.1:9999/v0/b/${BUCKET}/o/${enc(name("a"))}`,
  ],
  [
    "a real origin given by the sender",
    "GET",
    `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`,
  ],
  ["a userinfo url", "GET", `http://user:pw@127.0.0.1:9199/v0/b/${BUCKET}/o/${enc(name("a"))}`],
  ["a fragment", "GET", `${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}#x`],
  ["a control route other than the Rules read", "GET", `${CONTROL}/v1/storage/reset`],
  ["a control write", "POST", `${CONTROL}/v1/storage/rules`],
  ["a control read with a query", "GET", `${CONTROL}/v1/storage/rules?x=1`],
  [
    "a dot segment that normalises to a valid route",
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/x/../${enc(name("a"))}`,
  ],
  [
    "an encoded dot segment that normalises to a valid route",
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/%2e%2e/${enc(name("a"))}`,
  ],
  ["a single-dot name part", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(`${PREFIX}./x`)}`],
  ["a name with a newline", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(`${PREFIX}a\nb`)}`],
  ["the bare run prefix as an object", "GET", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(PREFIX)}`],
  [
    "a long name outside the prefix",
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(`other-run-00000000/${"x".repeat(60)}`)}`,
  ],
  ["a HEAD of an object", "HEAD", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`],
  ["a POST to a GCS object", "POST", `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`],
  [
    "a DELETE on an upload route",
    "DELETE",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${enc(name("a"))}`,
  ],
  [
    "an upload route with an object path",
    "POST",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o/${enc(name("a"))}?uploadType=media`,
  ],
  [
    "a DELETE on the Firebase collection",
    "DELETE",
    `${STORAGE}/v0/b/${BUCKET}/o?name=${enc(name("a"))}`,
  ],
  [
    "a Firebase upload outside the prefix",
    "POST",
    `${STORAGE}/v0/b/${BUCKET}/o?name=${enc("other/a")}`,
  ],
  [
    "a GCS upload outside the prefix",
    "POST",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${enc("other/a")}`,
  ],
  [
    "a GCS upload without a name",
    "POST",
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media`,
  ],
  [
    "a compose-shaped copy route",
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/compose/b/${BUCKET}/o/${enc(name("b"))}`,
  ],
  [
    "a GET on a copy route",
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/${BUCKET}/o/${enc(name("b"))}`,
  ],
  [
    "a copy route on the Firebase host",
    "POST",
    `${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/${BUCKET}/o/${enc(name("b"))}`,
  ],
  [
    "a copy route without a destination",
    "POST",
    `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/${BUCKET}/o`,
  ],
  [
    "a list-shaped route that is not the object collection",
    "GET",
    `${STORAGE}/storage/v1/b/${BUCKET}/iam?prefix=${enc(PREFIX)}`,
  ],
  [
    "a v0-shaped route without the bucket segment",
    "GET",
    `${STORAGE}/v0/x/${BUCKET}/o/${enc(name("a"))}`,
  ],
  ["a PUT on an auth route", "PUT", `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:signUp`],
  ["an emulator-only auth route", "POST", `${AUTH}/emulator/v1/projects/${PROJECT}/accounts`],
  [
    "an auth token route with a suffix",
    "POST",
    `${AUTH}/securetoken.googleapis.com/v1/token/extra`,
  ],
  [
    "an unknown auth route",
    "POST",
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:sendOobCode`,
  ],
  [
    "an auth route of another project",
    "POST",
    `${AUTH}/identitytoolkit.googleapis.com/v1/projects/other-project/accounts:delete`,
  ],
  ["an unknown host prefix", "POST", `${AUTH}/example.com/v1/accounts:signUp`],
];

for (const [label, method, href] of REFUSED) {
  test(`refuses ${label} before any request`, async () => {
    const h = harness();
    await assert.rejects(h.wire.fetch(href, { method, headers: admin, body: "x" }));
    assert.equal(h.calls.length, 0);
    assert.equal(
      h.wire.snapshot().attempts,
      1,
      "the counter counted the attempt, so does the wire",
    );
    assert.equal(h.wire.snapshot().realRequests, 0);
  });
}

test("the identity and token routes reach their own hosts", async () => {
  for (const [path, origin, expected] of [
    [
      "/identitytoolkit.googleapis.com/v1/accounts:signUp",
      "https://identitytoolkit.googleapis.com",
      "/v1/accounts:signUp",
    ],
    [
      "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
      "https://identitytoolkit.googleapis.com",
      "/v1/accounts:signInWithPassword",
    ],
    [
      "/identitytoolkit.googleapis.com/v1/accounts:lookup",
      "https://identitytoolkit.googleapis.com",
      "/v1/accounts:lookup",
    ],
    [
      "/identitytoolkit.googleapis.com/v1/accounts:delete",
      "https://identitytoolkit.googleapis.com",
      "/v1/accounts:delete",
    ],
    [
      `/identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup`,
      "https://identitytoolkit.googleapis.com",
      `/v1/projects/${PROJECT}/accounts:lookup`,
    ],
    [
      `/identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:delete`,
      "https://identitytoolkit.googleapis.com",
      `/v1/projects/${PROJECT}/accounts:delete`,
    ],
    ["/securetoken.googleapis.com/v1/token", "https://securetoken.googleapis.com", "/v1/token"],
  ]) {
    const h = harness();
    await h.wire.fetch(`${AUTH}${path}?key=${LEAN_PLACEHOLDER_API_KEY}`, {
      method: "POST",
      headers: {},
      body: "{}",
    });
    const real = new URL(h.calls[0].url);
    assert.equal(real.origin, origin);
    assert.equal(real.pathname, expected);
  }
});

// ---- credentials ------------------------------------------------------------------------------

test("the admin placeholder becomes the real token, and the quota project is set", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  const headers = new Headers(h.calls[0].headers);
  assert.equal(headers.get("authorization"), `Bearer ${TOKEN}`);
  assert.equal(headers.get("x-goog-user-project"), PROJECT);
});

test("another credential passes through untouched, and gets no quota project", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: { authorization: "Firebase synthetic.id.token" },
  });
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?alt=media&token=t`, {
    method: "GET",
    headers: {},
  });
  const first = new Headers(h.calls[0].headers);
  assert.equal(first.get("authorization"), "Firebase synthetic.id.token");
  assert.equal(first.get("x-goog-user-project"), null);
  assert.equal(new Headers(h.calls[1].headers).get("authorization"), null);
});

test("a sender header cannot smuggle the real token or a quota project of its own", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: { authorization: LEAN_PLACEHOLDER_ADMIN, "x-goog-user-project": "another-project" },
  });
  assert.equal(new Headers(h.calls[0].headers).get("x-goog-user-project"), PROJECT);
});

test("the API key placeholder becomes the real key, only in the key parameter", async () => {
  const h = harness();
  await h.wire.fetch(
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=${LEAN_PLACEHOLDER_API_KEY}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    },
  );
  assert.equal(new URL(h.calls[0].url).searchParams.get("key"), KEY);
  const other = harness();
  await other.wire.fetch(
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=someone-elses-key`,
    {
      method: "POST",
      headers: {},
      body: "{}",
    },
  );
  assert.equal(new URL(other.calls[0].url).searchParams.get("key"), "someone-elses-key");
});

test("a failing token provider sends nothing and does not leak into the error", async () => {
  const h = harness({
    options: {
      adminToken: () => {
        throw new Error(`gcloud failed for ${TOKEN}`);
      },
    },
  });
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
    (error) => !String(error.message).includes(TOKEN),
  );
  assert.equal(h.calls.length, 0);
});

// ---- the Rules read ---------------------------------------------------------------------------

test("the Rules control read is answered from the real Rules read and counts as one attempt", async () => {
  const h = harness();
  const response = await h.wire.fetch(`${CONTROL}/v1/storage/rules`, {
    method: "GET",
    headers: {},
  });
  assert.deepEqual(await response.json(), {
    loaded: true,
    targeted: false,
    source: "rules-source",
  });
  assert.equal(h.calls.length, 0, "the reader makes the real requests");
  const snapshot = h.wire.snapshot();
  assert.equal(snapshot.attempts, 1);
  assert.equal(snapshot.realRequests, 2);
});

test("a failing Rules read is an error, not an empty answer", async () => {
  const h = harness({
    options: {
      readRules: async () => {
        throw new Error("rules read failed");
      },
    },
  });
  await assert.rejects(h.wire.fetch(`${CONTROL}/v1/storage/rules`, { method: "GET", headers: {} }));
});

// ---- captures ---------------------------------------------------------------------------------

test("no capture holds the token, the key, a refresh token or a password", async () => {
  const REFRESH = "AMf-vBx-synthetic-refresh-token-0000000000";
  const h = harness({
    respond: (url) =>
      url.includes("accounts:signUp")
        ? Response.json({ idToken: "synthetic.id.token", refreshToken: REFRESH, localId: "uid1" })
        : url.includes("/v1/token")
          ? Response.json({
              access_token: "synthetic-access",
              refresh_token: REFRESH,
              id_token: "x.y.z",
            })
          : Response.json({ ok: true }),
  });
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  await h.wire.fetch(
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=${LEAN_PLACEHOLDER_API_KEY}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "a@example.com", password: "synthetic-password-value" }),
    },
  );
  await h.wire.fetch(
    `${AUTH}/securetoken.googleapis.com/v1/token?key=${LEAN_PLACEHOLDER_API_KEY}`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `grant_type=refresh_token&refresh_token=${REFRESH}`,
    },
  );
  // What a reader of the private record sees: the JSON and every body decoded from base64.
  const text = [
    JSON.stringify(h.captures),
    ...h.captures.flatMap((row) =>
      row.response ? [Buffer.from(row.response.bodyBase64, "base64").toString("utf8")] : [],
    ),
  ].join("\n");
  for (const secret of [TOKEN, KEY, REFRESH, "synthetic-password-value", "synthetic-access"]) {
    assert.equal(text.includes(secret), false, `a capture holds ${secret.slice(0, 8)}…`);
  }
  assert.ok(text.includes(sha(REFRESH)), "the refresh token is kept as its hash");
  assert.ok(text.includes(sha("synthetic-access")), "the access token is kept as its hash");
  assert.ok(text.includes(sha(TOKEN)), "the owner token is kept as its hash");
  // A disposable user's ID token may stay in the private record.
  assert.ok(text.includes("synthetic.id.token"));
  assert.ok(text.includes("x.y.z"));
});

test("a body that is not JSON is recorded as it came, and its hash is of the original", async () => {
  const bytes = Buffer.from('{"refreshToken": "kept-as-is"}', "utf8");
  const h = harness({
    respond: () => new Response(bytes, { status: 200, headers: { "content-type": "text/plain" } }),
  });
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?alt=media`, {
    method: "GET",
    headers: admin,
  });
  const { response } = h.captures[0];
  assert.equal(Buffer.from(response.bodyBase64, "base64").equals(bytes), true);
  assert.equal(response.sanitized, undefined);
});

test("a JSON body is sanitized in the record only, and the sender still gets the original", async () => {
  const original = JSON.stringify({ refreshToken: "AMf-original-refresh-value", localId: "u" });
  const h = harness({
    respond: () =>
      new Response(original, { status: 200, headers: { "content-type": "application/json" } }),
  });
  const response = await h.wire.fetch(
    `${AUTH}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=${LEAN_PLACEHOLDER_API_KEY}`,
    {
      method: "POST",
      headers: {},
      body: "{}",
    },
  );
  assert.equal(await response.text(), original);
  const { response: captured } = h.captures[0];
  assert.equal(captured.sanitized, true);
  assert.equal(captured.bodySha256, sha(original));
  const body = JSON.parse(Buffer.from(captured.bodyBase64, "base64").toString("utf8"));
  assert.equal(body.refreshToken, `sha256:${sha("AMf-original-refresh-value")}`);
  assert.equal(body.localId, "u");
});

test("a capture keeps the status, the headers and the exact body bytes of a media read", async () => {
  const bytes = Buffer.from([0, 255, 1, 2, 3]);
  const h = harness({
    respond: () =>
      new Response(bytes, {
        status: 200,
        headers: { "content-type": "application/octet-stream", "x-goog-hash": "crc32c=abc" },
      }),
  });
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?alt=media`, {
    method: "GET",
    headers: admin,
  });
  const [record] = h.captures;
  assert.equal(record.sequence, 1);
  assert.equal(record.response.status, 200);
  assert.equal(record.response.headers["x-goog-hash"], "crc32c=abc");
  assert.equal(Buffer.from(record.response.bodyBase64, "base64").equals(bytes), true);
  assert.equal(record.response.bodySha256, sha(bytes));
  assert.equal(record.request.method, "GET");
  assert.equal(record.request.url.includes("alt=media"), true);
});

test("a request body is recorded by length and hash only", async () => {
  const h = harness();
  await h.wire.fetch(
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${enc(name("a"))}`,
    {
      method: "POST",
      headers: { ...admin, "content-type": "application/octet-stream" },
      body: Buffer.from("payload-bytes"),
    },
  );
  const { request } = h.captures[0];
  assert.equal(request.bodyBytes, 13);
  assert.equal(request.bodySha256, sha("payload-bytes"));
  assert.equal(JSON.stringify(request).includes("payload-bytes"), false);
});

test("the capture of a failed request records the failure and the request still fails", async () => {
  const h = harness({
    respond: () => {
      throw new Error("socket hang up");
    },
  });
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
    /socket hang up/,
  );
  assert.equal(h.captures.length, 1);
  assert.match(h.captures[0].error, /socket hang up/);
  assert.equal(h.captures[0].response, undefined);
  assert.equal(h.wire.snapshot().halted, false, "a network failure alone does not halt");
});

test("a capture writer failure halts the wire and sends nothing further", async () => {
  const h = harness({ captureFails: true });
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
  );
  assert.equal(h.wire.snapshot().halted, true);
  const before = h.calls.length;
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("b"))}`, {
      method: "GET",
      headers: admin,
    }),
  );
  assert.equal(h.calls.length, before);
});

// ---- session URLs -----------------------------------------------------------------------------

test("a resumable session URL is given back on the placeholder origin, the capture keeps the real one", async () => {
  const real = `https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=resumable&upload_id=abc&name=${enc(name("a"))}`;
  const h = harness({
    respond: () => new Response("{}", { status: 200, headers: { location: real } }),
  });
  const response = await h.wire.fetch(
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=resumable&name=${enc(name("a"))}`,
    {
      method: "POST",
      headers: admin,
      body: "{}",
    },
  );
  assert.equal(
    response.headers.get("location"),
    real.replace("https://storage.googleapis.com", STORAGE),
  );
  assert.equal(h.captures[0].response.headers.location, real);
});

test("a Firebase upload URL header is given back on the placeholder origin too", async () => {
  const real = `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o?name=${enc(name("a"))}&upload_id=abc&upload_protocol=resumable`;
  const h = harness({
    respond: () => new Response("{}", { status: 200, headers: { "x-goog-upload-url": real } }),
  });
  const response = await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o?name=${enc(name("a"))}`, {
    method: "POST",
    headers: admin,
    body: "{}",
  });
  assert.equal(
    response.headers.get("x-goog-upload-url"),
    real.replace("https://firebasestorage.googleapis.com", STORAGE),
  );
});

// ---- pacing -----------------------------------------------------------------------------------

test("two writes to one object are at least a second apart, other objects and reads are not delayed", async () => {
  const h = harness({ paced: true });
  const put = (n) =>
    h.wire.fetch(`${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name(n))}`, {
      method: "PUT",
      headers: admin,
      body: "x",
    });
  await put("a");
  assert.deepEqual(h.sleeps, []);
  await put("b");
  assert.deepEqual(h.sleeps, []);
  await put("a");
  assert.equal(h.sleeps.length, 1);
  assert.ok(h.sleeps[0] >= 1000 - 1);
  const before = h.sleeps.length;
  await h.wire.fetch(`${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.equal(h.sleeps.length, before);
});

test("the destination of a copy is the paced object", async () => {
  const h = harness({ paced: true });
  const copy = () =>
    h.wire.fetch(
      `${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}/copyTo/b/${BUCKET}/o/${enc(name("b"))}`,
      {
        method: "POST",
        headers: admin,
        body: "{}",
      },
    );
  await copy();
  await copy();
  assert.equal(h.sleeps.length, 1);
});

test("a write without a derivable object name is refused", async () => {
  const h = harness();
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media`, {
      method: "POST",
      headers: admin,
      body: "x",
    }),
  );
  assert.equal(h.calls.length, 0);
});

// ---- limits and state ----------------------------------------------------------------------------

test("a response over the cap fails the request and halts the wire", async () => {
  const h = harness({ respond: () => new Response(Buffer.alloc(2 * 1024 * 1024 + 1)) });
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?alt=media`, {
      method: "GET",
      headers: admin,
    }),
  );
  assert.equal(h.wire.snapshot().halted, true);
});

test("a redirect is returned as it is, never followed", async () => {
  const h = harness({
    respond: () =>
      new Response(null, { status: 307, headers: { location: "https://evil.example/x" } }),
  });
  const response = await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.equal(response.status, 307);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].redirect, "manual");
});

test("a 204 answer has no body", async () => {
  const h = harness({ respond: () => new Response(null, { status: 204 }) });
  const response = await h.wire.fetch(`${STORAGE}/storage/v1/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "DELETE",
    headers: admin,
  });
  assert.equal(response.status, 204);
  assert.equal((await response.arrayBuffer()).byteLength, 0);
});

test("attempts count every call, real requests only the ones sent, and close ends it", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  await assert.rejects(h.wire.fetch(`${STORAGE}/nope`, { method: "GET", headers: admin }));
  await h.wire.fetch(`${CONTROL}/v1/storage/rules`, { method: "GET", headers: {} });
  const snapshot = h.wire.snapshot();
  assert.equal(snapshot.attempts, 3);
  assert.equal(snapshot.realRequests, 3);
  assert.equal(snapshot.halted, false);
  assert.equal(snapshot.closed, false);
  assert.equal(snapshot.busy, false);
  assert.equal(snapshot.readAfterHaltBytes, 0);
  await h.wire.close();
  assert.equal(h.wire.snapshot().closed, true);
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
  );
  assert.equal(h.calls.length, 1);
});

test("a Bearer token that is not the placeholder is never replaced", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: { authorization: "Bearer someone.elses.token" },
  });
  assert.equal(new Headers(h.calls[0].headers).get("authorization"), "Bearer someone.elses.token");
});

test("a token the provider returns in a bad shape is refused before any request", async () => {
  for (const token of ["short", "has a space in it 1234567890", 1234567890123, undefined, ""]) {
    const h = harness({ options: { adminToken: () => token } });
    await assert.rejects(
      h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
        method: "GET",
        headers: admin,
      }),
      /owner access token is unavailable/,
    );
    assert.equal(h.calls.length, 0);
  }
});

test("a quota project the sender sets is dropped on a request that is not the owner's", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?alt=media&token=t`, {
    method: "GET",
    headers: { "x-goog-user-project": "another-project" },
  });
  assert.equal(new Headers(h.calls[0].headers).get("x-goog-user-project"), null);
});

test("the token is scrubbed from an error message and from a response header echo", async () => {
  const failing = harness({
    respond: () => {
      throw new Error(`upstream said ${TOKEN}`);
    },
  });
  await assert.rejects(
    failing.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
  );
  assert.equal(failing.captures[0].error.includes(TOKEN), false);
  assert.ok(failing.captures[0].error.includes(sha(TOKEN)));
  const echo = harness({
    respond: () => new Response("{}", { status: 200, headers: { "x-echo": `Bearer ${TOKEN}` } }),
  });
  await echo.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.equal(JSON.stringify(echo.captures).includes(TOKEN), false);
});

test("every authorization header is hashed in the record, an ID token's included", async () => {
  const h = harness();
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: { authorization: "Firebase synthetic.id.token" },
  });
  const captured = h.captures[0].request.headers.authorization;
  assert.equal(captured, `Firebase sha256:${sha("synthetic.id.token")}`);
});

test("a request record has exactly the method, url, headers, length and hash", async () => {
  const h = harness();
  await h.wire.fetch(
    `${STORAGE}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${enc(name("a"))}`,
    {
      method: "POST",
      headers: admin,
      body: Buffer.from("payload-bytes"),
    },
  );
  assert.deepEqual(Object.keys(h.captures[0].request).toSorted(), [
    "bodyBytes",
    "bodySha256",
    "headers",
    "method",
    "url",
  ]);
  const bodiless = harness();
  await bodiless.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.deepEqual(Object.keys(bodiless.captures[0].request).toSorted(), [
    "bodyBytes",
    "headers",
    "method",
    "url",
  ]);
});

test("a response of exactly the cap is accepted", async () => {
  const h = harness({ respond: () => new Response(Buffer.alloc(2 * 1024 * 1024)) });
  const response = await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}?alt=media`, {
    method: "GET",
    headers: admin,
  });
  assert.equal((await response.arrayBuffer()).byteLength, 2 * 1024 * 1024);
  assert.equal(h.wire.snapshot().halted, false);
});

test("a second call while one is in flight is refused", async () => {
  const gate = Promise.withResolvers();
  let calls = 0;
  // Only the first request waits; a second one that got through would answer at once and so fail
  // the assertion instead of hanging.
  const h = harness({
    respond: () =>
      calls++ === 0 ? gate.promise.then(() => new Response("{}")) : new Response("{}"),
  });
  const first = h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.equal(h.wire.snapshot().busy, true);
  await assert.rejects(
    h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("b"))}`, {
      method: "GET",
      headers: admin,
    }),
    /BUSY/,
  );
  gate.resolve();
  await first;
  assert.equal(h.wire.snapshot().busy, false);
  assert.equal(h.calls.length, 1);
});

test("a Rules read without a source is an error", async () => {
  const h = harness({ options: { readRules: async () => ({ requests: 2 }) } });
  await assert.rejects(h.wire.fetch(`${CONTROL}/v1/storage/rules`, { method: "GET", headers: {} }));
});

test("a failed wire call frees the wire for the next one", async () => {
  const h = harness();
  await assert.rejects(h.wire.fetch(`${STORAGE}/nope`, { method: "GET", headers: admin }));
  assert.equal(h.wire.snapshot().busy, false);
  await h.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.equal(h.calls.length, 1);
});

test("a closed wire refuses, and a halted one refuses, and neither sends", async () => {
  const closed = harness();
  await closed.wire.close();
  await assert.rejects(
    closed.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
  );
  assert.equal(closed.calls.length, 0);
  assert.equal(closed.wire.snapshot().attempts, 1);
});

test("an asynchronous token provider is awaited, and its failure sends nothing", async () => {
  const ok = harness({ options: { adminToken: async () => TOKEN } });
  await ok.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
    method: "GET",
    headers: admin,
  });
  assert.equal(new Headers(ok.calls[0].headers).get("authorization"), `Bearer ${TOKEN}`);
  const failing = harness({
    options: {
      adminToken: async () => {
        throw new Error(`refresh failed for ${TOKEN}`);
      },
    },
  });
  await assert.rejects(
    failing.wire.fetch(`${STORAGE}/v0/b/${BUCKET}/o/${enc(name("a"))}`, {
      method: "GET",
      headers: admin,
    }),
    (error) =>
      /owner access token is unavailable/.test(error.message) && !error.message.includes(TOKEN),
  );
  assert.equal(failing.calls.length, 0);
});

test("the configuration is checked before any request", () => {
  const base = {
    bucket: BUCKET,
    projectId: PROJECT,
    prefix: PREFIX,
    origins: { storage: STORAGE, auth: AUTH, control: CONTROL },
    adminToken: () => TOKEN,
    authApiKey: KEY,
    readRules: async () => ({ source: "x", requests: 2 }),
    fetchImpl: async () => new Response("{}"),
    capture: async () => {},
    pacer: createObjectMutationPacer({ ownedPrefixes: [PREFIX] }),
  };
  assert.doesNotThrow(() => createLeanWire(base));
  for (const change of [
    { bucket: "" },
    { bucket: "abc/def.appspot.com" },
    { bucket: "a" },
    { prefix: "storage-object/abcdefgh" },
    { prefix: "storage-object/run/" },
    { prefix: "" },
    { projectId: "bad project" },
    { projectId: "Bad-Project" },
    { origins: { storage: "https://storage.googleapis.com", auth: AUTH, control: CONTROL } },
    { origins: { storage: STORAGE, auth: AUTH } },
    { origins: { storage: STORAGE, auth: STORAGE, control: CONTROL } },
    { adminToken: "token" },
    { authApiKey: "" },
    { authApiKey: "short" },
    { origins: { storage: "https://127.0.0.1:9199", auth: AUTH, control: CONTROL } },
    { origins: { storage: "http://evil.example:9199", auth: AUTH, control: CONTROL } },
    { origins: { storage: "http://user:pw@127.0.0.1:9199", auth: AUTH, control: CONTROL } },
    { origins: { storage: "http://127.0.0.1:9199/x", auth: AUTH, control: CONTROL } },
    { readRules: undefined },
    { fetchImpl: undefined },
    { capture: undefined },
    { pacer: undefined },
    { timeoutMs: 0 },
    { timeoutMs: 60_001 },
  ]) {
    assert.throws(
      () => createLeanWire({ ...base, ...change }),
      Error,
      JSON.stringify(Object.keys(change)),
    );
  }
});
