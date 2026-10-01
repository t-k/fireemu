import assert from "node:assert/strict";
import test from "node:test";
import {
  createContext,
  INFRASTRUCTURE_HEADERS,
  maskText,
  NORMALIZATIONS,
  normalizeBody,
  normalizeExchange,
  normalizeHeaders,
  routeOf,
} from "./storage-object-compare/normalize.mjs";

const RUN = "056c7ca3a8c6daa38e0a";
const BUCKET = "prod-bucket.firebasestorage.app";
const PROJECT = "prod-bucket";
const ctx = (extra = {}) =>
  createContext({ runId: RUN, bucket: BUCKET, project: PROJECT, ...extra });
const json = (value) => Buffer.from(JSON.stringify(value));

test("the context needs a run ID, a bucket and a project", () => {
  for (const name of ["runId", "bucket", "project"]) {
    const input = { runId: RUN, bucket: BUCKET, project: PROJECT, [name]: "" };
    assert.throws(() => createContext(input), new RegExp(name));
    assert.throws(() => createContext({ ...input, [name]: 7 }), new RegExp(name));
  }
  assert.equal(ctx().contentCarriesRun, false);
  assert.equal(ctx({ contentCarriesRun: true }).contentCarriesRun, true);
});

test("every mask has an ID, a mask and a reason", () => {
  assert.ok(NORMALIZATIONS.length >= 14);
  for (const row of NORMALIZATIONS) {
    assert.match(row.id, /^[A-Z_]+$/);
    assert.match(row.mask, /^<[A-Z_]+(:n)?>$/);
    assert.ok(row.reason.length > 20, row.id);
  }
  assert.equal(new Set(NORMALIZATIONS.map((row) => row.id)).size, NORMALIZATIONS.length);
  for (const [name, reason] of Object.entries(INFRASTRUCTURE_HEADERS)) {
    assert.equal(name, name.toLowerCase());
    assert.ok(reason.length > 5);
  }
});

test("the run ID, the bucket and the project are masked, the bucket before the project it contains", () => {
  const text = `${BUCKET}/storage-object/${RUN}/a.bin in ${PROJECT}`;
  assert.equal(maskText(text, ctx()), "<BUCKET>/storage-object/<RUN>/a.bin in <PROJECT>");
  const nested = createContext({ runId: RUN, bucket: "p-1.firebasestorage.app", project: "p-1" });
  assert.equal(maskText("p-1.firebasestorage.app p-1", nested), "<BUCKET> <PROJECT>");
});

test("a generation is masked to its order of first appearance, so equal and different generations stay distinguishable", () => {
  const c = ctx();
  const text = "1790810081541764 1790810086919331 1790810081541764 12345";
  assert.equal(maskText(text, c), "<GEN:1> <GEN:2> <GEN:1> 12345");
  assert.equal(
    maskText("1790810086919331", c),
    "<GEN:2>",
    "the order is the recipe's, not the string's",
  );
  // 15- and 17-digit numbers are not generations.
  assert.equal(
    maskText("179081008154176 17908100815417644", ctx()),
    "179081008154176 17908100815417644",
  );
});

test("download tokens are masked to their order of first appearance", () => {
  const a = "995cff2a-95bf-4bb5-90f8-0c0176c17e1f";
  const b = "a094c322-0cec-4daa-b406-e95d3203ab7a";
  assert.equal(maskText(`${a},${b},${a}`, ctx()), "<TOKEN:1>,<TOKEN:2>,<TOKEN:1>");
});

test("times, upload IDs, page tokens, API keys and JWTs are masked", () => {
  const c = ctx();
  assert.equal(
    maskText("2026-09-30T23:14:41.570Z and 2026-09-30T23:14:41Z", c),
    "<TIME> and <TIME>",
  );
  assert.equal(maskText("Wed, 30 Sep 2026 23:14:40 GMT", c), "<HTTPDATE>");
  assert.equal(maskText("Mon, 01 Jan 1990 00:00:00 GMT", c), "Mon, 01 Jan 1990 00:00:00 GMT");
  assert.equal(
    maskText(
      "o?name=x&upload_id=AP6rU81BlvOGz-fcTGYWUv7Mij3H11bxS9bQ&upload_protocol=resumable",
      c,
    ),
    "o?name=x&upload_id=<UPLOAD_ID>&upload_protocol=resumable",
  );
  assert.equal(maskText("AP6rU81BlvOGz-fcTGYWUv7Mij3H11bxS9bQ", c), "<UPLOAD_ID>");
  assert.equal(maskText("?pageToken=c3RvcmFnZS1v==&x=1", c), "?pageToken=<PAGE_TOKEN>&x=1");
  assert.equal(maskText("?key=sha256:abc&x=1", c), "?key=<API_KEY>&x=1");
  assert.equal(maskText("a.eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln b", c), "a.<JWT> b");
});

test("response headers: infrastructure ones are left out, the rest is lower-cased, masked and sorted", () => {
  const headers = {
    Date: "Wed, 30 Sep 2026 23:14:40 GMT",
    Server: "UploadServer",
    "Alt-Svc": 'h3=":443"',
    "X-GUploader-UploadID": "AP6rU8",
    "x-goog-gcs-base-ts": "1a0f",
    "Content-Length": "5",
    "Transfer-Encoding": "chunked",
    "Content-Type": "application/json; charset=UTF-8",
    "Cache-Control": "private, max-age=0",
    Expires: "Wed, 30 Sep 2026 23:14:40 GMT",
    "Last-Modified": "Wed, 30 Sep 2026 23:14:41 GMT",
    "X-Goog-Generation": "1790810081541764",
    ETag: "CKOZ3bi3l5cDEAE=",
  };
  assert.deepEqual(normalizeHeaders(headers, ctx()), {
    "cache-control": "private, max-age=0",
    "content-type": "application/json; charset=UTF-8",
    etag: "<ETAG>",
    expires: "<HTTPDATE>",
    "last-modified": "<HTTPDATE>",
    "x-goog-generation": "<GEN:1>",
  });
});

test("a quoted md5 etag is content-derived and kept, unless the recipe's bytes carry the run ID", () => {
  const etag = '"feea43e9b76fc31c34bcec403dcc4bf8"';
  assert.equal(normalizeHeaders({ etag }, ctx()).etag, etag);
  assert.equal(normalizeHeaders({ etag }, ctx({ contentCarriesRun: true })).etag, "<DIGEST>");
  assert.equal(normalizeHeaders({ etag: "CKOZ3bi3l5cDEAE=" }, ctx()).etag, "<ETAG>");
  const hash = {
    "x-goog-hash": "crc32c=1Kspzg==, md5=/upD6bdvwxw0vOxAPcxL+A==",
    "x-range-md5": "fc47",
    "x-goog-running-hash": "crc32c=Pj",
  };
  assert.deepEqual(normalizeHeaders(hash, ctx()), hash);
  for (const value of Object.values(normalizeHeaders(hash, ctx({ contentCarriesRun: true }))))
    assert.equal(value, "<DIGEST>");
});

test("a JSON body is parsed, its members sorted, and only the run-specific members masked", () => {
  const body = json({
    name: `storage-object/${RUN}/a.bin`,
    bucket: BUCKET,
    generation: "1790810081541764",
    metageneration: "2",
    size: "5",
    md5Hash: "/upD6bdvwxw0vOxAPcxL+A==",
    crc32c: "1Kspzg==",
    etag: "CKOZ3bi3l5cDEAE=",
    timeCreated: "2026-09-30T23:14:41.570Z",
    downloadTokens: "995cff2a-95bf-4bb5-90f8-0c0176c17e1f",
    nextPageToken: "abc",
    owner: { entity: "user-someone@example.net" },
    items: [{ name: `storage-object/${RUN}/b.bin` }],
  });
  const out = normalizeBody(body, "application/json; charset=UTF-8", ctx());
  assert.equal(out.type, "json");
  assert.deepEqual(Object.keys(out.value), [
    "bucket",
    "crc32c",
    "downloadTokens",
    "etag",
    "generation",
    "items",
    "md5Hash",
    "metageneration",
    "name",
    "nextPageToken",
    "owner",
    "size",
    "timeCreated",
  ]);
  assert.deepEqual(out.value, {
    bucket: "<BUCKET>",
    crc32c: "1Kspzg==",
    downloadTokens: "<TOKEN:1>",
    etag: "<ETAG>",
    generation: "<GEN:1>",
    items: [{ name: "storage-object/<RUN>/b.bin" }],
    md5Hash: "/upD6bdvwxw0vOxAPcxL+A==",
    metageneration: "2",
    name: "storage-object/<RUN>/a.bin",
    nextPageToken: "<PAGE_TOKEN>",
    owner: { entity: "<OWNER>" },
    size: "5",
    timeCreated: "<TIME>",
  });
});

test("md5Hash and crc32c are masked only in a recipe whose bytes carry the run ID", () => {
  const body = json({ md5Hash: "x", crc32c: "y", size: "5" });
  assert.deepEqual(
    normalizeBody(body, "application/json", ctx({ contentCarriesRun: true })).value,
    { crc32c: "<DIGEST>", md5Hash: "<DIGEST>", size: "5" },
  );
  assert.deepEqual(normalizeBody(body, "application/json", ctx()).value, {
    crc32c: "y",
    md5Hash: "x",
    size: "5",
  });
});

test("owner.entity is masked only under owner", () => {
  assert.deepEqual(
    normalizeBody(
      json({ owner: { entity: "a@b.c" }, other: { entity: "keep" }, entity: "keep" }),
      "application/json",
      ctx(),
    ).value,
    {
      entity: "keep",
      other: { entity: "keep" },
      owner: { entity: "<OWNER>" },
    },
  );
});

test("identity members are masked: tokens, ids and times", () => {
  const body = json({
    idToken: "eyJhbGciOiJSUzI1NiJ9.x.y",
    refreshToken: "AMf-secret",
    localId: "SADGoN9u",
    email: "storage-object@example.com",
    createdAt: "1790810782675",
    lastLoginAt: 1790810782675,
    validSince: "1790810782",
  });
  assert.deepEqual(normalizeBody(body, "application/json; charset=UTF-8", ctx()).value, {
    createdAt: "<EPOCH>",
    email: "storage-object@example.com",
    idToken: "<JWT>",
    lastLoginAt: "<EPOCH>",
    localId: "<UID>",
    refreshToken: "<UID>",
    validSince: "<EPOCH>",
  });
});

test("an error body keeps its code and message, with the names masked", () => {
  const body = json({
    error: {
      code: 404,
      message: `No such object: ${BUCKET}/storage-object/${RUN}/a.bin`,
      errors: [{ domain: "global", reason: "notFound" }],
    },
  });
  assert.deepEqual(normalizeBody(body, "application/json; charset=UTF-8", ctx()).value, {
    error: {
      code: 404,
      errors: [{ domain: "global", reason: "notFound" }],
      message: "No such object: <BUCKET>/storage-object/<RUN>/a.bin",
    },
  });
});

test("text and XML bodies are compared as masked text; a JSON body that does not parse is text too", () => {
  assert.deepEqual(
    normalizeBody(
      Buffer.from(`No such object: ${BUCKET}/x/${RUN}`),
      "text/html; charset=UTF-8",
      ctx(),
    ),
    { type: "text", value: "No such object: <BUCKET>/x/<RUN>" },
  );
  const xml = "<?xml version='1.0' encoding='UTF-8'?><Error><Code>InvalidRange</Code></Error>";
  assert.deepEqual(normalizeBody(Buffer.from(xml), "application/xml; charset=UTF-8", ctx()), {
    type: "text",
    value: xml,
  });
  assert.deepEqual(normalizeBody(Buffer.from("not json"), "application/json", ctx()), {
    type: "text",
    value: "not json",
  });
  assert.deepEqual(normalizeBody(Buffer.from("plain"), "text/plain", ctx()), {
    type: "text",
    value: "plain",
  });
});

test("an empty body is empty, whatever the type", () => {
  for (const body of [Buffer.alloc(0), null, undefined])
    assert.deepEqual(normalizeBody(body, "application/json", ctx()), { type: "empty" });
});

test("object bytes are compared by length and digest, inline when small, and with the run ID masked", () => {
  const small = Buffer.from([0, 1, 255, 128]);
  const out = normalizeBody(small, "application/octet-stream", ctx());
  assert.equal(out.type, "bytes");
  assert.equal(out.length, 4);
  assert.equal(out.base64, small.toString("base64"));
  assert.match(out.sha256, /^[0-9a-f]{64}$/);
  // 4,096 bytes are inline, 4,097 are not.
  assert.equal(
    "base64" in normalizeBody(Buffer.alloc(4096, 7), "application/octet-stream", ctx()),
    true,
  );
  assert.equal(
    "base64" in normalizeBody(Buffer.alloc(4097, 7), "application/octet-stream", ctx()),
    false,
  );
  const big = Buffer.alloc(5000, 7);
  const large = normalizeBody(big, "application/octet-stream", ctx());
  assert.equal(large.length, 5000);
  assert.equal("base64" in large, false);
  const carrying = Buffer.from(`prefix ${RUN} suffix`, "latin1");
  const masked = normalizeBody(carrying, "application/octet-stream", ctx());
  assert.equal(Buffer.from(masked.base64, "base64").toString("latin1"), "prefix <RUN> suffix");
  assert.equal(masked.length, "prefix <RUN> suffix".length);
  // Text that is not valid UTF-8 is bytes, not text.
  assert.equal(normalizeBody(Buffer.from([0xff, 0xfe, 0x41]), "text/plain", ctx()).type, "bytes");
});

test("an exchange is normalized: the route, the path, the sorted query, the status and the exact content type", () => {
  const exchange = {
    method: "POST",
    url: `https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=storage-object%2F${RUN}%2Fa%0Ab.bin&ifGenerationMatch=0&upload_id=AP6rU81BlvOGz-fcTGYWUv7Mij3H11bx&pageToken=zzz&key=sha256:ab`,
    status: 200,
    headers: { "content-type": "application/json; charset=UTF-8", server: "UploadServer" },
    body: json({ name: `storage-object/${RUN}/a\nb.bin` }),
  };
  const row = normalizeExchange(exchange, ctx());
  assert.equal(row.method, "POST");
  assert.equal(row.route, "POST /upload/storage/v1/b/<BUCKET>/o");
  assert.equal(row.path, "/upload/storage/v1/b/<BUCKET>/o");
  assert.deepEqual(row.query, [
    ["ifGenerationMatch", "0"],
    ["key", "<API_KEY>"],
    ["name", "storage-object/<RUN>/a\nb.bin"],
    ["pageToken", "<PAGE_TOKEN>"],
    ["uploadType", "media"],
    ["upload_id", "<UPLOAD_ID>"],
  ]);
  assert.equal(row.status, 200);
  assert.equal(row.contentType, "application/json; charset=UTF-8");
  assert.deepEqual(row.headers, { "content-type": "application/json; charset=UTF-8" });
  assert.deepEqual(row.body, { type: "json", value: { name: "storage-object/<RUN>/a\nb.bin" } });
  const none = normalizeExchange({ ...exchange, headers: {}, body: Buffer.alloc(0) }, ctx());
  assert.equal(none.contentType, null);
});

test("the same query in a different order is the same query", () => {
  const a = normalizeExchange(
    {
      method: "GET",
      url: `https://x.example/storage/v1/b/${BUCKET}/o?prefix=a&maxResults=2`,
      status: 200,
      headers: {},
      body: Buffer.alloc(0),
    },
    ctx(),
  );
  const b = normalizeExchange(
    {
      method: "GET",
      url: `https://x.example/storage/v1/b/${BUCKET}/o?maxResults=2&prefix=a`,
      status: 200,
      headers: {},
      body: Buffer.alloc(0),
    },
    ctx(),
  );
  assert.deepEqual(a.query, b.query);
});

test("routes are classed by method and path with the names removed", () => {
  const route = (method, path) => routeOf(method, path);
  assert.equal(route("GET", "/v0/b/<BUCKET>/o"), "GET /v0/b/<BUCKET>/o");
  assert.equal(
    route("GET", "/v0/b/<BUCKET>/o/storage-object/<RUN>/a.bin"),
    "GET /v0/b/<BUCKET>/o/<NAME>",
  );
  assert.equal(
    route("PUT", "/storage/v1/b/<BUCKET>/o/storage-object/<RUN>/a.bin"),
    "PUT /storage/v1/b/<BUCKET>/o/<NAME>",
  );
  assert.equal(
    route(
      "POST",
      "/storage/v1/b/<BUCKET>/o/storage-object/<RUN>/a.bin/copyTo/b/<BUCKET>/o/storage-object/<RUN>/c.bin",
    ),
    "POST /storage/v1/b/<BUCKET>/o/<NAME>/copyTo/b/<BUCKET>/o/<NAME>",
  );
  assert.equal(route("POST", "/v1/accounts:signUp"), "POST /v1/accounts:signUp");
});
