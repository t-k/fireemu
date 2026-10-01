import assert from "node:assert/strict";
import test from "node:test";
import {
  createContext,
  INFRASTRUCTURE_HEADERS,
  maskText,
  NORMALIZATIONS,
  layoutOverhead,
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
  assert.ok(NORMALIZATIONS.length >= 16);
  for (const row of NORMALIZATIONS) {
    assert.match(row.id, /^[A-Z_]+$/);
    assert.match(row.mask, /^(<[A-Z_]+(:[a-zA-Z:]+)?>|\(keys sorted\))$/);
    assert.ok(row.reason.length > 20, row.id);
  }
  assert.equal(new Set(NORMALIZATIONS.map((row) => row.id)).size, NORMALIZATIONS.length);
  for (const [name, reason] of Object.entries(INFRASTRUCTURE_HEADERS)) {
    assert.equal(name, name.toLowerCase());
    assert.ok(reason.length > 5);
  }
  // A mask never hides a format: the generation reason says a local counter is a difference.
  assert.match(
    NORMALIZATIONS.find((row) => row.id === "GEN").reason,
    /not masked and is a difference/,
  );
  assert.match(INFRASTRUCTURE_HEADERS["content-length"], /layout is judged separately/);
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

test("times keep their number of fractional digits; upload IDs, page tokens, API keys and JWTs are masked", () => {
  const c = ctx();
  assert.equal(
    maskText("2026-09-30T23:14:41.570Z and 2026-09-30T23:14:41Z", c),
    "<TIME:3> and <TIME:0>",
  );
  assert.equal(maskText("2026-10-01T01:24:29.241904125Z", c), "<TIME:9>");
  assert.equal(maskText("2026-10-01T01:24:29.241904Z", c), "<TIME:6>");
  assert.notEqual(
    maskText("2026-10-01T01:24:29.241Z", c),
    maskText("2026-10-01T01:24:29.241904125Z", c),
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
  assert.equal(
    maskText("o?upload_id=f1&upload_protocol=resumable", c),
    "o?upload_id=<UPLOAD_ID>&upload_protocol=resumable",
  );
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
    Connection: "keep-alive",
    "Keep-Alive": "timeout=5",
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
    etag: "<ETAG:1>",
    expires: "<HTTPDATE>",
    "last-modified": "<HTTPDATE>",
    "x-goog-generation": "<GEN:1>",
  });
});

test("an opaque etag is masked to its order of first appearance; any other form is kept, so that a different etag stays a difference", () => {
  const c = ctx();
  assert.equal(normalizeHeaders({ etag: "CKOZ3bi3l5cDEAE=" }, c).etag, "<ETAG:1>");
  assert.equal(normalizeHeaders({ etag: "CKOZ3bi3l5cDEAM=" }, c).etag, "<ETAG:2>");
  assert.equal(normalizeHeaders({ etag: "CKOZ3bi3l5cDEAE=" }, c).etag, "<ETAG:1>");
  assert.equal(normalizeHeaders({ etag: '"1-1"' }, ctx()).etag, '"1-1"');
  assert.equal(normalizeHeaders({ etag: 'W/"abc"' }, ctx()).etag, 'W/"abc"');
  // The body's etag member shares the ordinals.
  assert.equal(
    normalizeBody(json({ etag: "CKOZ3bi3l5cDEAM=" }), "application/json", c).value.etag,
    "<ETAG:2>",
  );
  assert.equal(
    normalizeBody(json({ etag: '"1-1"' }), "application/json", ctx()).value.etag,
    '"1-1"',
  );
});

test("last-modified is masked only when it is an HTTP date", () => {
  assert.equal(
    normalizeHeaders({ "last-modified": "Wed, 30 Sep 2026 23:14:41 GMT" }, ctx())["last-modified"],
    "<HTTPDATE>",
  );
  assert.equal(
    normalizeHeaders({ "last-modified": "2026-09-30" }, ctx())["last-modified"],
    "2026-09-30",
  );
  assert.equal(
    normalizeHeaders({ "last-modified": "Wed, 30 Sep 2026 23:14:41 GMT extra" }, ctx())[
      "last-modified"
    ],
    "<HTTPDATE> extra",
  );
});

test("a quoted md5 etag is content-derived and kept, unless the recipe's bytes carry the run ID", () => {
  const etag = '"feea43e9b76fc31c34bcec403dcc4bf8"';
  assert.equal(normalizeHeaders({ etag }, ctx()).etag, etag);
  assert.equal(normalizeHeaders({ etag }, ctx({ contentCarriesRun: true })).etag, "<DIGEST>");
  const hash = {
    "x-goog-hash": "crc32c=1Kspzg==, md5=/upD6bdvwxw0vOxAPcxL+A==",
    "x-range-md5": "fc47",
    "x-goog-running-hash": "crc32c=Pj",
  };
  assert.deepEqual(normalizeHeaders(hash, ctx()), hash);
  for (const value of Object.values(normalizeHeaders(hash, ctx({ contentCarriesRun: true }))))
    assert.equal(value, "<DIGEST>");
});

test("a JSON body is parsed, its members keep production's order, and only the run-specific members are masked", () => {
  const body = json({
    kind: "storage#object",
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
    "kind",
    "name",
    "bucket",
    "generation",
    "metageneration",
    "size",
    "md5Hash",
    "crc32c",
    "etag",
    "timeCreated",
    "downloadTokens",
    "nextPageToken",
    "owner",
    "items",
  ]);
  assert.deepEqual(out.value, {
    kind: "storage#object",
    name: "storage-object/<RUN>/a.bin",
    bucket: "<BUCKET>",
    generation: "<GEN:1>",
    metageneration: "2",
    size: "5",
    md5Hash: "/upD6bdvwxw0vOxAPcxL+A==",
    crc32c: "1Kspzg==",
    etag: "<ETAG:1>",
    timeCreated: "<TIME:3>",
    downloadTokens: "<TOKEN:1>",
    nextPageToken: "<PAGE_TOKEN>",
    owner: { entity: "<OWNER>" },
    items: [{ name: "storage-object/<RUN>/b.bin" }],
  });
});

test("the user metadata map is the one object whose members are sorted; every other object keeps its order", () => {
  const out = normalizeBody(
    json({ z: 1, a: 2, metadata: { remove: "present", marker: "first" }, nested: { b: 1, a: 2 } }),
    "application/json",
    ctx(),
  );
  assert.deepEqual(Object.keys(out.value), ["z", "a", "metadata", "nested"]);
  assert.deepEqual(Object.keys(out.value.metadata), ["marker", "remove"]);
  assert.deepEqual(Object.keys(out.value.nested), ["b", "a"]);
});

test("a member name that carries the run, bucket or project is masked too", () => {
  const out = normalizeBody(json({ [`k-${RUN}`]: 1, [PROJECT]: 2 }), "application/json", ctx());
  assert.deepEqual(Object.keys(out.value), ["k-<RUN>", "<PROJECT>"]);
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

test("identity members are masked: tokens, ids, and times in their own format", () => {
  const body = json({
    idToken: "eyJhbGciOiJSUzI1NiJ9.x.y",
    refreshToken: "AMf-secret",
    accessToken: "ya29.secret",
    access_token: "ya29.other",
    localId: "SADGoN9u",
    email: "storage-object@example.com",
    createdAt: "1790810782675",
    lastLoginAt: "1790810782675",
    passwordUpdatedAt: 1790810782675,
    validSince: "1790810782",
    lastRefreshAt: "2026-10-01T01:24:29.241Z",
  });
  assert.deepEqual(normalizeBody(body, "application/json; charset=UTF-8", ctx()).value, {
    idToken: "<JWT>",
    refreshToken: "<UID>",
    accessToken: "<JWT>",
    access_token: "<JWT>",
    localId: "<UID>",
    email: "storage-object@example.com",
    createdAt: "<EPOCH:string:13>",
    lastLoginAt: "<EPOCH:string:13>",
    passwordUpdatedAt: "<EPOCH:number:13>",
    validSince: "<EPOCH:string:10>",
    lastRefreshAt: "<TIME:3>",
  });
});

test("a time in epoch form keeps its type and its digits, so another format is a difference", () => {
  const mask = (value) =>
    normalizeBody(json({ createdAt: value }), "application/json", ctx()).value.createdAt;
  assert.notEqual(mask("1790810782675"), mask(1790810782675));
  assert.notEqual(mask("1790810782675"), mask("1790810782"));
  assert.equal(mask("not digits"), "not digits");
  assert.notEqual(
    normalizeBody(json({ lastRefreshAt: "2026-10-01T01:24:29.241Z" }), "application/json", ctx())
      .value.lastRefreshAt,
    normalizeBody(
      json({ lastRefreshAt: "2026-10-01T01:24:29.241904125Z" }),
      "application/json",
      ctx(),
    ).value.lastRefreshAt,
  );
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

test("object bytes carrying the bucket or the project are masked too", () => {
  const out = normalizeBody(
    Buffer.from(`in ${BUCKET} of ${PROJECT}`, "latin1"),
    "application/octet-stream",
    ctx(),
  );
  assert.equal(Buffer.from(out.base64, "base64").toString("latin1"), "in <BUCKET> of <PROJECT>");
});

test("the layout is the bytes the answer had beyond the stored form, and unknown without a length", () => {
  const stored = Buffer.from('{"a":1}');
  assert.equal(layoutOverhead({ bodyBytes: 20, body: stored }), 13);
  assert.equal(layoutOverhead({ bodyBytes: 7, body: stored }), 0);
  assert.equal(layoutOverhead({ bodyBytes: 7, body: undefined }), 7);
  for (const bodyBytes of [null, undefined, "7", 1.5, NaN])
    assert.equal(layoutOverhead({ bodyBytes, body: stored }), null);
  const exchange = {
    method: "GET",
    url: `https://x.example/storage/v1/b/${BUCKET}/o`,
    status: 200,
    headers: {},
    body: stored,
    bodyBytes: 20,
  };
  assert.equal(normalizeExchange(exchange, ctx()).layout, 13);
  assert.equal(normalizeExchange({ ...exchange, bodyBytes: null }, ctx()).layout, null);
});

test("the fixed 1990 date is kept everywhere except where last-modified would be a run-specific date", () => {
  const fixed = "Mon, 01 Jan 1990 00:00:00 GMT";
  assert.equal(normalizeHeaders({ expires: fixed }, ctx()).expires, fixed);
  assert.equal(normalizeHeaders({ "last-modified": fixed }, ctx())["last-modified"], "<HTTPDATE>");
  assert.equal(
    normalizeHeaders({ expires: "Wed, 30 Sep 2026 23:14:41 GMT" }, ctx()).expires,
    "<HTTPDATE>",
  );
});

test("headers come out sorted by name", () => {
  assert.deepEqual(
    Object.keys(normalizeHeaders({ b: "1", a: "1", c: "1", Aa: "1", B: "2" }, ctx())),
    ["a", "aa", "b", "c"],
  );
});

test("the query is sorted by name, then by value, so repeated names keep a stable order", () => {
  const row = normalizeExchange(
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o?b=1&a=2&a=1&c=0&b=0`,
      status: 200,
      headers: {},
      body: Buffer.alloc(0),
    },
    ctx(),
  );
  assert.deepEqual(row.query, [
    ["a", "1"],
    ["a", "2"],
    ["b", "0"],
    ["b", "1"],
    ["c", "0"],
  ]);
});

test("the origin of selfLink and mediaLink is masked, the path and the query are not", () => {
  // Production's mediaLink is on another host than its selfLink.
  const mediaOrigin = (origin) =>
    origin === "https://www.googleapis.com" ? "https://storage.googleapis.com" : origin;
  const link = (origin, path) =>
    normalizeBody(
      json({
        selfLink: `${origin}/storage/v1/b/${BUCKET}/o/${path}`,
        nested: [
          {
            mediaLink: `${mediaOrigin(origin)}/download/storage/v1/b/${BUCKET}/o/${path}?alt=media`,
          },
        ],
        other: `${origin}/kept`,
      }),
      "application/json",
      ctx(),
    ).value;
  const production = link("https://www.googleapis.com", "a.bin");
  assert.equal(production.selfLink, "<ORIGIN>/storage/v1/b/<BUCKET>/o/a.bin");
  assert.equal(
    production.nested[0].mediaLink,
    "<ORIGIN>/download/storage/v1/b/<BUCKET>/o/a.bin?alt=media",
  );
  // The same links from a local run have the same masked form; another path does not.
  assert.deepEqual(link("http://127.0.0.1:9199", "a.bin").selfLink, production.selfLink);
  assert.notEqual(link("http://127.0.0.1:9199", "b.bin").selfLink, production.selfLink);
  // Only these two members are masked.
  assert.equal(production.other, "https://www.googleapis.com/kept");
  assert.ok(
    NORMALIZATIONS.some((row) => row.id === "ORIGIN" && /path and the query/.test(row.reason)),
  );
});

test("the layout of a body with a member the recorder hashed is not judged", () => {
  const hashed = `sha256:${"a".repeat(64)}`;
  const stored = Buffer.from(`{"refreshToken":"${hashed}","idToken":"x"}`);
  // 71 characters of hash stand for a longer or shorter token: the difference is not whitespace.
  assert.equal(layoutOverhead({ bodyBytes: stored.length + 202, body: stored }), null);
  assert.equal(layoutOverhead({ bodyBytes: stored.length - 26, body: stored }), null);
  // One digit short is not that form; a plain body keeps its figure.
  const near = Buffer.from(`{"refreshToken":"sha256:${"a".repeat(63)}"}`);
  assert.equal(layoutOverhead({ bodyBytes: near.length + 5, body: near }), 5);
  assert.equal(layoutOverhead({ bodyBytes: 12, body: Buffer.from("{}") }), 10);
  const row = normalizeExchange(
    {
      method: "POST",
      url: `https://x.example/v1/accounts:signUp`,
      status: 200,
      headers: { "content-type": "application/json" },
      body: stored,
      bodyBytes: stored.length + 202,
    },
    ctx(),
  );
  assert.equal(row.layout, null);
});

test("the origin of a link is masked only when it is the expected one: the production host of that member or a loopback address", () => {
  const exchange = (url, self, media) => {
    const c = ctx();
    return normalizeExchange(
      {
        method: "GET",
        url,
        status: 200,
        headers: { "content-type": "application/json" },
        body: Buffer.from(
          JSON.stringify({
            selfLink: `${self}/storage/v1/b/${BUCKET}/o/a.bin`,
            mediaLink: `${media}/download/storage/v1/b/${BUCKET}/o/a.bin?alt=media`,
          }),
        ),
      },
      c,
    ).body.value;
  };
  const production = exchange(
    `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/a.bin`,
    "https://www.googleapis.com",
    "https://storage.googleapis.com",
  );
  const local = exchange(
    `http://127.0.0.1:9199/storage/v1/b/${BUCKET}/o/a.bin`,
    "http://127.0.0.1:9199",
    "http://127.0.0.1:9199",
  );
  assert.deepEqual(local, production);
  assert.match(production.selfLink, /^<ORIGIN>\/storage/);
  // fireemu swapping production's two hosts is not hidden.
  const swapped = exchange(
    `http://127.0.0.1:9199/storage/v1/b/${BUCKET}/o/a.bin`,
    "https://storage.googleapis.com",
    "https://www.googleapis.com",
  );
  assert.notDeepEqual(swapped, production);
  // Only a loopback address stands for the local emulator: another host or scheme is kept.
  for (const other of [
    "http://example.com:9199",
    "https://127.0.0.1:9199",
    "http://127.0.0.1",
    "http://127.0.0.1:",
  ])
    assert.notDeepEqual(
      exchange(`http://127.0.0.1:9199/storage/v1/b/${BUCKET}/o/a.bin`, other, other),
      local,
      other,
    );
  assert.deepEqual(
    exchange(`http://127.0.0.1:9199/x`, "http://localhost:19199", "http://[::1]:9199"),
    local,
  );
  // The production hosts are expected per member whatever host the request names.
  const viaThird = exchange(
    `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/a.bin`,
    "https://www.googleapis.com",
    "https://storage.googleapis.com",
  );
  assert.deepEqual(viaThird, production);
  const mediaOnWww = exchange(
    `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/a.bin`,
    "https://www.googleapis.com",
    "https://www.googleapis.com",
  );
  assert.equal(mediaOnWww.selfLink, production.selfLink);
  assert.notEqual(mediaOnWww.mediaLink, production.mediaLink);
  assert.equal(swapped.selfLink, `https://storage.googleapis.com/storage/v1/b/<BUCKET>/o/a.bin`);
});

test("a JSON document sent as text is compared in its compact form and its layout is the whitespace around it", () => {
  const compact = '{"error":{"code":400,"message":"bad"}}';
  const pretty = JSON.stringify(JSON.parse(compact), null, 2);
  const row = (body, bodyBytes) =>
    normalizeExchange(
      {
        method: "POST",
        url: "https://x.example/upload",
        status: 400,
        headers: { "content-type": "text/html; charset=UTF-8" },
        body: Buffer.from(body),
        bodyBytes,
      },
      ctx(),
    );
  // Production's recorder stored the compact form and kept the real length; a local run stored the text as sent.
  const production = row(compact, pretty.length);
  const local = row(pretty, pretty.length);
  assert.deepEqual(local.body, production.body);
  assert.equal(production.layout, pretty.length - compact.length);
  assert.equal(local.layout, production.layout);
  // The same text with less whitespace has another layout.
  assert.notEqual(
    row(JSON.stringify(JSON.parse(compact), null, 4), pretty.length + 30).layout,
    production.layout,
  );
  // Text that is not a JSON object or array, and non-text types, are left as they are.
  // (the spaces and the "1.0" would change if a scalar were re-serialized)
  for (const text of ["No such object", " 5 ", "1.0", '"quoted" ', " null ", "{broken"])
    assert.equal(row(text, text.length).body.value, text);
  assert.equal(row("No such object", 14).layout, 0);
  // Only text types: JSON-looking text of an XML type is left as it is.
  const xml = normalizeBody(Buffer.from(pretty), "application/xml", ctx());
  assert.equal(xml.value, pretty);
  assert.equal(
    layoutOverhead({
      headers: { "content-type": "application/xml" },
      body: Buffer.from(pretty),
      bodyBytes: pretty.length,
    }),
    0,
  );
  // The compact length is in bytes, not characters.
  const accented = '{"message":"é"}';
  const accentedPretty = JSON.stringify(JSON.parse(accented), null, 2);
  const accentedLength = Buffer.byteLength(accentedPretty);
  assert.equal(
    layoutOverhead({
      headers: { "content-type": "text/html" },
      body: Buffer.from(accented),
      bodyBytes: accentedLength,
    }),
    accentedLength - Buffer.byteLength(accented),
  );
  const plain = normalizeExchange(
    {
      method: "GET",
      url: "https://x.example/x",
      status: 200,
      headers: { "content-type": "application/octet-stream" },
      body: Buffer.from(pretty),
      bodyBytes: pretty.length,
    },
    ctx(),
  );
  assert.equal(plain.body.type, "bytes");
  assert.equal(plain.layout, 0);
});
