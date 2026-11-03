// The real network helpers, against a loopback server: the exact bytes and lower-case headers
// `fetchNet` returns, that it never follows a redirect and that it times out, and which hosts the
// egress guard lets the SDK transports reach.

import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { after, before, describe, it } from "node:test";

import { fetchNet, installEgressGuard } from "./storage-signed-put/deps.mjs";

let server;
let base;
let port;

before(async () => {
  server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      if (req.url === "/redirect") {
        res.writeHead(302, { location: "/echo" });
        res.end();
      } else if (req.url === "/slow") {
        // never answers
      } else if (req.url === "/bytes") {
        res.writeHead(200, { "Content-Type": "application/octet-stream", "X-Mixed-Case": "Yes" });
        res.end(Buffer.from(Array.from({ length: 256 }, (_, i) => i)));
      } else if (req.url === "/missing") {
        res.writeHead(404, { "content-type": "application/xml" });
        res.end("<Error><Code>NoSuchKey</Code></Error>");
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            method: req.method,
            headers: req.headers,
            body: body.toString("base64"),
          }),
        );
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = server.address().port;
  base = `http://127.0.0.1:${port}`;
  installEgressGuard(["127.0.0.1"]);
});

after(() => {
  server.closeAllConnections();
  server.close();
});

describe("fetchNet", () => {
  it("returns the status, lower-case headers and the exact bytes", async () => {
    const res = await fetchNet({
      method: "GET",
      url: `${base}/bytes`,
      headers: {},
      timeoutMs: 5000,
    });
    assert.equal(res.status, 200);
    assert.deepEqual(
      [...res.body],
      Array.from({ length: 256 }, (_, i) => i),
    );
    assert.equal(res.headers["x-mixed-case"], "Yes");
    assert.equal(res.headers["content-type"], "application/octet-stream");
    assert.ok(Buffer.isBuffer(res.body));
  });

  it("sends a GET without a body and a PUT with the exact bytes and headers", async () => {
    const get = await fetchNet({
      method: "GET",
      url: `${base}/echo`,
      headers: { "x-test": "1" },
      timeoutMs: 5000,
    });
    const seenGet = JSON.parse(get.body.toString("utf8"));
    assert.deepEqual([seenGet.method, seenGet.body, seenGet.headers["x-test"]], ["GET", "", "1"]);
    const bytes = Buffer.from([0, 255, 128, 10]);
    const put = await fetchNet({
      method: "PUT",
      url: `${base}/echo`,
      headers: { "content-type": "image/png", "x-goog-content-length-range": "0,10" },
      body: bytes,
      timeoutMs: 5000,
    });
    const seen = JSON.parse(put.body.toString("utf8"));
    assert.equal(seen.method, "PUT");
    assert.equal(seen.body, bytes.toString("base64"));
    assert.equal(seen.headers["content-type"], "image/png");
    assert.equal(seen.headers["x-goog-content-length-range"], "0,10");
    const empty = await fetchNet({
      method: "PUT",
      url: `${base}/echo`,
      headers: {},
      body: Buffer.alloc(0),
      timeoutMs: 5000,
    });
    assert.equal(JSON.parse(empty.body.toString("utf8")).body, "");
  });

  it("returns a 4xx as an answer and never follows a redirect", async () => {
    const missing = await fetchNet({
      method: "GET",
      url: `${base}/missing`,
      headers: {},
      timeoutMs: 5000,
    });
    assert.deepEqual(
      [missing.status, missing.body.toString("utf8")],
      [404, "<Error><Code>NoSuchKey</Code></Error>"],
    );
    const redirect = await fetchNet({
      method: "GET",
      url: `${base}/redirect`,
      headers: {},
      timeoutMs: 5000,
    });
    assert.equal(redirect.status, 302);
    assert.equal(redirect.headers.location, "/echo");
  });

  it("rejects when the server does not answer within the timeout", async () => {
    const started = Date.now();
    await assert.rejects(
      fetchNet({ method: "GET", url: `${base}/slow`, headers: {}, timeoutMs: 300 }),
    );
    assert.ok(Date.now() - started < 3000);
  });
});

describe("egress guard", () => {
  const get = (target) =>
    new Promise((resolve, reject) => {
      http
        .get(target, (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode));
        })
        .on("error", reject);
    });

  it("lets an allowed host through as a string, a URL and an options object", async () => {
    assert.equal(await get(`${base}/echo`), 200);
    assert.equal(await get(new URL(`${base}/echo`)), 200);
    assert.equal(await get({ hostname: "127.0.0.1", port, path: "/echo" }), 200);
    assert.equal(
      await get({ host: `127.0.0.1:${port}`.replace(/:\d+$/, ""), port, path: "/echo" }),
      200,
    );
  });

  it("refuses any other host, whatever the call form", () => {
    assert.throws(() => http.get("http://example.test/"), /egress refused: example.test/);
    assert.throws(() => http.get(new URL("http://example.test/")), /egress refused/);
    assert.throws(() => http.request({ hostname: "example.test", path: "/" }), /egress refused/);
    assert.throws(
      () => http.get({ host: "example.test:8080", path: "/" }),
      /egress refused: example.test/,
    );
    assert.throws(() => https.request("https://probe.invalid/"), /egress refused/);
    assert.throws(() => https.get({ path: "/" }), /egress refused/);
  });
});
