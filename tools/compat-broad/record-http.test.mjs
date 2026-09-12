import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { receiveHttp } from "./record-http.mjs";

test("bounded real HTTP separates non-JSON, empty, overflow, timeout and interrupted bodies", async () => {
  const dir = await mkdtemp(join(tmpdir(), "broad-http-"));
  const server = createServer((req, res) => {
    if (req.url === "/timeout") return;
    if (req.url === "/broken") {
      res.writeHead(200, { "content-type": "text/plain", "content-length": "100" });
      res.write("short");
      setTimeout(() => res.destroy(), 20);
      return;
    }
    if (req.url === "/json") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"n":1}');
      return;
    }
    if (req.url === "/empty") {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end(req.url === "/large" ? "x".repeat(100) : "private-body");
  });
  await new Promise((resolve) =>
    server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", resolve),
  );
  const origin = `http://127.0.0.1:${server.address().port}`;
  const get = (path, maxBytes = 1000) =>
    receiveHttp(
      origin + path,
      { signal: AbortSignal.timeout(100) },
      { origin, privateDirectory: dir, maxBytes },
    );
  try {
    const json = await get("/json");
    assert.deepEqual(json.body, { n: 1 });
    assert.equal(json.http.bodyKind, "json");
    const empty = await get("/empty");
    assert.equal(empty.http.status, 404);
    assert.equal(empty.http.bodyKind, "empty");
    assert.equal(empty.http.complete, true);
    assert.equal(empty.http.receivedBytes, 0);
    const text = await get("/text");
    assert.equal(text.http.bodyKind, "non-json");
    assert.equal(text.http.complete, true);
    assert.equal(text.http.receivedBytes, 12);
    assert.equal(text.http.contentType, "text/plain; charset=utf-8");
    assert.ok(!JSON.stringify(text.http).includes("private-body"));
    assert.equal(await readFile(join(dir, text.privateFile), "utf8"), "private-body");
    const large = await get("/large", 16);
    assert.equal(large.http.complete, false);
    assert.equal(large.http.failure, "size-limit");
    assert.equal(large.http.truncated, true);
    assert.equal(large.http.digestScope, "prefix");
    const timeout = await get("/timeout");
    assert.equal(timeout.http.complete, false);
    assert.equal(timeout.http.failure, "timeout");
    const broken = await get("/broken");
    assert.equal(broken.http.complete, false);
    assert.equal(broken.http.failure, "body-interrupted");
    assert.equal(broken.http.status, 200);
    await assert.rejects(
      receiveHttp("https://example.com", {}, { origin, privateDirectory: dir }),
      /owned origin/,
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});
