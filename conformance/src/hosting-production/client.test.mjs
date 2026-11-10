import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import test from "node:test";

import { edgeRequest } from "./client.mjs";

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await run(server.address().port);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}
const ask = (port, extra = {}, options) =>
  edgeRequest(
    { host: "127.0.0.1", port, secure: false, method: "GET", target: "/", ...extra },
    options,
  );

test("the request target reaches the server literally and no header is added but connection", async () => {
  const seen = [];
  await withServer(
    (req, res) => {
      seen.push({ url: req.url, headers: req.rawHeaders });
      res.end("ok");
    },
    async (port) => {
      for (const target of ["/../outside.txt", "/%2e%2e/x", "/go/\\evil", "/a%25b?x=%5c", "/%GG"]) {
        const answer = await ask(port, { target, headers: { "x-one": "1" } });
        assert.equal(answer.outcome, "answered", target);
      }
    },
  );
  assert.deepEqual(
    seen.map((s) => s.url),
    ["/../outside.txt", "/%2e%2e/x", "/go/\\evil", "/a%25b?x=%5c", "/%GG"],
  );
  const names = seen[0].headers.filter((_, i) => i % 2 === 0).map((n) => n.toLowerCase());
  assert.deepEqual(names.toSorted(), ["connection", "host", "x-one"]);
});

test("a redirect is an answer, never followed; raw header names and duplicates are kept", async () => {
  await withServer(
    (req, res) => {
      res.writeHead(302, [
        ["Location", "/next"],
        ["Set-Cookie", "a=1"],
        ["Set-Cookie", "b=2"],
        ["X-Mixed-Case", "v"],
      ]);
      res.end();
    },
    async (port) => {
      const answer = await ask(port);
      assert.equal(answer.status, 302);
      assert.deepEqual(
        answer.headers.filter(([n]) => n === "Set-Cookie").map(([, v]) => v),
        ["a=1", "b=2"],
      );
      assert.ok(answer.headers.some(([n]) => n === "X-Mixed-Case"));
      assert.equal(answer.body.length, 0);
    },
  );
});

test("a compressed answer stays compressed; HEAD and 304 carry no body", async () => {
  await withServer(
    (req, res) => {
      if (req.method === "HEAD") {
        res.writeHead(200, { "content-length": "10" });
        res.end();
      } else if (req.url === "/304") {
        res.writeHead(304);
        res.end();
      } else {
        res.writeHead(200, { "content-encoding": "gzip", "content-length": "3" });
        res.end(Buffer.from([1, 2, 3]));
      }
    },
    async (port) => {
      assert.deepEqual([...(await ask(port)).body], [1, 2, 3]);
      const head = await ask(port, { method: "HEAD" });
      assert.equal(head.outcome, "answered");
      assert.equal(head.body.length, 0);
      assert.equal((await ask(port, { target: "/304" })).status, 304);
    },
  );
});

test("an oversized body, a deadline and a reset are unknown answers with a reason, never retried", async () => {
  let count = 0;
  await withServer(
    (req, res) => {
      count += 1;
      if (req.url === "/big") res.end(Buffer.alloc(2000));
      else if (req.url === "/slow") setTimeout(() => res.end("late"), 400);
      else req.socket.destroy();
    },
    async (port) => {
      assert.equal(
        (await ask(port, { target: "/big" }, { maxBodyBytes: 1000 })).reason,
        "body-too-large",
      );
      assert.equal((await ask(port, { target: "/slow" }, { timeoutMs: 100 })).reason, "timeout");
      const reset = await ask(port, { target: "/reset" });
      assert.equal(reset.outcome, "unknown");
    },
  );
  assert.equal(count, 3, "one attempt per request");
});

test("a body shorter than its Content-Length is unknown", async () => {
  const server = net.createServer((socket) => {
    socket.on("data", () => {
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\nabc");
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const answer = await ask(server.address().port);
    assert.equal(answer.outcome, "unknown");
  } finally {
    server.close();
  }
});

test("a refused connection is unknown", async () => {
  const answer = await edgeRequest({
    host: "127.0.0.1",
    port: 1,
    secure: false,
    method: "GET",
    target: "/",
  });
  assert.equal(answer.outcome, "unknown");
  assert.equal(answer.reason, "ECONNREFUSED");
});

test("a body of exactly the bound is an answer; one byte more is unknown", async () => {
  await withServer(
    (req, res) => res.end(Buffer.alloc(req.url === "/exact" ? 1000 : 1001)),
    async (port) => {
      assert.equal(
        (await ask(port, { target: "/exact" }, { maxBodyBytes: 1000 })).outcome,
        "answered",
      );
      assert.equal(
        (await ask(port, { target: "/over" }, { maxBodyBytes: 1000 })).reason,
        "body-too-large",
      );
    },
  );
});
