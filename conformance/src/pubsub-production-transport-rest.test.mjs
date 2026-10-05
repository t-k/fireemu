import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createBudget, createCapture } from "./pubsub-production/capture.mjs";
import { createRest, parseBody } from "./pubsub-production/rest.mjs";
import { createTokenProvider } from "./pubsub-production/token.mjs";

const TOKEN = "ya29.a0AfH6SMBsecretsecretsecretsecretsecret";

async function server(handler) {
  const seen = [];
  const http = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    seen.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: Buffer.concat(chunks).toString(),
    });
    handler(request, response, seen.length);
  });
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${http.address().port}`, seen, close: () => http.close() };
}
const setup = (base, extra = {}) => {
  const lines = [];
  const budget = createBudget(extra.max ?? 10);
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  const rest = createRest({ base, budget, capture, ...extra });
  return { rest, lines, budget };
};

test("a body is JSON, or empty, or kept as text up to a limit", () => {
  assert.equal(parseBody(""), null);
  assert.deepEqual(parseBody('{"a":1}'), { a: 1 });
  assert.deepEqual(parseBody("<html>no</html>"), { raw: "<html>no</html>" });
  assert.equal(parseBody("x".repeat(5000)).raw.length, 4096);
});

test("a request carries the token and the quota project, is captured, and the token never reaches the capture", async (t) => {
  const s = await server((_, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"name":"projects/p/topics/t"}');
  });
  t.after(s.close);
  const { rest, lines, budget } = setup(s.base, {
    getToken: async () => TOKEN,
    quotaProject: "demo-project",
  });
  const reply = await rest.request({
    label: { case: "c", step: "s1" },
    op: "createTopic",
    method: "PUT",
    path: "/v1/projects/p/topics/t",
    body: { labels: { a: "b" } },
  });
  assert.deepEqual(reply, { status: 200, body: { name: "projects/p/topics/t" }, unknown: false });
  assert.equal(s.seen[0].headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(s.seen[0].headers["x-goog-user-project"], "demo-project");
  assert.equal(s.seen[0].headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(s.seen[0].body), { labels: { a: "b" } });
  assert.equal(budget.used(), 1);
  assert.equal(lines.length, 1);
  assert.equal(lines[0].case, "c");
  assert.equal(lines[0].transport, "rest");
  assert.deepEqual(lines[0].request, {
    method: "PUT",
    path: "/v1/projects/p/topics/t",
    body: { labels: { a: "b" } },
  });
  assert.deepEqual(lines[0].response, {
    status: 200,
    body: { name: "projects/p/topics/t" },
    bodyBytes: 30,
  });
  assert.equal(typeof lines[0].ms, "number");
  assert.equal(JSON.stringify(lines).includes(TOKEN), false);
  assert.equal(JSON.stringify(lines).includes("secretsecret"), false);
});

test("the token choices: none sends no credential, invalid a fixed bad one, and an emulator needs no token", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const withToken = setup(s.base, { getToken: async () => TOKEN, quotaProject: "demo-project" });
  await withToken.rest.request({ label: {}, op: "x", method: "GET", path: "/a", token: "none" });
  await withToken.rest.request({ label: {}, op: "x", method: "GET", path: "/b", token: "invalid" });
  const noToken = setup(s.base);
  await noToken.rest.request({ label: {}, op: "x", method: "GET", path: "/c" });
  assert.equal(s.seen[0].headers.authorization, undefined);
  assert.equal(
    s.seen[0].headers["x-goog-user-project"],
    undefined,
    "no quota project without a credential",
  );
  assert.equal(s.seen[1].headers.authorization, "Bearer invalid-token-for-the-recording");
  assert.equal(s.seen[1].headers["x-goog-user-project"], "demo-project");
  assert.equal(s.seen[2].headers.authorization, undefined);
  assert.equal(s.seen[2].headers["content-type"], undefined, "no body, no content type");
});

test("a request over the budget is refused before it is sent, and a transport error is an unknown answer, never retried", async (t) => {
  let calls = 0;
  const s = await server((_, response) => {
    calls += 1;
    response.destroy();
  });
  t.after(s.close);
  const { rest, lines } = setup(s.base, { max: 2 });
  const reply = await rest.request({
    label: { case: "c" },
    op: "publish",
    method: "POST",
    path: "/v1/x:publish",
    body: {},
  });
  assert.deepEqual(reply, { status: null, body: undefined, unknown: true });
  assert.equal(calls, 1, "one attempt");
  assert.equal(lines[0].unknown, true);
  assert.deepEqual(lines[0].response, { status: null, unknown: true, error: "transport" });
  await rest.request({ label: {}, op: "x", method: "GET", path: "/y" });
  await assert.rejects(
    rest.request({ label: {}, op: "x", method: "GET", path: "/z" }),
    /budget of 2 is spent/,
  );
  assert.equal(calls, 2, "the refused request was not sent");
});

test("a timeout is an unknown answer of its own kind, and the error message is not captured", async (t) => {
  const s = await server(() => {});
  t.after(() => s.close());
  const { rest, lines } = setup(s.base);
  const reply = await rest.request({
    label: {},
    op: "x",
    method: "GET",
    path: "/slow",
    timeoutMs: 100,
  });
  assert.equal(reply.unknown, true);
  assert.equal(lines[0].response.error, "timeout");
  assert.equal(lines[0].response.message, undefined);
  s.close();
});

test("the base must be an origin", () => {
  const budget = createBudget(1);
  const capture = createCapture({ journal: { write() {} } });
  for (const bad of ["", "pubsub.googleapis.com", "http://x/y", "ftp://x", undefined, 5])
    assert.throws(() => createRest({ base: bad, budget, capture }), /origin/, String(bad));
});

test("the token provider runs gcloud without a shell, caches the token, and an error never contains it", async () => {
  const calls = [];
  let clock = 0;
  const provider = createTokenProvider({
    execFile: async (file, args, options) => {
      calls.push({ file, args, options });
      return `${TOKEN}\n`;
    },
    now: () => clock,
    ttlMs: 1000,
  });
  assert.equal(await provider.get(), TOKEN);
  assert.equal(await provider.get(), TOKEN);
  assert.equal(provider.calls(), 1);
  assert.deepEqual(calls[0].args, ["auth", "application-default", "print-access-token"]);
  assert.equal(calls[0].file, "gcloud");
  assert.equal(calls[0].options.timeout, 30_000);
  clock = 999;
  await provider.get();
  assert.equal(provider.calls(), 1);
  clock = 1000;
  await provider.get();
  assert.equal(provider.calls(), 2, "refreshed when the ttl has passed");
  provider.invalidate();
  await provider.get();
  assert.equal(provider.calls(), 3);
  for (const output of [
    "",
    "short",
    "two words 1234567890123456789012345",
    `${TOKEN}\nsecond line`,
    "a".repeat(5000),
  ]) {
    const bad = createTokenProvider({ execFile: async () => output });
    await assert.rejects(
      bad.get(),
      (error) =>
        /not an access token/.test(error.message) &&
        !error.message.includes(TOKEN) &&
        !error.message.includes(output.slice(0, 12) || "~"),
    );
  }
  const failing = createTokenProvider({
    execFile: async () => {
      throw new Error(`failed with ${TOKEN}`);
    },
  });
  await assert.rejects(
    failing.get(),
    (error) =>
      error.message === "gcloud could not print an access token" && !error.message.includes(TOKEN),
  );
});

test("complete success and client errors are definite; all 5xx, redirects, sub-200 and unreadable bodies are unknown", async () => {
  const classify = async (status, text) => {
    const capture = createCapture({ journal: { write() {} } });
    const rest = createRest({
      base: "http://127.0.0.1:1",
      budget: createBudget(1),
      capture,
      fetchImpl: async () => ({ status, text: async () => text }),
    });
    return (await rest.request({ label: {}, op: "x", method: "GET", path: "/a" })).unknown;
  };
  for (const [status, text, unknown] of [
    [200, "{}", false],
    [204, "", false],
    [400, '{"error":{"status":"INVALID_ARGUMENT"}}', false],
    [404, "{}", false],
    [501, '{"error":{"status":"UNIMPLEMENTED"}}', true],
    [500, "{}", true],
    [503, "{}", true],
    [302, "", true],
    [100, "", true],
    [200, "<html>", true],
  ])
    assert.equal(await classify(status, text), unknown, String(status));
});

test("all 5xx including 501, cancellation, unreadable error bodies and scalar JSON are unknown", async () => {
  for (const [status, text] of [
    [501, '{"error":{"status":"UNIMPLEMENTED"}}'],
    [499, "{}"],
    [404, "<html>"],
    [200, "null"],
    [200, "[]"],
    [200, "true"],
    [200, '"ok"'],
  ]) {
    const { rest } = setup("http://127.0.0.1:1", {
      fetchImpl: async () => ({ status, text: async () => text }),
    });
    assert.equal(
      (await rest.request({ label: {}, op: "x", method: "GET", path: "/x" })).unknown,
      true,
      `${status}/${text}`,
    );
  }
});

test("redirects remain one counted unknown response and never reach the redirected route", async (t) => {
  const s = await server((request, response) => {
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/applied" });
      response.end("{}");
    } else response.end("{}");
  });
  t.after(s.close);
  const { rest, budget, lines } = setup(s.base);
  assert.equal(
    (await rest.request({ label: {}, op: "x", method: "GET", path: "/redirect" })).unknown,
    true,
  );
  assert.equal(s.seen.length, 1);
  assert.equal(budget.used(), 1);
  assert.equal(lines[0].response.status, 302);
});

test("REST captures the received UTF-8 body bytes and content length before compact JSON serialization", async (t) => {
  const raw = '{\n  "name": "topic-東京"\n}\n';
  const s = await server((_, response) => {
    response.writeHead(200, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(raw),
    });
    response.end(raw);
  });
  t.after(s.close);
  const { rest, lines } = setup(s.base);
  await rest.request({ label: {}, op: "getTopic", method: "GET", path: "/x" });
  assert.equal(lines[0].response.bodyBytes, Buffer.byteLength(raw));
  assert.equal(lines[0].response.contentLength, String(Buffer.byteLength(raw)));
  assert.notEqual(
    lines[0].response.bodyBytes,
    Buffer.byteLength(JSON.stringify(lines[0].response.body)),
  );
});
