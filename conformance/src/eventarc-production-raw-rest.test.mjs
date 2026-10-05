// The transport of the stage B recording keeps the bytes of every answer (stage A kept only the parsed
// JSON, so the layout of 87 answers was never recorded) and can send the credential variants of the
// token-format probes without ever writing a token into the capture.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createBudget, createCapture } from "./pubsub-production/capture.mjs";
import { TOKEN_MODES, createRawRest } from "./eventarc-production/rest.mjs";

async function server(handler) {
  const seen = [];
  const http = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      seen.push({ method: request.method, headers: request.headers, body: Buffer.concat(chunks) });
      handler(request, response, seen.length);
    });
  });
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${http.address().port}`, seen, close: () => http.close() };
}

function transport(base, extra = {}) {
  const lines = [];
  const budget = createBudget(extra.max ?? 20);
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  const rest = createRawRest({
    base,
    budget,
    capture,
    getToken: async () => "ya29.the-default-token-value",
    quotaProject: "demo-project",
    ...extra,
  });
  return { rest, lines, budget };
}
const get = (rest, extra = {}) =>
  rest.request({
    label: { case: "c", step: "01" },
    op: "getChannel",
    method: "GET",
    path: "/v1/x",
    ...extra,
  });

test("the raw bytes of an answer are captured as base64 with their length, whatever their layout", async (t) => {
  // Pretty-printed with two-space indentation, a non-ASCII character, and a final newline.
  const raw = Buffer.from('{\n  "error": {\n    "message": "café"\n  }\n}\n', "utf8");
  const s = await server((_, response) => {
    response.setHeader("content-type", "application/json; charset=UTF-8");
    response.setHeader("content-length", String(raw.length));
    response.statusCode = 404;
    response.end(raw);
  });
  t.after(s.close);
  const { rest, lines } = transport(s.base);
  const answer = await get(rest);
  assert.equal(answer.status, 404);
  assert.deepEqual(answer.body, { error: { message: "café" } });
  const entry = lines[0].response;
  assert.equal(Buffer.from(entry.bodyBase64, "base64").equals(raw), true);
  assert.equal(entry.bodyBytes, raw.length);
  assert.equal(entry.headers["content-length"], String(raw.length));
  assert.equal(entry.headers["content-type"], "application/json; charset=UTF-8");
  assert.equal(entry.status, 404);
});

test("the request asks for the identity encoding, so that the length of an answer is the length on the wire", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest } = transport(s.base);
  await get(rest);
  assert.equal(s.seen[0].headers["accept-encoding"], "identity");
});

test("an empty body is captured as zero bytes and a body that is not JSON keeps its raw bytes", async (t) => {
  const s = await server((_, response, n) => {
    if (n === 1) response.end("");
    else response.end("<html>oops</html>");
  });
  t.after(s.close);
  const { rest, lines } = transport(s.base);
  await get(rest);
  const second = await get(rest);
  assert.equal(lines[0].response.bodyBytes, 0);
  assert.equal(lines[0].response.bodyBase64, "");
  assert.equal(Buffer.from(lines[1].response.bodyBase64, "base64").toString(), "<html>oops</html>");
  assert.equal(second.unknown, true, "a 2xx that is not JSON says nothing about what was done");
});

test("the recorded size of the request body is the byte length of what was sent", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest, lines } = transport(s.base);
  await rest.request({
    label: {},
    op: "createChannel",
    method: "POST",
    path: "/v1/x",
    body: { name: "café" },
  });
  assert.equal(lines[0].requestBytes, s.seen[0].body.length);
  assert.equal(s.seen[0].body.toString(), '{"name":"café"}');
});

test("every credential mode sends what its name says, and no capture line carries a token", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest, lines } = transport(s.base, {});
  const modes = [
    "default",
    "none",
    "invalid",
    "ya29-garbage",
    "jwt-garbage",
    "jwt-expired-unsigned",
    { label: "wrong-scope", bearer: "ya29.scoped-secret-value" },
  ];
  for (const token of modes) await get(rest, { token });
  const auth = s.seen.map((request) => request.headers.authorization);
  assert.equal(auth[0], "Bearer ya29.the-default-token-value");
  assert.equal(auth[1], undefined);
  assert.equal(auth[2], "Bearer invalid-token-for-the-recording");
  assert.match(auth[3], /^Bearer ya29\.[A-Za-z0-9_-]{20,}$/);
  assert.match(auth[4], /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const [header, payload] = auth[5].replace("Bearer ", "").split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "RS256", typ: "JWT" });
  assert.equal(JSON.parse(Buffer.from(payload, "base64url")).exp, 1, "an expiry in 1970");
  assert.equal(auth[6], "Bearer ya29.scoped-secret-value");
  assert.deepEqual(
    lines.map((line) => line.tokenMode),
    [
      "default",
      "none",
      "invalid",
      "ya29-garbage",
      "jwt-garbage",
      "jwt-expired-unsigned",
      "wrong-scope",
    ],
  );
  const text = JSON.stringify(lines);
  for (const secret of [
    "the-default-token-value",
    "scoped-secret-value",
    "authorization",
    "Bearer",
  ])
    assert.equal(text.includes(secret), false, secret);
  assert.deepEqual(Object.keys(TOKEN_MODES).toSorted(), [
    "invalid",
    "jwt-expired-unsigned",
    "jwt-garbage",
    "ya29-garbage",
  ]);
});

test("a credential mode that is not known is refused before the budget is touched", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest, budget } = transport(s.base);
  await assert.rejects(() => get(rest, { token: "ya29-other" }), /unknown credential mode/);
  await assert.rejects(() => get(rest, { token: { label: "x" } }), /unknown credential mode/);
  assert.equal(budget.used(), 0);
  assert.equal(s.seen.length, 0);
});

test("the quota project is sent unless the request overrides it, and is recorded exactly when sent", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest, lines } = transport(s.base);
  await get(rest);
  await get(rest, { quotaProject: "other-project" });
  await get(rest, { quotaProject: null });
  await get(rest, { token: "none" });
  assert.deepEqual(
    s.seen.map((request) => request.headers["x-goog-user-project"]),
    ["demo-project", "other-project", undefined, undefined],
  );
  assert.deepEqual(
    lines.map((line) => line.quotaProject),
    ["demo-project", "other-project", undefined, undefined],
  );
});

test("a transport error and a timeout are unknown answers without the error message, and nothing is retried", async (t) => {
  const s = await server(() => {});
  t.after(s.close);
  const { rest, lines } = transport(s.base, { defaultTimeoutMs: 30 });
  const timedOut = await get(rest);
  assert.deepEqual(timedOut, { status: null, body: undefined, unknown: true });
  assert.equal(lines[0].response.error, "timeout");
  assert.equal(s.seen.length, 1);
  const refused = transport("http://127.0.0.1:9");
  const failed = await get(refused.rest);
  assert.equal(failed.unknown, true);
  assert.equal(refused.lines[0].response.error, "transport");
});

test("the budget is counted before the request is sent and a spent budget sends nothing", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest } = transport(s.base, { max: 1 });
  await get(rest);
  await assert.rejects(() => get(rest), { name: "BudgetExceeded" });
  assert.equal(s.seen.length, 1);
});

test("status 1xx/3xx/5xx (other than 501) are unknown at their edges too; 501 and 4xx are answers", async (t) => {
  const statuses = [300, 301, 399, 500, 503, 501, 404, 200];
  const s = await server((_, response, n) => {
    response.statusCode = statuses[n - 1];
    response.end("{}");
  });
  t.after(s.close);
  const { rest } = transport(s.base, { max: 10 });
  const unknown = [];
  for (let i = 0; i < statuses.length; i += 1) unknown.push((await get(rest)).unknown);
  assert.deepEqual(unknown, [true, true, true, true, true, false, false, false]);
});

test("a body is sent as JSON with its content type, and a request without a body carries none", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest } = transport(s.base);
  await rest.request({ label: {}, op: "x", method: "POST", path: "/v1/x", body: { a: 1 } });
  await get(rest);
  assert.equal(s.seen[0].headers["content-type"], "application/json");
  assert.equal(s.seen[1].headers["content-type"], undefined);
  assert.equal(s.seen[1].body.length, 0);
});

test("the base must be an origin: a path, a missing scheme and a non-string are refused", () => {
  const make = (base) => () =>
    createRawRest({
      base,
      budget: createBudget(1),
      capture: createCapture({ journal: { write() {} } }),
    });
  for (const base of [
    "http://127.0.0.1:1/path",
    "127.0.0.1:1",
    "ftp://host",
    "",
    undefined,
    5,
    null,
  ])
    assert.throws(make(base), /must be an origin/, String(base));
  assert.doesNotThrow(make("https://eventarc.googleapis.com"));
  assert.doesNotThrow(make("http://127.0.0.1:1"));
});

test("a labelled bearer needs a label of 1 to 40 lower-case characters, digits and dashes, and a non-empty bearer", async (t) => {
  const s = await server((_, response) => response.end("{}"));
  t.after(s.close);
  const { rest, budget } = transport(s.base, { max: 50 });
  for (const label of ["a", "a".repeat(40), "wrong-scope", "x1-2"])
    await get(rest, { token: { label, bearer: "ya29.value-of-the-token" } });
  const used = budget.used();
  for (const label of ["", "a".repeat(41), "Upper", "has space", "under_score", undefined, 5])
    await assert.rejects(
      () => get(rest, { token: { label, bearer: "ya29.value-of-the-token" } }),
      /unknown credential mode/,
      String(label),
    );
  await assert.rejects(
    () => get(rest, { token: { label: "ok", bearer: "" } }),
    /unknown credential mode/,
  );
  await assert.rejects(
    () => get(rest, { token: { label: "ok", bearer: 5 } }),
    /unknown credential mode/,
  );
  await assert.rejects(() => get(rest, { token: null }), /unknown credential mode/);
  assert.equal(budget.used(), used, "a refused mode never touches the budget");
});

test("the elapsed time of a request is recorded, and an unknown answer is counted by the capture", async (t) => {
  const s = await server((_, response, n) => {
    response.statusCode = n === 1 ? 503 : 200;
    response.end("{}");
  });
  t.after(s.close);
  const lines = [];
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  let clock = 1000;
  const rest = createRawRest({
    base: s.base,
    budget: createBudget(5),
    capture,
    now: () => (clock += 7),
  });
  await get(rest);
  await get(rest);
  assert.deepEqual(
    lines.map((line) => line.ms),
    [7, 7],
  );
  assert.equal(capture.unknownCount(), 1, "only the 503 is unknown");
  assert.equal(lines[0].unknown, true);
  assert.equal(lines[1].unknown, undefined);
});

test("a body over 4 KiB is captured whole, in parts, with its length and SHA-256: the byte layout is never truncated", async (t) => {
  const items = Array.from({ length: 200 }, (_, i) => ({
    name: `projects/p/locations/l/channels/c${i}`,
    state: "ACTIVE",
  }));
  const raw = Buffer.from(`${JSON.stringify({ channels: items }, null, 2)}\n`, "utf8");
  assert.ok(raw.length > 8000);
  const s = await server((_, response) => {
    response.setHeader("content-length", String(raw.length));
    response.end(raw);
  });
  t.after(s.close);
  const { rest, lines } = transport(s.base);
  await get(rest);
  const entry = lines[0].response;
  assert.equal(entry.bodyBase64, undefined);
  assert.ok(Array.isArray(entry.bodyBase64Parts) && entry.bodyBase64Parts.length > 1);
  assert.ok(entry.bodyBase64Parts.every((part) => typeof part === "string" && part.length <= 4096));
  assert.equal(Buffer.from(entry.bodyBase64Parts.join(""), "base64").equals(raw), true);
  assert.equal(entry.bodyBytes, raw.length);
  assert.equal(entry.bodySha256, createHash("sha256").update(raw).digest("hex"));
  // A small body keeps one string, and carries its digest too.
  const small = await server((_, response) => response.end("{}\n"));
  t.after(small.close);
  const again = transport(small.base);
  await get(again.rest);
  assert.equal(again.lines[0].response.bodyBase64, Buffer.from("{}\n").toString("base64"));
  assert.equal(again.lines[0].response.bodyBase64Parts, undefined);
  assert.equal(
    again.lines[0].response.bodySha256,
    createHash("sha256").update("{}\n").digest("hex"),
  );
  // The edge: exactly 4096 base64 characters stay one string, one more becomes parts.
  for (const [bytes, parts] of [
    [3072, false],
    [3073, true],
  ]) {
    const edge = await server((_, response) => response.end(Buffer.alloc(bytes, 65)));
    t.after(edge.close);
    const run = transport(edge.base);
    await get(run.rest);
    assert.equal(run.lines[0].response.bodyBase64Parts !== undefined, parts, String(bytes));
  }
});
