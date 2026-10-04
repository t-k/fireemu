import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { BudgetExhausted, GuardRefused, classify, createTransport, pick, resolveText } from "./functions-events/record/rest.mjs";
import { PROJECT } from "./functions-events/record/script.mjs";

const doc = (tail = "/fe_events_primary/e1") => `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents${tail}`;
const fakeResponse = (status, body) => ({ status, arrayBuffer: async () => Buffer.from(typeof body === "string" ? body : JSON.stringify(body)) });
function setup({ replies, ceiling = 10 }) {
  const directory = mkdtempSync(join(tmpdir(), "fe-rest-"));
  const calls = [];
  const queue = [...replies];
  const transport = createTransport({
    directory,
    ceiling,
    token: async () => "access-token",
    apiKey: "browser-key",
    fetch: async (url, init) => {
      calls.push({ url, init });
      const next = queue.shift();
      if (next instanceof Error) throw next;
      return next;
    },
  });
  return { transport, calls, directory };
}
const spec = (over = {}) => ({ id: "t.1", method: "GET", url: doc(), auth: "oauth", mutation: false, expect: [200], ...over });
const journal = (directory) => readFileSync(join(directory, "journal.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

test("classify: only a complete 2xx or a 4xx is settled; everything else is unknown", () => {
  assert.equal(classify({ status: 200, bodyReadable: true }), "success");
  assert.equal(classify({ status: 404, bodyReadable: true }), "refusal");
  for (const status of [0, 100, 199, 301, 302, 500, 503, undefined]) assert.equal(classify({ status, bodyReadable: true }), "unknown", String(status));
  assert.equal(classify({ status: 200, bodyReadable: false }), "unknown");
  assert.equal(classify({ error: "TimeoutError" }), "unknown");
});

test("placeholders resolve and a missing one stops the request", () => {
  assert.equal(resolveText("a/${x}/b", { x: 7 }), "a/7/b");
  assert.throws(() => resolveText("${y}", {}), /placeholder y/);
  assert.equal(pick({ a: { b: [{ c: 1 }] } }, "$.a.b[0].c"), 1);
  assert.equal(pick([{ document: { name: "n" } }], "$[0].document.name"), "n");
  assert.equal(pick({}, "$.missing.deeper"), undefined);
});

test("a request is sent once with the OAuth token, journaled before and after, and the answer is stored privately", async () => {
  const { transport, calls, directory } = setup({ replies: [fakeResponse(200, { name: "x" })] });
  const result = await transport.request(spec());
  assert.equal(result.kind, "success");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers.authorization, "Bearer access-token");
  assert.equal(calls[0].init.redirect, "manual");
  const states = journal(directory).map(({ state }) => state);
  assert.deepEqual(states, ["before-send", "response-persisted"]);
  assert.equal(readdirSync(join(directory, "responses")).length, 1);
});

test("a change that gets a 5xx, a timeout or a redirect is unknown and is never retried", async () => {
  for (const reply of [fakeResponse(503, {}), Object.assign(new Error("t"), { name: "TimeoutError" }), fakeResponse(302, "")]) {
    const { transport, calls } = setup({ replies: [reply, fakeResponse(200, {})] });
    const result = await transport.request(spec({ method: "DELETE", mutation: true, expect: [200] }));
    assert.equal(result.kind, "unknown");
    assert.equal(calls.length, 1);
  }
});

test("an unexpected status is recorded, not thrown", async () => {
  const { transport, directory } = setup({ replies: [fakeResponse(403, { error: { code: 403 } })] });
  const result = await transport.request(spec());
  assert.equal(result.expected, false);
  assert.equal(result.kind, "refusal");
  assert.equal(journal(directory).at(-1).expected, false);
});

test("the guard stops a request before anything is sent and the ceiling stops the run", async () => {
  const { transport, calls, directory } = setup({ replies: [fakeResponse(200, {}), fakeResponse(200, {})], ceiling: 1 });
  await assert.rejects(transport.request(spec({ url: "https://firestore.googleapis.com/v1/projects/other/databases/(default)/documents/fe_events_primary/e1" })), GuardRefused);
  assert.equal(calls.length, 0);
  await transport.request(spec());
  await assert.rejects(transport.request(spec({ id: "t.2" })), BudgetExhausted);
  assert.equal(calls.length, 1);
  assert.ok(journal(directory).some(({ state }) => state === "refused-before-send"));
});

test("captures feed later requests, secrets never reach the stored answer, and a skipped request is journaled", async () => {
  const { transport, calls, directory } = setup({
    replies: [fakeResponse(200, { idToken: "SECRET", localId: "u1" }), fakeResponse(200, {})],
  });
  await transport.request(spec({ id: "a", method: "POST", url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp", auth: "apikey", mutation: true, body: { email: "x@example.test" }, capture: { idToken: "$.idToken", uid: "$.localId" } }));
  assert.match(calls[0].url, /[?&]key=browser-key$/);
  const stored = readFileSync(join(directory, "responses", readdirSync(join(directory, "responses"))[0]), "utf8");
  assert.ok(!stored.includes("SECRET"));
  await transport.request(spec({ id: "b", url: doc("/fe_events_primary/${uid}"), auth: "idtoken" }));
  assert.equal(calls[1].init.headers.authorization, "Bearer SECRET");
  const skipped = await transport.request(spec({ id: "c", when: "nothingCaptured" }));
  assert.equal(skipped.skipped, true);
  assert.equal(calls.length, 2);
});

test("a body over the limit or not JSON on a 2xx is unreadable and therefore unknown", async () => {
  const { transport } = setup({ replies: [fakeResponse(200, "<html>"), fakeResponse(200, "x".repeat(1024 * 1024 + 1))] });
  assert.equal((await transport.request(spec())).kind, "unknown");
  assert.equal((await transport.request(spec({ id: "t.2" }))).kind, "unknown");
});

test("the OAuth requests name the sandbox project as the quota project; the API-key and ID-token calls do not", async () => {
  const { transport, calls } = setup({ replies: [fakeResponse(200, {}), fakeResponse(200, { localId: "u", idToken: "I" }), fakeResponse(200, {})] });
  await transport.request(spec());
  assert.equal(calls[0].init.headers["x-goog-user-project"], PROJECT);
  await transport.request(spec({ id: "k", method: "POST", url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp", auth: "apikey", mutation: true, body: {}, capture: { idToken: "$.idToken" } }));
  assert.equal(calls[1].init.headers["x-goog-user-project"], undefined);
  await transport.request(spec({ id: "i", auth: "idtoken" }));
  assert.equal(calls[2].init.headers["x-goog-user-project"], undefined);
});
