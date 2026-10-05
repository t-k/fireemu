// The capture: its argument checks, headers, timeouts, body bound and request cap, one condition each.
import assert from "node:assert/strict";
import test from "node:test";
import { AuthStop, MAX_BODY_BYTES, createCapture } from "./capture.mjs";

const ok = (body = "{}\n", status = 200) => new Response(body, { status });
function make(extra = {}) {
  const rows = [];
  const sent = [];
  const capture = createCapture({
    accessToken: "test-token",
    save: async (row) => rows.push(row),
    send: async (request) => {
      sent.push(request);
      return ok();
    },
    maxRequests: 3,
    maxRequestCap: 5,
    allow: () => true,
    quotaProject: "proj",
    ...extra,
  });
  return { ...capture, rows, sent };
}
const spec = (id = "a") => ({ id, method: "GET", url: "https://example.test/" + id });

test("the arguments are checked: a token, a journal, an allowlist, a cap and a quota project", () => {
  for (const accessToken of ["", undefined, 7, "a\nb", "a\rb"])
    assert.throws(() => make({ accessToken }), /coordinator token required/, String(accessToken));
  assert.throws(() => make({ save: undefined }), /private persistence required/);
  assert.throws(() => make({ allow: undefined }), /an allowlist is required/);
  for (const maxRequests of [0, -1, 1.5, "3", undefined, 6])
    assert.throws(() => make({ maxRequests }), /invalid request cap/, String(maxRequests));
  for (const maxRequests of [1, 5])
    assert.doesNotThrow(() => make({ maxRequests }), String(maxRequests));
  for (const quotaProject of ["", undefined, 5])
    assert.throws(() => make({ quotaProject }), /quota project required/, String(quotaProject));
});

test("a request carries the bearer, the quota project and the JSON type, and follows no redirect", async () => {
  const { capture, sent } = make();
  await capture({ ...spec(), json: { a: 1 }, method: "POST" });
  const [request] = sent;
  assert.equal(request.headers.authorization, "Bearer test-token");
  assert.equal(request.headers["x-goog-user-project"], "proj");
  assert.equal(request.headers["content-type"], "application/json");
  assert.equal(request.redirect, "manual");
  assert.equal(request.body, '{"a":1}');
  assert.ok(request.signal instanceof AbortSignal);
});

test("a request outside the allowlist is refused before anything is journaled or sent", async () => {
  const { capture, rows, sent } = make({ allow: (s) => s.id === "a" });
  await assert.rejects(() => capture(spec("zz")), /^Error: request not allowed: zz$/);
  assert.deepEqual(rows, []);
  assert.deepEqual(sent, []);
});

test("the cap is exact: the request after the last allowed one throws", async () => {
  const { capture, counts } = make({ maxRequests: 2 });
  await capture(spec("a"));
  await capture(spec("b"));
  await assert.rejects(() => capture(spec("c")), /request cap exceeded/);
  assert.deepEqual(counts(), { attempted: 2, completed: 2, unknown: 0 });
});

test("the timeout of a request is the one asked for, else the one the packet gives, else ten seconds", async () => {
  const a = make();
  await a.capture(spec("a"));
  assert.equal(a.rows[0].timeoutMs, 10000);
  const b = make({ timeoutFor: (s) => (s.id === "slow" ? 45000 : 7000) });
  await b.capture(spec("slow"));
  await b.capture(spec("fast"));
  await b.capture({ ...spec("own"), timeoutMs: 123 });
  assert.deepEqual(
    b.rows.filter((r) => r.state === "before-send").map((r) => r.timeoutMs),
    [45000, 7000, 123],
  );
});

test("a body of exactly the bound is read and one byte more is unknown", async () => {
  assert.equal(MAX_BODY_BYTES, 8 * 1024 * 1024);
  const at = make({ send: async () => ok(" ".repeat(MAX_BODY_BYTES - 2) + "{}") });
  const answer = await at.capture(spec());
  assert.equal(answer.bodyBytes, MAX_BODY_BYTES);
  assert.deepEqual(answer.json, {});
  const over = make({ send: async () => ok(" ".repeat(MAX_BODY_BYTES - 1) + "{}") });
  const unknown = await over.capture(spec());
  assert.equal(unknown.bodyUnknown, true);
  assert.equal(over.rows.at(-1).state, "body-unknown");
  const small = make({ maxBodyBytes: 4, send: async () => ok("{}\n") });
  assert.equal((await small.capture(spec())).bodyBytes, 3);
  const smaller = make({ maxBodyBytes: 2, send: async () => ok("{}\n") });
  assert.equal((await smaller.capture(spec())).bodyUnknown, true);
});

test("a transport failure is journaled and the answer is null", async () => {
  const { capture, rows, counts } = make({
    send: async () => {
      throw new Error("down");
    },
  });
  assert.equal(await capture(spec()), null);
  assert.deepEqual(
    rows.map((r) => r.state),
    ["before-send", "transport-unknown"],
  );
  assert.deepEqual(counts(), { attempted: 1, completed: 0, unknown: 1 });
});

test("a failed journal write stops before the request", async () => {
  let sent = 0;
  const { capture } = make({
    save: async () => {
      throw new Error("disk");
    },
    send: async () => {
      sent++;
      return ok();
    },
  });
  await assert.rejects(() => capture(spec()), /private persistence failed before dispatch/);
  assert.equal(sent, 0);
});

test("a response that reflects the credential stops the capture", async () => {
  const { capture } = make({ send: async () => ok('{"leak":"test-token"}') });
  await assert.rejects(() => capture(spec()), /reflected a credential/);
});

test("a 401 stops the run, and a 403 does too unless the request observes a permission", async () => {
  for (const status of [401, 403]) {
    const { capture, authStop } = make({ send: async () => ok("{}\n", status) });
    await assert.rejects(() => capture(spec("w")), AuthStop);
    assert.deepEqual(authStop(), { id: "w", status });
  }
  const observed = make({ send: async () => ok("{}\n", 403) });
  const answer = await observed.capture({ ...spec(), observe: true });
  assert.equal(answer.status, 403);
  assert.equal(observed.authStop(), null);
  const still401 = make({ send: async () => ok("{}\n", 401) });
  await assert.rejects(() => still401.capture({ ...spec(), observe: true }), AuthStop);
});
