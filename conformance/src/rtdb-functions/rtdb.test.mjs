// The RTDB side of the CV14 run: setup of the sandbox instance and the Rules, the nine writes (seven
// with the ADC token, two with none), and the cleanup back to the starting state, against an in-memory
// fake of the production APIs. The administration itself is the residual recorder's own code
// (tools/sdk-smoke-database/rtdb-admin.mjs); this tests the wiring and what CV14 adds.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { PREFIX } from "./frames.mjs";
import { CAPS, createRtdb, rulesFor } from "./rtdb.mjs";
import { STEPS, applyWrite } from "./sequence.mjs";

const N = "000000000000";
const P = "demo-project";
const BASE = '// baseline\n{"rules":{".read":false,".write":false}}';
const json = (status, value) => ({
  status,
  text: async () => (typeof value === "string" ? value : JSON.stringify(value)),
});

/** A fake of the production APIs: management plane, Rules, and a data plane that applies the REST writes. */
function fakeWorld(faults = []) {
  const w = { api: "DISABLED", inst: "DELETED", rules: BASE, tree: {}, ops: 0, sent: [], auth: [] };
  const inst = (state) => ({
    name: `projects/${N}/locations/us-central1/instances/fireemu-q-rtdb2`,
    type: "USER_DATABASE",
    state,
  });
  function apply(method, u, body) {
    const p = u.pathname;
    if (u.host === "serviceusage.googleapis.com") {
      if (p.startsWith("/v1/operations/")) return json(200, { name: p.slice(4), done: true });
      if (method === "GET") {
        return json(200, {
          name: `projects/${N}/services/firebasedatabase.googleapis.com`,
          state: w.api,
        });
      }
      w.api = p.endsWith(":enable") ? "ENABLED" : "DISABLED";
      return json(200, { name: `operations/op${++w.ops}`, done: w.ops % 2 === 0 });
    }
    if (u.host === "firebasedatabase.googleapis.com") {
      if (p.endsWith("/-/instances")) {
        return json(200, { instances: w.inst === "DELETED" ? [] : [inst(w.inst)] });
      }
      const verb = p.split(":")[1];
      if (method === "DELETE") w.inst = "DELETED";
      else if (verb)
        w.inst = { undelete: "DISABLED", reenable: "ACTIVE", disable: "DISABLED" }[verb];
      return json(200, inst(w.inst));
    }
    const key = decodeURIComponent(p.replace(/\.json$/u, "").slice(1));
    if (key === ".settings/rules") {
      if (method === "PUT") {
        w.rules = body;
        return json(200, { status: "ok" });
      }
      return json(200, w.rules);
    }
    if (method === "GET") {
      const value = key.split("/").reduce((node, part) => node?.[part], w.tree);
      return json(200, value ?? null);
    }
    w.tree = applyWrite(w.tree, method, key.split("/"), body);
    return json(200, method === "DELETE" ? null : body);
  }
  w.fetch = async (url, init) => {
    const u = new URL(url);
    const body =
      init.body === undefined
        ? undefined
        : /rules/u.test(u.pathname)
          ? init.body
          : JSON.parse(init.body);
    w.sent.push(`${init.method} ${u.host}${u.pathname}`);
    w.auth.push([init.method, u.pathname, init.headers.authorization ?? null]);
    const fault = faults.find(
      (f) => !f.used && f.method === init.method && f.path.test(u.pathname),
    );
    if (!fault) return apply(init.method, u, body);
    fault.used = true;
    if (fault.kind === "timeout") throw new Error("timeout");
    if (fault.kind === "lie") return json(200, init.method === "DELETE" ? null : {});
    return json(503, "");
  };
  w.baseline = () =>
    w.api === "DISABLED" &&
    w.inst === "DELETED" &&
    w.rules === BASE &&
    Object.keys(w.tree).length === 0;
  return w;
}

const packet = {
  projectId: P,
  projectNumber: N,
  baselineRulesSha256: createHash("sha256").update(BASE).digest("hex"),
};
const make = (w, extra = {}) =>
  createRtdb({
    fetchImpl: w.fetch,
    headers: { authorization: "Bearer test-token", "x-goog-user-project": P },
    packet,
    log: () => {},
    sleep: async () => {},
    now: () => 1_000,
    ...extra,
  });

test("the Rules give the anonymous client the one item it writes and nothing else", () => {
  assert.deepEqual(rulesFor(PREFIX), {
    rules: { ".read": false, ".write": false, [PREFIX]: { items: { c: { ".write": true } } } },
  });
});

test("setup brings the instance up with the Rules, the writes go in with and without a token, and the cleanup restores the baseline", async () => {
  const w = fakeWorld();
  const rtdb = make(w);
  await rtdb.setup();
  assert.equal(w.api, "ENABLED");
  assert.equal(w.inst, "ACTIVE");
  assert.deepEqual(JSON.parse(w.rules), rulesFor(PREFIX));
  const answers = [];
  for (const step of STEPS) answers.push(await rtdb.write(step));
  assert.ok(
    answers.every((a) => a.outcome === "ok" && a.status === 200 && a.answeredAtMs === 1_000),
  );
  const tree = w.tree[PREFIX];
  assert.deepEqual(Object.keys(tree).toSorted(), ["items", "other"]);
  const dataAuth = w.auth.filter(
    ([method, path]) => path.includes(`/${PREFIX}/`) && method !== "GET",
  );
  assert.deepEqual(
    dataAuth.map(([, , auth]) => auth !== null),
    [true, true, true, true, true, true, true, false, false],
    "seven writes carry the token, the last two do not",
  );
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, true, JSON.stringify(closed));
  assert.deepEqual(closed.unresolved, []);
  assert.equal(w.baseline(), true);
});

test("an unknown write answer is returned as unknown and is never sent again; the prefix delete still clears it", async () => {
  const w = fakeWorld([
    { method: "PATCH", path: new RegExp(`items/a.json$`, "u"), kind: "timeout" },
  ]);
  const rtdb = make(w);
  await rtdb.setup();
  await rtdb.write(STEPS[0]);
  const unknown = await rtdb.write(STEPS[1]);
  assert.equal(unknown.outcome, "unknown");
  assert.equal(w.sent.filter((s) => s.startsWith("PATCH")).length, 1);
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, true, JSON.stringify(closed));
  assert.equal(w.baseline(), true);
});

test("a refused anonymous write is an answer, not an error", async () => {
  const w = fakeWorld();
  const rtdb = make(w, {
    fetchImpl: async (url, init) => {
      if (init.headers.authorization === undefined && init.method === "PUT")
        return json(401, { error: "Permission denied" });
      return w.fetch(url, init);
    },
  });
  await rtdb.setup();
  const answer = await rtdb.write(STEPS[7]);
  assert.equal(answer.outcome, "refused");
  assert.equal(answer.status, 401);
  assert.equal((await rtdb.cleanup()).closed, true);
});

test("an instance step whose answer is a lie leaves the RTDB not closed", async () => {
  const w = fakeWorld([{ method: "POST", path: /:undelete$/u, kind: "lie" }]);
  const rtdb = make(w);
  await assert.rejects(() => rtdb.setup(), /./u);
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, false);
});

test("the caps of the admin client bound the requests, and the anonymous client cannot write more than twice", async () => {
  assert.deepEqual(CAPS, { observe: 80, cleanup: 30, mutations: 40, pollsPerOperation: 12 });
  const w = fakeWorld();
  const rtdb = make(w);
  await rtdb.setup();
  await rtdb.write(STEPS[7]);
  await rtdb.write(STEPS[8]);
  await assert.rejects(() => rtdb.write(STEPS[7]), /cap reached/);
  assert.equal(w.sent.filter((s) => s.startsWith("PUT") && s.includes("items/c")).length, 1);
  await rtdb.cleanup();
});

test("no row the client logs holds the token", async () => {
  const w = fakeWorld();
  const rows = [];
  const rtdb = make(w, { log: (row) => rows.push(JSON.stringify(row)) });
  await rtdb.setup();
  for (const step of STEPS) await rtdb.write(step);
  await rtdb.cleanup();
  assert.ok(rows.length > 20);
  assert.ok(rows.every((row) => !row.includes("test-token") && !/Bearer/u.test(row)));
});
