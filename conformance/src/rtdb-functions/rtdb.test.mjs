// The RTDB side of the CV14 run: setup of the sandbox instance and the Rules, the nine writes (seven
// with the ADC token, two with none), and the cleanup back to the starting state, against an in-memory
// fake of the production APIs. The administration itself is the residual recorder's own code
// (tools/sdk-smoke-database/rtdb-admin.mjs); this tests the wiring and what CV14 adds.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PREFIX } from "./frames.mjs";
import { CAPS, createRtdb, rulesFor } from "./rtdb.mjs";
import { P, fakeWorld, json, packet } from "./rtdb.fake.mjs";
import { STEPS } from "./sequence.mjs";

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

test("Rules that cannot be restored leave the RTDB not closed, whatever else was cleaned", async () => {
  // the second Rules PUT is the restore: the answer is a lie that never touched the Rules
  const w = fakeWorld([{ method: "PUT", path: /\.settings\/rules/u, kind: "lie", skip: 1 }]);
  const rtdb = make(w);
  await rtdb.setup();
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, false);
  assert.equal(closed.state.rules, "ours");
  assert.deepEqual(
    closed.unresolved,
    [],
    "nothing unknown was sent: the state alone says it is not closed",
  );
});

test("a row that cannot be logged means a sent request may be unaccounted for: not closed", async () => {
  const w = fakeWorld();
  let calls = 0;
  const rtdb = make(w, {
    log: () => {
      calls += 1;
      if (calls > 3) throw new Error("disk full");
    },
  });
  await rtdb.setup().catch(() => {});
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, false);
  assert.ok(closed.counts.admin.logFailures > 0);
});
