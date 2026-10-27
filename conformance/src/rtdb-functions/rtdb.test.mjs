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
  assert.deepEqual(CAPS, { observe: 80, cleanup: 40, mutations: 40, pollsPerOperation: 12 });
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

test("a log row that cannot be written for an unauthenticated write leaves the RTDB not closed", async () => {
  const w = fakeWorld();
  const rtdb = make(w, {
    log: (row) => {
      if (row.step === "s8") throw new Error("disk full");
    },
  });
  await rtdb.setup();
  const answer = await rtdb.write(STEPS[7]);
  assert.equal(answer.outcome, "unknown", "an answer that could not be logged is unknown");
  const closed = await rtdb.cleanup();
  assert.equal(closed.counts.anonymous.logFailures, 1);
  assert.deepEqual(closed.unresolved, []);
  assert.equal(closed.state.rules, "baseline");
  assert.equal(closed.closed, false);
});

const INSTANCE_GET = /instances\/fireemu-q-rtdb2$/u;

test("a transient 403 on a management read-back during the cleanup is retried with the setup's backoff, and the RTDB closes", async () => {
  // CV14 run 2026-10-27: the read-back after instance-disable answered 403 "Management API has not been used"
  // although the API was enabled; the same refusal at instance-before had passed on a retry
  const w = fakeWorld();
  const slept = [];
  const rtdb = make(w, { sleep: async (ms) => slept.push(ms) });
  await rtdb.setup();
  slept.length = 0;
  w.forbid = { path: INSTANCE_GET, remaining: 2 };
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, true, JSON.stringify(closed));
  assert.deepEqual(slept, [2000, 4000]);
  assert.equal(w.baseline(), true);
});

test("a read-back that keeps being refused is retried within 120 s in all and then leaves the RTDB not closed", async () => {
  const w = fakeWorld();
  const slept = [];
  const rtdb = make(w, { sleep: async (ms) => slept.push(ms) });
  await rtdb.setup();
  slept.length = 0;
  w.forbid = { path: INSTANCE_GET, remaining: 1000 };
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, false);
  assert.equal(
    slept.reduce((a, b) => a + b, 0),
    120_000,
  );
  assert.deepEqual(slept, [2000, 4000, 8000, 16_000, 30_000, 30_000, 30_000]);
  assert.ok(closed.counts.admin.cleanup <= CAPS.cleanup, "inside the cleanup cap");
  assert.equal(closed.state.instance, "ours");
  assert.deepEqual(closed.unresolved, [], "a refusal is an answer, nothing unknown was sent");
});

test("the cleanup has its own 120 s of retries even when the setup used some of them", async () => {
  const w = fakeWorld();
  w.forbid = { path: INSTANCE_GET, remaining: 4 };
  const slept = [];
  const rtdb = make(w, { sleep: async (ms) => slept.push(ms) });
  await rtdb.setup();
  // (the 5 s are the wait for the API-enable operation, not a retry)
  assert.deepEqual(
    slept.filter((ms) => ms !== 5000),
    [2000, 4000, 8000, 16_000],
    "30 s of the setup's budget are gone",
  );
  slept.length = 0;
  w.forbid = { path: INSTANCE_GET, remaining: 1000 };
  await rtdb.cleanup();
  assert.equal(
    slept.reduce((a, b) => a + b, 0),
    120_000,
  );
});

test("a retry in the cleanup is for a GET only: a refused mutation is not sent again", async () => {
  const w = fakeWorld();
  let disables = 0;
  const rtdb = make(w, {
    sleep: async () => {},
    fetchImpl: async (url, init) => {
      if (init.method === "POST" && url.endsWith(":disable")) {
        disables += 1;
        return json(403, { error: "denied" });
      }
      return w.fetch(url, init);
    },
  });
  await rtdb.setup();
  const closed = await rtdb.cleanup();
  assert.equal(closed.closed, false);
  assert.equal(disables, 1);
});

test("a log row that cannot be written for an admin write leaves the RTDB not closed", async () => {
  const w = fakeWorld();
  const rtdb = make(w, {
    log: (row) => {
      if (row.step === "s1") throw new Error("disk full");
    },
  });
  await rtdb.setup();
  assert.equal((await rtdb.write(STEPS[0])).outcome, "unknown");
  const closed = await rtdb.cleanup();
  assert.equal(closed.counts.admin.logFailures, 1);
  assert.equal(closed.counts.anonymous.logFailures, 0);
  assert.equal(closed.state.rules, "baseline");
  assert.equal(closed.closed, false);
});

test("with a nonce the Rules accept only a value that carries it, at the one item, and the nonce is in the Rules the RTDB gets", async () => {
  const nonce = "0123456789abcdef";
  assert.deepEqual(rulesFor(PREFIX, nonce), {
    rules: {
      ".read": false,
      ".write": false,
      [PREFIX]: {
        items: {
          c: { ".write": true, ".validate": "newData.child('run').val() === '0123456789abcdef'" },
        },
      },
    },
  });
  const w = fakeWorld();
  const rtdb = make(w, { nonce });
  await rtdb.setup();
  assert.deepEqual(JSON.parse(w.rules), rulesFor(PREFIX, nonce));
  await rtdb.cleanup();
});
