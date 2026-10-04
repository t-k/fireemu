import assert from "node:assert/strict";
import test from "node:test";
import {
  CASES,
  MAX_JOBS,
  MAX_REQUESTS,
  PROJECT,
  createCapture,
  resources,
  waitFor,
} from "./calendar-v6.mjs";
import { RUN, fakeServer, refuseSecond, reply, run } from "./calendar-v6-fake.mjs";

const NUMBER = "123456789012";
const key = (method, path) => method + " " + path;
const JOBS = "projects/" + PROJECT + "/locations/us-central1/jobs";
const TOPIC = "projects/" + PROJECT + "/topics/fe-cal6-" + RUN;
const JOB = (id) => JOBS + "/fe-cal6-" + RUN + "-" + id;
const error = (code, message) => reply(code, { error: { code, message, status: "X" } });
const writes = (server) => server.state.calls.filter((c) => /^(PUT|POST|DELETE) /.test(c));

// ---- request naming, timeouts and headers -------------------------------------------------

test("a clean run names every request the same way, so the journal can be read back", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const { journal } = await run(server);
  const ids = new Set(journal.filter((r) => r.state === "before-send").map((r) => r.id));
  for (const id of [
    "identity",
    "service-cloudscheduler",
    "service-pubsub",
    "before-list-jobs",
    "before-list-topics",
    "before-topic",
    "create-topic",
    "final-list-jobs",
    "delete-topic",
    "read-deleted-topic",
    "final-list-topics",
  ])
    assert.ok(ids.has(id), id);
  for (const c of CASES) {
    const refused = refuseSecond({ name: "x-" + c.id });
    const steps = refused
      ? ["create", "read-deleted"]
      : ["create", "pause", "delete", "read-deleted"];
    for (const step of steps) assert.ok(ids.has(c.id + "-" + step), c.id + "-" + step);
    if (refused)
      for (const step of ["pause", "delete"]) assert.ok(!ids.has(c.id + "-" + step), c.id);
  }
});

test("creates and the topic's PUT and DELETE get thirty seconds, everything else ten", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const { journal } = await run(server);
  for (const row of journal.filter((r) => r.state === "before-send")) {
    const long =
      row.id === "create-topic" || row.id === "delete-topic" || row.id.endsWith("-create");
    assert.equal(row.timeoutMs, long ? 30000 : 10000, row.id);
  }
});

test("every request carries the bearer, the quota project and the JSON type, and no redirect is followed", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const seen = [];
  await run(server, {
    send: (request) => {
      seen.push(request);
      return server.send(request);
    },
  });
  assert.ok(seen.length > 100);
  for (const request of seen) {
    assert.equal(request.headers.authorization, "Bearer test-token");
    assert.equal(request.headers["x-goog-user-project"], PROJECT);
    assert.equal(request.headers["content-type"], "application/json");
    assert.equal(request.redirect, "manual");
  }
});

// ---- capture limits -------------------------------------------------------------------------

const LIST = "https://pubsub.googleapis.com/v1/projects/" + PROJECT + "/topics?pageSize=1000";
function capture(overrides = {}) {
  return createCapture({
    accessToken: "t",
    save: async () => {},
    send: async () => reply(200, {}),
    clock: Date.now,
    maxRequests: 2,
    own: resources(RUN),
    projectNumber: NUMBER,
    ...overrides,
  });
}

test("capture stops exactly at its request cap", async () => {
  const { capture: take, counts } = capture();
  await take({ id: "1", method: "GET", url: LIST });
  await take({ id: "2", method: "GET", url: LIST });
  await assert.rejects(() => take({ id: "3", method: "GET", url: LIST }), /cap exceeded/);
  assert.deepEqual(counts(), { attempted: 2, completed: 2, unknown: 0 });
});

test("capture takes a body of exactly 1 MiB and calls a larger one unknown", async () => {
  const big = (n) => new Response("x".repeat(n), { status: 200 });
  const exact = await capture({ send: async () => big(1024 * 1024) }).capture({
    id: "a",
    method: "GET",
    url: LIST,
  });
  assert.equal(exact.bodyUnknown, undefined);
  assert.equal(exact.bodyBytes, 1024 * 1024);
  const over = capture({ send: async () => big(1024 * 1024 + 1) });
  const answer = await over.capture({ id: "b", method: "GET", url: LIST });
  assert.equal(answer.bodyUnknown, true);
  assert.deepEqual(over.counts(), { attempted: 1, completed: 0, unknown: 1 });
});

test("a transport failure is journaled and counted unknown", async () => {
  const rows = [];
  const failing = capture({
    save: async (row) => rows.push(row),
    send: async () => {
      throw new Error("down");
    },
  });
  assert.equal(await failing.capture({ id: "a", method: "GET", url: LIST }), null);
  assert.deepEqual(
    rows.map((r) => r.state),
    ["before-send", "transport-unknown"],
  );
  assert.deepEqual(failing.counts(), { attempted: 1, completed: 0, unknown: 1 });
});

test("the cap is bounded by the module's maximum and the case list by its job limit", () => {
  assert.throws(() => capture({ maxRequests: MAX_REQUESTS + 1 }), /cap/);
  assert.throws(() => capture({ maxRequests: 0 }), /cap/);
  assert.doesNotThrow(() => capture({ maxRequests: MAX_REQUESTS }));
  const ids = (n) =>
    Array.from({ length: n }, (_, i) => ({
      id: String.fromCharCode(97 + (i % 26)) + String.fromCharCode(97 + Math.floor(i / 26)) + "00",
    }));
  assert.doesNotThrow(() => resources(RUN, ids(MAX_JOBS)));
  assert.throws(() => resources(RUN, ids(MAX_JOBS + 1)), /too many jobs/);
  assert.throws(() => resources(RUN, [{ id: "cr01" }, { id: "cr01" }]), /invalid case ID/);
  assert.throws(() => resources(RUN, [{ id: "CR01" }]), /invalid case ID/);
  assert.throws(() => resources(RUN, [{ id: "cr1" }]), /invalid case ID/);
  assert.equal(resources(RUN).topic, TOPIC);
  assert.equal(resources(RUN).jobs.cr01, JOB("cr01"));
});

test("a project number must be 12 or 13 digits", () => {
  for (const bad of ["12345678901", "12345678901234", "12345678901a", undefined])
    assert.throws(() => capture({ projectNumber: bad }), /project number/);
  for (const good of ["123456789012", "1234567890123"])
    assert.doesNotThrow(() => capture({ projectNumber: good }));
});

// ---- timing boundaries ----------------------------------------------------------------------

test("waitFor keeps a slot exactly two seconds ahead and skips a run less than five seconds away", () => {
  const at = (iso) => Date.parse(iso);
  const t = at("2026-10-06T00:00:56.500Z");
  assert.equal(waitFor({ kind: "before-minute-boundary", leadMs: 1500 }, t), 2000);
  const late = at("2026-10-06T00:00:56.501Z");
  assert.equal(waitFor({ kind: "before-minute-boundary", leadMs: 1500 }, late), 62000 - 1);
  const onRun = at("2026-10-06T00:04:55.000Z");
  assert.equal(waitFor({ kind: "after-run", everyMinutes: 5, afterMs: 500 }, onRun), 5500);
  const closer = at("2026-10-06T00:04:55.001Z");
  assert.equal(waitFor({ kind: "after-run", everyMinutes: 5, afterMs: 500 }, closer), 305499);
});

// ---- preflight ------------------------------------------------------------------------------

async function stopsInPreflight(hooks, label) {
  const server = fakeServer({ hooks });
  const { result } = await run(server);
  assert.equal(result.stage, "preflight", label);
  assert.equal(result.closureReady, false, label);
  assert.equal(result.topicIssued, false, label);
  assert.deepEqual(writes(server), [], label);
}

test("preflight stops before any write on a wrong identity, a disabled service or a dirty sandbox", async () => {
  const identity = key("GET", "projects/" + PROJECT + "/releases/cloud.firestore");
  const ok = {
    name: "projects/" + PROJECT + "/releases/cloud.firestore",
    rulesetName: "projects/" + PROJECT + "/rulesets/abc",
  };
  await stopsInPreflight({ [identity]: async () => error(500, "boom") }, "identity 500");
  await stopsInPreflight(
    { [identity]: async () => reply(200, { ...ok, name: "projects/x/releases/y" }) },
    "wrong name",
  );
  await stopsInPreflight({ [identity]: async () => reply(200, { name: ok.name }) }, "no ruleset");
  await stopsInPreflight(
    { [identity]: async () => reply(200, { ...ok, rulesetName: "projects/other/rulesets/abc" }) },
    "other project ruleset",
  );
  const service = (s) => key("GET", "projects/" + NUMBER + "/services/" + s + ".googleapis.com");
  await stopsInPreflight(
    { [service("cloudscheduler")]: async () => reply(200, { state: "DISABLED" }) },
    "scheduler disabled",
  );
  await stopsInPreflight({ [service("pubsub")]: async () => error(403, "no") }, "pubsub denied");
  await stopsInPreflight(
    { [key("GET", JOBS + "?pageSize=500")]: async () => reply(200, { jobs: [{ name: "other" }] }) },
    "jobs not empty",
  );
  await stopsInPreflight(
    {
      [key("GET", "projects/" + PROJECT + "/topics?pageSize=1000")]: async () =>
        reply(200, { topics: [{ name: "other" }] }),
    },
    "topics not empty",
  );
  await stopsInPreflight(
    { [key("GET", TOPIC)]: async () => reply(200, { name: TOPIC }) },
    "topic exists",
  );
});

// ---- the topic ------------------------------------------------------------------------------

test("a topic create refused by the server stops the run with the name issued and nothing deleted", async () => {
  const server = fakeServer({ hooks: { [key("PUT", TOPIC)]: async () => error(403, "denied") } });
  const { result } = await run(server);
  assert.equal(result.stage, "topic");
  assert.equal(result.closureReady, false);
  assert.equal(result.topicIssued, true);
  assert.deepEqual(writes(server), ["PUT " + TOPIC]);
});

test("a topic create whose answer is lost is settled by reading the name, patiently", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("PUT", TOPIC)]: async ({ state }) => {
        state.topic = true;
        return "throw";
      },
    },
  });
  const { result, journal } = await run(server);
  assert.ok(journal.some((r) => r.id === "read-topic" && r.state === "before-send"));
  assert.ok(result.cases.filter((c) => c.outcome === "accepted").length > 30);
  assert.equal(server.state.topic, false, "the run's own topic is deleted at the end");
  assert.equal(result.closureReady, false, "an unknown answer needs the later read-back");
});

test("a topic that never becomes visible is polled four times, ten seconds apart, and then the run stops", async () => {
  const server = fakeServer({ hooks: { [key("PUT", TOPIC)]: async () => "throw" } });
  const { result, journal, sleeps } = await run(server);
  const reads = journal.filter((r) => r.state === "before-send" && r.id.startsWith("read-topic"));
  assert.deepEqual(
    reads.map((r) => r.id),
    ["read-topic", "read-topic-poll-1", "read-topic-poll-2", "read-topic-poll-3"],
  );
  assert.deepEqual(sleeps, [10000, 10000, 10000]);
  assert.equal(result.stage, "topic");
  assert.equal(result.closureReady, false);
  assert.ok(
    !server.state.calls.some((c) => c.startsWith("POST ")),
    "no job without a proven topic",
  );
});

test("a 2xx topic answer that names another topic is not ownership", async () => {
  const server = fakeServer({
    hooks: {
      [key("PUT", TOPIC)]: async () =>
        reply(200, { name: "projects/" + PROJECT + "/topics/other" }),
    },
  });
  const { result } = await run(server);
  assert.equal(result.stage, "topic");
  assert.ok(!server.state.calls.some((c) => c.startsWith("POST ")));
});

// ---- unknown creates ------------------------------------------------------------------------

test("an unknown create is read up to three times, ten seconds apart, and then left alone", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", JOBS)]: async ({ body }) => (body.name.endsWith("-cr02") ? "throw" : undefined),
    },
  });
  const { result, journal, sleeps } = await run(server);
  const settles = journal.filter(
    (r) => r.state === "before-send" && r.id.startsWith("cr02-settle-create-"),
  );
  assert.deepEqual(
    settles.map((r) => r.id),
    ["cr02-settle-create-1", "cr02-settle-create-2", "cr02-settle-create-3"],
  );
  assert.equal(sleeps.filter((ms) => ms === 10000).length, 2);
  assert.equal(result.cases.find((c) => c.id === "cr02").outcome, "unknown-unsettled");
});

test("an unknown create whose name shows another job is a contradiction and is never deleted", async () => {
  const name = JOB("cr02");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", JOBS)]: async ({ body }) => (body.name.endsWith("-cr02") ? "throw" : undefined),
      [key("GET", name)]: async () =>
        reply(200, {
          name,
          state: "ENABLED",
          pubsubTarget: { topicName: "projects/" + PROJECT + "/topics/other" },
        }),
    },
  });
  const { result } = await run(server);
  assert.equal(result.cases.find((c) => c.id === "cr02").outcome, "identity-contradiction");
  assert.ok(!server.state.calls.includes("DELETE " + name));
  assert.equal(result.closureReady, false);
});

// ---- pause ----------------------------------------------------------------------------------

test("a pause whose answer is lost is confirmed by reading the job", async () => {
  const name = JOB("cr02");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", name + ":pause")]: async ({ state }) => {
        state.jobs.get(name).state = "PAUSED";
        return "throw";
      },
    },
  });
  const { result, journal } = await run(server);
  assert.ok(journal.some((r) => r.id === "cr02-read-after-pause" && r.state === "before-send"));
  assert.equal(result.cases.find((c) => c.id === "cr02").paused, true);
});

test("a pause that failed leaves the job eligible for its delete and says so", async () => {
  const name = JOB("cr02");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: { [key("POST", name + ":pause")]: async () => error(500, "later") },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr02");
  assert.equal(rec.paused, false);
  assert.equal(rec.deleted, true);
  assert.equal(server.state.jobs.size, 0);
});

// ---- deletes --------------------------------------------------------------------------------

const busy = (name) =>
  reply(409, {
    error: {
      code: 409,
      message: "sync mutate calls cannot be queued",
      status: "ABORTED",
      details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name }],
    },
  });

test("a job whose DELETE stays busy is tried four times and left, with the topic", async () => {
  const name = JOB("cr01");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: { [key("DELETE", name)]: async () => busy(name) },
  });
  const { result, journal } = await run(server);
  const attempts = journal.filter(
    (r) => r.state === "before-send" && r.id.startsWith("cr01-delete"),
  );
  assert.deepEqual(
    attempts.map((r) => r.id),
    ["cr01-delete", "cr01-delete-retry-1", "cr01-delete-retry-2", "cr01-delete-retry-3"],
  );
  assert.ok(!result.cases.find((c) => c.id === "cr01").deleted);
  assert.equal(server.state.topic, true);
  assert.equal(result.closureReady, false);
});

test("a DELETE whose answer is lost is settled by reading the name and says how", async () => {
  const name = JOB("cr01");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("DELETE", name)]: async ({ state }) => {
        state.jobs.delete(name);
        return "throw";
      },
    },
  });
  const { result, journal } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr01");
  assert.equal(rec.deleted, true);
  assert.equal(rec.deletedSettledByGet, true);
  assert.ok(journal.some((r) => r.id === "cr01-settle-delete-0" && r.state === "before-send"));
  assert.equal(result.closureReady, false, "an unknown answer needs the later read-back");
});

// ---- the end --------------------------------------------------------------------------------

test("a job that appears in the final listing keeps the topic and the run open", async () => {
  let lists = 0;
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("GET", JOBS + "?pageSize=500")]: async () =>
        ++lists >= 2 ? reply(200, { jobs: [{ name: JOB("zz99") }] }) : undefined,
    },
  });
  const { result } = await run(server);
  assert.equal(server.state.topic, true);
  assert.ok(!server.state.calls.includes("DELETE " + TOPIC));
  assert.equal(result.closureReady, false);
});

test("a topic DELETE that is acknowledged but did not remove the topic does not close the run", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: { [key("DELETE", TOPIC)]: async () => reply(200, {}) },
  });
  const { result } = await run(server);
  assert.equal(server.state.topic, true);
  assert.equal(result.closureReady, false);
});

test("a topic listing that is not empty at the end does not close the run", async () => {
  let lists = 0;
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("GET", "projects/" + PROJECT + "/topics?pageSize=1000")]: async () =>
        ++lists >= 2 ? reply(200, { topics: [{ name: TOPIC }] }) : undefined,
    },
  });
  const { result } = await run(server);
  assert.equal(result.closureReady, false);
});

test("a clean run is closed and says it is not yet verified clean", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const { result } = await run(server);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.topicIssued, true);
  assert.equal(result.outcome, "calendar-v6-needs-review");
  assert.equal(result.stage, "done");
});

test("the budget guard takes more jobs as the budget grows, in steps a formula change would shift", async () => {
  const taken = [];
  for (let budget = 80; budget <= 100; budget++) {
    const server = fakeServer({ refuse: refuseSecond });
    const { result } = await run(server, { budget });
    taken.push(result.cases.filter((c) => c.issued).length);
    assert.ok(result.attempted <= budget, "budget " + budget);
    assert.equal(result.closureReady, true, "what it created is cleaned up, budget " + budget);
    assert.equal(result.complete, false, "skipped cases make the packet incomplete");
    assert.equal(server.state.jobs.size, 0);
  }
  assert.deepEqual(
    taken,
    [15, 15, 15, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20],
  );
});

test("the documented limits are the ones in force", () => {
  assert.equal(MAX_REQUESTS, 240);
  assert.equal(MAX_JOBS, 50);
});

test("waitFor names an unknown timing", () => {
  assert.throws(() => waitFor({ kind: "nope" }, 1), /unknown timing nope/);
});

test("capture needs a real token and a request cap of at least one", () => {
  for (const bad of ["", undefined, null, 5, "a\rb"])
    assert.throws(() => capture({ accessToken: bad }), /token/);
  assert.doesNotThrow(() => capture({ maxRequests: 1 }));
});

test("a clean run reads no topic back (the create proved it), and completes", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const { result, journal } = await run(server);
  assert.ok(!journal.some((r) => r.id.startsWith("read-topic")));
  assert.equal(result.complete, true);
});

// ---- topic create status boundaries ---------------------------------------------------------

test("a client error on the topic create is a refusal and is not polled; anything else is read", async () => {
  for (const status of [400, 404, 499]) {
    const server = fakeServer({ hooks: { [key("PUT", TOPIC)]: async () => error(status, "no") } });
    const { journal, result } = await run(server);
    assert.equal(result.stage, "topic", String(status));
    assert.ok(!journal.some((r) => r.id.startsWith("read-topic")), "no polling after " + status);
  }
  for (const status of [300, 399, 500, 503]) {
    const server = fakeServer({
      hooks: { [key("PUT", TOPIC)]: async () => error(status, "later") },
    });
    const { journal } = await run(server);
    assert.ok(
      journal.some((r) => r.id === "read-topic"),
      "read after " + status,
    );
  }
});

// ---- creates: layouts and 2xx boundaries ----------------------------------------------------

test("a 200 that names the own job in an unrecorded layout is accepted as ours and cleaned up", async () => {
  const name = JOB("cr02");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", JOBS)]: async ({ state, body, own }) => {
        if (!body.name.endsWith("-cr02")) return undefined;
        state.jobs.set(name, { ...body, state: "ENABLED" });
        state.everCreated.add(name);
        return new Response(
          JSON.stringify({ name, state: "ENABLED", pubsubTarget: { topicName: own.topic } }),
          { status: 200 },
        );
      },
    },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr02");
  assert.equal(rec.outcome, "accepted-unrecorded-layout");
  assert.equal(rec.created, true);
  assert.equal(rec.deleted, true);
  assert.equal(server.state.jobs.size, 0);
});

test("a 2xx create that is not the own job is a contradiction; a 3xx is merely unknown", async () => {
  const other = JOB("cr05");
  const body = JSON.stringify({ name: other, state: "ENABLED" }, null, 2) + "\n";
  for (const [status, outcome] of [
    [200, "identity-contradiction"],
    [299, "identity-contradiction"],
    [300, "unknown-unsettled"],
  ]) {
    const server = fakeServer({
      refuse: refuseSecond,
      hooks: {
        [key("POST", JOBS)]: async ({ body: sent }) =>
          sent.name.endsWith("-cr02") ? new Response(body, { status }) : undefined,
      },
    });
    const { result } = await run(server);
    assert.equal(result.cases.find((c) => c.id === "cr02").outcome, outcome, String(status));
    assert.ok(!server.state.calls.includes("DELETE " + JOB("cr02")));
  }
});

// ---- the bounded budget of settlement reads -------------------------------------------------

const failFirstFour = (extra = {}) => ({
  [key("POST", JOBS)]: async ({ body }) => (/-cr0[1-4]$/.test(body.name) ? "throw" : undefined),
  ...extra,
});

test("the settlement reads are bounded: twelve in all, however many creates are unknown", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", JOBS)]: async ({ body }) => (/-cr0[1-5]$/.test(body.name) ? "throw" : undefined),
    },
  });
  const { journal } = await run(server);
  const reads = journal.filter(
    (r) => r.state === "before-send" && r.id.includes("-settle-create-"),
  );
  assert.equal(reads.length, 12);
});

test("with the settlement budget spent, a failed pause is not read back", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: failFirstFour({
      [key("POST", JOB("cr05") + ":pause")]: async () => error(500, "later"),
    }),
  });
  const { journal } = await run(server);
  assert.ok(!journal.some((r) => r.id === "cr05-read-after-pause"));
});

test("with the settlement budget spent, a busy DELETE is tried once and not read back", async () => {
  const name = JOB("cr05");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: failFirstFour({ [key("DELETE", name)]: async () => busy(name) }),
  });
  const { journal } = await run(server);
  const ids = journal
    .filter((r) => r.state === "before-send" && r.id.startsWith("cr05-"))
    .map((r) => r.id);
  assert.ok(ids.includes("cr05-delete"));
  assert.ok(!ids.some((id) => id.includes("retry") || id.includes("settle-delete")), ids.join());
});

// ---- settling the end -----------------------------------------------------------------------

test("a refused case whose read-back fails is not settled, and the topic stays", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: { [key("GET", JOB("cr08"))]: async () => error(500, "later") },
  });
  const { result } = await run(server);
  assert.equal(result.cases.find((c) => c.id === "cr08").settled, false);
  assert.equal(server.state.topic, true);
  assert.equal(result.closureReady, false);
});

test("only a 2xx DELETE of a job is an acknowledgement: 204 is, 300 is not", async () => {
  const name = JOB("cr01");
  const ok = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("DELETE", name)]: async ({ state }) => {
        state.jobs.delete(name);
        return new Response(null, { status: 204 });
      },
    },
  });
  assert.equal((await run(ok)).result.cases.find((c) => c.id === "cr01").deleted, true);
  const redirect = fakeServer({
    refuse: refuseSecond,
    hooks: { [key("DELETE", name)]: async () => new Response("{}\n", { status: 300 }) },
  });
  const { result } = await run(redirect);
  assert.ok(!result.cases.find((c) => c.id === "cr01").deleted);
  assert.ok(redirect.state.jobs.has(name));
  assert.equal(result.closureReady, false);
});

test("only a 2xx DELETE of the topic settles it", async () => {
  for (const [status, closed] of [
    [200, true],
    [204, true],
    [299, true],
    [300, false],
    [404, false],
    [500, false],
  ]) {
    const server = fakeServer({
      refuse: refuseSecond,
      hooks: {
        [key("DELETE", TOPIC)]: async ({ state }) => {
          state.topic = false;
          return new Response(status === 204 ? null : "{}\n", { status });
        },
      },
    });
    const { result } = await run(server);
    assert.equal(result.closureReady, closed, String(status));
  }
});
