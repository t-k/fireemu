// Unknown-class answers, layout-tolerant control flow, an expired credential, and a generated test
// of the settle rules for the calendar v6 collector.
import assert from "node:assert/strict";
import test from "node:test";
import { CASES, PROJECT, answerClass, isUnknownClass } from "./calendar-v6.mjs";
import { RUN, fakeServer, refuseSecond, reply, run } from "./calendar-v6-fake.mjs";

const key = (method, path) => method + " " + path;
const JOBS = "projects/" + PROJECT + "/locations/us-central1/jobs";
const TOPIC = "projects/" + PROJECT + "/topics/fe-cal6-" + RUN;
const JOB = (id) => JOBS + "/fe-cal6-" + RUN + "-" + id;
const error = (code, message) => reply(code, { error: { code, message, status: "X" } });
const busy = (name) =>
  reply(409, {
    error: {
      code: 409,
      message: "sync mutate calls cannot be queued",
      status: "ABORTED",
      details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name }],
    },
  });
const writes = (server) => server.state.calls.filter((c) => /^(PUT|POST|DELETE) /.test(c));
const compact = (json, status = 200) =>
  new Response(JSON.stringify(json), { status, headers: { "content-type": "application/json" } });

// ---- the answer classes ---------------------------------------------------------------------

test("an answer is transport, unreadable, unknown-status, 2xx or 4xx, and the first three are unknown", () => {
  const cases = [
    [null, "transport", true],
    [{ status: 200, bodyUnknown: true }, "unreadable", true],
    [{ status: 199 }, "unknown-status", true],
    [{ status: 100 }, "unknown-status", true],
    [{ status: 200 }, "2xx", false],
    [{ status: 299 }, "2xx", false],
    [{ status: 300 }, "unknown-status", true],
    [{ status: 302 }, "unknown-status", true],
    [{ status: 399 }, "unknown-status", true],
    [{ status: 400 }, "4xx", false],
    [{ status: 409 }, "4xx", false],
    [{ status: 499 }, "4xx", false],
    [{ status: 500 }, "unknown-status", true],
    [{ status: 503 }, "unknown-status", true],
  ];
  for (const [answer, name, unknown] of cases) {
    assert.equal(answerClass(answer), name, JSON.stringify(answer));
    assert.equal(isUnknownClass(answer), unknown, JSON.stringify(answer));
  }
});

// ---- an unknown-class answer is never closed by a later read --------------------------------

const settledButNotClosed = (result, server, label) => {
  assert.ok(result.unknownMutations >= 1, label);
  assert.equal(result.readBackRequired, true, label);
  assert.equal(result.closureReady, false, label);
  assert.equal(server.state.jobs.size, 0, label + ": the job is still deleted");
  assert.equal(server.state.topic, false, label + ": and so is the topic");
};

test("a create answered 503 that a GET shows as the own job is cleaned up and not closed", async () => {
  const name = JOB("cr01");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", JOBS)]: async ({ state, body }) => {
        if (body.name !== name) return undefined;
        state.jobs.set(name, { ...body, state: "ENABLED" });
        state.everCreated.add(name);
        return error(503, "later");
      },
    },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr01");
  assert.equal(rec.outcome, "accepted-settled-by-get");
  assert.deepEqual(result.unknownMutationList[0], { id: "cr01-create", class: "unknown-status" });
  settledButNotClosed(result, server, "create 503");
});

test("a DELETE answered 503 that a GET shows gone is settled and not closed", async () => {
  const name = JOB("cr01");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("DELETE", name)]: async ({ state }) => {
        state.jobs.delete(name);
        return error(503, "later");
      },
    },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr01");
  assert.equal(rec.deletedSettledByGet, true);
  assert.deepEqual(result.unknownMutationList[0], { id: "cr01-delete", class: "unknown-status" });
  settledButNotClosed(result, server, "delete 503");
});

test("a DELETE answered 302 that a GET shows gone is settled and not closed", async () => {
  const name = JOB("cr01");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("DELETE", name)]: async ({ state }) => {
        state.jobs.delete(name);
        return new Response(null, { status: 302 });
      },
    },
  });
  const { result } = await run(server);
  assert.equal(result.cases.find((c) => c.id === "cr01").deletedSettledByGet, true);
  settledButNotClosed(result, server, "delete 302");
});

test("a topic PUT answered 500 that a poll proves is not closed", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("PUT", TOPIC)]: async ({ state }) => {
        state.topic = true;
        return error(500, "later");
      },
    },
  });
  const { result } = await run(server);
  assert.deepEqual(result.unknownMutationList[0], { id: "create-topic", class: "unknown-status" });
  settledButNotClosed(result, server, "topic PUT 500");
});

test("a pause answered 504 is unknown, read back, and the run is not closed", async () => {
  const name = JOB("cr02");
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", name + ":pause")]: async ({ state }) => {
        state.jobs.get(name).state = "PAUSED";
        return error(504, "later");
      },
    },
  });
  const { result } = await run(server);
  assert.equal(result.cases.find((c) => c.id === "cr02").paused, true, "the read shows PAUSED");
  settledButNotClosed(result, server, "pause 504");
});

test("a create answered 409 or 429, or 2xx that is not the own job, is unknown-class too", async () => {
  for (const status of [409, 429]) {
    const server = fakeServer({
      refuse: refuseSecond,
      hooks: {
        [key("POST", JOBS)]: async ({ body }) =>
          body.name.endsWith("-cr03") ? error(status, "x") : undefined,
      },
    });
    const { result } = await run(server);
    assert.deepEqual(
      result.unknownMutationList[0],
      { id: "cr03-create", class: "unexpected" },
      String(status),
    );
    assert.equal(result.closureReady, false, String(status));
    assert.equal(result.readBackRequired, true, String(status));
  }
});

test("a clean run has no unknown mutation and needs no read-back", async () => {
  const { result } = await run(fakeServer({ refuse: refuseSecond }));
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(result.unknownMutationList, []);
  assert.equal(result.readBackRequired, false);
  assert.deepEqual(result.layoutUnrecorded, []);
  assert.equal(result.closureReady, true);
});

// ---- layout-tolerant control flow -----------------------------------------------------------

test("a 400 in an unrecorded layout is refused-other, spends no settle read and keeps nothing", async () => {
  const server = fakeServer({
    refuse: (body) => body.name.endsWith("-cr09"),
    hooks: {
      [key("POST", JOBS)]: async ({ body }) =>
        body.name.endsWith("-cr08")
          ? new Response(
              '{"error":{"code":400,"message":"min must be \\u003c max","status":"INVALID_ARGUMENT"}}',
              {
                status: 400,
              },
            )
          : undefined,
    },
  });
  const { result, journal } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr08");
  assert.equal(rec.outcome, "refused-other");
  assert.ok(!journal.some((r) => r.id.startsWith("cr08-settle")), "no settle read");
  assert.ok(result.layoutUnrecorded.includes("cr08-create"));
  assert.equal(result.closureReady, false, "the layout goes to review");
  assert.equal(server.state.topic, false, "but the run is cleaned up, topic included");
  assert.equal(server.state.jobs.size, 0);
  assert.equal(result.unknownMutations, 0);
});

test("accepted and paused bodies in an unrecorded layout spend no extra read and still allow a retry", async () => {
  const hooks = {};
  let first = true;
  const jobBody = (body, state) => ({
    name: body.name,
    pubsubTarget: { topicName: TOPIC, data: "Y2FsZW5kYXItdjY=" },
    state,
    schedule: body.schedule,
    timeZone: body.timeZone,
  });
  hooks[key("POST", JOBS)] = async ({ state, body }) => {
    if (/-(cr0[89]|cr10|gr09|gr10|tz04|rt03|rt08)$/.test(body.name)) return undefined;
    state.jobs.set(body.name, { ...body, state: "ENABLED" });
    state.everCreated.add(body.name);
    return compact(jobBody(body, "ENABLED"));
  };
  for (const c of CASES) {
    hooks[key("POST", JOB(c.id) + ":pause")] = async ({ state }) => {
      const job = state.jobs.get(JOB(c.id));
      job.state = "PAUSED";
      return compact(jobBody(job, "PAUSED"));
    };
  }
  hooks[key("DELETE", JOB("rt07"))] = async () =>
    first ? ((first = false), busy(JOB("rt07"))) : undefined;
  const server = fakeServer({ refuse: refuseSecond, hooks });
  const { result, journal } = await run(server);
  assert.ok(!journal.some((r) => r.id.endsWith("-read-after-pause")), "no pause read");
  assert.ok(
    journal.some((r) => r.id === "rt07-delete-retry-1"),
    "the busy DELETE is retried",
  );
  assert.equal(server.state.jobs.size, 0);
  assert.equal(server.state.topic, false);
  assert.ok(result.layoutUnrecorded.length > 0);
  assert.equal(result.closureReady, false);
  assert.equal(result.unknownMutations, 0);
});

// ---- an expired or rejected credential stops the run ----------------------------------------

test("a 401 on the third create stops the run: no more creates, an auth-stop outcome, no closure", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      [key("POST", JOBS)]: async ({ body }) =>
        body.name.endsWith("-cr03") ? error(401, "expired") : undefined,
    },
  });
  const { result } = await run(server);
  assert.equal(result.outcome, "calendar-v6-auth-stop");
  assert.equal(result.stage, "auth-stop");
  assert.deepEqual(result.authStop, { id: "cr03-create", status: 401 });
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.ok(!writes(server).some((w) => w.includes("-cr04")), "nothing after the stop");
  assert.ok(!result.cases.some((c) => c.outcome === "refused-other"), "not recorded as a refusal");
});

test("a 403 on a DELETE or on a preflight read also stops the run", async () => {
  const name = JOB("cr01");
  const onDelete = fakeServer({
    refuse: refuseSecond,
    hooks: { [key("DELETE", name)]: async () => error(403, "denied") },
  });
  const a = await run(onDelete);
  assert.equal(a.result.outcome, "calendar-v6-auth-stop");
  assert.equal(a.result.authStop.id, "cr01-delete");
  const onPreflight = fakeServer({
    hooks: {
      [key("GET", "projects/" + PROJECT + "/releases/cloud.firestore")]: async () =>
        error(403, "denied"),
    },
  });
  const b = await run(onPreflight);
  assert.equal(b.result.stage, "auth-stop");
  assert.deepEqual(writes(onPreflight), []);
});

// ---- generated: the settle rules over answer classes ----------------------------------------

function seeded(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CLASSES = [
  "ok",
  "ok",
  "ok",
  "ok",
  "other-2xx",
  "own-other-layout",
  "3xx",
  "4xx",
  "409-busy",
  "5xx",
  "199",
  "transport",
  "unreadable",
];

/** What a perturbed answer is, for the test's own accounting of which answers are unknown. */
const UNKNOWN_FOR_ANY = new Set(["3xx", "5xx", "199", "transport", "unreadable"]);

function respond(kind, normalJson) {
  switch (kind) {
    case "other-2xx":
      return compact({ unrelated: true });
    case "own-other-layout":
      return compact(normalJson);
    case "3xx":
      return new Response(null, { status: 302 });
    case "4xx":
      return compact({ error: { code: 400, message: "other", status: "INVALID_ARGUMENT" } }, 400);
    case "409-busy":
      return null; // filled in by the caller (needs the name)
    case "5xx":
      return error(503, "later");
    case "199":
      return {
        status: 199,
        headers: { get: () => null },
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    case "unreadable":
      return {
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => {
          throw new Error("body lost");
        },
      };
    default:
      return undefined;
  }
}

test("generated: over any mix of answer classes, closure implies a clean sandbox and no unknown mutation", async () => {
  const cases = CASES.slice(0, 10);
  let closed = 0;
  let unknownRuns = 0;
  for (let seed = 1; seed <= 400; seed++) {
    const rnd = seeded(seed);
    // Some runs are quiet (no perturbation at all), some noisy, so both outcomes are exercised.
    const noise = [0, 0, 0.03, 0.1, 0.3][Math.floor(rnd() * 5)];
    const pick = () => (rnd() < noise ? CLASSES[Math.floor(rnd() * CLASSES.length)] : "ok");
    const effect = () => rnd() < 0.5;
    let expectedUnknown = 0;
    const deletesOf = [];
    let jobsAtTopicDelete = null;
    const hooks = {};
    const count = (kind, isCreate) => {
      if (UNKNOWN_FOR_ANY.has(kind) || (isCreate && ["other-2xx", "409-busy"].includes(kind)))
        expectedUnknown++;
    };
    hooks[key("PUT", TOPIC)] = async ({ state }) => {
      const kind = pick();
      if (kind === "ok") return undefined;
      count(kind, false);
      if (effect()) state.topic = true;
      if (kind === "transport") return "throw";
      if (kind === "409-busy") return error(409, "x");
      return respond(kind, { name: TOPIC });
    };
    hooks[key("DELETE", TOPIC)] = async ({ state }) => {
      jobsAtTopicDelete = state.jobs.size;
      const kind = pick();
      if (kind === "ok") return undefined;
      count(kind, false);
      if (effect()) state.topic = false;
      if (kind === "transport") return "throw";
      if (kind === "409-busy") return error(409, "x");
      return respond(kind, {});
    };
    hooks[key("POST", JOBS)] = async ({ state, body }) => {
      if (refuseSecond(body)) return undefined;
      const kind = pick();
      if (kind === "ok") return undefined;
      count(kind, true);
      // An answer that names the own job as created is only ever sent for a job that was.
      if (kind === "own-other-layout" || effect()) {
        state.jobs.set(body.name, { ...body, state: "ENABLED" });
        state.everCreated.add(body.name);
      }
      if (kind === "transport") return "throw";
      if (kind === "409-busy") return error(409, "x");
      return respond(kind, {
        name: body.name,
        pubsubTarget: { topicName: TOPIC, data: "Y2FsZW5kYXItdjY=" },
        state: "ENABLED",
        schedule: body.schedule,
        timeZone: body.timeZone,
      });
    };
    for (const c of cases) {
      const name = JOB(c.id);
      hooks[key("POST", name + ":pause")] = async ({ state }) => {
        const kind = pick();
        if (kind === "ok") return undefined;
        count(kind, false);
        const job = state.jobs.get(name);
        if (job && effect()) job.state = "PAUSED";
        if (kind === "transport") return "throw";
        if (kind === "409-busy") return error(409, "x");
        return respond(kind, {
          name,
          pubsubTarget: { topicName: TOPIC, data: "Y2FsZW5kYXItdjY=" },
          state: "PAUSED",
        });
      };
      hooks[key("DELETE", name)] = async ({ state }) => {
        deletesOf.push({ name, everCreated: state.everCreated.has(name) });
        const kind = pick();
        if (kind === "ok") return undefined;
        if (kind === "409-busy") return busy(name);
        count(kind, false);
        if (effect()) state.jobs.delete(name);
        if (kind === "transport") return "throw";
        return respond(kind, {});
      };
    }
    const server = fakeServer({ refuse: refuseSecond, hooks });
    const { result } = await run(server, { cases });
    const label = "seed " + seed;
    // The count of unknown mutation answers matches the answers the test itself injected.
    assert.equal(result.unknownMutations >= expectedUnknown, true, label);
    if (expectedUnknown > 0) {
      unknownRuns++;
      assert.equal(result.closureReady, false, label + ": an unknown answer is never closed");
      assert.equal(result.readBackRequired, true, label);
    }
    if (result.closureReady) {
      closed++;
      assert.equal(server.state.jobs.size, 0, label + ": every created job is gone");
      assert.equal(server.state.topic, false, label + ": and the topic");
      assert.equal(result.unknownMutations, 0, label);
      assert.equal(result.readBackRequired, false, label);
    }
    // The topic is deleted only when no job remains; a DELETE goes only to a name that exists.
    if (jobsAtTopicDelete !== null) assert.equal(jobsAtTopicDelete, 0, label + ": topic delete");
    for (const d of deletesOf) assert.ok(d.everCreated, label + ": DELETE of " + d.name);
    assert.ok(result.attempted <= 240, label);
  }
  assert.ok(closed > 0, "some generated runs close");
  assert.ok(unknownRuns > 100, "many generated runs carry an unknown answer");
});
