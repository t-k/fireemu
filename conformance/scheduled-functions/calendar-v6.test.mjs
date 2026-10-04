import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CASES,
  MAX_REQUESTS,
  PROJECT,
  REFUSED_400,
  createAccepted,
  createBody,
  createCapture,
  createRefusedExact,
  createRefusedOther,
  deleted,
  emptyList,
  jobAbsent,
  jobAbsentDetailed,
  jobAbsentPlain,
  layoutOk,
  mutationBusy,
  ownJob,
  paused,
  resources,
  topicAbsent,
  topicOwned,
  waitFor,
} from "./calendar-v6.mjs";
import { RUN, fakeServer, refuseSecond, reply, run } from "./calendar-v6-fake.mjs";

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/calendar-v5-recorded.json", import.meta.url), "utf8"),
);
const closure = JSON.parse(
  readFileSync(
    new URL("../../spec/compatibility/closure/SCHEDULED-FUNCTIONS.json", import.meta.url),
    "utf8",
  ),
);

// ---- the recorded v5 production answers (c01 to c08) --------------------------------------

const V5_PREFIX = "fe-scheduled-calendar-5a73ba99b7014cfd";
const v5 = {
  prefix: V5_PREFIX,
  topic: "projects/" + PROJECT + "/topics/" + V5_PREFIX,
  jobs: Object.fromEntries(
    ["c01", "c02", "c03", "c04", "c05", "c06", "c07", "c08"].map((id) => [
      id,
      "projects/" + PROJECT + "/locations/us-central1/jobs/" + V5_PREFIX + "-" + id,
    ]),
  ),
};
const recorded = (id) => {
  const row = fixture.answers[id];
  assert.ok(row, "fixture lacks " + id);
  const rawBytes = Buffer.from(row.bodyBase64, "base64");
  let json = null;
  try {
    json = JSON.parse(rawBytes.toString("utf8"));
  } catch {}
  return { status: row.status, json, rawBytes, bodyBytes: rawBytes.length };
};
// The same answer with one byte changed, a compact re-serialisation, and another status.
const flipped = (a) => {
  const rawBytes = Buffer.from(a.rawBytes);
  rawBytes[Math.floor(rawBytes.length / 2)] ^= 1;
  let json = null;
  try {
    json = JSON.parse(rawBytes.toString("utf8"));
  } catch {}
  return { ...a, rawBytes, json };
};
const compact = (a) => {
  const rawBytes = Buffer.from(JSON.stringify(a.json));
  return { ...a, rawBytes, bodyBytes: rawBytes.length };
};
const acceptedIds = ["c01", "c02", "c03", "c04", "c05", "c06"];
const refusedIds = ["c07", "c08"];
const caseOf = (id) => ({ id });

test("the recorded v5 fixture is the whole of c01 to c08", () => {
  for (const id of acceptedIds)
    for (const step of ["before", "create", "pause", "delete", "read-deleted"])
      assert.ok(fixture.answers[id + "-" + step], id + "-" + step);
  for (const id of refusedIds)
    for (const step of ["before", "create", "read-deleted"])
      assert.ok(fixture.answers[id + "-" + step], id + "-" + step);
  assert.match(fixture.provenance.journalSha256, /^[0-9a-f]{64}$/);
  assert.ok(!/\d{12,13}/.test(JSON.stringify(fixture)), "no project number in the fixture");
});

test("emptyList and deleted accept the recorded 3-byte bodies and nothing else", () => {
  for (const id of ["before-list-jobs", "before-list-topics", "final-list-jobs"]) {
    assert.ok(emptyList(recorded(id)), id);
    assert.ok(!emptyList(flipped(recorded(id))), id);
    assert.ok(!emptyList({ ...recorded(id), status: 201 }), id);
  }
  for (const id of acceptedIds) {
    assert.ok(deleted(recorded(id + "-delete")), id);
    assert.ok(!deleted({ ...recorded(id + "-delete"), status: 204 }), id);
    assert.ok(!deleted(recorded(id + "-before")), "an absence is not an acknowledged delete");
  }
});

test("topic judges accept the recorded topic answers for their own name only", () => {
  assert.ok(topicAbsent(recorded("before-topic"), v5));
  assert.ok(topicOwned(recorded("create-topic"), v5));
  assert.ok(topicOwned(recorded("read-topic"), v5));
  const other = {
    ...v5,
    prefix: V5_PREFIX.replace("5a73", "5a74"),
    topic: v5.topic.replace("5a73", "5a74"),
  };
  assert.ok(!topicAbsent(recorded("before-topic"), other));
  assert.ok(!topicOwned(recorded("create-topic"), other));
  assert.ok(!topicOwned(recorded("before-topic"), v5), "an absence is not ownership");
  assert.ok(!topicAbsent(recorded("create-topic"), v5), "ownership is not an absence");
  assert.ok(!topicOwned(flipped(recorded("create-topic")), v5));
  assert.ok(!topicAbsent(flipped(recorded("before-topic")), v5));
});

test("job absence judges accept both recorded layouts, each only for its own situation", () => {
  for (const id of acceptedIds) {
    assert.ok(jobAbsentPlain(recorded(id + "-before")), id);
    assert.ok(jobAbsentPlain(recorded(id + "-read-deleted")), id);
    assert.ok(jobAbsent(recorded(id + "-read-deleted"), v5.jobs[id]), id);
    assert.ok(!jobAbsentDetailed(recorded(id + "-read-deleted"), v5.jobs[id]), id);
    assert.ok(!jobAbsentPlain(flipped(recorded(id + "-read-deleted"))), id);
    assert.ok(!jobAbsentPlain(compact(recorded(id + "-read-deleted"))), id);
  }
  for (const id of refusedIds) {
    assert.ok(jobAbsentPlain(recorded(id + "-before")), id);
    assert.ok(jobAbsentDetailed(recorded(id + "-read-deleted"), v5.jobs[id]), id);
    assert.ok(jobAbsent(recorded(id + "-read-deleted"), v5.jobs[id]), id);
    assert.ok(!jobAbsentPlain(recorded(id + "-read-deleted")), id);
    assert.ok(
      !jobAbsentDetailed(recorded(id + "-read-deleted"), v5.jobs[id === "c07" ? "c08" : "c07"]),
      "the detailed absence names its own job",
    );
  }
});

test("createAccepted and paused judge the recorded job bodies by their own job and state", () => {
  for (const id of acceptedIds) {
    const created = recorded(id + "-create");
    assert.ok(createAccepted(caseOf(id), created, v5), id);
    assert.ok(ownJob(created, caseOf(id), v5), id);
    assert.ok(
      !createAccepted(caseOf(id), recorded(id + "-pause"), v5),
      "a paused body is not a create",
    );
    const pause = recorded(id + "-pause");
    assert.ok(paused(caseOf(id), pause, v5), id);
    assert.ok(!paused(caseOf(id), created, v5), "an ENABLED body is not paused");
    const other = acceptedIds.find((x) => x !== id);
    assert.ok(!createAccepted(caseOf(other), created, v5), "another job's body");
    assert.ok(!paused(caseOf(other), pause, v5), "another job's body");
    assert.ok(!createAccepted(caseOf(id), flipped(created), v5), id);
    assert.ok(!createAccepted(caseOf(id), compact(created), v5), "layout");
    assert.ok(!createAccepted(caseOf(id), { ...created, status: 201 }, v5), id);
    assert.ok(
      !createAccepted(caseOf(id), created, { ...v5, topic: v5.topic + "x" }),
      "the topic must be the run's own",
    );
  }
});

test("the recorded refusals are exactly the 136-byte INVALID_ARGUMENT, and nothing else is", () => {
  for (const id of refusedIds) {
    const answer = recorded(id + "-create");
    assert.equal(answer.bodyBytes, 136);
    assert.ok(createRefusedExact(answer), id);
    assert.deepEqual(answer.json, REFUSED_400);
    assert.ok(!createRefusedOther(answer), "the exact refusal is not 'other'");
    assert.ok(!createRefusedExact(flipped(answer)), id);
    assert.ok(!createRefusedExact({ ...answer, status: 404 }), id);
    assert.ok(!createAccepted(caseOf(id), answer, v5), "a refusal is not an accepted create");
  }
  // A 400 with another message is new data: recorded as 'other', never as the known refusal.
  const other = {
    status: 400,
    json: {
      error: { code: 400, message: "Invalid retry configuration", status: "INVALID_ARGUMENT" },
    },
  };
  other.rawBytes = Buffer.from(JSON.stringify(other.json, null, 2) + "\n");
  other.bodyBytes = other.rawBytes.length;
  assert.ok(createRefusedOther(other));
  assert.ok(!createRefusedExact(other));
  assert.ok(!createRefusedOther({ ...other, status: 429 }));
  assert.ok(!createRefusedOther({ ...other, status: 409 }));
  assert.ok(!createRefusedOther({ ...other, status: 500 }));
});

test("layoutOk refuses what is not the recorded two-space layout", () => {
  for (const id of ["c01-create", "c03-pause", "c01-read-deleted", "before-topic"])
    assert.ok(layoutOk(recorded(id)), id);
  assert.ok(!layoutOk({ ...recorded("c01-create"), bodyUnknown: true }));
  assert.ok(!layoutOk({ ...recorded("c01-create"), bodyBytes: 1 }));
  assert.ok(!layoutOk({ status: 200, json: null, rawBytes: Buffer.from("x"), bodyBytes: 1 }));
});

test("mutationBusy matches the recorded 409 shape only", () => {
  const name = v5.jobs.c01;
  const busy = {
    status: 409,
    json: {
      error: {
        code: 409,
        message: "sync mutate calls cannot be queued",
        status: "ABORTED",
        details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name }],
      },
    },
  };
  assert.ok(mutationBusy(busy, name));
  assert.ok(!mutationBusy(busy, v5.jobs.c02));
  assert.ok(!mutationBusy({ ...busy, status: 400 }, name));
  assert.ok(!mutationBusy(recorded("c01-delete"), name));
});

// ---- the case table -------------------------------------------------------------------------

const frozen = new Map(
  closure.conditions
    .filter((c) => c.evidenceType === "production-parity")
    .map((c) => [c.conditionId, new Set(c.cases)]),
);

test("the case table has 47 uniquely named cases inside the frozen closure inventory", () => {
  assert.equal(CASES.length, 47);
  assert.equal(new Set(CASES.map((c) => c.id)).size, CASES.length);
  const seen = new Set();
  for (const c of CASES) {
    assert.ok(frozen.get(c.conditionId)?.has(c.case), c.conditionId + "#" + c.case);
    const key = c.conditionId + "#" + c.case;
    assert.ok(!seen.has(key), "one probe per frozen case: " + key);
    seen.add(key);
  }
});

test("every calendar-observable frozen case is covered except the two that need a deployment", () => {
  const calendar = [
    "cron-grammar",
    "groc-grammar",
    "next-occurrence",
    "dst-calendar",
    "timezone-validation-defaults",
    "retry-config-validation",
  ].map((n) => "SCHEDULED-FUNCTIONS/" + n);
  const deployNeeded = new Set([
    "timezone-validation-defaults#v1-default",
    "timezone-validation-defaults#v2-default",
  ]);
  const covered = new Set(CASES.map((c) => c.conditionId.split("/")[1] + "#" + c.case));
  for (const condition of calendar)
    for (const name of frozen.get(condition)) {
      const key = condition.split("/")[1] + "#" + name;
      assert.equal(covered.has(key), !deployNeeded.has(key), key);
    }
});

test("no probe repeats a schedule recorded in v5, and the three required cases are present", () => {
  const recordedV5 = new Set(
    Object.values(fixture.createRequests).map((r) => r.schedule + "|" + r.timeZone),
  );
  // The two deliberate repeats: v5's c04 recorded `quarter` before October's first Friday, and
  // its c01 was created in one window only, so the same texts are created again, timed.
  const repeats = CASES.filter((c) => recordedV5.has(c.schedule + "|" + c.timeZone));
  assert.deepEqual(
    repeats.map((c) => c.mustHave),
    ["quarter-after-the-first-friday-of-october", "create-just-before-a-minute-boundary"],
  );
  const must = Object.fromEntries(CASES.filter((c) => c.mustHave).map((c) => [c.mustHave, c]));
  assert.equal(
    must["quarter-after-the-first-friday-of-october"].schedule,
    "1st friday of quarter 9:00",
  );
  assert.equal(must["create-just-before-a-minute-boundary"].timing.kind, "before-minute-boundary");
  const dst = CASES.filter((c) => c.mustHave === "dst-groc");
  assert.deepEqual(dst.map((c) => c.schedule).toSorted(), [
    "1st sun of nov 1:30",
    "2nd sun of mar 2:30",
  ]);
  assert.ok(dst.every((c) => c.timeZone === "America/New_York"));
});

test("only the retry cases carry retryConfig or attemptDeadline, and createBody names the own job and topic", () => {
  const own = resources("0123456789abcdef");
  for (const c of CASES) {
    const body = createBody(c, own);
    assert.equal(body.name, own.jobs[c.id]);
    assert.equal(body.pubsubTarget.topicName, own.topic);
    assert.equal(
      !!(body.retryConfig || body.attemptDeadline),
      c.conditionId.endsWith("retry-config-validation") && c.case !== "omitted-options",
      c.id,
    );
  }
  assert.throws(() => resources("not-a-run-id"));
  assert.throws(() => resources("0123456789abcdef", [...CASES, ...CASES]));
});

test("waitFor places a request just before a minute boundary and just after a run", () => {
  const at = (iso) => Date.parse(iso);
  const before = waitFor(
    { kind: "before-minute-boundary", leadMs: 1500 },
    at("2026-10-06T00:00:10.000Z"),
  );
  assert.equal(
    new Date(at("2026-10-06T00:00:10.000Z") + before).toISOString(),
    "2026-10-06T00:00:58.500Z",
  );
  const soon = waitFor(
    { kind: "before-minute-boundary", leadMs: 1500 },
    at("2026-10-06T00:00:58.000Z"),
  );
  assert.equal(
    new Date(at("2026-10-06T00:00:58.000Z") + soon).toISOString(),
    "2026-10-06T00:01:58.500Z",
  );
  const after = waitFor(
    { kind: "after-run", everyMinutes: 5, afterMs: 500 },
    at("2026-10-06T00:02:03.000Z"),
  );
  assert.equal(
    new Date(at("2026-10-06T00:02:03.000Z") + after).toISOString(),
    "2026-10-06T00:05:00.500Z",
  );
  const exact = waitFor(
    { kind: "after-run", everyMinutes: 5, afterMs: 500 },
    at("2026-10-06T00:05:00.000Z"),
  );
  assert.equal(
    new Date(at("2026-10-06T00:05:00.000Z") + exact).toISOString(),
    "2026-10-06T00:10:00.500Z",
  );
  assert.equal(waitFor(undefined, 1), 0);
  assert.throws(() => waitFor({ kind: "nope" }, 1));
});

test("a clean run deletes only the jobs it created and settles every name by a direct read", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const { result, sleeps } = await run(server);
  assert.equal(
    result.closureReady,
    true,
    JSON.stringify(result.cases.filter((c) => c.settled !== true)),
  );
  assert.ok(result.attempted <= MAX_REQUESTS, "attempted " + result.attempted);
  const deletes = server.state.calls.filter((c) => c.startsWith("DELETE ") && c.includes("/jobs/"));
  const refused = CASES.filter((c) => refuseSecond({ name: "x-" + c.id }));
  assert.equal(deletes.length, CASES.length - refused.length);
  for (const c of refused)
    assert.ok(!deletes.some((d) => d.endsWith("-" + c.id)), "no DELETE for the refused " + c.id);
  assert.equal(result.cases.filter((c) => c.outcome === "refused").length, refused.length);
  assert.ok(sleeps.includes(60000), "waits before the first delete");
  assert.equal(server.state.topic, false);
  assert.equal(server.state.jobs.size, 0);
  // Every name was read back directly.
  for (const c of CASES)
    assert.ok(
      server.state.calls.some(
        (x) => x.endsWith("/jobs/fe-cal6-" + RUN + "-" + c.id) && x.startsWith("GET "),
      ),
      c.id,
    );
});

test("every issued name is journaled before its create is dispatched", async () => {
  const server = fakeServer();
  const { journal } = await run(server);
  const index = (predicate) => journal.findIndex(predicate);
  assert.ok(
    index((r) => r.id === "issue-topic") <
      index((r) => r.id === "create-topic" && r.state === "before-send"),
  );
  for (const c of CASES) {
    const issued = index((r) => r.id === "issue-" + c.id && r.state === "issued");
    const sent = index((r) => r.id === c.id + "-create" && r.state === "before-send");
    assert.ok(issued >= 0 && issued < sent, c.id);
    assert.equal(journal[issued].name, resources(RUN).jobs[c.id]);
  }
});

test("an unknown create is settled by a direct GET of its name, and a visible own job is then deleted", async () => {
  const target = "cr02";
  const server = fakeServer({
    hooks: {
      ["POST projects/" + PROJECT + "/locations/us-central1/jobs"]: async ({ state, body }) => {
        if (!body.name.endsWith("-" + target)) return undefined;
        // The create took effect but the answer was lost.
        state.jobs.set(body.name, { ...body, state: "ENABLED" });
        state.everCreated.add(body.name);
        return "throw";
      },
    },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === target);
  assert.equal(rec.outcome, "accepted-settled-by-get");
  assert.ok(rec.deleted && rec.settled);
  assert.ok(server.state.calls.some((c) => c.startsWith("GET ") && c.endsWith("-" + target)));
  assert.equal(server.state.jobs.size, 0);
  assert.equal(result.closureReady, false, "an unknown answer needs the later read-back");
});

test("an unknown create that never becomes visible is never deleted and keeps the topic", async () => {
  const target = "cr03";
  const server = fakeServer({
    hooks: {
      ["POST projects/" + PROJECT + "/locations/us-central1/jobs"]: async ({ body }) =>
        body.name.endsWith("-" + target) ? "throw" : undefined,
    },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === target);
  assert.equal(rec.outcome, "unknown-unsettled");
  assert.ok(!server.state.calls.some((c) => c.startsWith("DELETE ") && c.endsWith("-" + target)));
  assert.equal(server.state.topic, true, "the topic stays while a create is unresolved");
  assert.equal(result.closureReady, false);
});

test("a 2xx that names another job is a contradiction: no delete, no topic delete", async () => {
  const target = "cr04";
  const server = fakeServer({
    hooks: {
      ["POST projects/" + PROJECT + "/locations/us-central1/jobs"]: async ({ body, own }) =>
        body.name.endsWith("-" + target)
          ? reply(200, {
              name: own.jobs.cr05,
              state: "ENABLED",
              pubsubTarget: { topicName: own.topic },
            })
          : undefined,
    },
  });
  const { result } = await run(server);
  assert.equal(result.cases.find((c) => c.id === target).outcome, "identity-contradiction");
  assert.ok(!server.state.calls.some((c) => c.startsWith("DELETE ") && c.endsWith("-" + target)));
  assert.equal(server.state.topic, true);
  assert.equal(result.closureReady, false);
});

test("a 400 with a new message is recorded as refused-other and never deleted", async () => {
  const server = fakeServer({
    hooks: {
      ["POST projects/" + PROJECT + "/locations/us-central1/jobs"]: async ({ body }) =>
        body.name.endsWith("-rt03")
          ? reply(400, {
              error: { code: 400, message: "retryCount out of range", status: "INVALID_ARGUMENT" },
            })
          : undefined,
    },
  });
  const { result } = await run(server);
  assert.equal(result.cases.find((c) => c.id === "rt03").outcome, "refused-other");
  assert.ok(!server.state.calls.some((c) => c.startsWith("DELETE ") && c.endsWith("-rt03")));
  assert.equal(result.closureReady, true);
});

test("a DELETE answered 409 is retried after a pause and settled", async () => {
  let busy = 2;
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      ["DELETE projects/" + PROJECT + "/locations/us-central1/jobs/fe-cal6-<run>-cr01"]: async ({
        own,
      }) =>
        busy-- > 0
          ? reply(409, {
              error: {
                code: 409,
                message: "sync mutate calls cannot be queued",
                status: "ABORTED",
                details: [
                  {
                    "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                    resourceName: own.jobs.cr01,
                  },
                ],
              },
            })
          : undefined,
    },
  });
  const { result, sleeps } = await run(server);
  assert.ok(result.cases.find((c) => c.id === "cr01").deleted);
  assert.ok(
    sleeps.filter((ms) => ms === 60000).length >= 3,
    "one wait before deleting and one per 409",
  );
  assert.equal(result.closureReady, true);
});

test("an unknown DELETE is settled by reading the name, never by the final listing", async () => {
  const server = fakeServer({
    refuse: refuseSecond,
    hooks: {
      ["DELETE projects/" + PROJECT + "/locations/us-central1/jobs/fe-cal6-<run>-cr06"]: async () =>
        "throw",
    },
  });
  const { result } = await run(server);
  const rec = result.cases.find((c) => c.id === "cr06");
  // The DELETE never took effect: direct reads show the job, so it is not settled and the run
  // is not closed, whatever the listings say.
  assert.ok(server.state.jobs.has(resources(RUN).jobs.cr06));
  assert.ok(!rec.deleted);
  assert.ok(!rec.settled);
  assert.equal(result.closureReady, false);
  assert.equal(server.state.topic, true);
  assert.ok(server.state.calls.some((c) => c.startsWith("GET ") && c.endsWith("-cr06")));
});

test("a request outside the run's own names is not allowed", async () => {
  const own = resources(RUN);
  const { capture } = createCapture({
    accessToken: "t",
    save: async () => {},
    send: async () => reply(200, {}),
    clock: Date.now,
    maxRequests: 5,
    own,
    projectNumber: "123456789012",
  });
  for (const spec of [
    {
      id: "x",
      method: "DELETE",
      url:
        "https://cloudscheduler.googleapis.com/v1/projects/" +
        PROJECT +
        "/locations/us-central1/jobs/other",
    },
    {
      id: "x",
      method: "DELETE",
      url:
        "https://cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-idp/locations/us-central1/jobs/fe-cal6-" +
        RUN +
        "-cr01",
    },
    {
      id: "x",
      method: "POST",
      url:
        "https://cloudscheduler.googleapis.com/v1/projects/" +
        PROJECT +
        "/locations/us-central1/jobs",
      json: { name: "projects/" + PROJECT + "/locations/us-central1/jobs/other" },
    },
    {
      id: "x",
      method: "DELETE",
      url: "https://pubsub.googleapis.com/v1/projects/" + PROJECT + "/topics/other",
    },
    { id: "x", method: "GET", url: "https://example.com/" },
  ])
    await assert.rejects(() => capture(spec), /not allowed/);
});

test("capture refuses a reflected credential, an oversized cap and a failed journal", async () => {
  const own = resources(RUN);
  const base = {
    save: async () => {},
    send: async () => reply(200, {}),
    clock: Date.now,
    own,
    projectNumber: "123456789012",
  };
  assert.throws(() => createCapture({ ...base, accessToken: "a\nb", maxRequests: 5 }), /token/);
  assert.throws(
    () => createCapture({ ...base, accessToken: "t", maxRequests: MAX_REQUESTS + 1 }),
    /cap/,
  );
  assert.throws(
    () => createCapture({ ...base, accessToken: "t", maxRequests: 5, projectNumber: "12" }),
    /project number/,
  );
  const reflected = createCapture({
    ...base,
    accessToken: "secret-token",
    maxRequests: 5,
    send: async () => reply(200, { echoed: "secret-token" }),
  });
  await assert.rejects(
    () =>
      reflected.capture({
        id: "i",
        method: "GET",
        url: "https://pubsub.googleapis.com/v1/projects/" + PROJECT + "/topics?pageSize=1000",
      }),
    /reflected a credential/,
  );
  const failing = createCapture({
    ...base,
    accessToken: "t",
    maxRequests: 5,
    save: async () => {
      throw new Error("disk");
    },
  });
  await assert.rejects(
    () =>
      failing.capture({
        id: "i",
        method: "GET",
        url: "https://pubsub.googleapis.com/v1/projects/" + PROJECT + "/topics?pageSize=1000",
      }),
    /persistence failed before dispatch/,
  );
});

test("preflight stops before any write when the sandbox is not empty or the project is wrong", async () => {
  const dirty = fakeServer();
  dirty.state.jobs.set("projects/" + PROJECT + "/locations/us-central1/jobs/leftover", {
    state: "PAUSED",
  });
  const first = await run(dirty);
  assert.equal(first.result.stage, "preflight");
  assert.ok(
    !dirty.state.calls.some(
      (c) => c.startsWith("PUT ") || c.startsWith("POST ") || c.startsWith("DELETE "),
    ),
  );
  const wrong = fakeServer({
    hooks: {
      ["GET projects/" + PROJECT + "/releases/cloud.firestore"]: async () =>
        reply(200, {
          name: "projects/other/releases/cloud.firestore",
          rulesetName: "projects/other/rulesets/x",
        }),
    },
  });
  const second = await run(wrong);
  assert.equal(second.result.stage, "preflight");
  assert.ok(!wrong.state.calls.some((c) => c.startsWith("PUT ")));
});

test("importing the module sends nothing and reads no environment", () => {
  const source = readFileSync(new URL("./calendar-v6.mjs", import.meta.url), "utf8");
  assert.ok(!/process\.env|child_process|fetch\(/.test(source));
});

test("when production accepts all 47 the run still fits the budget and cleans up", async () => {
  const server = fakeServer();
  const { result } = await run(server);
  assert.ok(result.attempted <= MAX_REQUESTS, "attempted " + result.attempted);
  assert.equal(result.cases.filter((c) => c.outcome === "skipped-budget").length, 0);
  assert.equal(server.state.jobs.size, 0);
  assert.equal(server.state.topic, false);
});

test("a run that cannot afford to clean up another job skips it and still cleans up", async () => {
  const server = fakeServer({ refuse: refuseSecond });
  const { result } = await run(server, { budget: 90 });
  const skipped = result.cases.filter((c) => c.outcome === "skipped-budget");
  assert.ok(skipped.length > 0, "a budget of 90 cannot take all 47");
  assert.ok(skipped.every((c) => !c.issued));
  assert.ok(result.attempted <= 90, "attempted " + result.attempted);
  // Everything it did create is gone and the topic with it.
  assert.equal(server.state.jobs.size, 0);
  assert.equal(server.state.topic, false);
  assert.ok(result.cases.filter((c) => c.issued).every((c) => c.settled === true));
});
