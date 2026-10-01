import assert from "node:assert/strict";
import { test } from "node:test";
import { calendarRequests, calendarResources, CALENDAR_CASES } from "./calendar.mjs";
import { calendarRecoveryRequests, collectCalendarRecovery } from "./calendar-recovery.mjs";
import {
  recordedRecoveryJobAbsent,
  proveSettledCalendarJobs,
  recordedRecoveryLayout,
  recordedRecoveryTopicOwned,
  recordedRecoveryTopicAbsent,
  recordedRecoveryEmpty,
} from "./calendar-settled-topic.mjs";

const runId = "c1".repeat(8),
  recoveryId = "d2".repeat(8);
const packet = { runId, projectNumber: "123456789012" };
const own = calendarResources(runId);
const wire = (json) => Buffer.from(JSON.stringify(json, null, 2) + "\n");
const proof = (status, json) => {
  const rawBytes = wire(json);
  return { status, json, bodyBytes: rawBytes.length, rawBytes };
};
const absent = (job, detailed = false) => ({
  error: {
    code: 404,
    message: detailed ? "Resource '" + job + "' was not found" : "Job not found.",
    status: "NOT_FOUND",
    ...(detailed
      ? { details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: job }] }
      : {}),
  },
});
const topicAbsent = () => ({
  error: {
    code: 404,
    message: "Resource not found (resource=" + own.prefix + ").",
    status: "NOT_FOUND",
  },
});
const refused = () => ({
  error: {
    code: 400,
    message: "The provided schedule or timezone are invalid.",
    status: "INVALID_ARGUMENT",
  },
});
function fixture() {
  let now = Date.parse("2026-10-01T05:00:00Z");
  const requests = calendarRequests(runId, packet.projectNumber, now).filter(
    ({ id }) =>
      ![
        "delete-topic",
        "c07-pause",
        "c07-read-paused",
        "c07-delete",
        "c08-pause",
        "c08-read-paused",
        "c08-delete",
      ].includes(id),
  );
  const journal = [];
  for (const request of requests) {
    if (request.id === "c01-delete") now += 60000;
    const match = /^(c0[1-8])-(before|create|pause|read-paused|delete|read-deleted)$/.exec(
      request.id,
    );
    let status = 200,
      json = {};
    if (match) {
      const [, id, action] = match;
      if (action === "before" || action === "read-deleted") {
        status = 404;
        json = absent(own.jobs[id], action === "read-deleted" && ["c07", "c08"].includes(id));
      } else if (action === "create" && ["c07", "c08"].includes(id)) {
        status = 400;
        json = refused();
      } else if (action !== "delete") {
        const item = CALENDAR_CASES.find((c) => c.id === id);
        json = {
          name: own.jobs[id],
          pubsubTarget: { topicName: own.topic, data: "c2VlZC1vbmx5" },
          userUpdateTime: "2026-10-01T05:00:00.123456Z",
          state: action === "create" ? "ENABLED" : "PAUSED",
          status: { code: -1 },
          ...(action === "create" ? { scheduleTime: "2027-01-01T00:00:00Z" } : {}),
          schedule: item.schedule,
          timeZone: item.timeZone,
        };
      }
    } else if (["create-topic", "read-topic", "read-deleted-topic"].includes(request.id))
      json = { name: own.topic };
    else if (request.id === "before-topic") {
      status = 404;
      json = topicAbsent();
    } else if (request.id === "final-list-topics") json = { topics: [{ name: own.topic }] };
    const dispatchAt = new Date(now++).toISOString(),
      responseAt = new Date(now++).toISOString(),
      persistedAt = new Date(now++).toISOString();
    const raw = wire(json);
    journal.push(
      { ...request, state: "before-send", dispatchAt, timeoutMs: request.timeoutMs ?? 10000 },
      { id: request.id, state: "response-headers", status, responseAt },
      {
        id: request.id,
        state: "response-persisted",
        status,
        dispatchAt,
        responseAt: persistedAt,
        bodyBase64: raw.toString("base64"),
        bodyBytes: raw.length,
      },
    );
  }
  return journal;
}

test("recovery accepts only the two recorded97/433byte own job absence layouts", () => {
  for (const detailed of [false, true]) {
    const answer = proof(404, absent(own.jobs.c07, detailed));
    assert.equal(answer.bodyBytes, detailed ? 433 : 97);
    assert.equal(recordedRecoveryJobAbsent(answer, own.jobs.c07), true);
    assert.equal(
      recordedRecoveryJobAbsent({ ...answer, bodyBytes: answer.bodyBytes + 1 }, own.jobs.c07),
      false,
    );
    assert.equal(recordedRecoveryJobAbsent({ ...answer, status: 503 }, own.jobs.c07), false);
  }
  assert.equal(
    recordedRecoveryJobAbsent(proof(404, absent(own.jobs.c08, true)), own.jobs.c07),
    false,
  );
});
test("exact54 complete groups prove settled six jobs and refused two without changing seed readiness", () => {
  const journal = fixture();
  assert.equal(journal.length, 162);
  assert.deepEqual(proveSettledCalendarJobs(journal, packet), {
    requests: 54,
    createdJobs: 6,
    refusedJobs: ["c07", "c08"],
  });
});
test("settled-job recovery confines eleven templates to one original topic DELETE", () => {
  const requests = calendarRecoveryRequests(runId, "settled-jobs-topic-only");
  assert.equal(requests.length, 11);
  assert.deepEqual(
    requests.filter((r) => r.method !== "GET").map((r) => [r.id, r.method, r.url, r.timeoutMs]),
    [["delete-topic", "DELETE", "https://pubsub.googleapis.com/v1/" + own.topic, 30000]],
  );
  assert.ok(
    requests.some((r) => r.id === "c07-before") && requests.some((r) => r.id === "c08-before"),
  );
});

export { fixture, packet, own, wire, proof, absent, topicAbsent, recoveryEnvironment };

function generated(seed = 0x51ed07) {
  let state = seed;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}
test("generated byte-layout near misses refuse without masking format or equal-length foreign names", () => {
  const random = generated();
  for (let i = 0; i < 600; i++) {
    const detailed = Boolean(random() & 1),
      good = proof(404, absent(own.jobs.c07, detailed));
    const mutation = random() % 7;
    let bad;
    if (mutation === 0) bad = { ...good, bodyBytes: good.bodyBytes + 1 + (random() % 4) };
    else if (mutation === 1)
      bad = { ...good, status: [199, 302, 307, 500, 503, 504][random() % 6] };
    else if (mutation === 2) bad = { ...good, bodyUnknown: true };
    else if (mutation === 3)
      bad = {
        ...good,
        rawBytes: Buffer.from(good.rawBytes.toString().replace('"code": 404', '"code": 403')),
      };
    else if (mutation === 4)
      bad = { ...good, rawBytes: Buffer.from(good.rawBytes.toString().replace(/\n$/, " ")) };
    else if (mutation === 5)
      bad = {
        ...good,
        rawBytes: Buffer.from(
          good.rawBytes
            .toString()
            .replace("Job not found.", "Job not Found.")
            .replace("-c07", "-c08"),
        ),
      };
    else {
      const rawBytes = Buffer.from(JSON.stringify(good.json));
      bad = { ...good, rawBytes, bodyBytes: rawBytes.length };
    }
    assert.equal(recordedRecoveryJobAbsent(good, own.jobs.c07), true, `seed51ed07/${i}/positive`);
    assert.equal(
      recordedRecoveryJobAbsent(bad, own.jobs.c07),
      false,
      `seed51ed07/${i}/mutation${mutation}`,
    );
  }
});
test("generated journal transition and settlement near misses reject against a complete-triple reference model", () => {
  const random = generated(0x54cafe);
  const referenceComplete = (rows) =>
    rows.length === 162 &&
    rows.every(
      (r, i) => r.state === ["before-send", "response-headers", "response-persisted"][i % 3],
    );
  for (let i = 0; i < 250; i++) {
    const rows = fixture(),
      mutation = random() % 8,
      index = (random() % 54) * 3;
    if (mutation === 0) rows.splice(index + 2, 1);
    else if (mutation === 1) rows[index + 2].state = "body-unknown";
    else if (mutation === 2) rows.splice(index + 1, 0, { ...rows[index + 1] });
    else if (mutation === 3)
      [rows[index + 1], rows[index + 2]] = [rows[index + 2], rows[index + 1]];
    else if (mutation === 4) rows[index + 2].status = 503;
    else if (mutation === 5) rows[index + 2].bodyBytes++;
    else if (mutation === 6)
      rows[index].timeoutMs = rows[index].timeoutMs === 10000 ? 30000 : 10000;
    else rows[index].dispatchAt = "2026-10-01T04:00:00.000Z";
    if (mutation < 4) assert.equal(referenceComplete(rows), false);
    assert.throws(
      () => proveSettledCalendarJobs(rows, packet),
      /proof differs/,
      `seed54cafe/${i}/mutation${mutation}`,
    );
  }
  for (const id of ["c01-create", "c06-pause", "c01-delete", "c07-create"]) {
    for (const status of [199, 302, 307, 500, 503, 504]) {
      const rows = fixture();
      for (const r of rows) if (r.id === id && r.state !== "before-send") r.status = status;
      assert.throws(
        () => proveSettledCalendarJobs(rows, packet),
        /proof differs/,
        `${id}/${status}`,
      );
    }
  }
  const rows = fixture(),
    firstDelete = rows.find((r) => r.id === "c01-delete" && r.state === "before-send");
  firstDelete.dispatchAt = new Date(Date.parse(firstDelete.dispatchAt) - 60000).toISOString();
  const following = rows.filter((r) => r.id === "c01-delete" && r.state !== "before-send");
  following[1].dispatchAt = firstDelete.dispatchAt;
  assert.throws(() => proveSettledCalendarJobs(rows, packet), /proof differs/);
});

function recoveryEnvironment({
  detailed = true,
  unknownDelete = false,
  createVisible = true,
  answers = {},
} = {}) {
  const sends = [],
    waits = [];
  let topicPresent = createVisible;
  const deps = {
    originalRunId: runId,
    runId: recoveryId,
    recoveryScope: "settled-jobs-topic-only",
    accessToken: "offline-settled-topic",
    clock: () => Date.parse("2026-10-01T05:00:00Z"),
    save: async () => {},
    sleep: async (ms) => waits.push(ms),
    send: async (request) => {
      sends.push(request);
      if (Object.hasOwn(answers, request.id)) return answers[request.id]();
      let status = 200,
        json = {};
      if (["c07-before", "c08-before"].includes(request.id)) {
        status = 404;
        json = absent(own.jobs[request.id.slice(0, 3)], detailed);
      } else if (request.id === "delete-topic") {
        topicPresent = false;
        if (unknownDelete) throw new Error("DELETE outcome unknown");
      } else if (request.id.startsWith("read-topic-")) {
        if (topicPresent) json = { name: own.topic };
        else {
          status = 404;
          json = topicAbsent();
        }
      } else if (request.id === "final-list-topics" && topicPresent)
        json = { topics: [{ name: own.topic }] };
      return new Response(wire(json), { status });
    },
  };
  return { sends, waits, deps };
}
test("settled-topic live capture uses recorded raw bytes and only one acknowledged DELETE", async () => {
  for (const detailed of [false, true]) {
    const e = recoveryEnvironment({ detailed });
    const answer = await collectCalendarRecovery(e.deps);
    assert.equal(answer.closureReady, true);
    assert.equal(answer.cleanupVerified, false);
    assert.equal(answer.attempted, 8);
    assert.equal(e.sends.filter((r) => r.method !== "GET").length, 1);
    assert.deepEqual(e.waits, []);
  }
});
test("settled-topic unknown DELETE and initial404 cannot be closed by later absent reads", async () => {
  for (const options of [{ unknownDelete: true }, { createVisible: false }]) {
    const e = recoveryEnvironment(options);
    const answer = await collectCalendarRecovery(e.deps);
    assert.equal(answer.closureReady, false);
    assert.equal(answer.cleanupVerified, false);
    assert.ok(answer.attempted <= 11);
    assert.equal(e.sends.filter((r) => r.method !== "GET").length, options.unknownDelete ? 1 : 0);
    assert.ok(e.waits.length <= 3);
  }
});

test("settled-topic closure needs every answer known and both final lists empty", async () => {
  const unknown = () => {
    throw new Error("read outcome unknown");
  };
  const cases = {
    // An unknown read before the owned poll still sends the one DELETE, but stays open.
    "unknown-read-before": { "read-topic-before": unknown },
    "unknown-final-jobs": { "final-list-jobs": unknown },
    "foreign-final-topic": {
      "final-list-topics": () =>
        new Response(wire({ topics: [{ name: "projects/fireemu-oracle-sbx/topics/foreign" }] })),
    },
    "nonempty-final-jobs": {
      "final-list-jobs": () => new Response(wire({ jobs: [{ name: own.jobs.c01 }] })),
    },
    "compact-after-404": {
      "read-topic-after": () => new Response(JSON.stringify(topicAbsent()), { status: 404 }),
    },
  };
  for (const [name, answers] of Object.entries(cases)) {
    const e = recoveryEnvironment({ answers });
    const answer = await collectCalendarRecovery(e.deps);
    assert.equal(answer.closureReady, false, name);
    assert.equal(answer.cleanupVerified, false, name);
    assert.equal(e.sends.filter((r) => r.method !== "GET").length, 1, name);
    assert.ok(answer.attempted <= 11, name);
  }
});

test("generated shared recovery layouts reject raw near misses without inferring unavailable Content-Length", () => {
  const examples = [
    [proof(200, {}), recordedRecoveryEmpty],
    [proof(200, { name: own.topic }), (a) => recordedRecoveryTopicOwned(a, own)],
    [proof(404, topicAbsent()), (a) => recordedRecoveryTopicAbsent(a, own)],
  ];
  const random = generated(0xb17e);
  for (let i = 0; i < 300; i++) {
    const [good, judge] = examples[random() % examples.length];
    assert.equal(judge(good), true);
    const change = random() % 4;
    const rawBytes = Buffer.from(good.rawBytes);
    if (change === 0) rawBytes[rawBytes.length - 1] = 32;
    else if (change === 1) rawBytes[0] = 91;
    else if (change === 2) rawBytes[1] = 32;
    else rawBytes[rawBytes.length - 2] ^= 1;
    assert.equal(judge({ ...good, rawBytes }), false, `seedb17e/${i}`);
    assert.equal(judge({ ...good, bodyBytes: good.bodyBytes + 1 }), false);
    assert.equal(judge({ ...good, bodyUnknown: true }), false);
  }
  assert.equal(recordedRecoveryLayout(proof(200, {}), 200, {}, 3), true);
});
test("settlement proof rejects trailing operations, contradictory acknowledgments and inverted response time", () => {
  for (const kind of ["trailing", "ack-layout", "headers-time", "persisted-time"]) {
    const rows = fixture();
    if (kind === "trailing") rows.push(...rows.slice(-3));
    else if (kind === "ack-layout") {
      const row = rows.find((r) => r.id === "c01-delete" && r.state === "response-persisted");
      row.bodyBase64 = Buffer.from("{}").toString("base64");
      row.bodyBytes = 2;
    } else {
      const index = rows.findIndex((r) => r.id === "c01-delete" && r.state === "before-send");
      if (kind === "headers-time")
        rows[index + 1].responseAt = new Date(Date.parse(rows[index].dispatchAt) - 1).toISOString();
      else
        rows[index + 2].responseAt = new Date(
          Date.parse(rows[index + 1].responseAt) - 1,
        ).toISOString();
    }
    assert.throws(() => proveSettledCalendarJobs(rows, packet), /proof differs/, kind);
  }
});
test("generated recovery poll sequences agree with independent three-extra state model", async () => {
  const random = generated(0xb0de1);
  for (let i = 0; i < 60; i++) {
    const pre = random() % 5,
      post = random() % 5,
      e = recoveryEnvironment();
    const original = e.deps.send;
    let deleted = false,
      beforeReads = 0,
      afterReads = 0;
    e.deps.send = async (request) => {
      if (request.id === "delete-topic") deleted = true;
      if (request.id.startsWith("read-topic-")) {
        const stale = deleted ? afterReads++ < post : beforeReads++ < pre;
        if (stale) {
          e.sends.push(request);
          return new Response(wire(deleted ? { name: own.topic } : topicAbsent()), {
            status: deleted ? 200 : 404,
          });
        }
      }
      return original(request);
    };
    const answer = await collectCalendarRecovery(e.deps);
    assert.equal(
      answer.closureReady,
      pre <= 3 && post <= 3 - pre,
      `seedb0de1/${i}/pre${pre}/post${post}`,
    );
    assert.ok(answer.attempted <= 11);
    assert.ok(e.waits.length <= 3);
    assert.equal(answer.cleanupVerified, false);
    assert.equal(e.sends.filter((r) => r.method !== "GET").length, pre <= 3 ? 1 : 0);
  }
});
test("unexpected job presence, foreign absence, malformed bytes or nonempty job list cannot authorize topic deletion", async () => {
  for (const kind of ["job-present", "foreign-job", "malformed-body", "list-present"]) {
    const e = recoveryEnvironment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id === "c07-before" && kind !== "list-present") {
        e.sends.push(request);
        if (kind === "job-present")
          return new Response(wire({ name: own.jobs.c07, state: "ENABLED" }));
        if (kind === "foreign-job")
          return new Response(wire(absent(own.jobs.c08, true)), { status: 404 });
        return new Response(JSON.stringify(absent(own.jobs.c07)), { status: 404 });
      }
      if (request.id === "before-list-jobs" && kind === "list-present") {
        e.sends.push(request);
        return new Response(wire({ jobs: [{ name: own.jobs.c01 }] }));
      }
      return original(request);
    };
    const answer = await collectCalendarRecovery(e.deps);
    assert.equal(answer.closureReady, false);
    assert.ok(!e.sends.some((r) => r.method !== "GET"));
  }
});

test("recorded resource-info absence never admits a foreign project or an unowned case name", () => {
  for (const job of [
    own.jobs.c07.replace("oracle-sbx", "oracle-idp"),
    own.jobs.c07.replace("-c07", "-c09"),
  ])
    assert.equal(recordedRecoveryJobAbsent(proof(404, absent(job, true)), job), false);
});
