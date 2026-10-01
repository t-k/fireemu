import assert from "node:assert/strict";
import { test } from "node:test";
import { calendarResources } from "./calendar.mjs";
import { calendarRecoveryRequests, collectCalendarRecovery } from "./calendar-recovery.mjs";

const originalRunId = "c1".repeat(8),
  runId = "d2".repeat(8);

function environment(state = "ENABLED") {
  const own = calendarResources(originalRunId),
    sends = [],
    rows = [],
    waits = [];
  const jobs = new Map(
    Object.entries(own.jobs).map(([id, name]) => [
      id,
      {
        name,
        state,
        pubsubTarget: { topicName: own.topic },
      },
    ]),
  );
  if (state === "ABSENT") jobs.clear();
  let topicPresent = true,
    now = Date.parse("2026-09-30T09:00:00Z");
  const deps = {
    originalRunId,
    runId,
    accessToken: "offline-calendar-recovery-bearer",
    clock: () => now++,
    save: async (row) => rows.push(row),
    sleep: async (ms) => {
      waits.push(ms);
      now += ms;
    },
    send: async (request) => {
      sends.push(request);
      let status = 200,
        body = {};
      const match = /^(c[0-9]{2})-(before|pause|read-paused|delete-[123]|after)$/.exec(request.id);
      if (match) {
        const [, id, action] = match;
        if (action === "pause" && jobs.has(id)) jobs.set(id, { ...jobs.get(id), state: "PAUSED" });
        if (action.startsWith("delete-")) jobs.delete(id);
        else if (jobs.has(id)) body = jobs.get(id);
        else {
          status = 404;
          body = { error: { code: 404, status: "NOT_FOUND", message: "Job not found." } };
        }
      } else if (request.id === "read-topic-before" || request.id === "read-topic-after") {
        if (topicPresent) body = { name: own.topic };
        else {
          status = 404;
          body = {
            error: {
              code: 404,
              status: "NOT_FOUND",
              message: "Resource not found (resource=" + own.prefix + ").",
            },
          };
        }
      } else if (request.id === "delete-topic") topicPresent = false;
      else if (request.id === "final-list-jobs")
        body = jobs.size ? { jobs: [...jobs.values()] } : {};
      else if (request.id === "final-list-topics")
        body = topicPresent ? { topics: [{ name: own.topic }] } : {};
      return new Response(JSON.stringify(body), { status });
    },
  };
  return { own, deps, sends, rows, waits, jobs };
}

function busy(name) {
  return new Response(
    JSON.stringify({
      error: {
        code: 409,
        status: "ABORTED",
        message: "sync mutate calls cannot be queued",
        details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: name }],
      },
    }),
    { status: 409 },
  );
}

test("calendar recovery fixes61templates and only original owned read/pause/delete routes", () => {
  const requests = calendarRecoveryRequests(originalRunId);
  assert.equal(requests.length, 61);
  assert.ok(requests.every(({ method }) => ["GET", "POST", "DELETE"].includes(method)));
  assert.ok(
    requests.filter(({ method }) => method === "POST").every(({ url }) => url.endsWith(":pause")),
  );
  assert.ok(
    requests.every(({ url }) => !/:run|:publish|:pull|setIamPolicy|:batchEnable/.test(url)),
  );
  assert.equal(requests.filter(({ id }) => /^c[0-9]{2}-delete-[123]$/.test(id)).length, 24);
  assert.throws(() => calendarRecoveryRequests("../../foreign"), /run ID/);
});

test("all ENABLED jobs require PAUSED readback then one settled cleanup; no terminal cleanup claim", async () => {
  const e = environment(),
    result = await collectCalendarRecovery(e.deps);
  assert.equal(result.attempted, 45);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.outcome, "calendar-recovery-needs-review");
  assert.deepEqual(e.waits, [60000]);
  const lastPause = e.rows.findLast(
    (row) => row.id.endsWith("-pause") && row.state === "response-persisted",
  );
  for (const requestRow of e.rows.filter(
    (row) => /-delete-[123]$/.test(row.id) && row.state === "before-send",
  ))
    assert.ok(Date.parse(requestRow.dispatchAt) - Date.parse(lastPause.responseAt) >= 60000);
  assert.ok(!JSON.stringify(e.rows).includes("offline-calendar-recovery-bearer"));
});

test("all absent original jobs use21read/topic operations and no job mutation or real wait", async () => {
  const e = environment("ABSENT"),
    result = await collectCalendarRecovery(e.deps);
  assert.equal(result.attempted, 21);
  assert.equal(result.closureReady, true);
  assert.deepEqual(e.waits, []);
  assert.ok(e.sends.every(({ id, method }) => !id.startsWith("c") || method === "GET"));
});

test("each busy job gets at most3DELETEs and retains its topic after bounded exhaustion", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (!/^c[0-9]{2}-delete-[123]$/.test(request.id)) return original(request);
    e.sends.push(request);
    return busy(e.own.jobs[request.id.slice(0, 3)]);
  };
  const result = await collectCalendarRecovery(e.deps);
  assert.equal(result.attempted, 60);
  assert.ok(result.attempted <= 64);
  assert.equal(result.closureReady, false);
  assert.equal(e.sends.filter(({ id }) => /-delete-[123]$/.test(id)).length, 24);
  assert.equal(e.waits.length, 17);
  assert.ok(e.waits.every((ms) => ms === 60000));
  assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  for (const id of Object.keys(e.own.jobs))
    assert.ok(e.sends.some((request) => request.id === id + "-after"));
});

test("foreign initial identity or unrecorded state never authorizes that job's mutation", async () => {
  for (const identity of ["name", "topic", "state"]) {
    const e = environment();
    const job = e.jobs.get("c01");
    if (identity === "name") job.name += "-foreign";
    else if (identity === "topic") job.pubsubTarget.topicName += "-foreign";
    else job.state = "UNKNOWN";
    const result = await collectCalendarRecovery(e.deps);
    assert.equal(result.closureReady, false);
    assert.ok(e.sends.some(({ id }) => id === "c01-before"));
    assert.ok(!e.sends.some(({ id }) => id === "c01-pause" || id.startsWith("c01-delete-")));
    assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  }
});

test("a lost DELETE acknowledgment remains debt even if readonly postflight sees absence", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    if (request.id === "c01-delete-1") throw new Error("accepted DELETE response lost");
    return response;
  };
  const result = await collectCalendarRecovery(e.deps);
  assert.equal(result.unknown, 1);
  assert.equal(result.closureReady, false);
  assert.ok(e.sends.some(({ id }) => id === "c01-after"));
  assert.ok(!e.sends.some(({ id }) => id === "c01-delete-2" || id === "delete-topic"));
});

test("an unrecorded PAUSED containment read refuses deletion of the ENABLED job", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    if (request.id !== "c01-read-paused") return response;
    return new Response(
      JSON.stringify({
        name: e.own.jobs.c01,
        state: "ENABLED",
        pubsubTarget: { topicName: e.own.topic },
      }),
      { status: 200 },
    );
  };
  const result = await collectCalendarRecovery(e.deps);
  assert.equal(result.closureReady, false);
  assert.ok(e.sends.some(({ id }) => id === "c01-pause"));
  assert.ok(!e.sends.some(({ id }) => id.startsWith("c01-delete-") || id === "delete-topic"));
});

test("unknown recovery topic DELETE cannot discharge settlement debt using later404", async () => {
  const e = environment("ABSENT"),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    if (request.id === "delete-topic") throw new Error("recovery topic delete response lost");
    return response;
  };
  const result = await collectCalendarRecovery(e.deps);
  assert.equal(result.unknown, 1);
  assert.ok(e.sends.some(({ id }) => id === "read-topic-after"));
  assert.equal(result.closureReady, false);
});

test("only the exact recorded409tuple permits another job DELETE", async () => {
  for (const mutation of ["message", "resource", "details", "status"]) {
    const e = environment("PAUSED"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id !== "c01-delete-1") return original(request);
      e.sends.push(request);
      const body = await busy(e.own.jobs.c01).json();
      if (mutation === "message") body.error.message += "-unrecorded";
      if (mutation === "resource") body.error.details[0].resourceName += "-foreign";
      if (mutation === "details") body.error.details.push(body.error.details[0]);
      return new Response(JSON.stringify(body), { status: mutation === "status" ? 500 : 409 });
    };
    const result = await collectCalendarRecovery(e.deps);
    assert.equal(result.closureReady, false);
    assert.ok(e.sends.some(({ id }) => id === "c01-delete-1"));
    assert.ok(!e.sends.some(({ id }) => id === "c01-delete-2" || id === "delete-topic"));
  }
});

test("foreign topic read or an unrecorded final list never authorizes recovery topic DELETE", async () => {
  for (const mutation of ["topic", "jobs-list", "topics-list"]) {
    const e = environment("ABSENT"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      const response = await original(request);
      if (mutation === "topic" && request.id === "read-topic-before")
        return new Response(JSON.stringify({ name: e.own.topic + "-foreign" }), { status: 200 });
      if (mutation === "jobs-list" && request.id === "final-list-jobs")
        return new Response(JSON.stringify({ jobs: [] }), { status: 200 });
      if (mutation === "topics-list" && request.id === "final-list-topics")
        return new Response(JSON.stringify({ topics: [] }), { status: 200 });
      return response;
    };
    const result = await collectCalendarRecovery(e.deps);
    assert.equal(result.closureReady, false);
    if (mutation !== "topics-list") assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  }
});

test("recovery cannot reuse the original run ID and rejects before any send", async () => {
  const e = environment();
  e.deps.runId = originalRunId;
  await assert.rejects(collectCalendarRecovery(e.deps), /distinct attempt/);
  assert.equal(e.sends.length, 0);
});

test("topic-only recovery inventory has9templates and exactly one fixed original topic DELETE", () => {
  const requests = calendarRecoveryRequests(originalRunId, "topic-only");
  assert.equal(requests.length, 9);
  const writes = requests.filter((r) => r.method !== "GET");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].id, "delete-topic");
  assert.equal(
    writes[0].url,
    "https://pubsub.googleapis.com/v1/" + calendarResources(originalRunId).topic,
  );
  assert.equal(writes[0].timeoutMs, 30000);
  assert.ok(!requests.some((r) => /:pause|\/jobs\//.test(r.url)));
  assert.throws(() => calendarRecoveryRequests(originalRunId, "unknown"), /scope/);
});

test("topic-only recovery deletes the proven topic without any job mutation", async () => {
  const e = environment("ABSENT");
  const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
  assert.equal(result.attempted, 6);
  assert.equal(e.sends.filter((r) => r.method !== "GET").length, 1);
  assert.ok(e.sends.some((r) => r.id === "before-list-jobs"));
  assert.ok(
    e.rows.some(
      (r) => r.id === "delete-topic" && r.state === "before-send" && r.timeoutMs === 30000,
    ),
  );
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
});

test("topic-only recovery stops before mutation if any job exists or jobs preflight is unknown", async () => {
  for (const kind of ["job", "unknown", "malformed"]) {
    const e = environment(kind === "job" ? "ENABLED" : "ABSENT"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id === "before-list-jobs") {
        if (kind === "unknown") {
          e.sends.push(request);
          throw new Error("unknown initial jobs list");
        }
        if (kind === "malformed") {
          e.sends.push(request);
          return new Response("null", { status: 200 });
        }
        return original({ ...request, id: "final-list-jobs" });
      }
      return original(request);
    };
    const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
    assert.equal(result.closureReady, false);
    assert.ok(e.sends.every((r) => r.method === "GET"));
  }
});

test("topic-only initial404 and unknown CREATE debt stay open after bounded absent polls", async () => {
  const e = environment("ABSENT"),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id.startsWith("read-topic-")) {
      e.sends.push(request);
      return new Response(
        JSON.stringify({
          error: {
            code: 404,
            status: "NOT_FOUND",
            message: "Resource not found (resource=" + e.own.prefix + ").",
          },
        }),
        { status: 404 },
      );
    }
    if (request.id === "final-list-topics") {
      e.sends.push(request);
      return new Response("{}", { status: 200 });
    }
    return original(request);
  };
  const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
  assert.ok(e.sends.every((r) => r.method === "GET"));
  assert.deepEqual(e.waits, [10000, 10000, 10000]);
  assert.equal(result.closureReady, false);
  assert.ok(result.attempted <= 9);
});

test("topic-only DELETE404 settles only with exact separate absence and final empty lists", async () => {
  for (const visibleAfter of [false, true]) {
    const e = environment("ABSENT"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id === "delete-topic") {
        if (!visibleAfter) await original(request);
        else e.sends.push(request);
        return new Response(
          JSON.stringify({
            error: {
              code: 404,
              status: "NOT_FOUND",
              message: "Resource not found (resource=" + e.own.prefix + ").",
            },
          }),
          { status: 404 },
        );
      }
      if (/^read-topic-poll-[1-3]$/.test(request.id))
        return original({ ...request, id: "read-topic-after" });
      return original(request);
    };
    const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
    assert.equal(result.closureReady, !visibleAfter);
    assert.equal(result.cleanupVerified, false);
    assert.equal(e.sends.filter((r) => r.method === "DELETE").length, 1);
    assert.ok(result.attempted <= 9);
  }
});

test("topic-only unknown DELETE never settles even when readbacks show404", async () => {
  for (const kind of ["transport", "body"]) {
    const e = environment("ABSENT"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      const response = await original(request);
      if (request.id !== "delete-topic") return response;
      if (kind === "transport") throw new Error("DELETE accepted but answer lost");
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error("DELETE body lost"));
          },
        }),
        { status: 404 },
      );
    };
    const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
    assert.equal(result.unknown, 1);
    assert.equal(result.closureReady, false);
    assert.equal(e.sends.filter((r) => r.method === "DELETE").length, 1);
  }
});

test("topic-only polling shares3extras before and after one DELETE", async () => {
  const e = environment("ABSENT"),
    original = e.deps.send;
  let polls = 0;
  e.deps.send = async (request) => {
    if (
      request.id === "read-topic-before" ||
      (/^read-topic-poll-[1-3]$/.test(request.id) && ++polls < 3)
    ) {
      e.sends.push(request);
      return new Response(
        JSON.stringify({
          error: {
            code: 404,
            status: "NOT_FOUND",
            message: "Resource not found (resource=" + e.own.prefix + ").",
          },
        }),
        { status: 404 },
      );
    }
    if (request.id === "read-topic-after") {
      e.sends.push(request);
      return new Response(JSON.stringify({ name: e.own.topic }), { status: 200 });
    }
    if (/^read-topic-poll-[1-3]$/.test(request.id))
      return original({ ...request, id: "read-topic-before" });
    return original(request);
  };
  const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
  assert.equal(polls, 3);
  assert.equal(result.attempted, 9);
  assert.equal(result.closureReady, false);
  assert.deepEqual(e.waits, [10000, 10000, 10000]);
  assert.equal(e.sends.filter((r) => r.method === "DELETE").length, 1);
});

test("topic-only foreign or malformed complete ownership read cannot authorize DELETE", async () => {
  for (const body of [{ name: "projects/foreign/topics/foreign" }, null, {}]) {
    const e = environment("ABSENT"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id !== "read-topic-before") return original(request);
      e.sends.push(request);
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
    assert.equal(result.closureReady, false);
    assert.ok(e.sends.every((r) => r.method === "GET"));
  }
});
