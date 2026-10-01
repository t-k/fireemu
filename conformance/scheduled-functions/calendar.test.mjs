import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CALENDAR_CASES,
  calendarRequests,
  calendarResources,
  collectCalendar,
} from "./calendar.mjs";

const runId = "c1".repeat(8);
const projectNumber = "123456789012";
const instant = Date.parse("2026-09-30T09:00:00Z");

function environment() {
  const owned = calendarResources(runId);
  const rows = [],
    sends = [],
    waits = [];
  let now = instant;
  let jobs = new Map(),
    topicPresent = false;
  const deps = {
    runId,
    projectNumber,
    accessToken: "offline-calendar-bearer",
    clock: () => now++,
    sleep: async (ms) => {
      waits.push(ms);
      now += ms;
    },
    save: async (row) => rows.push(row),
    send: async (request) => {
      sends.push(request);
      let status = 200,
        body = {};
      const match =
        /^(c[0-9]{2})-(before|create|pause|read-paused|read-before-pause|delete|read-deleted)$/.exec(
          request.id,
        );
      if (request.id === "identity")
        body = {
          name: "projects/fireemu-oracle-sbx/releases/cloud.firestore",
          rulesetName: "projects/fireemu-oracle-sbx/rulesets/offline",
        };
      else if (request.id.startsWith("service-")) body = { state: "ENABLED" };
      else if (request.id === "appengine-location") {
        status = 404;
        body = { error: { code: 404, status: "NOT_FOUND" } };
      } else if (request.id === "before-topic" || request.id === "read-deleted-topic") {
        if (topicPresent) body = { name: owned.topic };
        else {
          status = 404;
          body = {
            error: {
              code: 404,
              status: "NOT_FOUND",
              message: "Resource not found (resource=" + owned.prefix + ").",
            },
          };
        }
      } else if (request.id === "create-topic") {
        topicPresent = true;
        body = { name: owned.topic };
      } else if (request.id === "read-topic") body = { name: owned.topic };
      else if (request.id === "delete-topic") topicPresent = false;
      else if (request.id === "final-list-jobs")
        body = jobs.size ? { jobs: [...jobs.values()] } : {};
      else if (match) {
        const [, id, action] = match;
        const target = owned.jobs[id];
        if (action === "create") {
          body = {
            name: target,
            state: "ENABLED",
            schedule: request.json.schedule,
            timeZone: request.json.timeZone,
            pubsubTarget: { topicName: owned.topic },
            scheduleTime: "2027-01-01T00:00:00Z",
          };
          jobs.set(id, body);
        } else if (action === "pause") {
          body = { ...jobs.get(id), state: "PAUSED" };
          delete body.scheduleTime;
          jobs.set(id, body);
        } else if (action === "delete") jobs.delete(id);
        else if (jobs.has(id)) body = jobs.get(id);
        else {
          status = 404;
          body = { error: { code: 404, status: "NOT_FOUND", message: "Job not found." } };
        }
      }
      return new Response(JSON.stringify(body), { status });
    },
  };
  return { deps, owned, rows, sends, waits };
}

function busy(job) {
  return new Response(
    JSON.stringify({
      error: {
        code: 409,
        status: "ABORTED",
        message: "sync mutate calls cannot be queued",
        details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: job }],
      },
    }),
    { status: 409 },
  );
}

test("calendar seed fixes eight inputs and61routes without API, IAM, deploy or manual invocation", () => {
  assert.equal(CALENDAR_CASES.length, 8);
  assert.equal(new Set(CALENDAR_CASES.map((c) => c.id)).size, 8);
  const requests = calendarRequests(runId, projectNumber, instant);
  assert.equal(requests.length, 61);
  assert.ok(
    requests.every(({ url }) => !/:run|:publish|:pull|:batchEnable|setIamPolicy/.test(url)),
  );
  assert.ok(
    requests
      .filter(({ id }) => id.endsWith("-create"))
      .every(({ json }) => json.state === undefined),
  );
  assert.throws(() => calendarResources("../../other"), /run ID/);
});

test("calendar readiness uses the recorded numeric Service Usage route and bounds its seed window", async () => {
  const requests = calendarRequests(runId, projectNumber, instant);
  assert.ok(
    requests
      .filter(({ id }) => id.startsWith("service-"))
      .every(({ url }) => url.includes("/projects/" + projectNumber + "/services/")),
  );
  assert.throws(() => calendarRequests(runId, "foreign", instant), /project number/);
  assert.throws(
    () => calendarRequests(runId, projectNumber, Date.parse("2026-11-01T00:00:00Z")),
    /seed window/,
  );
  assert.throws(
    () => calendarRequests(runId, projectNumber, Date.parse("2026-01-01T00:00:00Z")),
    /seed window/,
  );
  const e = environment();
  e.deps.projectNumber = "foreign";
  await assert.rejects(collectCalendar(e.deps), /project number/);
  assert.equal(e.sends.length, 0);
});

test("eight synthetic successful cases capture CREATE next-time and settle all jobs before deletion", async () => {
  const e = environment();
  const result = await collectCalendar(e.deps);
  assert.equal(result.attempted, 61);
  assert.equal(result.completed, 61);
  assert.equal(result.unknown, 0);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.outcome, "calendar-needs-review");
  assert.deepEqual(e.waits, [60000]);
  const lastPause = e.rows.findLast(
    (r) => r.id.endsWith("-pause") && r.state === "response-persisted",
  );
  for (const row of e.rows.filter((r) => r.id.endsWith("-delete") && r.state === "before-send"))
    assert.ok(Date.parse(row.dispatchAt) - Date.parse(lastPause.responseAt) >= 60000);
  assert.ok(!JSON.stringify(e.rows).includes("offline-calendar-bearer"));
});

test("only three extra DELETEs are available globally even across different jobs", async () => {
  const e = environment(),
    original = e.deps.send;
  let conflicts = 0;
  e.deps.send = async (request) => {
    if (/^c0[12]-delete(?:-retry-[0-9]+)?$/.test(request.id)) {
      conflicts++;
      e.sends.push(request);
      return busy(e.owned.jobs[request.id.slice(0, 3)]);
    }
    return original(request);
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.attempted, 63);
  assert.ok(result.attempted <= 64);
  assert.equal(conflicts, 5);
  assert.equal(result.closureReady, false);
  assert.deepEqual(e.waits, [60000, 60000, 60000, 60000]);
  assert.ok(e.sends.some(({ id }) => id === "c02-read-deleted"));
  assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
});

for (const identity of ["name", "topic", "state"])
  test(
    "unrecorded paused job " + identity + " refuses DELETE and preserves its topic",
    async () => {
      const e = environment(),
        original = e.deps.send;
      e.deps.send = async (request) => {
        if (request.id !== "c01-read-paused") return original(request);
        e.sends.push(request);
        const body = {
          name: e.owned.jobs.c01,
          state: "PAUSED",
          pubsubTarget: { topicName: e.owned.topic },
        };
        if (identity === "name") body.name += "-foreign";
        if (identity === "topic") body.pubsubTarget.topicName += "-foreign";
        if (identity === "state") body.state = "UNKNOWN";
        return new Response(JSON.stringify(body), { status: 200 });
      };
      const result = await collectCalendar(e.deps);
      assert.equal(result.closureReady, false);
      assert.ok(!e.sends.some(({ id }) => id === "c01-delete" || id === "delete-topic"));
      assert.ok(!e.sends.some(({ id }) => id === "c02-create"));
    },
  );

test("definitive create conflict never owns the raced job and stops further creates", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id !== "c01-create") return original(request);
    e.sends.push(request);
    return busy(e.owned.jobs.c01);
  };
  await collectCalendar(e.deps);
  assert.ok(e.sends.some(({ id }) => id === "c01-create"));
  assert.ok(!e.sends.some(({ id }) => /^c01-(pause|delete)/.test(id) || id === "c02-create"));
});

test("unknown DELETE stops retries but captures read-only postflight and retains cleanup debt", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id !== "c01-delete") return original(request);
    e.sends.push(request);
    throw new Error("offline transport failure");
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.unknown, 1);
  assert.equal(result.closureReady, false);
  assert.ok(e.sends.some(({ id }) => id === "c01-read-deleted"));
  assert.ok(e.sends.some(({ id }) => id === "final-list-jobs"));
  assert.ok(!e.sends.some(({ id }) => id.startsWith("c01-delete-retry")));
  assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
});

test("unrecorded final list bodies never prove cleanup or permit topic deletion", async () => {
  for (const body of [null, [], { nextPageToken: "" }, { jobs: [] }]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id !== "final-list-jobs") return original(request);
      e.sends.push(request);
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const result = await collectCalendar(e.deps);
    assert.equal(result.closureReady, false);
    assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  }
});

test("a complete create response with foreign identity never authorizes pause or delete", async () => {
  for (const identity of ["name", "topic"]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      const response = await original(request);
      if (request.id !== "c01-create") return response;
      const body = await response.json();
      if (identity === "name") body.name += "-foreign";
      else body.pubsubTarget.topicName += "-foreign";
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const result = await collectCalendar(e.deps);
    assert.equal(result.closureReady, false);
    assert.ok(!e.sends.some(({ id }) => id === "c01-pause" || id === "c01-delete"));
    assert.ok(!e.sends.some(({ id }) => id === "c02-create" || id === "delete-topic"));
  }
});

test("foreign create identity remains debt even when the requested namespace is empty", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id !== "c01-create") return original(request);
    e.sends.push(request);
    return new Response(
      JSON.stringify({
        name: "projects/foreign/locations/us-central1/jobs/foreign",
        state: "ENABLED",
        pubsubTarget: { topicName: "projects/foreign/topics/foreign" },
      }),
      { status: 200 },
    );
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.closureReady, false);
  assert.ok(!e.sends.some(({ id }) => id === "c01-pause" || id === "c01-delete"));
});

test("a lost create response still contains and deletes the proven owned job", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    if (request.id === "c01-create") throw new Error("lost response after accepted create");
    return response;
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.unknown, 1);
  assert.equal(result.cleanupVerified, false);
  assert.ok(e.sends.some(({ id }) => id === "c01-pause"));
  assert.ok(e.sends.some(({ id }) => id === "c01-delete"));
  assert.ok(!e.sends.some(({ id }) => id === "c02-create"));
});

test("a contradictory complete topic-create identity cannot authorize deletion or closure", async () => {
  for (const requestedTopicPresent of [true, false]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id !== "create-topic") return original(request);
      if (requestedTopicPresent) await original(request);
      else e.sends.push(request);
      return new Response(JSON.stringify({ name: "projects/foreign/topics/foreign" }), {
        status: 200,
      });
    };
    const result = await collectCalendar(e.deps);
    assert.ok(e.sends.some(({ id }) => id === "create-topic"));
    assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
    assert.equal(result.closureReady, false);
    assert.ok(!e.sends.some(({ id }) => id.endsWith("-create")));
  }
});

test("a lost topic-create response can only contain its proven requested topic", async () => {
  for (const kind of ["transport", "body"]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      const response = await original(request);
      if (request.id !== "create-topic") return response;
      if (kind === "transport") throw new Error("lost topic response after accepted create");
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error("offline body read failure"));
          },
        }),
        { status: 200 },
      );
    };
    const result = await collectCalendar(e.deps);
    assert.equal(result.unknown, 1);
    if (kind === "body")
      assert.ok(e.rows.some((row) => row.id === "create-topic" && row.state === "body-unknown"));
    assert.equal(result.cleanupVerified, false);
    assert.ok(e.sends.some(({ id }) => id === "delete-topic"));
    assert.ok(!e.sends.some(({ id }) => id.endsWith("-create")));
  }
});

test("a fully persisted malformed topic-create body retains identity debt", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    return request.id === "create-topic" ? new Response("{", { status: 200 }) : response;
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.unknown, 0);
  assert.ok(e.rows.some((row) => row.id === "create-topic" && row.state === "response-persisted"));
  assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  assert.equal(result.closureReady, false);
});

test("unknown topic DELETE retains settlement debt even when its readonly postflight is absent", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    if (request.id === "delete-topic") throw new Error("topic delete accepted but response lost");
    return response;
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.unknown, 1);
  assert.ok(e.sends.some(({ id }) => id === "read-deleted-topic"));
  assert.equal(result.closureReady, false);
});

function lostBody() {
  return new Response(
    new ReadableStream({
      pull(controller) {
        controller.error(new Error("offline streamed body failure"));
      },
    }),
    { status: 200 },
  );
}

test("failed or unknown PAUSE stops later CREATE even when GET proves own PAUSED cleanup", async () => {
  for (const kind of ["transport", "body", "failure"]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      const response = await original(request);
      if (request.id !== "c01-pause") return response;
      if (kind === "transport") throw new Error("pause accepted but response lost");
      if (kind === "body") return lostBody();
      return new Response(JSON.stringify({ error: { code: 503, status: "UNAVAILABLE" } }), {
        status: 503,
      });
    };
    const result = await collectCalendar(e.deps);
    assert.ok(e.sends.some(({ id }) => id === "c01-pause"));
    assert.ok(e.sends.some(({ id }) => id === "c01-delete"));
    assert.ok(!e.sends.some(({ id }) => id === "c02-create"));
    assert.equal(result.unknown, kind === "failure" ? 0 : 1);
  }
});

test("ambiguous CREATE never mutates an intervening foreign identity or unknown state", async () => {
  for (const kind of ["transport", "body"])
    for (const identity of ["name", "topic", "state"]) {
      const e = environment(),
        original = e.deps.send;
      let createTried = false;
      e.deps.send = async (request) => {
        if (request.id === "c01-create") {
          createTried = true;
          e.sends.push(request);
          if (kind === "transport") throw new Error("create failed before acceptance");
          return lostBody();
        }
        if (createTried && request.method === "GET" && request.url.endsWith(e.owned.jobs.c01)) {
          e.sends.push(request);
          const body = {
            name: e.owned.jobs.c01,
            state: "ENABLED",
            pubsubTarget: { topicName: e.owned.topic },
          };
          if (identity === "name") body.name += "-foreign";
          if (identity === "topic") body.pubsubTarget.topicName += "-foreign";
          if (identity === "state") body.state = "UNKNOWN";
          return new Response(JSON.stringify(body), { status: 200 });
        }
        return original(request);
      };
      const result = await collectCalendar(e.deps);
      assert.ok(createTried);
      assert.ok(!e.sends.some(({ id }) => id === "c01-pause" || id === "c01-delete"));
      assert.ok(!e.sends.some(({ id }) => id === "c02-create" || id === "delete-topic"));
      assert.equal(result.closureReady, false);
    }
});

test("lost CREATE proves exact own identity before PAUSE and shares its read with retry budget", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (/^c01-delete(?:-retry-[0-9]+)?$/.test(request.id)) {
      e.sends.push(request);
      return busy(e.owned.jobs.c01);
    }
    const response = await original(request);
    if (request.id === "c08-create") throw new Error("last create accepted but response lost");
    return response;
  };
  const result = await collectCalendar(e.deps);
  const before = e.sends.findIndex(({ id }) => id === "c08-read-before-pause");
  const pause = e.sends.findIndex(({ id }) => id === "c08-pause");
  assert.ok(before >= 0 && pause > before);
  assert.equal(e.sends.filter(({ id }) => /^c01-delete(?:-retry-[0-9]+)?$/.test(id)).length, 3);
  assert.equal(result.attempted, 63);
  assert.ok(result.attempted <= 64);
  assert.equal(result.closureReady, false);
});

for (const refusals of [["c04"], ["c07"], ["c04", "c07"]])
  test(
    "complete400 refusals " +
      refusals.join(",") +
      " retain later corpus observations without mutation",
    async () => {
      const e = environment(),
        original = e.deps.send;
      e.deps.send = async (request) => {
        if (!refusals.some((id) => request.id === id + "-create")) return original(request);
        e.sends.push(request);
        return new Response(JSON.stringify({ error: { code: 400, status: "INVALID_ARGUMENT" } }), {
          status: 400,
        });
      };
      const result = await collectCalendar(e.deps);
      assert.equal(e.sends.filter(({ id }) => id.endsWith("-create")).length, 8);
      assert.ok(e.sends.some(({ id }) => id === "c08-create"));
      for (const id of refusals) {
        assert.ok(!e.sends.some((r) => r.id === id + "-pause" || r.id === id + "-delete"));
        assert.ok(
          e.rows.some(
            (r) => r.id === id + "-create" && r.state === "response-persisted" && r.status === 400,
          ),
        );
      }
      assert.equal(result.attempted, 61 - 3 * refusals.length);
      assert.equal(result.closureReady, true);
      assert.equal(result.cleanupVerified, false);
    },
  );

test("non400 client refusals stop later creates and never acquire the refused job", async () => {
  for (const status of [401, 403, 404, 409, 422, 429]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id !== "c04-create") return original(request);
      e.sends.push(request);
      return new Response(JSON.stringify({ error: { code: status } }), { status });
    };
    await collectCalendar(e.deps);
    assert.ok(
      !e.sends.some(({ id }) => id === "c05-create" || id === "c04-pause" || id === "c04-delete"),
    );
  }
});

test("400 with an unreadable body stops later creates and retains raw-response debt", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id !== "c04-create") return original(request);
    e.sends.push(request);
    return new Response(
      new ReadableStream({
        start(controller) {
          controller.error(new Error("lost400body"));
        },
      }),
      { status: 400 },
    );
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.unknown, 1);
  assert.ok(
    !e.sends.some(({ id }) => id === "c05-create" || id === "c04-pause" || id === "c04-delete"),
  );
  assert.ok(
    e.rows.some((r) => r.id === "c04-create" && r.state === "body-unknown" && r.status === 400),
  );
  assert.equal(result.cleanupVerified, false);
});

test("failed pause with exact own ENABLED readback gets a settled DELETE and bounded busy retry", async () => {
  for (const outcome of ["success", "busy", "unsettled"]) {
    const e = environment(),
      original = e.deps.send;
    let deletes = 0;
    e.deps.send = async (request) => {
      if (request.id === "c01-pause") {
        e.sends.push(request);
        return new Response(JSON.stringify({ error: { code: 503 } }), { status: 503 });
      }
      if (/^c01-delete(?:-retry-[0-9]+)?$/.test(request.id)) {
        deletes++;
        if (outcome === "unsettled" || (outcome === "busy" && deletes === 1)) {
          e.sends.push(request);
          return outcome === "busy" ? busy(e.owned.jobs.c01) : new Response("{}", { status: 503 });
        }
        if (request.id !== "c01-delete") return original({ ...request, id: "c01-delete" });
      }
      return original(request);
    };
    const result = await collectCalendar(e.deps);
    const read = e.rows.find((r) => r.id === "c01-read-paused" && r.state === "response-persisted");
    const deletion = e.rows.find((r) => r.id === "c01-delete" && r.state === "before-send");
    assert.ok(deletion);
    assert.ok(Date.parse(deletion.dispatchAt) - Date.parse(read.responseAt) >= 60000);
    assert.equal(deletes, outcome === "busy" ? 2 : 1);
    assert.deepEqual(e.waits, outcome === "busy" ? [60000, 60000] : [60000]);
    assert.ok(!e.sends.some(({ id }) => id === "c02-create"));
    assert.equal(
      e.sends.some(({ id }) => id === "delete-topic"),
      outcome !== "unsettled",
    );
    assert.equal(result.closureReady, outcome !== "unsettled");
    assert.equal(result.cleanupVerified, false);
  }
});

test("failed pause cannot delete a foreign or unreadable ENABLED readback", async () => {
  for (const kind of ["name", "topic", "state", "body", "transport"]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id === "c01-pause") {
        e.sends.push(request);
        return new Response("{}", { status: 503 });
      }
      if (request.id !== "c01-read-paused") return original(request);
      e.sends.push(request);
      if (kind === "body") return lostBody();
      if (kind === "transport") throw new Error("unknown readback");
      const body = {
        name: e.owned.jobs.c01,
        state: "ENABLED",
        pubsubTarget: { topicName: e.owned.topic },
      };
      if (kind === "name") body.name += "-foreign";
      if (kind === "topic") body.pubsubTarget.topicName += "-foreign";
      if (kind === "state") body.state = "UNKNOWN";
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const result = await collectCalendar(e.deps);
    assert.ok(
      !e.sends.some(
        ({ id }) => id === "c01-delete" || id === "delete-topic" || id === "c02-create",
      ),
    );
    assert.equal(result.closureReady, false);
  }
});

test("one or two400 refusals plus ambiguous CREATE and busy cleanup share exactly three extras", async () => {
  for (const refusals of [["c04"], ["c04", "c07"]]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (refusals.some((id) => request.id === id + "-create")) {
        e.sends.push(request);
        return new Response("{}", { status: 400 });
      }
      if (/^c01-delete(?:-retry-[0-9]+)?$/.test(request.id)) {
        e.sends.push(request);
        return busy(e.owned.jobs.c01);
      }
      const response = await original(request);
      if (request.id === "c08-create") throw new Error("accepted CREATE response lost");
      return response;
    };
    const result = await collectCalendar(e.deps);
    assert.ok(e.sends.some(({ id }) => id === "c08-read-before-pause"));
    assert.equal(e.sends.filter(({ id }) => /^c01-delete(?:-retry-[0-9]+)?$/.test(id)).length, 3);
    assert.equal(result.attempted, 63 - 3 * refusals.length);
    assert.ok(result.attempted <= 64);
    assert.equal(result.closureReady, false);
    assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  }
});

test("late topic CREATE visibility after timeout and initial404 is polled before own cleanup", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id === "create-topic") {
      await original(request);
      throw new Error("topic PUT accepted with delayed visibility after timeout");
    }
    if (request.id === "read-topic") {
      e.sends.push(request);
      return new Response(
        JSON.stringify({
          error: {
            code: 404,
            status: "NOT_FOUND",
            message: "Resource not found (resource=" + e.owned.prefix + ").",
          },
        }),
        { status: 404 },
      );
    }
    if (/^read-topic-poll-[1-3]$/.test(request.id))
      return original({ ...request, id: "read-topic" });
    return original(request);
  };
  const result = await collectCalendar(e.deps);
  assert.ok(e.rows.some((r) => r.id === "read-topic-poll-1" && r.state === "before-send"));
  assert.ok(e.sends.some(({ id }) => id === "delete-topic"));
  assert.equal(e.sends.filter(({ id }) => id === "create-topic").length, 1);
  assert.ok(!e.sends.some(({ id }) => /^c[0-9]{2}-create$/.test(id)));
  assert.equal(result.attempted, 14);
  assert.equal(result.unknown, 1);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.deepEqual(e.waits, [10000]);
});

test("unknown topic CREATE with bounded still404 polls never earns absence settlement", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id === "create-topic") {
      e.sends.push(request);
      throw new Error("unknown create outcome");
    }
    if (request.id === "read-topic" || /^read-topic-poll-[1-3]$/.test(request.id)) {
      e.sends.push(request);
      return new Response(
        JSON.stringify({
          error: {
            code: 404,
            status: "NOT_FOUND",
            message: "Resource not found (resource=" + e.owned.prefix + ").",
          },
        }),
        { status: 404 },
      );
    }
    return original(request);
  };
  const result = await collectCalendar(e.deps);
  assert.equal(
    e.rows.filter((r) => /^read-topic-poll-[1-3]$/.test(r.id) && r.state === "before-send").length,
    3,
  );
  assert.deepEqual(e.waits, [10000, 10000, 10000]);
  assert.equal(e.sends.filter(({ id }) => id === "create-topic").length, 1);
  assert.ok(!e.sends.some(({ id }) => id === "delete-topic" || /^c[0-9]{2}-create$/.test(id)));
  assert.equal(result.closureReady, false);
  assert.equal(result.attempted, 15);
});

test("seed topic PUT and DELETE and job CREATE advertise30second deadlines while other requests remain10seconds", () => {
  const requests = calendarRequests(runId, projectNumber, instant);
  assert.equal(requests.find((r) => r.id === "create-topic").timeoutMs, 30000);
  assert.equal(requests.find((r) => r.id === "delete-topic").timeoutMs, 30000);
  assert.equal(
    requests.filter((r) => /^c0[1-8]-create$/.test(r.id) && r.timeoutMs === 30000).length,
    8,
  );
  assert.ok(
    requests
      .filter(
        (r) => !["create-topic", "delete-topic"].includes(r.id) && !/^c0[1-8]-create$/.test(r.id),
      )
      .every((r) => r.timeoutMs === undefined),
  );
});

test("unknown job CREATE retains debt and topic through all404 readbacks or late200 visibility", async () => {
  for (const late of [false, true]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id === "c01-create") {
        e.sends.push(request);
        throw new Error("unknown job CREATE outcome");
      }
      if (request.id === "c01-read-before-pause" || request.id === "c01-read-deleted") {
        e.sends.push(request);
        if (late && request.id === "c01-read-deleted")
          return new Response(
            JSON.stringify({
              name: e.owned.jobs.c01,
              state: "ENABLED",
              pubsubTarget: { topicName: e.owned.topic },
            }),
          );
        return new Response(
          JSON.stringify({ error: { code: 404, status: "NOT_FOUND", message: "Job not found." } }),
          { status: 404 },
        );
      }
      return original(request);
    };
    const result = await collectCalendar(e.deps);
    assert.equal(result.closureReady, false);
    assert.equal(result.cleanupVerified, false);
    assert.ok(!e.sends.some((r) => r.id === "delete-topic"));
    assert.equal(e.sends.filter((r) => /^c0[1-8]-create$/.test(r.id)).length, 1);
    assert.equal(result.unknown, 1);
    assert.ok(result.attempted <= 64);
  }
});

test("unknown job CREATE settles only after an exact own positive read and normal acknowledged cleanup", async () => {
  const e = environment(),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id === "c01-create") {
      await original(request);
      throw new Error("created job response lost");
    }
    return original(request);
  };
  const result = await collectCalendar(e.deps);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(result.unknown, 1);
  assert.ok(e.sends.some((r) => r.id === "c01-read-before-pause"));
  assert.ok(e.sends.some((r) => r.id === "c01-pause"));
  assert.ok(e.sends.some((r) => r.id === "c01-delete"));
  assert.ok(e.sends.some((r) => r.id === "delete-topic"));
  assert.equal(e.sends.filter((r) => /^c0[1-8]-create$/.test(r.id)).length, 1);
});

test("unknown job or topic DELETE cannot settle through later exact absent reads and empty lists", async () => {
  for (const id of ["c01-delete", "delete-topic"])
    for (const unreadable of [false, true]) {
      const e = environment(),
        original = e.deps.send;
      e.deps.send = async (request) => {
        if (request.id === id) {
          await original(request);
          if (!unreadable) throw new Error("DELETE outcome unknown");
          return new Response(
            new ReadableStream({
              start(c) {
                c.error(new Error("DELETE body unreadable"));
              },
            }),
            { status: 200 },
          );
        }
        return original(request);
      };
      const result = await collectCalendar(e.deps);
      assert.equal(result.closureReady, false);
      assert.equal(result.cleanupVerified, false);
      assert.equal(result.unknown, 1);
      assert.equal(e.sends.filter((r) => r.id === id).length, 1);
      if (id === "c01-delete") assert.ok(!e.sends.some((r) => r.id === "delete-topic"));
    }
});

test("unreadable job CREATE body remains debt even with400 headers and all later reads absent", async () => {
  for (const status of [200, 400]) {
    const e = environment(),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id === "c01-create") {
        e.sends.push(request);
        return new Response(
          new ReadableStream({
            start(c) {
              c.error(new Error("CREATE body interrupted"));
            },
          }),
          { status },
        );
      }
      return original(request);
    };
    const result = await collectCalendar(e.deps);
    assert.equal(result.closureReady, false);
    assert.equal(result.cleanupVerified, false);
    assert.equal(result.unknown, 1);
    assert.ok(!e.sends.some((r) => r.id === "delete-topic"));
    assert.equal(e.sends.filter((r) => /^c0[1-8]-create$/.test(r.id)).length, 1);
  }
});
