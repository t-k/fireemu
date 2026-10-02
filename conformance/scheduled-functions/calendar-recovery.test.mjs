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
          body = { error: { code: 404, message: "Job not found.", status: "NOT_FOUND" } };
        }
      } else if (request.id === "read-topic-before" || request.id === "read-topic-after") {
        if (topicPresent) body = { name: own.topic };
        else {
          status = 404;
          body = {
            error: {
              code: 404,
              message: "Resource not found (resource=" + own.prefix + ").",
              status: "NOT_FOUND",
            },
          };
        }
      } else if (request.id === "delete-topic") topicPresent = false;
      else if (request.id === "final-list-jobs")
        body = jobs.size ? { jobs: [...jobs.values()] } : {};
      else if (request.id === "final-list-topics")
        body = topicPresent ? { topics: [{ name: own.topic }] } : {};
      return new Response(JSON.stringify(body, null, 2) + "\n", { status });
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
        JSON.stringify(
          {
            error: {
              code: 404,
              message: "Resource not found (resource=" + e.own.prefix + ").",
              status: "NOT_FOUND",
            },
          },
          null,
          2,
        ) + "\n",
        { status: 404 },
      );
    }
    if (request.id === "final-list-topics") {
      e.sends.push(request);
      return new Response("{}\n", { status: 200 });
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
          JSON.stringify(
            {
              error: {
                code: 404,
                message: "Resource not found (resource=" + e.own.prefix + ").",
                status: "NOT_FOUND",
              },
            },
            null,
            2,
          ) + "\n",
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
        JSON.stringify(
          {
            error: {
              code: 404,
              message: "Resource not found (resource=" + e.own.prefix + ").",
              status: "NOT_FOUND",
            },
          },
          null,
          2,
        ) + "\n",
        { status: 404 },
      );
    }
    if (request.id === "read-topic-after") {
      e.sends.push(request);
      return new Response(JSON.stringify({ name: e.own.topic }, null, 2) + "\n", { status: 200 });
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

// Review S-B1: as in the settled-topic scope, an unknown answer in the topic-only and the
// jobs-and-topic scopes needs the separate later read-back, so neither is closure-ready with
// unknown > 0 even when every later proof is positive.
test("topic-only and jobs-and-topic recovery withhold closure after any unknown answer", async () => {
  for (const [scope, state, id] of [
    ["topic-only", "ABSENT", "read-topic-before"],
    [undefined, "ENABLED", "c01-pause"],
  ]) {
    const control = environment(state);
    const clean = await collectCalendarRecovery({ ...control.deps, recoveryScope: scope });
    assert.equal(clean.unknown, 0, String(scope));
    assert.equal(clean.closureReady, true, `${scope}: positive control`);
    const e = environment(state),
      original = e.deps.send;
    let lost = false;
    e.deps.send = async (request) => {
      // A poll reads the same topic as the first read.
      if (/^read-topic-poll-[1-3]$/.test(request.id))
        return original({ ...request, id: "read-topic-before" });
      if (request.id !== id || lost) return original(request);
      lost = true;
      // The pause is applied and only its answer is lost; the topic read is lost outright.
      if (id === "c01-pause") await original(request);
      else e.sends.push(request);
      throw new Error("offline lost answer");
    };
    const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: scope });
    assert.equal(result.unknown, 1, String(scope));
    assert.equal(result.closureReady, false, String(scope));
  }
});

// A complete status below 200, a 3xx or a 5xx is as unknown as a lost answer: an applied pause
// answered with a complete 503 still gets its cleanup, but closure waits for the read-back.
test("jobs-and-topic recovery withholds closure after a complete but ambiguous answer", async () => {
  for (const status of [302, 500, 503]) {
    const e = environment("ENABLED"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      if (request.id !== "c01-pause") return original(request);
      await original(request);
      return new Response("{}", { status });
    };
    const result = await collectCalendarRecovery(e.deps);
    assert.equal(result.unknown, 0, String(status));
    assert.ok(
      e.sends.some(({ id }) => id === "c01-delete-1"),
      `${status}: cleanup proceeds`,
    );
    assert.equal(result.closureReady, false, String(status));
  }
});

test("topic-only recovery refuses compact preflight before any DELETE", async () => {
  const e = environment("ABSENT"),
    original = e.deps.send;
  e.deps.send = async (request) => {
    if (request.id !== "before-list-jobs") return original(request);
    e.sends.push(request);
    return new Response("{}", { status: 200 });
  };
  const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
  assert.equal(result.closureReady, false);
  assert.ok(e.sends.every(({ method }) => method === "GET"));
});

// Independent fixtures for calendar-5a73ba99b7014cfd seq30/15/18/156/21 and
// calendar-recovery-96f34e030642e9ca / calendar-recovery-894572e2d854a511.
function byteVariant(bytes, variant) {
  const json = JSON.parse(bytes);
  if (variant === "compact") return JSON.stringify(json);
  if (variant === "order" && json.error) {
    const { code, message, status } = json.error;
    return JSON.stringify({ error: { code, status, message } }, null, 2) + "\n";
  }
  if (variant === "newline") return bytes.replace(/\n$/, "\r\n");
  if (variant === "length") return bytes + " ";
  return bytes.replace(/\n$/, "");
}

async function proofPosition(scope, position, variant) {
  const e = environment("ABSENT"),
    original = e.deps.send;
  e.deps.send = async (request) => {
    const response = await original(request);
    if (request.id !== position) return response;
    return new Response(byteVariant(await response.text(), variant), { status: response.status });
  };
  const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: scope });
  return { e, result };
}

const variants = ["compact", "order", "newline", "length", "missing-newline"];

test("topic-only recovery refuses compact ownership before any DELETE", async () => {
  const { e, result } = await proofPosition("topic-only", "read-topic-before", "compact");
  assert.equal(result.closureReady, false);
  assert.ok(e.sends.every(({ method }) => method === "GET"));
});

test("topic-only recovery requires recorded postflight layouts at every proof position", async () => {
  for (const position of [
    "delete-topic",
    "read-topic-after",
    "final-list-jobs",
    "final-list-topics",
  ])
    for (const variant of variants) {
      const { result } = await proofPosition("topic-only", position, variant);
      assert.equal(result.closureReady, false, `${position}/${variant}`);
    }
});

test("jobs-and-topic recovery requires recorded job absence and final list layouts", async () => {
  for (const position of [
    ...Object.keys(calendarResources(originalRunId).jobs).flatMap((id) => [
      id + "-before",
      id + "-after",
    ]),
    "final-list-jobs",
    "read-topic-after",
    "final-list-topics",
  ])
    for (const variant of variants) {
      const { e, result } = await proofPosition("jobs-and-topic", position, variant);
      assert.equal(result.closureReady, false, `${position}/${variant}`);
      if (position !== "read-topic-after" && position !== "final-list-topics")
        assert.ok(!e.sends.some(({ id }) => id === "delete-topic"), `${position}/${variant}`);
    }
});

test("jobs-and-topic recovery requires byte-exact ownership before topic DELETE", async () => {
  for (const variant of variants) {
    const { e, result } = await proofPosition("jobs-and-topic", "read-topic-before", variant);
    assert.equal(result.closureReady, false, variant);
    assert.ok(!e.sends.some(({ id }) => id === "delete-topic"), variant);
  }
});

test("recorded recovery proofs reject the same parsed JSON with different bytes", async () => {
  // Deterministic seeded generation; the oracle compares independent expected strings,
  // never the imported production judge. Scope, position and whitespace vary together.
  let seed = 0x790792;
  const next = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  for (let sample = 0; sample < 128; sample++) {
    const scope = next() % 2 ? "topic-only" : "jobs-and-topic";
    const positions =
      scope === "topic-only"
        ? [
            "before-list-jobs",
            "read-topic-before",
            "read-topic-after",
            "final-list-jobs",
            "final-list-topics",
          ]
        : [
            "c01-before",
            "c08-after",
            "read-topic-before",
            "read-topic-after",
            "final-list-jobs",
            "final-list-topics",
          ];
    const position = positions[next() % positions.length];
    const e = environment("ABSENT"),
      original = e.deps.send;
    const expected = position.startsWith("c")
      ? '{\n  "error": {\n    "code": 404,\n    "message": "Job not found.",\n    "status": "NOT_FOUND"\n  }\n}\n'
      : position === "read-topic-before"
        ? '{\n  "name": "' + e.own.topic + '"\n}\n'
        : position === "read-topic-after"
          ? '{\n  "error": {\n    "code": 404,\n    "message": "Resource not found (resource=' +
            e.own.prefix +
            ').",\n    "status": "NOT_FOUND"\n  }\n}\n'
          : "{}\n";
    const candidate =
      next() % 4 === 0 ? expected : byteVariant(expected, variants[next() % variants.length]);
    assert.deepEqual(JSON.parse(candidate), JSON.parse(expected));
    e.deps.send = async (request) => {
      const response = await original(request);
      if (request.id !== position) return response;
      assert.equal(await response.text(), expected, position);
      return new Response(candidate, { status: response.status });
    };
    const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: scope });
    assert.equal(result.closureReady, candidate === expected, `${sample}/${scope}/${position}`);
    assert.ok(result.attempted <= (scope === "topic-only" ? 9 : 64));
  }
});

test("ordinary recovery rejects detailed job absence and mismatched persisted length", async () => {
  for (const scope of ["topic-only", "jobs-and-topic"]) {
    const e = environment("ABSENT"),
      save = e.deps.save;
    e.deps.save = async (row) => {
      await save(row);
      if (row.state === "response-persisted" && row.id === "final-list-jobs") row.bodyBytes++;
    };
    assert.equal(
      (await collectCalendarRecovery({ ...e.deps, recoveryScope: scope })).closureReady,
      false,
    );
  }
  for (const position of ["c01-before", "c01-after"]) {
    const e = environment("ABSENT"),
      original = e.deps.send;
    e.deps.send = async (request) => {
      const response = await original(request);
      if (request.id !== position) return response;
      return new Response(
        JSON.stringify(
          {
            error: {
              code: 404,
              message: "Resource '" + e.own.jobs.c01 + "' was not found",
              status: "NOT_FOUND",
              details: [
                {
                  "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                  resourceName: e.own.jobs.c01,
                },
              ],
            },
          },
          null,
          2,
        ) + "\n",
        { status: 404 },
      );
    };
    const result = await collectCalendarRecovery(e.deps);
    assert.equal(result.closureReady, false, position);
    assert.ok(!e.sends.some(({ id }) => id === "delete-topic"));
  }
});

test("cross-scope initial absence and later ownership preserve settlement debt", async () => {
  for (const scope of ["topic-only", "jobs-and-topic"])
    for (const variant of ["exact", "compact", "unknown-then-owned", "unknown-then-absent"]) {
      const e = environment("ABSENT"),
        original = e.deps.send;
      e.deps.send = async (request) => {
        if (request.id === "read-topic-before" && variant.startsWith("unknown")) {
          e.sends.push(request);
          throw new Error("unknown CREATE readback");
        }
        if (request.id === "read-topic-before" || request.id.startsWith("read-topic-poll-")) {
          if (variant === "unknown-then-owned")
            return original({ ...request, id: "read-topic-before" });
          e.sends.push(request);
          const body = {
            error: {
              code: 404,
              message: "Resource not found (resource=" + e.own.prefix + ").",
              status: "NOT_FOUND",
            },
          };
          return new Response(
            variant === "compact" ? JSON.stringify(body) : JSON.stringify(body, null, 2) + "\n",
            { status: 404 },
          );
        }
        if (request.id === "read-topic-after" || request.id === "final-list-topics") {
          const body =
            request.id === "read-topic-after"
              ? {
                  error: {
                    code: 404,
                    message: "Resource not found (resource=" + e.own.prefix + ").",
                    status: "NOT_FOUND",
                  },
                }
              : {};
          e.sends.push(request);
          return new Response(JSON.stringify(body, null, 2) + "\n", {
            status: request.id === "read-topic-after" ? 404 : 200,
          });
        }
        return original(request);
      };
      const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: scope });
      assert.equal(
        result.closureReady,
        scope === "jobs-and-topic" && variant === "exact",
        `${scope}/${variant}`,
      );
      assert.equal(
        e.sends.some(({ id }) => id === "delete-topic"),
        scope === "topic-only" && variant === "unknown-then-owned",
        `${scope}/${variant}`,
      );
      assert.ok(result.attempted <= (scope === "topic-only" ? 9 : 64));
    }
});

test("topic-only polling accepts only recorded absence and ownership layouts", async () => {
  for (const position of ["read-topic-before", "read-topic-after"])
    for (const exact of [false, true]) {
      const e = environment("ABSENT"),
        original = e.deps.send;
      e.deps.send = async (request) => {
        if (position === "read-topic-before" && request.id === "read-topic-after") {
          e.sends.push(request);
          return new Response(
            JSON.stringify(
              {
                error: {
                  code: 404,
                  message: "Resource not found (resource=" + e.own.prefix + ").",
                  status: "NOT_FOUND",
                },
              },
              null,
              2,
            ) + "\n",
            { status: 404 },
          );
        }
        if (request.id !== position && !request.id.startsWith("read-topic-poll-"))
          return original(request);
        e.sends.push(request);
        const body =
          position === "read-topic-before"
            ? {
                error: {
                  code: 404,
                  message: "Resource not found (resource=" + e.own.prefix + ").",
                  status: "NOT_FOUND",
                },
              }
            : { name: e.own.topic };
        return new Response(exact ? JSON.stringify(body, null, 2) + "\n" : JSON.stringify(body), {
          status: position === "read-topic-before" ? 404 : 200,
        });
      };
      const result = await collectCalendarRecovery({ ...e.deps, recoveryScope: "topic-only" });
      assert.equal(result.closureReady, false);
      assert.deepEqual(e.waits, exact ? [10000, 10000, 10000] : [], `${position}/${exact}`);
      assert.equal(
        e.sends.filter(({ id }) => id === "delete-topic").length,
        position === "read-topic-after" ? 1 : 0,
      );
    }
});
