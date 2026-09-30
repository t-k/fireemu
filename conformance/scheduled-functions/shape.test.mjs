import assert from "node:assert/strict";
import { test } from "node:test";
import { collectShape, ownedResources, shapeRequests } from "./shape.mjs";

const runId = "a1".repeat(8);
const projectNumber = "123456789012";
const instant = Date.parse("2026-09-30T09:00:00Z");
const options = { runId, projectNumber, now: instant };

function environment(failAt) {
  const rows = [],
    sends = [],
    waits = [];
  let time = instant;
  return {
    rows,
    sends,
    waits,
    deps: {
      ...options,
      accessToken: "offline-test-bearer",
      clock: () => time++,
      sleep: async (ms) => waits.push(ms),
      save: async (row) => rows.push(row),
      send: async (request) => {
        sends.push(request);
        if (request.id === failAt) throw new Error("offline-test-bearer transport failure");
        const body =
          request.id === "identity"
            ? {
                name: "projects/fireemu-oracle-sbx/releases/cloud.firestore",
                rulesetName: "projects/fireemu-oracle-sbx/rulesets/offline",
              }
            : request.id === "enable-apis"
              ? { name: "operations/offline", done: true }
              : request.id.startsWith("service-")
                ? { state: "ENABLED" }
                : {};
        const status = /^before-(job|topic|subscription)$/.test(request.id) ? 404 : 200;
        return new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        });
      },
    },
  };
}

test("shape routes are fixed, scoped and never initialize App Engine or invoke functions", () => {
  const resources = ownedResources(runId);
  const requests = shapeRequests(options);
  assert.equal(requests.length, 31);
  assert.ok(Object.values(resources).every((name) => name.includes(runId)));
  assert.equal(requests.find(({ id }) => id === "create-job").json.state, undefined);
  assert.equal(requests.find(({ id }) => id === "create-job").json.schedule, "0 0 1 4 *");
  assert.ok(
    requests.every(
      ({ url, method }) =>
        !url.includes(":run") &&
        !url.includes(":publish") &&
        !(url.includes("appengine") && method !== "GET"),
    ),
  );
  assert.equal(requests[requests.findIndex(({ id }) => id === "create-job") + 1].id, "pause-job");
  assert.throws(() => ownedResources("../../foreign"), /run ID/);
  assert.throws(
    () => shapeRequests({ ...options, now: Date.parse("2027-03-31T23:59:00Z") }),
    /expired/,
  );
});

test("captures dispatch and response separately, saves no bearer, and awaits private persistence", async () => {
  const { deps, rows, sends } = environment();
  const result = await collectShape(deps);
  assert.equal(result.attempted, 31);
  assert.equal(result.completed, 31);
  assert.equal(result.outcome, "shape-needs-review");
  for (const request of sends) {
    const before = rows.find(({ id, state }) => id === request.id && state === "before-send");
    const after = rows.find(({ id, state }) => id === request.id && state === "response-persisted");
    assert.ok(before.dispatchAt < after.responseAt);
    assert.equal(request.redirect, "manual");
    assert.equal(request.headers["x-goog-user-project"], "fireemu-oracle-sbx");
  }
  assert.ok(!JSON.stringify(rows).includes("offline-test-bearer"));
});

test("an ambiguous job create still pauses and deletes the exact owned resources", async () => {
  const { deps, rows, sends } = environment("create-job");
  const result = await collectShape(deps);
  assert.equal(result.unknown, 1);
  assert.equal(result.outcome, "shape-needs-review");
  const ids = new Set(sends.map(({ id }) => id));
  assert.ok(ids.has("pause-job"));
  assert.ok(ids.has("delete-job"));
  assert.ok(ids.has("delete-subscription"));
  assert.ok(ids.has("delete-topic"));
  assert.ok(rows.some(({ id, state }) => id === "create-job" && state === "transport-unknown"));
  assert.ok(!JSON.stringify(rows).includes("offline-test-bearer"));
});

test("pre-existing or unreadable owned name stops before mutation and deletion", async () => {
  const { deps, sends } = environment();
  const original = deps.send;
  deps.send = async (request) => {
    if (request.id !== "before-topic") return original(request);
    sends.push(request);
    return new Response(JSON.stringify({ name: ownedResources(runId).topic }), { status: 200 });
  };
  const result = await collectShape(deps);
  assert.equal(result.outcome, "shape-needs-review");
  assert.ok(!sends.some(({ id }) => id.startsWith("create-") || id.startsWith("delete-")));
});

test("wrong project identity and persistence failure send no dependent request", async () => {
  const { deps, sends } = environment();
  deps.send = async (request) => {
    sends.push(request);
    return new Response(
      JSON.stringify({ projectId: "foreign", name: `projects/${projectNumber}` }),
      { status: 200 },
    );
  };
  await collectShape(deps);
  assert.equal(sends.length, 1);
  const failed = environment();
  failed.deps.save = async () => {
    throw new Error("private disk unavailable");
  };
  await assert.rejects(collectShape(failed.deps), /persistence/);
  assert.equal(failed.sends.length, 0);
});

test("invalid configuration needs no token, and redirects never reach another host", async () => {
  const { deps, sends } = environment();
  await assert.rejects(
    collectShape({ ...deps, runId: "invalid", accessToken: undefined }),
    /run ID/,
  );
  assert.equal(sends.length, 0);
  deps.send = async (request) => {
    sends.push(request);
    return new Response("", { status: 302 });
  };
  await collectShape(deps);
  assert.equal(sends.length, 1);
});

for (const kind of ["topic", "subscription", "job"]) {
  test(`a ${kind} create conflict is never paused or deleted`, async () => {
    const { deps, sends } = environment();
    const original = deps.send;
    deps.send = async (request) => {
      if (request.id !== `create-${kind}`) return original(request);
      sends.push(request);
      return new Response(JSON.stringify({ error: { status: "ALREADY_EXISTS" } }), { status: 409 });
    };
    const summary = await collectShape(deps);
    assert.equal(summary.outcome, "shape-needs-review");
    const ids = new Set(sends.map(({ id }) => id));
    assert.ok(!ids.has(`delete-${kind}`));
    if (kind === "job") assert.ok(!ids.has("pause-job"));
    if (kind !== "topic") assert.ok(ids.has("delete-topic"));
    if (kind === "job") assert.ok(ids.has("delete-subscription"));
  });
}

for (const kind of ["topic", "subscription", "job"]) {
  for (const bodyFailure of ["stream-error", "byte-bound"]) {
    test(`${kind} conflict survives ${bodyFailure} without pause or delete`, async () => {
      const { deps, sends } = environment();
      const original = deps.send;
      deps.send = async (request) => {
        if (request.id !== `create-${kind}`) return original(request);
        sends.push(request);
        const body =
          bodyFailure === "stream-error"
            ? new ReadableStream({
                start(controller) {
                  controller.error(new Error("broken body"));
                },
              })
            : new Uint8Array(1024 * 1024 + 1);
        return new Response(body, { status: 409 });
      };
      const summary = await collectShape(deps);
      assert.equal(summary.unknown, 1);
      const ids = new Set(sends.map(({ id }) => id));
      assert.ok(!ids.has(`delete-${kind}`));
      if (kind === "job") assert.ok(!ids.has("pause-job"));
      if (kind !== "topic") assert.ok(ids.has("delete-topic"));
    });
  }
}

test("a successful create with an incomplete body retains conservative cleanup", async () => {
  const { deps, sends } = environment();
  const original = deps.send;
  deps.send = async (request) => {
    if (request.id !== "create-topic") return original(request);
    sends.push(request);
    return new Response(
      new ReadableStream({
        start(controller) {
          controller.error(new Error("broken body"));
        },
      }),
      { status: 200 },
    );
  };
  const summary = await collectShape(deps);
  assert.equal(summary.unknown, 1);
  assert.ok(sends.some(({ id }) => id === "delete-topic"));
  assert.ok(!sends.some(({ id }) => id === "create-subscription"));
});

test("Scheduler job lists stay within the documented500 maximum independently of Pub/Sub", () => {
  const requests = shapeRequests(options);
  for (const phase of ["before", "final"]) {
    assert.equal(
      new URL(requests.find(({ id }) => id === `${phase}-list-jobs`).url).searchParams.get(
        "pageSize",
      ),
      "500",
    );
    assert.equal(
      new URL(requests.find(({ id }) => id === `${phase}-list-topics`).url).searchParams.get(
        "pageSize",
      ),
      "1000",
    );
  }
});

test("App Engine absence is captured without skipping the native job shape", async () => {
  const { deps, sends, rows } = environment();
  const original = deps.send;
  deps.send = async (request) => {
    if (request.id !== "appengine-location") return original(request);
    sends.push(request);
    return new Response(JSON.stringify({ error: { code: 404, status: "NOT_FOUND" } }), {
      status: 404,
    });
  };
  const summary = await collectShape(deps);
  assert.equal(summary.attempted, 31);
  assert.ok(sends.some(({ id }) => id === "create-job"));
  assert.ok(
    rows.some(
      ({ id, status, state }) =>
        id === "appengine-location" && status === 404 && state === "response-persisted",
    ),
  );
});

for (const [id, status, body, expected] of [
  ["identity", 403, { error: { status: "PERMISSION_DENIED", reason: "SERVICE_DISABLED" } }, 1],
  ["before-job", 403, { error: { status: "PERMISSION_DENIED", reason: "SERVICE_DISABLED" } }, 10],
  ["service-after-pubsub.googleapis.com", 200, { state: "DISABLED" }, 7],
  ["before-topic", 200, { name: ownedResources(runId).topic }, 11],
]) {
  test(`${id} stop judge blocks all resource mutations`, async () => {
    const { deps, sends } = environment();
    const original = deps.send;
    deps.send = async (request) => {
      if (request.id !== id) return original(request);
      sends.push(request);
      return new Response(JSON.stringify(body), { status });
    };
    const summary = await collectShape(deps);
    assert.equal(summary.attempted, expected);
    assert.ok(
      !sends.some(
        ({ id: requestId }) => requestId.startsWith("create-") || requestId.startsWith("delete-"),
      ),
    );
  });
}

for (const outcome of ["done", "pending", "error", "malformed"]) {
  test(`enable operation ${outcome} uses bounded polling before product reads`, async () => {
    const { deps, sends, waits } = environment();
    const original = deps.send;
    deps.send = async (request) => {
      if (request.id !== "enable-apis" && !request.id.startsWith("enable-poll-"))
        return original(request);
      sends.push(request);
      const done = request.id === "enable-poll-2";
      const body =
        outcome === "malformed"
          ? { name: "../foreign" }
          : {
              name: "operations/offline",
              done: (outcome === "done" && done) || outcome === "error",
              ...(outcome === "error" ? { error: { code: 7 } } : {}),
            };
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const summary = await collectShape(deps);
    const polls = sends.filter(({ id }) => id.startsWith("enable-poll-"));
    if (outcome === "done") {
      assert.equal(polls.length, 2);
      assert.deepEqual(waits, [8000, 8000, 90000]);
      assert.equal(summary.attempted, 33);
      assert.ok(sends.some(({ id }) => id === "create-job"));
    } else {
      assert.equal(polls.length, outcome === "pending" ? 15 : 0);
      assert.deepEqual(waits, Array(outcome === "pending" ? 15 : 0).fill(8000));
      assert.ok(!sends.some(({ url }) => /\/(jobs|topics|subscriptions)/.test(url)));
    }
  });
}

test("successful service readbacks settle before the first product request", async () => {
  const { deps, waits } = environment();
  await collectShape(deps);
  assert.deepEqual(waits, [90000]);
});

test("identity reads the recorded Rules release route and requires its scoped source", async () => {
  assert.equal(
    shapeRequests(options)[0].url,
    "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-sbx/releases/cloud.firestore",
  );
  for (const body of [
    { name: "projects/fireemu-oracle-sbx/releases/cloud.firestore" },
    {
      name: "projects/fireemu-oracle-sbx/releases/cloud.firestore",
      rulesetName: "projects/foreign/rulesets/source",
    },
    {
      name: "projects/fireemu-oracle-sbx/releases/cloud.firestore",
      rulesetName: "projects/fireemu-oracle-sbx/rulesets/../foreign",
    },
  ]) {
    const { deps, sends } = environment();
    deps.send = async (request) => {
      sends.push(request);
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const summary = await collectShape(deps);
    assert.equal(summary.attempted, 1);
  }
});

test("the recorded identity predicate requires HTTP 200 exactly", async () => {
  const { deps, sends } = environment();
  deps.send = async (request) => {
    sends.push(request);
    return new Response(
      JSON.stringify({
        name: "projects/fireemu-oracle-sbx/releases/cloud.firestore",
        rulesetName: "projects/fireemu-oracle-sbx/rulesets/offline",
      }),
      { status: 201 },
    );
  };
  await collectShape(deps);
  assert.equal(sends.length, 1);
});

test("a reflected bearer stops before persistence and dependent mutation", async () => {
  const { deps, rows, sends } = environment();
  deps.send = async (request) => {
    sends.push(request);
    return new Response(JSON.stringify({ token: deps.accessToken }), { status: 200 });
  };
  await assert.rejects(collectShape(deps), /reflected/);
  assert.equal(sends.length, 1);
  assert.ok(!JSON.stringify(rows).includes(deps.accessToken));
  assert.ok(!rows.some(({ state }) => state === "response-persisted"));
});

test("a refused enable poll stops before all product reads", async () => {
  const { deps, sends, waits } = environment();
  const original = deps.send;
  deps.send = async (request) => {
    if (request.id === "enable-apis") {
      sends.push(request);
      return new Response(JSON.stringify({ name: "operations/offline" }), { status: 200 });
    }
    if (request.id.startsWith("enable-poll-")) {
      sends.push(request);
      return new Response(JSON.stringify({ error: { code: 403 } }), { status: 403 });
    }
    return original(request);
  };
  await collectShape(deps);
  assert.deepEqual(waits, [8000]);
  assert.ok(!sends.some(({ id }) => id.startsWith("before-")));
});
