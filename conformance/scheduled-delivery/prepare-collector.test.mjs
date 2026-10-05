// The preparation collector against the fake: the clean run, what it asks for, and every way an
// answer can be unknown, refused or unexpected.
import assert from "node:assert/strict";
import test from "node:test";
import { MAX_REQUESTS, PROJECT, TARGET_SERVICES, collect } from "./prepare.mjs";
import { BASE_ENABLED, NUMBER, fakeServer, recorded, reply, run } from "./prepare-fake.mjs";

const key = (method, path) => method + " " + path;
const SERVICES = "v1/projects/<number>/services";
const ENABLE = key("POST", SERVICES + ":batchEnable");
const error = (code, message) => reply(code, { error: { code, message, status: "X" } });
const writes = (server) =>
  server.state.calls.filter((c) => c.startsWith("POST ") && c.endsWith(":batchEnable"));
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

test("a clean run enables the eight services once, reads before and after, and may close", async () => {
  const server = fakeServer();
  const { result, journal, sleeps } = await run(server);
  assert.equal(result.stage, "done");
  assert.deepEqual(result.requested, [...TARGET_SERVICES]);
  assert.deepEqual(result.alreadyEnabled, []);
  assert.deepEqual(result.missingAfter, []);
  assert.equal(writes(server).length, 1);
  assert.equal(result.closureReady, true);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(result.incompleteReads, []);
  assert.equal(result.cleanupVerified, false);
  assert.deepEqual(sleeps, [10000], "one pending poll waited ten seconds");
  assert.deepEqual(ids(journal), [
    "identity",
    "services-before",
    "iam-before",
    "admin-sdk-config",
    "appengine-app",
    "logging-read",
    "enable-apis",
    "enable-poll-1",
    "enable-poll-2",
    "services-after",
    "logging-read-after",
    "iam-after",
    "list-functions-v1",
    "list-functions-v2",
    "list-run-services",
    "list-artifact-repositories",
  ]);
  assert.ok(result.attempted <= MAX_REQUESTS);
  assert.deepEqual(result.adminSdkConfig, {
    status: 200,
    locationIdPresent: false,
    projectIdMatches: true,
  });
  assert.deepEqual(result.appEngine, { status: 404, exists: false });
  assert.equal(result.logging.canRead, true);
  assert.deepEqual(Object.keys(result.lists), [
    "functions-v1",
    "functions-v2",
    "run-services",
    "artifact-repositories",
  ]);
});

test("a journal row is written before each request and the issued services before the mutation", async () => {
  const { journal } = await run(fakeServer());
  const at = (id) => journal.findIndex((r) => r.id === id && r.state === "before-send");
  const issued = journal.findIndex((r) => r.state === "issued");
  assert.ok(issued >= 0 && issued < at("enable-apis"));
  assert.deepEqual(journal[issued].serviceIds, [...TARGET_SERVICES]);
  for (const r of journal.filter((r) => r.state === "before-send"))
    assert.ok(
      journal.some((x) => x.id === r.id && x.state === "response-persisted"),
      r.id,
    );
});

test("services that are already enabled are not asked for, and nothing is enabled when none is missing", async () => {
  const some = fakeServer({
    enabled: [...BASE_ENABLED, "run.googleapis.com", "storage.googleapis.com"],
  });
  const a = await run(some);
  assert.deepEqual(a.result.alreadyEnabled, ["run.googleapis.com", "storage.googleapis.com"]);
  assert.equal(a.result.requested.length, 6);
  assert.deepEqual(
    some.state.calls.filter((c) => c === ENABLE),
    [ENABLE],
  );
  const all = fakeServer({ enabled: [...BASE_ENABLED, ...TARGET_SERVICES] });
  const b = await run(all);
  assert.equal(b.result.requested.length, 0);
  assert.equal(writes(all).length, 0, "no mutation at all");
  assert.equal(b.result.batchEnable, null);
  assert.equal(b.result.closureReady, true);
  assert.ok(!ids(b.journal).includes("issue-enable"));
});

test("services listed over several pages are all counted", async () => {
  const server = fakeServer({ pageSize: 5 });
  const { result, journal } = await run(server);
  assert.ok(ids(journal).includes("services-before-page-2"));
  assert.ok(ids(journal).includes("services-after-page-2"));
  assert.deepEqual(result.missingAfter, []);
  assert.equal(result.closureReady, true);
});

test("a service list that never ends stops the run as incomplete", async () => {
  const server = fakeServer({
    hooks: {
      [key("GET", SERVICES)]: async () => reply(200, { services: [], nextPageToken: "more" }),
    },
  });
  const { result } = await run(server);
  assert.equal(result.stage, "preflight");
  assert.equal(result.closureReady, false);
  assert.deepEqual(result.incompleteReads, [
    { id: "services-before", class: "more-than-five-pages" },
  ]);
  assert.equal(writes(server).length, 0);
});

// ---- preflight --------------------------------------------------------------------------------

test("a wrong identity or a service list that cannot be read stops before any write", async () => {
  const wrong = fakeServer({
    hooks: {
      "GET v1/projects/fireemu-oracle-sbx/releases/cloud.firestore": async () =>
        reply(200, { name: "projects/other/releases/cloud.firestore" }),
    },
  });
  const a = await run(wrong);
  assert.equal(a.result.stage, "preflight");
  assert.equal(writes(wrong).length, 0);
  assert.equal(a.result.closureReady, false);
  const unreadable = fakeServer({
    hooks: { [key("GET", SERVICES)]: async () => error(500, "later") },
  });
  const b = await run(unreadable);
  assert.equal(b.result.stage, "preflight");
  assert.equal(writes(unreadable).length, 0);
  assert.equal(b.result.incompleteReads[0].id, "services-before");
});

// ---- a mutation answer that is unknown ----------------------------------------------------------

for (const [label, hook] of [
  [
    "503",
    async ({ state, body }) => {
      state.pending = body.serviceIds;
      return error(503, "later");
    },
  ],
  ["302", async () => new Response(null, { status: 302 })],
  ["a lost answer", async () => "throw"],
]) {
  test(
    "a batchEnable answered with " + label + " is never re-sent and never closes the run",
    async () => {
      const server = fakeServer({ hooks: { [ENABLE]: hook } });
      const { result } = await run(server);
      assert.equal(writes(server).length, 1, "sent once");
      assert.equal(result.unknownMutations, 1);
      assert.equal(result.readBackRequired, true);
      assert.equal(result.closureReady, false);
      assert.equal(result.stage, "done", "the services are still read after it");
    },
  );
}

test("a batchEnable that took effect before an unknown answer is seen by the read after", async () => {
  const server = fakeServer({
    hooks: {
      [ENABLE]: async ({ state, body }) => {
        for (const id of body.serviceIds) state.enabled.add(id);
        return error(503, "later");
      },
    },
  });
  const { result } = await run(server);
  assert.deepEqual(result.missingAfter, [], "the read after shows them enabled");
  assert.equal(
    result.closureReady,
    false,
    "but the unknown answer still needs the later read-back",
  );
});

test("a pending operation that never finishes, and one that failed, do not close the run", async () => {
  const never = fakeServer({ pendingPolls: 99 });
  const a = await run(never);
  assert.equal(a.result.batchEnable.done, false);
  assert.equal(a.result.missingAfter.length, 8);
  assert.equal(a.result.closureReady, false);
  assert.equal(
    never.state.calls.filter((c) => c.includes("v1/operations/")).length,
    18,
    "polled eighteen times",
  );
  const failed = fakeServer({
    hooks: {
      "GET v1/operations/acf.p2-<number>-e627f9a7-0f50-48e6-856c-93ad311e8f0e": async () =>
        reply(200, {
          name: "operations/acf.p2-" + NUMBER + "-e627f9a7-0f50-48e6-856c-93ad311e8f0e",
          done: true,
          error: { code: 13, message: "internal" },
        }),
    },
  });
  const b = await run(failed);
  assert.deepEqual(b.result.batchEnable.failed, { code: 13, message: "internal" });
  assert.equal(b.result.closureReady, false);
});

// ---- a refused credential and the observations that may be 403 -----------------------------------

test("a 401 or a 403 on a write or an ordinary read stops the run and is not recorded as data", async () => {
  for (const [hookKey, status] of [
    [ENABLE, 403],
    [ENABLE, 401],
    [key("POST", "v1/projects/" + PROJECT + ":getIamPolicy"), 403],
    [key("GET", SERVICES), 401],
  ]) {
    const server = fakeServer({ hooks: { [hookKey]: async () => error(status, "denied") } });
    const { result } = await run(server);
    assert.equal(result.outcome, "scheduled-delivery-prepare-auth-stop", hookKey);
    assert.equal(result.stage, "auth-stop");
    assert.equal(result.authStop.status, status);
    assert.equal(result.closureReady, false);
    assert.equal(result.readBackRequired, true);
    if (hookKey === ENABLE) assert.equal(writes(server).length, 1);
  }
});

test("a 403 on an observation (admin SDK config, App Engine, Logging, the new lists) is the answer", async () => {
  const denied = (k) => [key("GET", k), async () => error(403, "denied")];
  const server = fakeServer({
    hooks: Object.fromEntries([
      denied("v1beta1/projects/" + PROJECT + "/adminSdkConfig"),
      denied("v1/apps/" + PROJECT),
      [key("POST", "v2/entries:list"), async () => error(403, "denied")],
      denied("v1/projects/" + PROJECT + "/locations/us-central1/functions"),
      denied("v2/projects/" + PROJECT + "/locations/us-central1/functions"),
      denied("v2/projects/" + PROJECT + "/locations/us-central1/services"),
      denied("v1/projects/" + PROJECT + "/locations/us-central1/repositories"),
    ]),
  });
  const { result } = await run(server);
  assert.equal(result.outcome, "scheduled-delivery-prepare-needs-review");
  assert.equal(result.stage, "done");
  assert.deepEqual(result.adminSdkConfig, { status: 403 });
  assert.deepEqual(result.appEngine, { status: 403, exists: false });
  assert.deepEqual(result.logging, { status: 403, canRead: false });
  assert.deepEqual(result.lists["functions-v1"], { status: 403, empty: false });
  assert.deepEqual(result.incompleteReads, [], "an observation that answers 403 is complete");
});

test("an observation that gets no answer leaves the run open", async () => {
  const server = fakeServer({
    hooks: { [key("POST", "v2/entries:list")]: async () => "throw" },
  });
  const { result } = await run(server);
  assert.deepEqual(result.incompleteReads, [
    { id: "logging-read", class: "transport" },
    { id: "logging-read-after", class: "transport" },
  ]);
  assert.equal(result.closureReady, false);
});

test("a read that is an error where an answer was expected leaves the run open", async () => {
  const server = fakeServer({
    hooks: {
      [key("POST", "v1/projects/" + PROJECT + ":getIamPolicy")]: async () => error(404, "x"),
    },
  });
  const { result } = await run(server);
  assert.ok(result.incompleteReads.some((r) => r.id === "iam-before" && r.class === "4xx"));
  assert.equal(result.closureReady, false);
});

// ---- what the enabling did to the project ---------------------------------------------------------

test("an IAM binding for a principal that is not a Google-managed service account is not closed", async () => {
  const server = fakeServer({
    hooks: {
      [ENABLE]: async ({ state, body }) => {
        state.pending = body.serviceIds;
        state.policy.bindings.push({
          role: "roles/editor",
          members: ["user:intruder@example.com"],
        });
        return undefined;
      },
    },
  });
  const { result } = await run(server);
  assert.deepEqual(result.iam.unexpected, ["roles/editor|user:intruder@example.com"]);
  assert.equal(result.closureReady, false);
});

test("a removed IAM member is not closed", async () => {
  const server = fakeServer({
    hooks: {
      [ENABLE]: async ({ state, body }) => {
        state.pending = body.serviceIds;
        state.policy.bindings[0].members = [];
        return undefined;
      },
    },
  });
  const { result } = await run(server);
  assert.equal(result.iam.removed.length, 1);
  assert.equal(result.closureReady, false);
});

test("a service that is still disabled after the operation is named and not closed", async () => {
  const server = fakeServer({
    hooks: {
      [key("GET", SERVICES)]: async ({ state, entry }) => {
        // Hide one service from the list after the enable.
        if (state.polls === 0) return undefined;
        const listed = [...state.enabled].filter((id) => id !== "run.googleapis.com").toSorted();
        return reply(200, { services: listed.map(entry) });
      },
    },
  });
  const { result } = await run(server);
  assert.deepEqual(result.missingAfter, ["run.googleapis.com"]);
  assert.equal(result.closureReady, false);
});

test("an API that was enabled as a dependency is reported, not requested", async () => {
  const server = fakeServer({
    hooks: {
      "GET v1/operations/acf.p2-<number>-e627f9a7-0f50-48e6-856c-93ad311e8f0e": async ({
        state,
      }) => {
        if (state.polls < 1) return undefined;
        state.enabled.add("containerregistry.googleapis.com");
        return undefined;
      },
    },
  });
  const { result } = await run(server);
  assert.deepEqual(result.dependentApis, ["containerregistry.googleapis.com"]);
  assert.equal(result.closureReady, true);
});

test("the admin SDK config's location id is read before anything is enabled", async () => {
  const server = fakeServer();
  server.state.adminSdkConfig.locationId = "us-central";
  const { result, journal } = await run(server);
  assert.deepEqual(result.adminSdkConfig, {
    status: 200,
    locationIdPresent: true,
    locationId: "us-central",
    projectIdMatches: true,
  });
  const order = ids(journal);
  assert.ok(order.indexOf("admin-sdk-config") < order.indexOf("enable-apis"));
});

test("the request budget stops the run instead of exceeding the cap", async () => {
  await assert.rejects(() => run(fakeServer(), { budget: 5 }), /request cap exceeded/);
  await assert.rejects(
    () => run(fakeServer(), { budget: MAX_REQUESTS + 1 }),
    /invalid request cap/,
  );
  await assert.rejects(() => run(fakeServer(), { projectNumber: "12" }), /invalid project number/);
  await assert.rejects(
    () => collect({ projectNumber: NUMBER, accessToken: "x\ny", save() {}, send() {} }),
    /coordinator token required/,
  );
});

test("the recorded services list is the shape the fake answers with", () => {
  assert.equal(recorded.servicesEnabledList.body.services[0].state, "ENABLED");
});

test("the project number may have thirteen digits and not fourteen", async () => {
  // Accepted as an argument: whatever else happens with the fake, it is not this refusal.
  await run(fakeServer(), { projectNumber: "1234567890123" }).catch((error) =>
    assert.doesNotMatch(String(error.message), /invalid project number/),
  );
  await assert.rejects(
    () => run(fakeServer(), { projectNumber: "12345678901234" }),
    /invalid project number/,
  );
  await assert.rejects(
    () => run(fakeServer(), { projectNumber: "12345678901" }),
    /invalid project number/,
  );
});

test("the timeouts are sixty seconds for the enable, thirty for a service list and ten for the rest", async () => {
  const { journal } = await run(fakeServer());
  for (const row of journal.filter((r) => r.state === "before-send")) {
    const expected =
      row.id === "enable-apis" ? 60000 : row.id.startsWith("services-") ? 30000 : 10000;
    assert.equal(row.timeoutMs, expected, row.id);
  }
});

test("a service list of exactly five pages is read and one of six is incomplete", async () => {
  const targets = [...TARGET_SERVICES];
  const five = fakeServer({ enabled: [...targets, ...BASE_ENABLED.slice(0, 7)], pageSize: 3 }); // 15 services
  const a = await run(five);
  assert.deepEqual(a.result.incompleteReads, []);
  assert.equal(a.result.stage, "done");
  assert.ok(ids(a.journal).includes("services-before-page-5"));
  const six = fakeServer({ enabled: [...targets, ...BASE_ENABLED.slice(0, 8)], pageSize: 3 }); // 16 services
  const b = await run(six);
  assert.deepEqual(b.result.incompleteReads, [
    { id: "services-before", class: "more-than-five-pages" },
  ]);
  assert.equal(b.result.stage, "preflight");
});

test("one missing service is enough to enable, and none is not", async () => {
  const one = fakeServer({ enabled: [...BASE_ENABLED, ...TARGET_SERVICES.slice(1)] });
  const a = await run(one);
  assert.deepEqual(a.result.requested, [TARGET_SERVICES[0]]);
  assert.equal(writes(one).length, 1);
  assert.equal(a.result.closureReady, true);
});

test("an operation that failed is polled once, and one that is done at once is not polled", async () => {
  const failed = fakeServer({
    pendingPolls: 0,
    hooks: {
      "GET v1/operations/acf.p2-<number>-e627f9a7-0f50-48e6-856c-93ad311e8f0e": async () =>
        reply(200, {
          name: "operations/acf.p2-" + NUMBER + "-e627f9a7-0f50-48e6-856c-93ad311e8f0e",
          done: true,
          error: { code: 13 },
        }),
    },
  });
  const a = await run(failed);
  assert.equal(failed.state.calls.filter((c) => c.includes("v1/operations/")).length, 1);
  assert.equal(a.result.batchEnable.done, true);
  const immediate = fakeServer({
    hooks: {
      [ENABLE]: async ({ state, body }) => {
        for (const id of body.serviceIds) state.enabled.add(id);
        return reply(200, {
          name: "operations/acf.p2-" + NUMBER + "-e627f9a7-0f50-48e6-856c-93ad311e8f0e",
          done: true,
          response: {},
        });
      },
    },
  });
  const b = await run(immediate);
  assert.equal(immediate.state.calls.filter((c) => c.includes("v1/operations/")).length, 0);
  assert.equal(b.result.batchEnable.done, true);
  assert.equal(b.result.closureReady, true);
});

test("a 400 on an ordinary read is incomplete, and the empty-list judgement needs a 200 with no keys", async () => {
  const bad = fakeServer({
    hooks: {
      [key("POST", "v1/projects/" + PROJECT + ":getIamPolicy")]: async () => error(400, "bad"),
    },
  });
  const a = await run(bad);
  assert.ok(a.result.incompleteReads.some((r) => r.id === "iam-before" && r.class === "4xx"));
  const lists = [
    [
      "GET v1/projects/" + PROJECT + "/locations/us-central1/functions",
      reply(200, { functions: [{ name: "f" }] }),
      "functions-v1",
      false,
    ],
    [
      "GET v2/projects/" + PROJECT + "/locations/us-central1/functions",
      error(404, "x"),
      "functions-v2",
      false,
    ],
    [
      "GET v2/projects/" + PROJECT + "/locations/us-central1/services",
      new Response("not json", { status: 200 }),
      "run-services",
      false,
    ],
    [
      "GET v1/projects/" + PROJECT + "/locations/us-central1/repositories",
      new Response("{}\n", { status: 201 }),
      "artifact-repositories",
      false,
    ],
  ];
  const server = fakeServer({
    hooks: Object.fromEntries(lists.map(([k, response]) => [k, async () => response.clone()])),
  });
  const { result } = await run(server);
  for (const [, , id, empty] of lists) assert.equal(result.lists[id].empty, empty, id);
  const clean = await run(fakeServer());
  for (const id of Object.keys(clean.result.lists))
    assert.equal(clean.result.lists[id].empty, true, id);
});

test("an operation that never reports done does not close the run even when the services read ENABLED", async () => {
  const enableNow = async ({ state, body }) => {
    for (const id of body.serviceIds) state.enabled.add(id);
    return undefined;
  };
  const never = fakeServer({
    pendingPolls: 99,
    hooks: {
      [ENABLE]: enableNow,
      "GET v1/operations/acf.p2-<number>-e627f9a7-0f50-48e6-856c-93ad311e8f0e": async () =>
        reply(200, {
          name: "operations/acf.p2-" + NUMBER + "-e627f9a7-0f50-48e6-856c-93ad311e8f0e",
        }),
    },
  });
  const a = await run(never);
  assert.deepEqual(a.result.missingAfter, [], "every service reads ENABLED");
  assert.equal(a.result.batchEnable.done, false);
  assert.equal(a.result.closureReady, false);
  assert.equal(a.result.unknownMutations, 0, "the answer was known; the operation is what is open");
});

test("a 2xx batchEnable that is not an operation does not close the run", async () => {
  const server = fakeServer({
    hooks: {
      [ENABLE]: async ({ state, body }) => {
        for (const id of body.serviceIds) state.enabled.add(id);
        return reply(200, { unrelated: true });
      },
    },
  });
  const { result } = await run(server);
  assert.deepEqual(result.missingAfter, []);
  assert.equal(result.batchEnable.done, undefined);
  assert.equal(result.closureReady, false);
});

test("Logging is read again after the enable, and what the services list says is reported", async () => {
  const server = fakeServer();
  const { result, journal } = await run(server);
  const order = ids(journal);
  assert.ok(order.indexOf("logging-read") < order.indexOf("enable-apis"));
  assert.ok(order.indexOf("enable-apis") < order.indexOf("logging-read-after"));
  assert.deepEqual(result.loggingAfter, { status: 200, canRead: true, entries: 0 });
  assert.equal(result.loggingEnabledAfter, false, "the fake's services list does not name logging");
  const enabled = fakeServer({ enabled: [...BASE_ENABLED, "logging.googleapis.com"] });
  assert.equal((await run(enabled)).result.loggingEnabledAfter, true);
  const denied = fakeServer({
    hooks: { [key("POST", "v2/entries:list")]: async () => error(403, "denied") },
  });
  const d = await run(denied);
  assert.deepEqual(d.result.loggingAfter, { status: 403, canRead: false });
  assert.deepEqual(d.result.incompleteReads, [], "a 403 on the observation is the answer");
});

test("an enabled service whose list cannot be read leaves loggingEnabledAfter unknown", async () => {
  const server = fakeServer({
    hooks: {
      [key("GET", SERVICES)]: async ({ state }) =>
        state.polls === 0 ? undefined : error(500, "later"),
    },
  });
  const { result } = await run(server);
  assert.equal(result.loggingEnabledAfter, null);
  assert.equal(result.closureReady, false);
});
