// The recorder's judges replayed on real recorded bodies: the lists readiness reads, the two 404 layouts of a
// Scheduler job, the Pub/Sub 404s, and the job bodies.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { allActive, nonePresent, summarize } from "./deploy.mjs";
import { ALL_FUNCTIONS, functionName, runServiceId } from "./plan.mjs";
import { absent, iamChanges, isBusy, jobSummary } from "./run.mjs";

const recorded = JSON.parse(
  readFileSync(new URL("../fixtures/delivery-recorded.json", import.meta.url), "utf8"),
).answers;
const answer = (r) => ({ status: r.status, json: r.body });

test("the recorded fixture is the real bodies, without a project number", () => {
  assert.equal(recorded.gcfV1List.recordedBytes, 25092);
  assert.equal(recorded.gcfV2List.recordedBytes, 73683);
  assert.equal(recorded.runServicesList.recordedBytes, 75540);
  assert.equal(recorded.schedulerAbsentPlain.recordedBytes, 97);
  assert.equal(recorded.schedulerAbsentDetailed.recordedBytes, 433);
  assert.ok(!/\b\d{12,13}\b/.test(JSON.stringify(recorded).replaceAll("123456789012", "")));
});

test("readiness reads the real lists of another project's functions: none of the five is among them", () => {
  const out = summarize({
    v1: recorded.gcfV1List.body,
    v2: recorded.gcfV2List.body,
    run: recorded.runServicesList.body,
  });
  assert.equal(nonePresent(out), true);
  assert.equal(allActive(out), false);
  assert.ok(
    recorded.gcfV1List.body.functions.length > 5 && recorded.gcfV2List.body.functions.length > 5,
  );
  const v2 = recorded.gcfV2List.body.functions;
  assert.ok(
    v2.some((f) => f.environment === "GEN_1"),
    "the v2 list also returns Gen1 functions, as the plan says",
  );
  assert.ok(
    v2.every((f) => /\/functions\/[A-Za-z0-9]+$/.test(f.name)),
    "names keep their case",
  );
  assert.ok(
    recorded.runServicesList.body.services.every(
      (s) =>
        s.name === s.name.toLowerCase().replace(/functions/g, "functions") ||
        /\/services\/[a-z0-9-]+$/.test(s.name),
    ),
  );
});

test("a real v2 function name and its lower-case Cloud Run service: only the cased name is a function", () => {
  const real = recorded.gcfV2List.body.functions.find(
    (f) => f.environment === "GEN_2" && /[A-Z]/.test(f.name.split("/").at(-1)),
  );
  assert.ok(real, "a real v2 function with a cased name");
  const short = real.name.split("/").at(-1);
  const service = recorded.runServicesList.body.services.find((s) =>
    s.name.endsWith("/" + short.toLowerCase()),
  );
  assert.ok(service, "its Run service is the lower-case id");
  assert.ok(
    !recorded.runServicesList.body.services.some((s) => s.name.endsWith("/" + short)),
    "never the cased id",
  );
  assert.equal(runServiceId("declNullV2"), "declnullv2");
  assert.equal(functionName("declNullV2").endsWith("/declNullV2"), true);
  assert.equal(ALL_FUNCTIONS.length, 6);
});

test("an absence is a direct read of 404 NOT_FOUND, in either recorded Scheduler layout and the Pub/Sub one", () => {
  for (const key of [
    "schedulerAbsentPlain",
    "schedulerAbsentDetailed",
    "topicAbsent",
    "subscriptionAbsent",
  ])
    assert.equal(absent(answer(recorded[key])), true, key);
  for (const key of [
    "emptyList",
    "schedulerJobCreated",
    "schedulerJobPaused",
    "schedulerJobDeleted",
    "subscriptionCreated",
  ])
    assert.equal(absent(answer(recorded[key])), false, key);
  assert.equal(absent({ status: 200, json: recorded.schedulerAbsentPlain.body }), false);
  assert.equal(absent({ status: 404, json: { error: { status: "OTHER" } } }), false);
  assert.equal(absent({ status: 404, json: null }), false);
  assert.equal(absent(null), false);
  assert.equal(absent({ status: 404, bodyUnknown: true, json: null }), false);
});

test("a real job body is summarized by its state, schedule, target and retry rule", () => {
  const created = jobSummary(recorded.schedulerJobCreated.body);
  assert.equal(created.state, "ENABLED");
  assert.equal(created.target, "pubsub");
  assert.match(created.name, /\/jobs\/fe-scheduled-calendar-/);
  assert.equal(jobSummary(recorded.schedulerJobPaused.body).state, "PAUSED");
  assert.deepEqual(
    jobSummary({
      httpTarget: { uri: "x" },
      retryConfig: { retryCount: 1 },
      attemptDeadline: "180s",
    }),
    {
      state: null,
      schedule: null,
      timeZone: null,
      retryConfig: { retryCount: 1 },
      attemptDeadline: "180s",
      target: "http",
      name: null,
    },
  );
  assert.equal(jobSummary({}).target, null);
});

test("the recorded 409 is not among the real answers the recorder reads, and a real DELETE answer is 3 bytes", () => {
  assert.equal(recorded.schedulerJobDeleted.recordedBytes, 3);
  assert.deepEqual(recorded.schedulerJobDeleted.body, {});
  assert.equal(isBusy(answer(recorded.schedulerAbsentPlain)), false);
});

test("IAM changes are the members added and removed between two policy reads", () => {
  const policy = (bindings) => ({ status: 200, json: { bindings } });
  const a = policy([
    { role: "roles/editor", members: ["serviceAccount:1-compute@developer.gserviceaccount.com"] },
  ]);
  const b = policy([
    {
      role: "roles/editor",
      members: [
        "serviceAccount:1-compute@developer.gserviceaccount.com",
        "serviceAccount:2@x.iam.gserviceaccount.com",
      ],
    },
    {
      role: "roles/test.addedByTheTest",
      members: ["serviceAccount:1-compute@developer.gserviceaccount.com"],
    },
  ]);
  assert.deepEqual(iamChanges(a, b), {
    added: [
      "roles/editor|serviceAccount:2@x.iam.gserviceaccount.com",
      "roles/test.addedByTheTest|serviceAccount:1-compute@developer.gserviceaccount.com",
    ],
    removed: [],
  });
  assert.deepEqual(iamChanges(b, a).added, []);
  assert.equal(iamChanges(b, a).removed.length, 2);
  assert.deepEqual(iamChanges(a, a), { added: [], removed: [] });
  assert.equal(iamChanges(null, a), null);
  assert.equal(iamChanges(a, { status: 500, json: {} }), null);
  assert.deepEqual(iamChanges(policy([]), policy([{ role: "r" }])), { added: [], removed: [] });
});

// ---- the review's replay gaps (S3) ------------------------------------------------------------------

const fixture = JSON.parse(
  readFileSync(new URL("../fixtures/delivery-recorded.json", import.meta.url), "utf8"),
);
const prepared = JSON.parse(
  readFileSync(new URL("../fixtures/prepare-recorded.json", import.meta.url), "utf8"),
).answers;

test("the recorded 409 of a job delete right after a pause is the busy answer, and no other 409 is", () => {
  const busy = answer(recorded.schedulerBusy409);
  assert.equal(recorded.schedulerBusy409.status, 409);
  assert.equal(recorded.schedulerBusy409.recordedBytes, 336);
  assert.equal(isBusy(busy), true);
  assert.equal(isBusy({ ...busy, status: 400 }), false);
  assert.equal(
    isBusy({ ...busy, json: { error: { ...busy.json.error, status: "ALREADY_EXISTS" } } }),
    false,
  );
  assert.equal(
    isBusy({ ...busy, json: { error: { ...busy.json.error, message: "other" } } }),
    false,
  );
  assert.equal(isBusy({ status: 409, json: null, bodyUnknown: true }), false);
});

test("the recorded Gen1 operation names pass the allowlist and are polled under /v1/operations", async () => {
  const { createGuard } = await import("./guard.mjs");
  const { createWorld, NUMBER, reply } = await import("./world.mjs");
  const { record } = await import("./run.mjs");
  const names = fixture.gcfV1OperationNames;
  assert.ok(names.length >= 1 && names.every((n) => /^[A-Za-z0-9._-]+$/.test(n)));
  const guard = createGuard("0123456789abcdef", NUMBER);
  for (const name of names)
    assert.equal(
      guard.allow({
        id: "t",
        method: "GET",
        url: "https://cloudfunctions.googleapis.com/v1/operations/" + name,
      }),
      true,
    );
  const world = createWorld({
    leaveOnDelete: ["schedFailV1"],
    hooks: {
      "DELETE cloudfunctions.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/functions/schedFailV1":
        async ({ w }) => {
          w.functionsV1.delete(functionName("schedFailV1"));
          return reply(200, { name: "operations/" + names[0], done: false });
        },
    },
  });
  const result = await record({
    runId: "0123456789abcdef",
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async () => {},
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    passes: 1,
    naturalWindowMs: 60_000,
  });
  assert.equal(result.cleanup.errors, undefined, "no step was refused");
  assert.ok(world.calls.includes("GET cloudfunctions.googleapis.com/v1/operations/" + names[0]));
});

test("the recorded IAM policy of the sandbox gives no change when read twice, and a new agent is an addition", () => {
  const policy = { status: 200, json: prepared.iamPolicy.body };
  assert.deepEqual(iamChanges(policy, policy), { added: [], removed: [] });
  const grown = {
    status: 200,
    json: {
      ...prepared.iamPolicy.body,
      bindings: [
        ...prepared.iamPolicy.body.bindings,
        {
          role: "roles/test.addedByTheTest",
          members: ["serviceAccount:123456789012-compute@developer.gserviceaccount.com"],
        },
      ],
    },
  };
  assert.deepEqual(iamChanges(policy, grown), {
    added: [
      "roles/test.addedByTheTest|serviceAccount:123456789012-compute@developer.gserviceaccount.com",
    ],
    removed: [],
  });
});
