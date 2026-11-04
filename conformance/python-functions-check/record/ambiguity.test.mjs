// The review rounds of events v1.4: the Scheduler and Tasks lists are read after the APIs are enabled, a failed read-only
// preflight check stops the run before anything is enabled, an ambiguous CLI create stays an unconfirmed create, an unknown
// upload stays open through A2, A2 verifies project IAM and the default bucket's notification configs, a journal row that
// could not be saved is an open obligation, and the policy write keeps every other binding verbatim.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { redactCliText, withCliLog } from "./deploy.mjs";
import { withoutPublicMember } from "./guard.mjs";
import { ALL_FUNCTIONS, JOB_IDS, PROJECT, QUEUE_IDS, REGION, queueName } from "./plan.mjs";
import { readbackRun } from "./readback.mjs";
import { record } from "./run.mjs";
import { tempDir } from "./testtmp.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const BUCKET = `${PROJECT}.firebasestorage.app`;
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
const SCHEDULER_HOST = "cloudscheduler.googleapis.com";
const TASKS_HOST = "cloudtasks.googleapis.com";

async function go(
  worldOptions = {},
  wrapSend = (send) => send,
  wrapCli = (cli) => cli,
  extra = {},
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => {
      if (extra.refuseSave?.(row)) throw new Error("disk full");
      journal.push(row);
    },
    send: wrapSend(world.send, world),
    runCli: wrapCli((args) => world.runCli(args), world),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
  });
  return { world, journal, sleeps, result };
}
const a2 = (world, result, over = {}) =>
  readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: over.send ?? world.send,
    clock: () => world.now,
    baseline: result.inventory.before,
    enabled: result.servicesEnabled ?? [],
    channel: result.cleanup?.channel ?? {},
    uploadObjects: result.cleanup?.uploadObjectsDeleted ?? [],
    ...over,
  });
const requestIds = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const answers403 = (journal) =>
  journal.filter((r) => r.state === "response-persisted" && r.status === 403).length;
const FN_POST = {
  method: "POST",
  url: `cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/functions`,
  requests: 1,
  statuses: [],
  class: "unanswered",
};

// ---- Must 1: the Scheduler and Tasks lists come after the enable --------------------------------------------------------

test("with Cloud Scheduler and Cloud Tasks off, their lists are read after the one enable and the run reaches the deploy", async () => {
  const { world, journal, result } = await go({ withoutServices: [SCHEDULER_HOST, TASKS_HOST] });
  const ids = requestIds(journal);
  assert.equal(world.enableRequests.length, 1);
  assert.deepEqual(world.enableRequests[0].toSorted(), [SCHEDULER_HOST, TASKS_HOST]);
  assert.ok(ids.indexOf("enable-services") >= 0);
  assert.ok(ids.indexOf("preflight-jobs") > ids.indexOf("enable-services"));
  assert.ok(ids.indexOf("preflight-queues") > ids.indexOf("enable-services"));
  assert.equal(answers403(journal), 0, "no request reached a disabled API");
  assert.ok(world.cliRuns.includes("deploy"));
  assert.equal(result.outcome, "pycheck-recorded");
});

test("a 403 SERVICE_DISABLED that lasts while the enable propagates is read again, a bounded number of times, 30 seconds apart", async () => {
  const { world, journal, sleeps, result } = await go({
    withoutServices: [SCHEDULER_HOST, TASKS_HOST],
    propagationReads: 3,
  });
  const ids = requestIds(journal);
  assert.ok(ids.includes("preflight-jobs-attempt-4"), ids.filter((id) => /jobs/.test(id)).join());
  assert.ok(ids.includes("preflight-queues-attempt-4"));
  assert.ok(!ids.includes("preflight-jobs-attempt-5"));
  assert.equal(answers403(journal), 6);
  assert.equal(sleeps.filter((ms) => ms === 30_000).length >= 6, true);
  assert.ok(world.cliRuns.includes("deploy"));
  assert.equal(result.outcome, "pycheck-recorded");
});

test("lists that stay 403 after the enable stop the run clean, with the services enabled and no CLI run", async () => {
  const { world, sleeps, result } = await go({
    withoutServices: [SCHEDULER_HOST, TASKS_HOST],
    propagationReads: 1000,
  });
  assert.equal(result.stoppedBecause, "lists-after-enable");
  assert.equal(result.outcome, "pycheck-stopped-clean");
  assert.deepEqual(world.cliRuns, []);
  assert.equal(result.closureReady, false);
  assert.equal(world.enableRequests.length, 1);
  assert.deepEqual(result.servicesEnabled.toSorted(), [SCHEDULER_HOST, TASKS_HOST]);
  assert.ok(result.incompleteReads.some((r) => r.class === "service-disabled"));
  assert.equal(sleeps.filter((ms) => ms === 30_000).length, 9, "ten attempts, nine waits");
});

test("a stray run queue that is visible only after the enable stops the run on the namespace check, with no CLI run", async () => {
  for (const [label, host, plant] of [
    [
      "queue",
      TASKS_HOST,
      (w) => w.queues.set(QUEUE_IDS[0], { name: queueName(QUEUE_IDS[0]), state: "RUNNING" }),
    ],
    [
      "job",
      SCHEDULER_HOST,
      (w) => w.jobs.set(JOB_IDS[0], { name: "projects/x/jobs/" + JOB_IDS[0], state: "ENABLED" }),
    ],
  ]) {
    const { world, result } = await go(
      { withoutServices: [SCHEDULER_HOST, TASKS_HOST] },
      (send, w) => async (request) => {
        if (new URL(request.url).hostname === host && w.services.has(host)) plant(w);
        return send(request);
      },
    );
    assert.equal(result.stoppedBecause, "namespace", label);
    assert.deepEqual(world.cliRuns, [], label);
  }
});

test("a list that fails for another reason after the enable is not read again", async () => {
  const { sleeps, result, world } = await go(
    {},
    (send) => async (request) =>
      request.url.includes("/queues?") ? error(500, "INTERNAL") : send(request),
  );
  assert.equal(result.stoppedBecause, "lists-after-enable");
  assert.equal(sleeps.filter((ms) => ms === 30_000).length, 0);
  assert.deepEqual(world.cliRuns, []);
});

// ---- Must 5: a failed read-only check stops the run before anything is enabled ----------------------------------------

test("an IAM baseline that cannot be read stops the run before the enable, the dry run and everything else", async () => {
  for (const [label, hook] of [
    ["a 500", () => error(500, "INTERNAL")],
    ["a 200 that is not JSON", () => new Response("not json", { status: 200 })],
  ]) {
    const { world, result } = await go(
      { withoutServices: [TASKS_HOST] },
      (send) => async (request) =>
        request.method === "POST" &&
        request.url.endsWith(":getIamPolicy") &&
        !request.url.includes("run.")
          ? hook()
          : send(request),
    );
    assert.equal(result.stoppedBecause, "iam", label);
    assert.deepEqual(world.enableRequests, [], label);
    assert.deepEqual(world.cliRuns, [], label);
    assert.equal(result.outcome, "pycheck-stopped-clean", label);
  }
});

test("a preflight log poll that gives no entries list stops the run before the enable", async () => {
  const { world, result } = await go(
    { withoutServices: [TASKS_HOST] },
    (send) => async (request) =>
      request.url.includes("entries:list") ? error(500, "INTERNAL") : send(request),
  );
  assert.equal(result.stoppedBecause, "preflight-reads");
  assert.deepEqual(world.enableRequests, []);
  assert.deepEqual(world.cliRuns, []);
  assert.equal(result.outcome, "pycheck-stopped-clean");
});

test("a default-bucket notification list that cannot be read stops the preflight", async () => {
  const { world, result } = await go(
    {},
    (send) => async (request) =>
      request.url.endsWith("/notificationConfigs") ? error(500, "INTERNAL") : send(request),
  );
  assert.equal(result.stoppedBecause, "lists");
  assert.deepEqual(world.cliRuns, []);
});

// ---- Should: services are read to the end ------------------------------------------------------------------------------

test("the enabled services are read page by page in the preflight, after the enable and in the final inventory", async () => {
  const { journal, result, world } = await go({
    servicePageSize: 4,
    withoutServices: [TASKS_HOST],
  });
  const ids = requestIds(journal);
  for (const prefix of ["services-before", "services-after-enable", "services-after"])
    assert.ok(ids.includes(prefix + "-page-2"), prefix);
  assert.ok(world.services.size > 4);
  assert.deepEqual(result.inventory.differences, []);
  assert.equal(result.outcome, "pycheck-recorded");
});

// ---- Must 2: an ambiguous CLI create stays an unconfirmed create ---------------------------------------------------------

test("a failed deploy whose function POST went unanswered leaves every name the CLI makes unconfirmed; absence reads never settle it", async () => {
  const { result, world } = await go(
    { failDeploy: true },
    (send) => send,
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "deploy" ? { cliWrites: [FN_POST] } : {}),
    }),
  );
  const labels = result.unconfirmedCreates.map((c) => c.label);
  for (const fn of ALL_FUNCTIONS) assert.ok(labels.includes("function-" + fn), fn);
  assert.ok(labels.includes("job-" + JOB_IDS[0]) && labels.includes("queue-" + QUEUE_IDS[0]));
  assert.ok(result.unconfirmedCreates.every((c) => c.class === "cli-write-unanswered"));
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.equal(world.functions.size, 0, "the reads after it only ever found nothing");
});

test("every kind of ambiguous deploy write keeps the names unconfirmed: retried, unanswered, non-2xx, an unreadable log", async () => {
  const cases = [
    [
      "retried",
      { cliWrites: [{ ...FN_POST, class: "retried", requests: 2, statuses: [503, 200] }] },
      "cli-write-retried",
    ],
    ["unanswered", { cliWrites: [FN_POST] }, "cli-write-unanswered"],
    [
      "non-2xx",
      { cliWrites: [{ ...FN_POST, class: "non-2xx", statuses: [500] }] },
      "cli-write-non-2xx",
    ],
    ["an unreadable log", { cliWrites: null }, "cli-log-unreadable"],
  ];
  for (const [label, patch, klass] of cases) {
    const { result } = await go(
      { failDeploy: true },
      (send) => send,
      (cli) => async (args) => ({
        ...(await cli(args)),
        ...(args.action === "deploy" ? patch : {}),
      }),
    );
    assert.equal(result.unconfirmedCreates[0]?.class, klass, label);
    assert.equal(result.readBackRequired, true, label);
    assert.equal(result.closureReady, false, label);
  }
});

test("an ambiguous write of the delete or dry-run action is an unknown write but never an unconfirmed create", async () => {
  for (const action of ["delete", "dry-run"]) {
    const { result } = await go(
      { failDeploy: true },
      (send) => send,
      (cli) => async (args) => ({
        ...(await cli(args)),
        ...(args.action === action ? { cliWrites: [FN_POST] } : {}),
      }),
    );
    assert.deepEqual(result.unconfirmedCreates, [], action);
    assert.ok(
      result.unknownMutationList.some((m) => m.class === "cli-write-unanswered"),
      action,
    );
  }
});

test("the shared parser's unknown writes are unknown writes whichever action reported them", async () => {
  for (const action of ["dry-run", "deploy", "delete"]) {
    const { result } = await go(
      {},
      (send) => send,
      (cli) => async (args) => ({
        ...(await cli(args)),
        ...(args.action === action
          ? { unknownWrites: [{ method: "POST", host: "cloudfunctions", status: 500 }] }
          : {}),
      }),
    );
    assert.ok(
      result.unknownMutationList.some(
        (m) => m.class === "cli-unknown-write" && m.id.startsWith(`cli-${action}-unknown-write`),
      ),
      action,
    );
    assert.equal(result.readBackRequired, true, action);
    assert.equal(result.closureReady, false, action);
  }
});

test("a deploy write that was ambiguous but whose names later read 2xx is settled; the write stays unknown", async () => {
  const { result } = await go(
    {},
    (send) => send,
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "deploy"
        ? { cliWrites: [{ ...FN_POST, class: "retried", requests: 2, statuses: [503, 200] }] }
        : {}),
    }),
  );
  assert.deepEqual(result.unconfirmedCreates, []);
  assert.ok(result.unknownMutationList.some((m) => m.class === "cli-write-retried"));
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
});

// ---- Must 4: a journal row that could not be saved is an open obligation --------------------------------------------------

test("a cli-write row that could not be journaled is a sticky unknown write: never closureReady, the read-back is required", async () => {
  const ok = {
    method: "POST",
    url: `cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/functions`,
    requests: 1,
    statuses: [200],
    class: "ok",
  };
  const clean = await go({ cliWrites: [ok] });
  assert.equal(clean.result.closureReady, true);
  const { result } = await go(
    { cliWrites: [ok] },
    (send) => send,
    (cli) => cli,
    { refuseSave: (row) => row.state === "cli-write" },
  );
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.ok(result.unknownMutationList.some((m) => m.class === "cli-write-unjournaled"));
  assert.notEqual(result.outcome, "pycheck-recorded");
});

// ---- Must 2: an unknown upload stays open ----------------------------------------------------------------------------------

test("a receipt with no PUT answer and a 404 on the object is an unconfirmed create that a clean inventory never settles", async () => {
  const name = "514cacbe-3258-46fd-9a02-54b7485b7777.zip";
  const { result } = await go(
    {},
    (send) => send,
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "deploy"
        ? {
            uploadEvents: [
              {
                type: "receipt",
                bucket: `gcf-v2-uploads-${NUMBER}.us-central1.cloudfunctions.appspot.com`,
                object: name,
              },
            ],
          }
        : {}),
    }),
  );
  assert.ok(result.cleanup.uploadReasons.includes(`receipt-unconfirmed:${name}`));
  assert.deepEqual(
    result.unconfirmedCreates
      .filter((c) => c.label === "upload-object")
      .map((c) => [c.label, c.name, c.class]),
    [["upload-object", name, "receipt-unconfirmed"]],
  );
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
});

test("the other reasons that leave an upload unknown are unconfirmed creates with no name, and a refused upload is not", async () => {
  for (const [label, patch, klass] of [
    ["no receipt", { uploadEvents: [] }, "no-receipt"],
    ["a log that cannot be read", { uploadEvents: null }, "receipt-log-unreadable"],
    [
      "a killed CLI",
      { uploadEvents: [], exitCode: null, signal: "SIGKILL" },
      "killed-without-receipt",
    ],
  ]) {
    const { result } = await go(
      {},
      (send) => send,
      (cli) => async (args) => ({
        ...(await cli(args)),
        ...(args.action === "deploy" ? patch : {}),
      }),
    );
    const found = result.unconfirmedCreates.filter((c) => c.label === "upload-object");
    assert.ok(
      found.some((c) => c.class === klass),
      label,
    );
    assert.ok(
      found.every((c) => c.name === null),
      `${label}: a reason with no object name leaves the name null`,
    );
  }
  const refused = await go({ uploadLines: "refused" });
  assert.ok(!refused.result.unconfirmedCreates.some((c) => c.label === "upload-object"));
});

test("readBackRequired is true for an upload reason, an unexplained object, an inventory difference and an incomplete inventory, each alone", async () => {
  const reasonOnly = await go(
    {},
    (send) => send,
    (cli) => async (args) => {
      const ran = await cli(args);
      return args.action === "deploy"
        ? {
            ...ran,
            uploadEvents: [
              { type: "receipt", bucket: "another-bucket", object: "x.zip" },
              ...ran.uploadEvents,
            ],
          }
        : ran;
    },
  );
  assert.deepEqual(reasonOnly.result.cleanup.uploadReasons, ["receipt-invalid"]);
  assert.deepEqual(reasonOnly.result.cleanup.uploadObjectsUnexplained, []);
  assert.deepEqual(reasonOnly.result.inventory.differences, []);
  assert.equal(reasonOnly.result.unknownMutations, 0);
  assert.deepEqual(reasonOnly.result.unconfirmedCreates, []);
  assert.equal(reasonOnly.result.readBackRequired, true);
  const diff = await go({}, (send, w) => async (request) => {
    if (w.cliRuns.includes("delete")) w.topics.add("stray");
    return send(request);
  });
  assert.ok(diff.result.inventory.differences.length > 0);
  assert.equal(diff.result.cleanup.uploadReasons.length, 0);
  assert.equal(diff.result.readBackRequired, true);
  const incomplete = await go({}, (send, w) => async (request) => {
    if (
      w.cliRuns.includes("delete") &&
      request.method === "POST" &&
      request.url.endsWith(":getIamPolicy") &&
      !request.url.includes("run.")
    )
      return error(500, "INTERNAL");
    return send(request);
  });
  assert.equal(incomplete.result.inventory.complete, false);
  assert.equal(incomplete.result.readBackRequired, true);
  const clean = await go();
  assert.equal(clean.result.readBackRequired, false);
});

// ---- Must 2 and 3: A2 --------------------------------------------------------------------------------------------------------

test("the read-back never reports everything absent while the run carries an obligation", async () => {
  const { world, result } = await go();
  assert.equal((await a2(world, result, { carried: [] })).allAbsent, true);
  for (const carried of [
    ["upload:receipt-unconfirmed:x.zip"],
    ["unexplained-upload-object:x.zip"],
    ["inventory:" + JSON.stringify({ kind: "iam", what: "added roles/owner|user:a@b.c" })],
    ["inventory-incomplete"],
  ])
    assert.equal((await a2(world, result, { carried })).allAbsent, false, carried[0]);
});

test("the read-back compares a fresh project IAM policy with the baseline: only service-account additions are expected", async () => {
  const { world, result } = await go();
  assert.deepEqual(result.inventory.before.iam, []);
  assert.equal((await a2(world, result)).allAbsent, true);
  const policyAs = (bindings) => async (request) =>
    request.url.endsWith(":getIamPolicy") && request.url.includes("cloudresourcemanager")
      ? reply(200, { bindings })
      : world.send(request);
  const agent = await a2(world, result, {
    send: policyAs([
      { role: "roles/run.invoker", members: ["serviceAccount:a@b.iam.gserviceaccount.com"] },
    ]),
  });
  assert.equal(agent.allAbsent, true);
  for (const [label, bindings] of [
    ["a foreign user", [{ role: "roles/owner", members: ["user:foreign@example.com"] }]],
    ["allUsers", [{ role: "roles/viewer", members: ["allUsers"] }]],
  ]) {
    const rb = await a2(world, result, { send: policyAs(bindings) });
    assert.equal(rb.allAbsent, false, label);
    assert.ok(
      rb.inventory.differences.some((d) => d.kind === "iam" && d.what.startsWith("added ")),
      label,
    );
  }
  const removed = await go({
    projectIam: [{ role: "roles/owner", members: ["user:a@example.com"] }],
  });
  assert.deepEqual(removed.result.inventory.before.iam, ["roles/owner|user:a@example.com"]);
  const gone = await a2(removed.world, removed.result, {
    send: async (request) =>
      request.url.endsWith(":getIamPolicy") && request.url.includes("cloudresourcemanager")
        ? reply(200, { bindings: [] })
        : removed.world.send(request),
  });
  assert.ok(gone.inventory.differences.some((d) => d.what?.startsWith("removed ")));
  const unreadable = await a2(world, result, {
    send: async (request) =>
      request.url.endsWith(":getIamPolicy") && request.url.includes("cloudresourcemanager")
        ? error(500, "INTERNAL")
        : world.send(request),
  });
  assert.equal(unreadable.allAbsent, false);
  assert.ok(unreadable.inventory.missing.includes("iam"));
  const noBaseline = await a2(world, result, {
    baseline: { ...result.inventory.before, iam: undefined },
  });
  assert.equal(noBaseline.allAbsent, false);
  assert.ok(noBaseline.inventory.missing.includes("iam"));
});

test("the read-back sends one POST, the project IAM read, and nothing else but GETs", async () => {
  const { world, result } = await go();
  const before = world.calls.length;
  await a2(world, result);
  const posts = world.calls.slice(before).filter((call) => !call.startsWith("GET "));
  assert.equal(posts.length, 1);
  assert.match(
    posts[0],
    /^POST cloudresourcemanager\.googleapis\.com\/v1\/projects\/.*:getIamPolicy$/,
  );
});

// ---- Should: the default bucket's notification configs ---------------------------------------------------------------------

test("a notification config the run leaves on the default bucket is an inventory difference in the run and in the read-back", async () => {
  const clean = await go({ notifications: ["existing"] });
  assert.deepEqual(clean.result.inventory.before.notifications, ["existing"]);
  assert.deepEqual(clean.result.inventory.differences, []);
  assert.equal((await a2(clean.world, clean.result)).allAbsent, true);
  const left = await go({ notifications: ["existing"] }, (send, w) => async (request) => {
    if (w.cliRuns.includes("deploy")) w.notifications.add("left-by-eventarc");
    return send(request);
  });
  assert.deepEqual(left.result.inventory.differences, [
    { kind: "notifications", added: ["left-by-eventarc"], removed: [] },
  ]);
  assert.equal(left.result.cleanup.verified, false);
  assert.equal(left.result.readBackRequired, true);
  const later = await a2(clean.world, clean.result, {
    send: async (request) => {
      clean.world.notifications.add("added-later");
      return clean.world.send(request);
    },
  });
  assert.equal(later.allAbsent, false);
  assert.ok(later.inventory.differences.some((d) => d.kind === "notifications"));
  const removed = await go({ notifications: ["existing"] }, (send, w) => async (request) => {
    if (w.cliRuns.includes("delete")) w.notifications.delete("existing");
    return send(request);
  });
  assert.deepEqual(removed.result.inventory.differences, [
    { kind: "notifications", added: [], removed: ["existing"] },
  ]);
});

// ---- Must 4 of the blocking round, shared: the policy write keeps every other binding verbatim -----------------------

const CONDITIONAL = {
  role: "roles/run.invoker",
  members: ["user:cond@example.com"],
  condition: { title: "t", expression: "request.time < timestamp('2030-01-01T00:00:00Z')" },
};

test("removing allUsers keeps a conditional binding exactly, and only that member goes", async () => {
  const { journal, result } = await go({
    invokerBindings: [
      CONDITIONAL,
      { role: "roles/run.invoker", members: ["allUsers", "user:keep@example.com"] },
    ],
  });
  const write = journal.find(
    (r) => r.state === "before-send" && r.id === `cleanup-remove-invoker-${ALL_FUNCTIONS[0]}`,
  );
  assert.deepEqual(write.json.policy.bindings, [
    CONDITIONAL,
    { role: "roles/run.invoker", members: ["user:keep@example.com"] },
  ]);
  assert.equal(result.cleanup.invoker[ALL_FUNCTIONS[0]].removed, true);
});

test("a policy shape the write could not keep is refused before anything is sent", async () => {
  const { journal, result } = await go(
    { invokerBindings: [{ role: "roles/run.invoker", members: ["allUsers"], extra: 1 }] },
    (send) => send,
  );
  const finding = result.cleanup.invoker[ALL_FUNCTIONS[0]];
  assert.equal(finding.refused, "binding-shape");
  assert.equal(finding.removed, false);
  assert.ok(!journal.some((r) => r.id?.startsWith("cleanup-remove-invoker")));
  assert.deepEqual(withoutPublicMember([]), { ok: false, why: "policy-not-an-object" });
  assert.deepEqual(withoutPublicMember({ auditConfigs: [] }), { ok: false, why: "policy-fields" });
  assert.deepEqual(withoutPublicMember({ bindings: {} }), {
    ok: false,
    why: "bindings-not-a-list",
  });
  assert.deepEqual(
    withoutPublicMember({
      version: 3,
      etag: "e",
      bindings: [{ role: "roles/x", members: ["allUsers"] }],
    }),
    { ok: true, policy: { version: 3, etag: "e", bindings: [] } },
  );
});

// ---- Should: signed query strings after a space -------------------------------------------------------------------------------

test("the signed upload query of the real CLI line, which follows a space, is redacted too", () => {
  const line = `[2026-11-04T01:02:03.000Z] >>> [apiv2][query] PUT https://storage.googleapis.com/gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com/514cacbe-3258-46fd-9a02-54b7485b11c1.zip GoogleAccessId=service-123456789012%40gcf-admin-robot.iam.gserviceaccount.com&Expires=1792000000&Signature=AbC%2Bdef%3D%3D`;
  const out = redactCliText(line);
  assert.ok(!/Signature=AbC|GoogleAccessId=service/.test(out), out);
  assert.ok(out.includes("514cacbe-3258-46fd-9a02-54b7485b11c1.zip"), "the object name stays");
  assert.ok(out.includes("Expires=1792000000"));
  const directory = tempDir("pce-amb-");
  writeFileSync(join(directory, "cli-deploy-stdout.txt"), line + "\n");
  writeFileSync(join(directory, "cli-deploy-stderr.txt"), "");
  withCliLog({ action: "deploy" }, directory);
  assert.ok(!/Signature=AbC/.test(readFileSync(join(directory, "cli-deploy-stdout.txt"), "utf8")));
});
