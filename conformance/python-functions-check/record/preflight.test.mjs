// The preflight and the closure rules of coordinator rulings R1 to R6 and the Codex/Opus musts: the project's identity and
// number, the two services the run enables, no App Engine app, the Eventarc channel the run owns, CLI writes, malformed
// JSON, and the inventory the closure compares.
import assert from "node:assert/strict";
import test from "node:test";
import { cliWritesFromOutput, inventoryDifferences, iamUnexpected } from "./deploy.mjs";
import { ENABLE_SERVICES } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(
  worldOptions = {},
  wrapSend = (send) => send,
  options = {},
  wrapCli = (cli) => cli,
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: wrapSend(world.send, world),
    runCli: wrapCli((args) => world.runCli(args), world),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...options,
  });
  return { world, journal, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const writes = (world) => world.calls.filter((c) => !c.startsWith("GET "));
const SCHEDULER = ENABLE_SERVICES[0];
const TASKS = ENABLE_SERVICES[1];

// ---- identity and number ---------------------------------------------------------------------------

test("the identity is the recorded read of this project: a 200 with its id and an ACTIVE state", async () => {
  const bodies = [
    [
      "a different project id",
      { projectId: "other", projectNumber: NUMBER, lifecycleState: "ACTIVE" },
    ],
    [
      "a project being deleted",
      {
        projectId: "fireemu-oracle-events",
        projectNumber: NUMBER,
        lifecycleState: "DELETE_REQUESTED",
      },
    ],
    ["no state", { projectId: "fireemu-oracle-events", projectNumber: NUMBER }],
  ];
  for (const [label, body] of bodies) {
    const { result, journal } = await go(
      {},
      (send) => async (request) =>
        request.url.endsWith("/v1/projects/fireemu-oracle-events")
          ? reply(200, body)
          : send(request),
    );
    assert.equal(result.stoppedBecause, "identity", label);
    assert.deepEqual(ids(journal), ["identity"], label);
  }
  const missing = await go(
    {},
    (send) => async (request) =>
      request.url.endsWith("/v1/projects/fireemu-oracle-events")
        ? error(404, "NOT_FOUND")
        : send(request),
  );
  assert.equal(missing.result.stoppedBecause, "identity");
});

test("a number that is not the project's stops the run before any write: it names the buckets whose objects get deleted", async () => {
  const { result, world } = await go({ projectNumberReported: "999999999999" });
  assert.equal(result.stoppedBecause, "project-number");
  assert.equal(result.outcome, "pycheck-stopped-clean");
  assert.deepEqual(writes(world), []);
  assert.equal(world.calls.length, 1, "nothing else was read, no bucket was listed");
  const same = await go({ projectNumberReported: Number(NUMBER) });
  assert.notEqual(same.result.stoppedBecause, "project-number", "a number compares as text");
});

// ---- no App Engine app --------------------------------------------------------------------------------

test("the run never creates an App Engine app: it records what it finds and goes on", async () => {
  for (const options of [{ appEngine: false }, { appEngine: true }]) {
    const { result, world } = await go(options);
    assert.equal(result.outcome, "pycheck-recorded");
    assert.equal(result.appEngine.present, options.appEngine);
    assert.ok(!world.calls.some((c) => c.includes("appengine") && !c.startsWith("GET ")));
  }
});

// ---- the two services the run enables -------------------------------------------------------------------

test("the missing ones of the two services are enabled once, after every read-only check, and stay enabled", async () => {
  const { result, world, journal } = await go({ withoutServices: [SCHEDULER, TASKS] });
  assert.deepEqual(world.enableRequests, [[SCHEDULER, TASKS]]);
  assert.deepEqual(result.servicesEnabled, [SCHEDULER, TASKS]);
  assert.ok(world.services.has(SCHEDULER) && world.services.has(TASKS));
  const order = ids(journal);
  assert.ok(order.indexOf("enable-services") > order.indexOf("preflight-documents"));
  assert.ok(order.indexOf("enable-services") > order.indexOf("logs-preflight-frames"));
  assert.ok(
    journal.findIndex((r) => r.id === "enable-services") <
      journal.findIndex((r) => r.id === "cli-dry-run"),
  );
  assert.ok(order.indexOf("services-after-enable") > order.indexOf("enable-operation-1"));
  assert.deepEqual(result.inventory.services, { added: [SCHEDULER, TASKS], removed: [] });
  assert.deepEqual(result.inventory.differences, []);
  assert.equal(result.outcome, "pycheck-recorded");
  const one = await go({ withoutServices: [TASKS] });
  assert.deepEqual(one.world.enableRequests, [[TASKS]]);
  const none = await go();
  assert.deepEqual(none.world.enableRequests, []);
  assert.deepEqual(none.result.servicesEnabled, []);
});

test("another missing required service stops the run and nothing is enabled", async () => {
  const { result, world } = await go({ withoutServices: [SCHEDULER, "cloudbuild.googleapis.com"] });
  assert.equal(result.stoppedBecause, "services");
  assert.deepEqual(result.servicesMissing, ["cloudbuild.googleapis.com"]);
  assert.deepEqual(world.enableRequests, []);
  assert.deepEqual(writes(world), []);
});

test("nothing is enabled when a later preflight check stops the run", async () => {
  const { result, world } = await go(
    { withoutServices: [SCHEDULER], projectNumberReported: NUMBER },
    (send) => async (request) =>
      request.url.includes("/subscriptions") ? error(500, "INTERNAL") : send(request),
  );
  assert.equal(result.stoppedBecause, "lists");
  assert.deepEqual(world.enableRequests, []);
  const stray = await go({ withoutServices: [SCHEDULER] });
  assert.equal(stray.result.stoppedBecause, undefined);
  const present = createWorld({ runId: RUN, withoutServices: [SCHEDULER] });
  present.topics.add("pycheck-orders");
  const r = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: present.send,
    runCli: present.runCli,
    clock: () => present.now,
    sleep: async (ms) => present.advance(ms),
  });
  assert.equal(r.stoppedBecause, "namespace");
  assert.deepEqual(present.enableRequests, []);
});

test("an unknown answer to the enable is sticky and stops the run; a refusal stops it clean; a service that does not show stops it", async () => {
  let sent = 0;
  const unknown = await go({ withoutServices: [SCHEDULER] }, (send) => async (request) => {
    if (request.method === "POST" && request.url.endsWith(":batchEnable")) {
      sent += 1;
      await send(request);
      return error(503, "UNAVAILABLE");
    }
    return send(request);
  });
  assert.equal(sent, 1, "never re-sent");
  assert.equal(unknown.result.stoppedBecause, "enable-services");
  assert.equal(unknown.result.outcome, "pycheck-needs-review");
  assert.equal(unknown.result.readBackRequired, true);
  assert.deepEqual(unknown.world.cliRuns, []);
  const refused = await go(
    { withoutServices: [SCHEDULER] },
    (send) => async (request) =>
      request.method === "POST" && request.url.endsWith(":batchEnable")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(
    refused.result.outcome,
    "pycheck-auth-stop",
    "a 403 on a write is an owner-credential stop",
  );
  const hidden = await go({ withoutServices: [SCHEDULER] }, (send, w) => async (request) => {
    const answer = await send(request);
    if (request.method === "POST" && request.url.endsWith(":batchEnable"))
      w.services.delete(SCHEDULER);
    return answer;
  });
  assert.equal(hidden.result.stoppedBecause, "enable-services");
  assert.deepEqual(hidden.result.servicesEnabled, []);
  assert.deepEqual(hidden.world.cliRuns, []);
});

test("the enable's operation is read until it is done, at most thirty times", async () => {
  const { result, journal } = await go(
    { withoutServices: [SCHEDULER] },
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("/v1/operations/")
        ? reply(200, { name: "operations/enable-1", done: false })
        : send(request),
  );
  assert.equal(ids(journal).filter((id) => id.startsWith("enable-operation-")).length, 30);
  assert.equal(result.stoppedBecause, undefined, "the services list settles it");
});

// ---- the Eventarc channel the run owns ------------------------------------------------------------------

test("a channel the CLI creates is deleted once, its operation read, and the channel and its topic read back; one that was there stays", async () => {
  const { result, world, journal } = await go({ seedChannels: [] });
  assert.equal(result.channel.ownedByRun, true);
  assert.equal(world.calls.filter((c) => c.startsWith("DELETE eventarc")).length, 1);
  assert.ok(
    ids(journal).includes("channel-operation-1") || ids(journal).includes("delete-channel"),
  );
  assert.equal(result.cleanup.channel.topic, "eventarc-channel-us-central1-firebase-450");
  assert.equal(result.cleanup.readBack.channel, true);
  assert.equal(result.cleanup.readBack["channel-topic"], true);
  assert.ok(
    !world.channels.has("firebase") &&
      !world.topics.has("eventarc-channel-us-central1-firebase-450"),
  );
  assert.deepEqual(result.inventory.differences, []);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.outcome, "pycheck-recorded");
  const kept = await go({ seedChannels: ["firebase"] });
  assert.equal(kept.result.channel.ownedByRun, false);
  assert.equal(kept.world.calls.filter((c) => c.startsWith("DELETE eventarc")).length, 0);
  assert.ok(kept.world.channels.has("firebase"));
  assert.equal(kept.result.cleanup.readBack.channel, undefined);
});

test("a channel delete that is unknown or leaves the channel keeps the cleanup unverified and the run open", async () => {
  const unknown = await go(
    { seedChannels: [] },
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("/channels/")
        ? error(503, "UNAVAILABLE")
        : send(request),
  );
  assert.equal(
    ids(unknown.journal).filter((id) => id === "delete-channel").length,
    1,
    "never re-sent",
  );
  assert.equal(unknown.result.cleanup.readBack.channel, false);
  assert.equal(unknown.result.cleanup.verified, false);
  assert.equal(unknown.result.closureReady, false);
  const left = await go(
    { seedChannels: [], leaveOnDelete: ["pcps"] },
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("/functions/pcps")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(
    left.world.calls.filter((c) => c.startsWith("DELETE eventarc")).length,
    0,
    "not while a function is left",
  );
  assert.equal(left.result.cleanup.readBack.channel, false);
});

test("a channel that cannot be read in the cleanup is not deleted blindly", async () => {
  const { result, world } = await go(
    { seedChannels: [] },
    (send) => async (request) =>
      request.method === "GET" && new URL(request.url).pathname.endsWith("/channels/firebase")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(world.calls.filter((c) => c.startsWith("DELETE eventarc")).length, 0);
  assert.equal(result.cleanup.verified, false);
});

// ---- the inventory the closure compares ------------------------------------------------------------------

test("a service the deploy enabled, a leftover subscription, a foreign topic or a missing package keep the cleanup unverified", async () => {
  const extraService = await go({}, (send, w) => async (request) => {
    if (request.url.includes("services?filter") && w.cliRuns.includes("delete"))
      w.services.add("extra.googleapis.com");
    return send(request);
  });
  assert.deepEqual(extraService.result.inventory.differences, [
    { kind: "services", added: ["extra.googleapis.com"], removed: [] },
  ]);
  assert.equal(extraService.result.cleanup.verified, false);
  assert.equal(extraService.result.closureReady, false);
  assert.equal(extraService.result.outcome, "pycheck-needs-recovery");
  const subs = await go({ leaveSubscriptions: true });
  assert.ok(
    subs.result.inventory.differences.some(
      (d) => d.kind === "subscriptions" && d.added.length === 9,
    ),
  );
  const topics = await go({}, (send, w) => async (request) => {
    if (request.url.includes("/topics?") && w.cliRuns.includes("delete"))
      w.topics.add("stray-topic");
    return send(request);
  });
  assert.ok(topics.result.inventory.differences.some((d) => d.kind === "topics"));
  const triggers = await go({}, (send, w) => async (request) => {
    if (request.url.includes("/triggers") && w.cliRuns.includes("delete"))
      w.triggers.add("stray-trigger");
    return send(request);
  });
  assert.ok(triggers.result.inventory.differences.some((d) => d.kind === "triggers"));
  const packages = await go({}, (send, w) => async (request) => {
    if (request.url.includes("/packages?") && w.cliRuns.includes("delete"))
      w.packages.add("somebody-else");
    return send(request);
  });
  assert.ok(packages.result.inventory.differences.some((d) => d.kind === "packages"));
  const same = await go({ foreignSubscriptions: 2 });
  assert.deepEqual(same.result.inventory.differences, []);
});

test("an inventory list that cannot be read to its end makes the inventory incomplete and blocks the closure", async () => {
  for (const [needle, kind] of [
    ["/subscriptions", "subscriptions"],
    ["/triggers", "triggers"],
    ["/channels", "channels"],
    ["services?filter", "services"],
  ]) {
    const { result } = await go(
      {},
      (send, w) => async (request) =>
        request.url.includes(needle) && w.cliRuns.includes("delete") && request.method === "GET"
          ? error(500, "INTERNAL")
          : send(request),
    );
    assert.equal(result.inventory.complete, false, needle);
    assert.ok(result.inventory.missing.includes(kind), needle);
    assert.equal(result.cleanup.verified, false, needle);
    assert.equal(result.closureReady, false, needle);
  }
});

test("only a service-agent addition to the project IAM is expected; a removal or any other member blocks the closure", async () => {
  const base = [{ role: "roles/owner", members: ["user:a@example.com"] }];
  const wrap = (members) => (send, w) => async (request) => {
    if (request.url.includes("cloudresourcemanager") && request.url.endsWith(":getIamPolicy")) {
      const after = w.cliRuns.includes("delete");
      return reply(200, { version: 1, etag: "e", bindings: after ? members : base });
    }
    return send(request);
  };
  const agent = await go(
    {},
    wrap([
      ...base,
      { role: "roles/run.invoker", members: ["serviceAccount:x@y.iam.gserviceaccount.com"] },
    ]),
  );
  assert.deepEqual(agent.result.inventory.differences, []);
  const removed = await go({}, wrap([]));
  assert.ok(
    removed.result.inventory.differences.some(
      (d) => d.kind === "iam" && d.what.startsWith("removed "),
    ),
  );
  const user = await go(
    {},
    wrap([...base, { role: "roles/viewer", members: ["user:b@example.com"] }]),
  );
  assert.ok(
    user.result.inventory.differences.some((d) => d.kind === "iam" && d.what.startsWith("added ")),
  );
  const unreadable = await go(
    {},
    (send, w) => async (request) =>
      request.url.endsWith(":getIamPolicy") &&
      request.url.includes("cloudresourcemanager") &&
      w.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(unreadable.result.inventory.complete, false);
  assert.equal(unreadable.result.cleanup.verified, false);
});

test("inventoryDifferences compares by identity, allows only what the run enabled and the build's copies", () => {
  const before = {
    channels: ["firebase"],
    triggers: ["t1"],
    subscriptions: ["s1", "s2"],
    topics: ["p1"],
    packages: ["k1"],
    services: ["a", "b"],
    sourceObjects: { uploads: ["u1"], sources: ["x/function-source.zip"] },
  };
  const same = structuredClone(before);
  assert.deepEqual(inventoryDifferences({ before, after: same }), {
    complete: true,
    missing: [],
    differences: [],
  });
  const swapped = { ...same, subscriptions: ["s1", "s3"] };
  assert.deepEqual(inventoryDifferences({ before, after: swapped }).differences, [
    { kind: "subscriptions", added: ["s3"], removed: ["s2"] },
  ]);
  const enabled = { ...same, services: ["a", "b", "c"] };
  assert.equal(inventoryDifferences({ before, after: enabled }).differences.length, 1);
  assert.deepEqual(
    inventoryDifferences({ before, after: enabled, enabled: ["c"] }).differences,
    [],
  );
  assert.equal(
    inventoryDifferences({ before, after: { ...same, services: ["a"] }, enabled: ["a"] })
      .differences.length,
    1,
  );
  const copies = {
    ...same,
    sourceObjects: {
      uploads: ["u1"],
      sources: ["x/function-source.zip", "pcps/function-source.zip"],
    },
  };
  assert.deepEqual(inventoryDifferences({ before, after: copies }).differences, []);
  const odd = {
    ...same,
    sourceObjects: {
      uploads: ["u1"],
      sources: ["x/function-source.zip", "pcps/other.zip", "other/function-source.zip"],
    },
  };
  assert.deepEqual(inventoryDifferences({ before, after: odd }).differences, [
    { kind: "sourceObjects", added: ["other/function-source.zip", "pcps/other.zip"], removed: [] },
  ]);
  const uploads = {
    ...same,
    sourceObjects: { uploads: ["u1", "u2"], sources: ["x/function-source.zip"] },
  };
  assert.deepEqual(inventoryDifferences({ before, after: uploads }).differences, [
    { kind: "uploadObjects", added: ["u2"], removed: [] },
  ]);
  const gone = { ...same, sourceObjects: { uploads: [], sources: [] } };
  assert.equal(inventoryDifferences({ before, after: gone }).differences.length, 2);
  for (const key of ["channels", "triggers", "subscriptions", "topics", "packages", "services"]) {
    const missing = { ...same, [key]: null };
    assert.deepEqual(inventoryDifferences({ before, after: missing }).missing, [key], key);
    assert.equal(
      inventoryDifferences({ before: { ...before, [key]: undefined }, after: same }).complete,
      false,
      key,
    );
  }
  assert.deepEqual(
    inventoryDifferences({
      before,
      after: { ...same, sourceObjects: { uploads: null, sources: null } },
    }).missing,
    ["uploadObjects", "sourceObjects"],
  );
  assert.equal(inventoryDifferences({ before: null, after: null }).complete, false);
});

test("iamUnexpected lets service accounts in and nothing else", () => {
  assert.deepEqual(iamUnexpected(null), { complete: false, unexpected: [] });
  assert.deepEqual(iamUnexpected({ added: [], removed: [] }), { complete: true, unexpected: [] });
  assert.deepEqual(
    iamUnexpected({ added: ["roles/x|serviceAccount:a@b"], removed: [] }).unexpected,
    [],
  );
  assert.deepEqual(
    iamUnexpected({
      added: ["roles/x|user:a@b", "roles/y|allUsers"],
      removed: ["roles/z|user:c@d"],
    }).unexpected,
    ["removed roles/z|user:c@d", "added roles/x|user:a@b", "added roles/y|allUsers"],
  );
  assert.deepEqual(iamUnexpected({ added: ["roles/x"], removed: [] }).unexpected, [
    "added roles/x",
  ]);
});

// ---- what the CLI wrote -------------------------------------------------------------------------------

const REQ = (m, u, q = "[none]") => `[t] >>> [apiv2][query] ${m} https://${u} ${q}`;
const STAT = (m, u, c) => `[t] <<< [apiv2][status] ${m} https://${u} ${c}`;

test("the CLI log gives every mutating request with its answers; reads and the upload are left out", () => {
  const text = [
    REQ(
      "POST",
      "cloudfunctions.googleapis.com/v2/projects/p/locations/l/functions",
      "functionId=a",
    ),
    STAT("POST", "cloudfunctions.googleapis.com/v2/projects/p/locations/l/functions", 200),
    REQ("POST", "run.googleapis.com/v2/projects/p/locations/l/services/a:setIamPolicy"),
    STAT("POST", "run.googleapis.com/v2/projects/p/locations/l/services/a:setIamPolicy", 503),
    REQ("POST", "run.googleapis.com/v2/projects/p/locations/l/services/a:setIamPolicy"),
    STAT("POST", "run.googleapis.com/v2/projects/p/locations/l/services/a:setIamPolicy", 200),
    REQ("PATCH", "identitytoolkit.googleapis.com/admin/v2/projects/p/config", "updateMask=x"),
    REQ("DELETE", "cloudscheduler.googleapis.com/v1/projects/p/locations/l/jobs/j"),
    STAT("DELETE", "cloudscheduler.googleapis.com/v1/projects/p/locations/l/jobs/j", 409),
    REQ("POST", "cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy"),
    STAT("POST", "cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy", 200),
    REQ("POST", "iam.googleapis.com/v1/projects/p/serviceAccounts/a:testIamPermissions"),
    REQ(
      "POST",
      "cloudfunctions.googleapis.com/v2/projects/p/locations/l/functions:generateUploadUrl",
    ),
    REQ("POST", "logging.googleapis.com/v2/entries:list"),
    REQ(
      "PUT",
      "storage.googleapis.com/gcf-v2-uploads-1.us-central1.cloudfunctions.appspot.com/x.zip",
      "GoogleAccessId=g",
    ),
    STAT(
      "PUT",
      "storage.googleapis.com/gcf-v2-uploads-1.us-central1.cloudfunctions.appspot.com/x.zip",
      503,
    ),
    REQ("GET", "cloudfunctions.googleapis.com/v2/projects/p/locations/l/functions"),
    "not a log line",
  ].join("\n");
  const found = cliWritesFromOutput(text);
  assert.deepEqual(
    found.map((w) => [w.method, w.url.split("/").slice(0, 1)[0], w.requests, w.statuses, w.class]),
    [
      ["POST", "cloudfunctions.googleapis.com", 1, [200], "ok"],
      ["POST", "run.googleapis.com", 2, [503, 200], "retried"],
      ["PATCH", "identitytoolkit.googleapis.com", 1, [], "unanswered"],
      ["DELETE", "cloudscheduler.googleapis.com", 1, [409], "non-2xx"],
    ],
  );
  assert.deepEqual(cliWritesFromOutput(""), []);
  assert.equal(
    cliWritesFromOutput(
      REQ("POST", "x.example/a") +
        "\n" +
        REQ("POST", "x.example/a") +
        "\n" +
        STAT("POST", "x.example/a", 200) +
        "\n" +
        STAT("POST", "x.example/a", 200),
    )[0].class,
    "ok",
    "two good writes to one address are not a retry",
  );
  assert.equal(
    cliWritesFromOutput(
      REQ("POST", "x.example/a") +
        "\n" +
        REQ("POST", "x.example/a") +
        "\n" +
        STAT("POST", "x.example/a", 200),
    )[0].class,
    "unanswered",
  );
  assert.equal(cliWritesFromOutput("[t] >>> [apiv2][query] POST not-a-url x")[0], undefined);
});

test("every CLI write is journaled; one that was retried, unanswered or refused is an unknown write that only A2 closes", async () => {
  const ok = {
    method: "POST",
    url: "cloudfunctions.googleapis.com/v2/f",
    requests: 1,
    statuses: [200],
    class: "ok",
  };
  const clean = await go({ cliWrites: [ok] });
  assert.equal(
    clean.journal.filter((r) => r.state === "cli-write").length,
    3,
    "the dry run's, the deploy's and the delete's",
  );
  assert.equal(clean.result.closureReady, true);
  for (const cls of ["retried", "unanswered", "non-2xx"]) {
    const bad = {
      ...ok,
      class: cls,
      statuses: cls === "unanswered" ? [] : [503, 200],
      requests: cls === "retried" ? 2 : 1,
    };
    const { result, journal } = await go({ cliWrites: [ok, bad] });
    assert.equal(result.closureReady, false, cls);
    assert.equal(result.readBackRequired, true, cls);
    assert.ok(
      result.unknownMutationList.some(
        (m) => m.class === "cli-write-" + cls && m.id.startsWith("cli-"),
      ),
      cls,
    );
    assert.ok(
      journal.some((r) => r.state === "cli-write" && r.class === cls),
      cls,
    );
  }
});

test("a CLI log that cannot be read is an unknown write for the deploy and the delete", async () => {
  const { result } = await go(
    {},
    (send) => send,
    {},
    (cli) => async (args) => ({
      ...(await cli(args)),
      cliWrites: null,
    }),
  );
  const classes = result.unknownMutationList.map((m) => m.class);
  assert.equal(classes.filter((c) => c === "cli-log-unreadable").length, 2);
  assert.equal(result.closureReady, false);
});

test("a read-after-an-ambiguous-delete: a function the CLI delete left is deleted only when a fresh list shows it", async () => {
  const { world } = await go(
    { leaveOnDelete: [] },
    (send) => send,
    {},
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "delete"
        ? {
            cliWrites: [
              { method: "DELETE", url: "x", requests: 2, statuses: [503, 200], class: "retried" },
            ],
          }
        : {}),
    }),
  );
  assert.equal(world.calls.filter((c) => c.startsWith("DELETE cloudfunctions")).length, 0);
});

// ---- malformed JSON ------------------------------------------------------------------------------------

test("a 200, 201 or 202 whose JSON body does not parse is an unknown answer; an empty 204 and an empty object are answers", async () => {
  for (const status of [200, 201, 202]) {
    let sent = 0;
    const { result } = await go({}, (send) => async (request) => {
      if (request.method === "PUT" && request.url.includes("/topics/pycheck-orders")) {
        sent += 1;
        await send(request);
        return new Response("not json", { status });
      }
      return send(request);
    });
    assert.equal(sent, 1, String(status));
    assert.equal(result.closureReady, false, String(status));
    assert.equal(result.readBackRequired, true, String(status));
    assert.ok(
      result.unknownMutationList.some((m) => m.id === "create-topic" && m.class === "unreadable"),
      String(status),
    );
  }
  const empty = await go(
    {},
    (send) => async (request) =>
      request.method === "DELETE" &&
      request.url.includes("gcf-v2-uploads") &&
      request.url.includes("ifGenerationMatch")
        ? (await send(request), new Response(null, { status: 204 }))
        : send(request),
  );
  assert.equal(empty.result.unknownMutationList?.length ?? 0, 0);
  assert.equal(empty.result.cleanup.uploadObjectsDeleted[0].class, "2xx");
  const object = await go(
    {},
    (send) => async (request) =>
      request.method === "PUT" && request.url.includes("/topics/")
        ? new Response("{}", { status: 200 })
        : send(request),
  );
  assert.equal(object.result.unknownMutationList?.length ?? 0, 0);
});

// ---- the finer points the mutation run asked for -----------------------------------------------------------------

test("the CLI log parser keeps PUT writes to other hosts, tells methods apart, and draws the 2xx line at 200 and 299", () => {
  const text = [
    REQ("PUT", "cloudresourcemanager.googleapis.com/v1/projects/p/x"),
    STAT("PUT", "cloudresourcemanager.googleapis.com/v1/projects/p/x", 200),
    REQ(
      "PUT",
      "storage.googleapis.com/gcf-v2-uploads-1.us-central1.cloudfunctions.appspot.com/u.zip",
    ),
    REQ("POST", "x.appspot.com.example/a"),
    STAT("POST", "x.appspot.com.example/a", 200),
    REQ("POST", "iam.example/r"),
    STAT("POST", "iam.example/r", 299),
    REQ("DELETE", "iam.example/r"),
    STAT("DELETE", "iam.example/r", 300),
    REQ("PATCH", "iam.example/s"),
    STAT("PATCH", "iam.example/s", 199),
    REQ("PUT", "iam.example/t"),
    STAT("PUT", "iam.example/t", 201),
    REQ("PUT", "iam.example/u"),
    REQ("PUT", "iam.example/u"),
    STAT("PUT", "iam.example/u", 503),
    STAT("PUT", "iam.example/u", 200),
    REQ("PUT", "iam.example/v"),
    REQ("PUT", "iam.example/v"),
    STAT("PUT", "iam.example/v", 200),
    STAT("PUT", "iam.example/v", 201),
    REQ("POST", "iam.example/w:getIamPolicy"),
    REQ("POST", "iam.example/entries:list"),
    REQ("POST", "iam.example/w:testIamPermissions"),
    REQ("POST", "iam.example/w:generateUploadUrl"),
  ].join("\n");
  const found = Object.fromEntries(
    cliWritesFromOutput(text).map((w) => [`${w.method} ${w.url}`, w]),
  );
  assert.deepEqual(Object.keys(found), [
    "PUT cloudresourcemanager.googleapis.com/v1/projects/p/x",
    "POST x.appspot.com.example/a",
    "POST iam.example/r",
    "DELETE iam.example/r",
    "PATCH iam.example/s",
    "PUT iam.example/t",
    "PUT iam.example/u",
    "PUT iam.example/v",
  ]);
  assert.equal(found["PUT cloudresourcemanager.googleapis.com/v1/projects/p/x"].class, "ok");
  assert.equal(found["POST iam.example/r"].class, "ok", "299 is a 2xx answer");
  assert.equal(found["DELETE iam.example/r"].class, "non-2xx", "300 is not");
  assert.equal(found["PATCH iam.example/s"].class, "non-2xx", "199 is not");
  assert.equal(found["PUT iam.example/t"].class, "ok");
  assert.equal(found["PUT iam.example/u"].class, "retried");
  assert.equal(found["PUT iam.example/v"].class, "ok", "two good answers to two requests");
  assert.equal(found["POST iam.example/r"].requests, 1);
  assert.deepEqual(found["PUT iam.example/u"].statuses, [503, 200]);
});

test("the CLI write rows are numbered from one per action and a log that cannot be read is named after its action", async () => {
  const ok = { method: "POST", url: "x.example/a", requests: 1, statuses: [200], class: "ok" };
  const { journal } = await go({ cliWrites: [ok, { ...ok, url: "x.example/b" }] });
  const rowIds = journal.filter((r) => r.state === "cli-write").map((r) => r.id);
  assert.deepEqual(rowIds, [
    "cli-dry-run-write-1",
    "cli-dry-run-write-2",
    "cli-deploy-write-1",
    "cli-deploy-write-2",
    "cli-delete-write-1",
    "cli-delete-write-2",
  ]);
  const bad = await go(
    {},
    (send) => send,
    {},
    (cli) => async (args) => ({
      ...(await cli(args)),
      cliWrites: null,
    }),
  );
  assert.deepEqual(
    bad.result.unknownMutationList.map((m) => m.id),
    ["cli-deploy", "cli-delete"],
  );
  const unknown = await go({ cliWrites: [{ ...ok, class: "unanswered", statuses: [] }] });
  const row = unknown.result.unknownMutationList.find((m) => m.id === "cli-deploy-write-1");
  assert.equal(row.request, "POST x.example/a");
  assert.equal(row.class, "cli-write-unanswered");
});

test("a clean run records an empty list of missing inventory reads, and the enable is recorded with its class", async () => {
  const clean = await go();
  assert.deepEqual(clean.result.inventory.missing, []);
  assert.equal(clean.result.inventory.complete, true);
  const enabled = await go({ withoutServices: [SCHEDULER] });
  assert.deepEqual(enabled.result.enable, { serviceIds: [SCHEDULER], class: "2xx" });
});

test("the enable's operation is read ten seconds apart and no more once it is done", async () => {
  const sleeps = [];
  const { journal } = await go({ withoutServices: [SCHEDULER] }, (send) => send, {
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  assert.equal(ids(journal).filter((id) => id.startsWith("enable-operation-")).length, 2);
  const at = ids(journal).indexOf("enable-operation-1");
  assert.ok(sleeps.includes(10_000), JSON.stringify(sleeps));
  assert.ok(at > 0);
});

test("a services list that cannot be read after the enable, or an operation read that answers 403, is handled as data", async () => {
  const unreadable = await go(
    { withoutServices: [SCHEDULER] },
    (send, w) => async (request) =>
      request.url.includes("services?filter") && w.enableRequests.length > 0
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(unreadable.result.stoppedBecause, "enable-services");
  const forbidden = await go(
    { withoutServices: [SCHEDULER] },
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("/v1/operations/")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.notEqual(forbidden.result.outcome, "pycheck-auth-stop");
  assert.equal(forbidden.result.stoppedBecause, undefined, "the services list settles it");
  assert.deepEqual(forbidden.result.servicesEnabled, [SCHEDULER]);
});

// ---- the channel's operation and reads -----------------------------------------------------------------------------

test("the channel delete's operation is read ten seconds apart until it is done, at most twelve times", async () => {
  for (const [label, doneAfter, reads] of [
    ["done at the second read", 2, 2],
    ["never done", Infinity, 12],
  ]) {
    let seen = 0;
    const sleeps = [];
    const { result, journal } = await go(
      { seedChannels: [] },
      (send) => async (request) => {
        if (
          request.method === "GET" &&
          request.url.includes("/locations/us-central1/operations/")
        ) {
          seen += 1;
          return reply(200, {
            name: "projects/p/locations/us-central1/operations/ch-1",
            done: seen >= doneAfter,
          });
        }
        return send(request);
      },
      { sleep: async (ms) => void sleeps.push(ms) },
    );
    assert.equal(
      ids(journal).filter((id) => id.startsWith("channel-operation-")).length,
      reads,
      label,
    );
    assert.equal(seen, reads, label);
    assert.equal(result.cleanup.channel.deleteClass, "2xx", label);
    assert.ok(sleeps.filter((ms) => ms === 10_000).length >= reads, label);
  }
});

test("a channel that is already gone is recorded, and a 403 on its read is data; a run past its ceiling still cleans the channel up", async () => {
  const gone = await go({ seedChannels: [], failDeploy: true });
  assert.equal(gone.result.cleanup.channel.absentAlready, true);
  assert.equal(gone.world.calls.filter((c) => c.startsWith("DELETE eventarc")).length, 0);
  const forbidden = await go(
    { seedChannels: [] },
    (send) => async (request) =>
      request.method === "GET" && new URL(request.url).pathname.endsWith("/channels/firebase")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.notEqual(forbidden.result.outcome, "pycheck-auth-stop");
  assert.equal(forbidden.world.calls.filter((c) => c.startsWith("DELETE eventarc")).length, 0);
  const late = await go({ seedChannels: [] }, (send) => send, { normalCeiling: 30 });
  assert.equal(late.result.cleanup.channel.deleteClass, "2xx");
  assert.equal(late.result.cleanup.readBack["channel-topic"], true);
  assert.equal(late.result.cleanup.errors, undefined);
  assert.equal(late.result.cleanup.verified, true);
});

test("an identity answer that is 200 but not JSON stops the run as an identity problem and does not throw", async () => {
  const { result, journal } = await go(
    {},
    (send) => async (request) =>
      request.url.endsWith("/v1/projects/fireemu-oracle-events")
        ? new Response("<html>", { status: 200 })
        : send(request),
  );
  assert.equal(result.stoppedBecause, "identity");
  assert.deepEqual(ids(journal), ["identity"]);
});

test("a retried CLI write is retried even when the failing answer is a 300", () => {
  const found = cliWritesFromOutput(
    [
      REQ("POST", "x.example/a"),
      REQ("POST", "x.example/a"),
      STAT("POST", "x.example/a", 300),
      STAT("POST", "x.example/a", 200),
    ].join("\n"),
  );
  assert.equal(found[0].class, "retried");
  const two = cliWritesFromOutput(
    [
      REQ("POST", "x.example/a"),
      REQ("POST", "x.example/a"),
      STAT("POST", "x.example/a", 299),
      STAT("POST", "x.example/a", 200),
    ].join("\n"),
  );
  assert.equal(two[0].class, "ok");
});

test("a settle read that answers 403 is data, not a stop", async () => {
  const { result } = await go({}, (send) => async (request) => {
    if (request.method === "POST" && request.url.includes("/documents/pycheck-src?"))
      throw new Error("reset");
    if (request.method === "GET" && request.url.includes("/documents/pycheck-src/"))
      return error(403, "PERMISSION_DENIED");
    return send(request);
  });
  assert.notEqual(result.outcome, "pycheck-auth-stop");
  assert.ok(result.unconfirmedCreates.some((c) => c.label === "document"));
});

test("the channel delete's operation is read only when the answer is a 2xx that names a pending operation; an operation read that answers 403 is data", async () => {
  const cases = [
    [
      "a 409 that looks like an operation",
      () =>
        reply(409, {
          name: "projects/fireemu-oracle-events/locations/us-central1/operations/x",
          done: false,
        }),
    ],
    ["a 200 with no name", () => reply(200, {})],
    ["a 200 with a name that is not text", () => reply(200, { name: 5, done: false })],
    [
      "a 200 that is already done",
      () =>
        reply(200, {
          name: "projects/fireemu-oracle-events/locations/us-central1/operations/x",
          done: true,
        }),
    ],
  ];
  for (const [label, answer] of cases) {
    const { journal, result } = await go(
      { seedChannels: [] },
      (send) => async (request) =>
        request.method === "DELETE" && request.url.includes("/channels/")
          ? (await send(request), answer())
          : send(request),
    );
    assert.equal(result.cleanup.errors, undefined, label);
    assert.equal(ids(journal).filter((id) => id.startsWith("channel-operation-")).length, 0, label);
  }
  const forbidden = await go(
    { seedChannels: [] },
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("/locations/us-central1/operations/")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.notEqual(forbidden.result.outcome, "pycheck-auth-stop");
  assert.equal(
    ids(forbidden.journal).filter((id) => id.startsWith("channel-operation-")).length,
    12,
    "a 403 never says done",
  );
});
