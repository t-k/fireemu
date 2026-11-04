// The ambiguity rules of the second review round: an ambiguous CLI create stays unconfirmed, A2 verifies project IAM, an
// unknown upload create stays open through A2, and the policy write keeps every other binding exactly as it was.
import assert from "node:assert/strict";
import test from "node:test";
import { redactCliText, withCliLog } from "./deploy.mjs";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readbackRun } from "./readback.mjs";
import { FUNCTION, PROJECT, REGION } from "./plan.mjs";
import { record } from "./run.mjs";
import { withoutPublicMember } from "./guard.mjs";
import { tempDir } from "./testtmp.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(worldOptions = {}, wrapSend = (send) => send, wrapCli = (cli) => cli) {
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
  });
  return { world, journal, result };
}
const a2 = (world, result, over = {}) =>
  readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: over.send ?? world.send,
    localId: result.signUp.localId,
    accountsBefore: result.inventory.before.accounts,
    configBeforeDigest: result.configBefore.sha256,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
    baseline: world.baseline,
    ...over,
  });
const FN_POST = {
  method: "POST",
  url: `cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/functions`,
  requests: 1,
  statuses: [500],
  class: "non-2xx",
};

// ---- Must 1: an ambiguous CLI create stays an unconfirmed create --------------------------------------------------------

test("a failed deploy whose function-create POST answered 500 leaves the function unconfirmed; absence reads never settle it", async () => {
  const { result, world } = await go(
    { failDeploy: true },
    (send) => send,
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "deploy" ? { cliWrites: [FN_POST] } : {}),
    }),
  );
  assert.deepEqual(
    result.unconfirmedCreates.map((c) => [c.label, c.class]),
    [["function", "cli-write-non-2xx"]],
  );
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.equal(world.functions.size, 0, "the reads after it only ever found nothing");
});

test("every kind of ambiguous deploy write keeps the function unconfirmed: retried, unanswered, non-2xx, an unreadable log, the shared parser's unknown writes", async () => {
  const cases = [
    [
      "retried",
      { cliWrites: [{ ...FN_POST, class: "retried", requests: 2, statuses: [503, 200] }] },
      "cli-write-retried",
    ],
    [
      "unanswered",
      { cliWrites: [{ ...FN_POST, class: "unanswered", statuses: [] }] },
      "cli-write-unanswered",
    ],
    ["an unreadable log", { cliWrites: null }, "cli-log-unreadable"],
    [
      "the shared list",
      { unknownWrites: [{ method: "POST", host: "cloudfunctions", status: 500 }] },
      "cli-unknown-write",
    ],
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

test("an ambiguous write of the delete or dry-run action never makes the function an unconfirmed create", async () => {
  for (const action of ["delete", "dry-run"]) {
    const { result } = await go(
      { failDeploy: true },
      (send) => send,
      (cli) => async (args) => ({
        ...(await cli(args)),
        ...(args.action === action
          ? { unknownWrites: [{ method: "POST", host: "cloudfunctions", status: 500 }] }
          : {}),
      }),
    );
    assert.ok(
      !result.unconfirmedCreates.some((c) => c.label === "function"),
      `${action}: the function was not created by that action`,
    );
  }
});

test("the shared parser's unknown writes alone make an unknown write, whichever action reported them", async () => {
  const { result } = await go(
    {},
    (send) => send,
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "delete"
        ? { unknownWrites: [{ method: "DELETE", host: "cloudfunctions", status: 503 }] }
        : {}),
    }),
  );
  assert.ok(
    result.unknownMutationList.some(
      (m) => m.id === "cli-delete-unknown-write-1" && m.request === "DELETE cloudfunctions 503",
    ),
  );
  assert.equal(result.closureReady, false);
  assert.deepEqual(result.unconfirmedCreates, [], "a delete is not a create");
});

test("a deploy write that was ambiguous but whose function a later 2xx read shows is settled; the write stays unknown", async () => {
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
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
});

// ---- Must 2: A2 verifies project IAM -------------------------------------------------------------------------------------

test("the read-back compares a fresh project IAM policy with the baseline: only service-account additions are expected", async () => {
  const { world, result } = await go();
  assert.deepEqual(result.inventory.before.iam, []);
  const clean = await a2(world, result);
  assert.equal(clean.allAbsent, true);
  const agent = await a2(world, result, {
    send: async (request) =>
      request.url.endsWith(":getIamPolicy") && request.url.includes("cloudresourcemanager")
        ? reply(200, {
            bindings: [
              {
                role: "roles/run.invoker",
                members: ["serviceAccount:a@b.iam.gserviceaccount.com"],
              },
            ],
          })
        : world.send(request),
  });
  assert.equal(agent.allAbsent, true);
  for (const [label, bindings] of [
    ["a foreign user", [{ role: "roles/owner", members: ["user:foreign@example.com"] }]],
    ["allUsers", [{ role: "roles/viewer", members: ["allUsers"] }]],
  ]) {
    const rb = await a2(world, result, {
      send: async (request) =>
        request.url.endsWith(":getIamPolicy") && request.url.includes("cloudresourcemanager")
          ? reply(200, { bindings })
          : world.send(request),
    });
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
  const noBaseline = await a2(world, result, { baseline: { ...world.baseline, iam: undefined } });
  assert.equal(noBaseline.allAbsent, false);
  assert.ok(noBaseline.inventory.missing.includes("iam"));
});

// ---- Must 3: an unknown upload create stays open --------------------------------------------------------------------------

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
    result.unconfirmedCreates.map((c) => [c.label, c.name, c.class]),
    [["upload-object", name, "receipt-unconfirmed"]],
  );
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
});

test("the other reasons that leave an upload unknown are unconfirmed creates too, and a refused upload is not", async () => {
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
    assert.ok(
      result.unconfirmedCreates.some((c) => c.label === "upload-object" && c.class === klass),
      label,
    );
    assert.ok(
      result.unconfirmedCreates.every((c) => c.label !== "upload-object" || c.name === null),
      `${label}: a reason with no object name leaves the name null, not an empty string`,
    );
  }
  const refused = await go({ uploadLines: "refused" });
  assert.ok(!refused.result.unconfirmedCreates.some((c) => c.label === "upload-object"));
  const unreadable = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("?fields=")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.ok(unreadable.result.unconfirmedCreates.some((c) => c.class === "object-unreadable"));
});

test("readBackRequired is true for upload reasons, unexplained objects and inventory differences alone", async () => {
  const reasonOnly = await go(
    {},
    (send) => send,
    (cli) => async (args) => ({
      ...(await cli(args)),
      ...(args.action === "deploy"
        ? {
            uploadEvents: [
              { type: "receipt", bucket: "another-bucket", object: "x.zip" },
              ...(await cli(args)).uploadEvents,
            ],
          }
        : {}),
    }),
  );
  assert.deepEqual(reasonOnly.result.cleanup.uploadReasons, ["receipt-invalid"]);
  assert.equal(reasonOnly.result.readBackRequired, true);
  assert.equal(reasonOnly.result.unknownMutations, 0);
  assert.deepEqual(reasonOnly.result.unconfirmedCreates, []);
  const unexplained = await go({}, (send, w) => async (request) => {
    if (
      request.method === "GET" &&
      request.url.includes("gcf-v2-uploads") &&
      request.url.includes("/o?") &&
      w.cliRuns.includes("deploy") &&
      !w.sourceBuckets
        .get(`gcf-v2-uploads-${NUMBER}.us-central1.cloudfunctions.appspot.com`)
        .includes("stray.zip")
    )
      w.sourceBuckets
        .get(`gcf-v2-uploads-${NUMBER}.us-central1.cloudfunctions.appspot.com`)
        .push("stray.zip");
    return send(request);
  });
  assert.equal(unexplained.result.cleanup.uploadObjectsUnexplained.length, 1);
  assert.equal(unexplained.result.readBackRequired, true);
  const diff = await go({}, (send, w) => async (request) => {
    if (w.cliRuns.includes("delete")) w.topics.add("stray");
    return send(request);
  });
  assert.ok(diff.result.inventory.differences.length > 0);
  assert.equal(diff.result.readBackRequired, true);
  const clean = await go();
  assert.equal(clean.result.readBackRequired, false);
});

// ---- Must 4: the policy write keeps every other binding verbatim ----------------------------------------------------------

const CONDITIONAL = {
  role: "roles/run.invoker",
  members: ["serviceAccount:a@b.iam.gserviceaccount.com"],
  condition: {
    title: "until",
    expression: "request.time < timestamp('2030-01-01T00:00:00Z')",
    description: "d",
  },
};

test("removing allUsers keeps a conditional binding exactly, and only that member goes", async () => {
  const { journal, result } = await go({
    invokerBindings: [
      CONDITIONAL,
      { role: "roles/run.invoker", members: ["allUsers", "user:keep@example.com"] },
    ],
  });
  const write = journal.find((r) => r.state === "before-send" && r.id === "cleanup-remove-invoker");
  assert.deepEqual(write.json.policy.bindings, [
    CONDITIONAL,
    { role: "roles/run.invoker", members: ["user:keep@example.com"] },
  ]);
  assert.equal(write.json.policy.version, 1);
  assert.equal(result.cleanup.invoker.removed, true);
  assert.equal(result.closureReady, true);
});

test("a binding that held only allUsers is dropped, a conditional one with allUsers keeps its condition", () => {
  const out = withoutPublicMember({
    version: 3,
    etag: "e",
    bindings: [
      { role: "roles/run.invoker", members: ["allUsers"] },
      { ...CONDITIONAL, members: ["allUsers", "user:a@b.c"] },
    ],
  });
  assert.equal(out.ok, true);
  assert.deepEqual(out.policy, {
    version: 3,
    etag: "e",
    bindings: [{ ...CONDITIONAL, members: ["user:a@b.c"] }],
  });
});

test("a policy shape the write could not keep is refused before anything is sent", async () => {
  const shapes = [
    ["a field beyond version, etag and bindings", { auditConfigs: [] }, "policy-fields"],
  ];
  for (const [label, extra, why] of shapes) {
    const { journal, result } = await go({}, (send, w) => async (request) => {
      if (
        request.method === "GET" &&
        request.url.endsWith(":getIamPolicy") &&
        request.url.includes("run.googleapis") &&
        w.policy
      )
        return reply(200, { ...w.policy, ...extra });
      return send(request);
    });
    assert.equal(result.cleanup.invoker.refused, why, label);
    assert.equal(result.cleanup.invoker.removed, false, label);
    assert.ok(!journal.some((r) => r.id === "cleanup-remove-invoker"), label);
    assert.ok(result.cleanup.invoker.allUsers, label);
  }
  for (const [label, policy, why] of [
    ["not an object", [], "policy-not-an-object"],
    ["bindings not a list", { bindings: {} }, "bindings-not-a-list"],
    [
      "a binding field",
      { bindings: [{ role: "roles/x", members: ["allUsers"], extra: 1 }] },
      "binding-shape",
    ],
    ["members not text", { bindings: [{ role: "roles/x", members: [5] }] }, "binding-shape"],
    ["a role that is not text", { bindings: [{ role: 5, members: [] }] }, "binding-shape"],
    ["members missing", { bindings: [{ role: "roles/x" }] }, "binding-shape"],
    [
      "allAuthenticatedUsers",
      { bindings: [{ role: "roles/x", members: ["allUsers", "allAuthenticatedUsers"] }] },
      "binding-shape",
    ],
    [
      "a condition that is not an object",
      { bindings: [{ role: "roles/x", members: ["allUsers"], condition: "c" }] },
      "binding-shape",
    ],
    ["a null binding", { bindings: [null] }, "binding-shape"],
  ])
    assert.deepEqual(withoutPublicMember(policy), { ok: false, why }, label);
  assert.deepEqual(withoutPublicMember({}), { ok: true, policy: { bindings: [] } });
  assert.deepEqual(withoutPublicMember({ version: 1.5, etag: 5, bindings: [] }), {
    ok: true,
    policy: { bindings: [] },
  });
});

// ---- Should: services paging, signed URLs after a space ------------------------------------------------------------------

test("the enabled services are read page by page in the run, before and after", async () => {
  const { result, journal, world } = await go({ servicePageSize: 3 });
  const reads = journal
    .filter((r) => r.state === "before-send" && r.id.startsWith("services-"))
    .map((r) => r.id);
  assert.ok(
    reads.includes("services-before-page-2") && reads.includes("services-after-page-2"),
    reads.join(),
  );
  assert.deepEqual(result.inventory.differences, []);
  assert.equal(result.outcome, "pcblock-recorded");
  assert.ok(world.services.size > 3);
});

test("the signed upload query of the real CLI line, which follows a space, is redacted too", () => {
  const line = `[2026-11-04T01:02:03.000Z] >>> [apiv2][query] PUT https://storage.googleapis.com/gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com/514cacbe-3258-46fd-9a02-54b7485b11c1.zip GoogleAccessId=service-123456789012%40gcf-admin-robot.iam.gserviceaccount.com&Expires=1792000000&Signature=AbC%2Bdef%3D%3D`;
  const out = redactCliText(line);
  assert.ok(!/Signature=AbC|GoogleAccessId=service/.test(out), out);
  assert.ok(out.includes("514cacbe-3258-46fd-9a02-54b7485b11c1.zip"), "the object name stays");
  assert.ok(out.includes("Expires=1792000000"));
  const directory = tempDir("pcb-amb-");
  writeFileSync(join(directory, "cli-deploy-stdout.txt"), line + "\n");
  writeFileSync(join(directory, "cli-deploy-stderr.txt"), "");
  withCliLog({ action: "deploy" }, directory);
  assert.ok(!/Signature=AbC/.test(readFileSync(join(directory, "cli-deploy-stdout.txt"), "utf8")));
  assert.equal(FUNCTION, "pcblock");
});
