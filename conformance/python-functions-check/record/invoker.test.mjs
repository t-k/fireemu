// The public invoker the CLI may add to a function's Cloud Run service: every service of the run is read before the delete,
// `allUsers` alone is removed (one write per service, never re-sent) and read back, so that a failed delete cannot leave a
// public service. What was found is part of the result.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, policyWithoutPublicMembers } from "./guard.mjs";
import { ALL_FUNCTIONS, PROJECT, REGION } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SERVICE = (fn, verb) =>
  `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services/${fn}:${verb}IamPolicy`;
async function go(worldOptions = {}, wrapSend = (send) => send) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: wrapSend(world.send, world),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  return { world, journal, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const bodies = (journal, prefix) =>
  journal
    .filter((r) => r.state === "before-send" && r.id.startsWith(prefix))
    .map((r) => ({ id: r.id, url: r.url, json: r.json }));

test("a service without a public invoker is only read: the finding is recorded and nothing is written", async () => {
  const { result, journal } = await go();
  assert.deepEqual(Object.keys(result.cleanup.invoker).toSorted(), [...ALL_FUNCTIONS].toSorted());
  for (const fn of ALL_FUNCTIONS) assert.equal(result.cleanup.invoker[fn].allUsers, false, fn);
  assert.deepEqual(result.cleanup.invoker.pcsch.invokers, [
    `serviceAccount:${NUMBER}-compute@developer.gserviceaccount.com`,
  ]);
  assert.deepEqual(result.cleanup.invoker.pcps.invokers, []);
  assert.equal(bodies(journal, "cleanup-remove-invoker").length, 0);
  assert.equal(result.cleanup.verified, true);
});

test("a public invoker is removed alone, before the function delete, and read back; other members stay", async () => {
  const { result, journal, world } = await go({ publicInvokers: ["pcps"] });
  assert.equal(result.cleanup.invoker.pcps.allUsers, true);
  assert.equal(result.cleanup.invoker.pcps.removeClass, "2xx");
  assert.equal(result.cleanup.invoker.pcps.removed, true);
  const writes = bodies(journal, "cleanup-remove-invoker");
  assert.deepEqual(
    writes.map((w) => w.id),
    ["cleanup-remove-invoker-pcps"],
    "pcsch has no allUsers: one write only",
  );
  assert.equal(writes[0].url, SERVICE("pcps", "set"));
  assert.deepEqual(writes[0].json, {
    policy: { version: 1, etag: "etag-pcps-1", bindings: [] },
  });
  const order = ids(journal);
  assert.ok(
    order.indexOf("cleanup-invoker-readback-pcps") > order.indexOf("cleanup-remove-invoker-pcps"),
  );
  assert.ok(order.indexOf("cleanup-remove-invoker-pcps") < order.indexOf("cleanup-1-functions-v2"));
  assert.equal(world.cliRuns.at(-1), "delete");
  assert.equal(result.cleanup.verified, true);
});

test("a service that has other members besides allUsers keeps them in the written policy", async () => {
  const { journal, result } = await go(
    { publicInvokers: ["pcsch"] },
    (send, w) => async (request) => {
      if (request.url === SERVICE("pcsch", "get") && w.policies.has("pcsch")) {
        const bindings = w.policies.get("pcsch").bindings;
        if (bindings.length === 1)
          bindings.push(
            { role: "roles/run.invoker", members: ["allUsers", "user:a@example.com"] },
            { role: "roles/viewer", members: ["user:b@example.com"] },
          );
      }
      return send(request);
    },
  );
  const [write] = bodies(journal, "cleanup-remove-invoker");
  assert.deepEqual(write.json.policy.bindings, [
    { role: "roles/run.invoker", members: ["user:a@example.com"] },
    { role: "roles/viewer", members: ["user:b@example.com"] },
  ]);
  assert.equal(result.cleanup.invoker.pcsch.removed, true);
});

test("the write is never re-sent: an unknown answer keeps the run open, a conflict is recorded, the delete still runs", async () => {
  const unknown = await go({ publicInvokers: ["pcps"] }, (send) => async (request) => {
    if (request.method === "POST" && request.url.endsWith(":setIamPolicy")) {
      await send(request);
      return reply(503, { error: { code: 503, status: "UNAVAILABLE", message: "x" } });
    }
    return send(request);
  });
  assert.equal(bodies(unknown.journal, "cleanup-remove-invoker").length, 1);
  assert.equal(unknown.result.cleanup.invoker.pcps.removeClass, "unknown-status");
  assert.equal(unknown.result.cleanup.invoker.pcps.removed, true, "the read back shows it gone");
  assert.equal(unknown.result.closureReady, false);
  assert.equal(unknown.world.cliRuns.at(-1), "delete");
  const conflict = await go(
    { publicInvokers: ["pcps"] },
    (send) => async (request) =>
      request.method === "POST" && request.url.endsWith(":setIamPolicy")
        ? reply(409, { error: { code: 409, status: "ABORTED", message: "etag" } })
        : send(request),
  );
  assert.equal(conflict.result.cleanup.invoker.pcps.removeClass, "4xx");
  assert.equal(conflict.result.cleanup.invoker.pcps.removed, false);
  assert.equal(conflict.world.cliRuns.at(-1), "delete");
  assert.equal(bodies(conflict.journal, "cleanup-remove-invoker").length, 1);
});

test("a policy that cannot be read is recorded, nothing is written, and the cleanup goes on", async () => {
  const { result, journal, world } = await go(
    { publicInvokers: ["pcps"] },
    (send) => async (request) =>
      request.method === "GET" && request.url === SERVICE("pcps", "get")
        ? reply(500, { error: { code: 500, status: "INTERNAL", message: "x" } })
        : send(request),
  );
  assert.deepEqual(result.cleanup.invoker.pcps, { read: "unknown-status" });
  assert.equal(bodies(journal, "cleanup-remove-invoker").length, 0);
  assert.equal(world.cliRuns.at(-1), "delete");
});

test("no policy is read for a service that is not there, and none before the deploy", async () => {
  const { result, journal } = await go({ failDeploy: true });
  assert.deepEqual(result.cleanup.invoker, {});
  assert.equal(ids(journal).filter((id) => id.startsWith("cleanup-invoker-policy")).length, 0);
});

test("the guard allows the policy write only on this run's services, only as a removal", () => {
  const g = createGuard(RUN, NUMBER);
  const set = (fn, json) => ({ method: "POST", url: SERVICE(fn, "set"), json });
  const policy = {
    version: 1,
    etag: "e",
    bindings: [{ role: "roles/run.invoker", members: ["user:a@b.c"] }],
  };
  assert.equal(g.allow(set("pcps", { policy })), true);
  assert.equal(g.isMutation(set("pcps", { policy })), true);
  assert.equal(g.allow({ method: "GET", url: SERVICE("pcps", "get") }), true);
  assert.equal(g.allow(set("another", { policy })), false);
  assert.equal(g.allow({ method: "GET", url: SERVICE("another", "get") }), false);
  assert.equal(g.allow({ method: "PUT", url: SERVICE("pcps", "set"), json: { policy } }), false);
  assert.equal(
    g.allow({ method: "POST", url: SERVICE("pcps", "set") + "?x=1", json: { policy } }),
    false,
  );
  assert.equal(g.allow({ method: "POST", url: SERVICE("pcps", "get"), json: {} }), false);
});

test("the policy body can only remove: no public member, no condition, no unknown key", () => {
  const ok = {
    policy: {
      version: 1,
      etag: "e",
      bindings: [{ role: "roles/run.invoker", members: ["user:a@b.c"] }],
    },
  };
  assert.equal(policyWithoutPublicMembers(ok), true);
  assert.equal(policyWithoutPublicMembers({ policy: { bindings: [] } }), true);
  assert.equal(policyWithoutPublicMembers({ policy: {} }), true);
  const withMember = (m) => ({
    policy: { bindings: [{ role: "roles/run.invoker", members: [m] }] },
  });
  for (const m of ["allUsers", "allAuthenticatedUsers"])
    assert.equal(policyWithoutPublicMembers(withMember(m)), false, m);
  assert.equal(policyWithoutPublicMembers(withMember("user:allUsers")), true);
  for (const bad of [
    undefined,
    null,
    [],
    {},
    { policy: null },
    { policy: [] },
    { policy: "x" },
    { ...ok, updateMask: "bindings" },
    { policy: { ...ok.policy, auditConfigs: [] } },
    { policy: { ...ok.policy, etag: 1 } },
    { policy: { ...ok.policy, version: "1" } },
    { policy: { ...ok.policy, version: 1.5 } },
    { policy: { bindings: "x" } },
    { policy: { bindings: [null] } },
    { policy: { bindings: [{ role: "owner", members: [] }] } },
    { policy: { bindings: [{ role: 5, members: [] }] } },
    { policy: { bindings: [{ role: "roles/x" }] } },
    { policy: { bindings: [{ role: "roles/x", members: "u" }] } },
    { policy: { bindings: [{ role: "roles/x", members: [1] }] } },
    { policy: { bindings: [{ role: "roles/x", members: [], condition: {} }] } },
  ])
    assert.equal(policyWithoutPublicMembers(bad), false, JSON.stringify(bad));
});
