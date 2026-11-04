// The public invoker the CLI adds to a blocking function's Cloud Run service: the service's policy is read before the
// delete, `allUsers` alone is removed (one write, never re-sent) and read back, so that a failed delete cannot leave a public
// service. What was found is part of the result.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, policyWithoutPublicMembers } from "./guard.mjs";
import { FUNCTION, PROJECT, REGION } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SERVICE = (verb) =>
  `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services/${FUNCTION}:${verb}IamPolicy`;
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
const writes = (journal) =>
  journal.filter((r) => r.state === "before-send" && r.id === "cleanup-remove-invoker");

test("the public invoker is removed alone, after the account and before the function delete, and read back", async () => {
  const { result, journal, world } = await go();
  assert.equal(result.cleanup.invoker.allUsers, true);
  assert.deepEqual(result.cleanup.invoker.invokers, ["allUsers"]);
  assert.equal(result.cleanup.invoker.removeClass, "2xx");
  assert.equal(result.cleanup.invoker.removed, true);
  const [write] = writes(journal);
  assert.equal(write.url, SERVICE("set"));
  assert.deepEqual(write.json, { policy: { version: 1, etag: "etag-1", bindings: [] } });
  const order = ids(journal);
  assert.ok(order.indexOf("cleanup-account-delete") < order.indexOf("cleanup-invoker-policy"));
  assert.ok(order.indexOf("cleanup-invoker-policy") < order.indexOf("cleanup-remove-invoker"));
  assert.ok(order.indexOf("cleanup-remove-invoker") < order.indexOf("cleanup-invoker-readback"));
  assert.ok(order.indexOf("cleanup-invoker-readback") < order.indexOf("cleanup-1-functions-v2"));
  assert.equal(world.cliRuns.at(-1), "delete");
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, true);
});

test("a service without a public invoker is only read: the finding is recorded and nothing is written", async () => {
  const { result, journal } = await go({ publicInvoker: false });
  assert.deepEqual(result.cleanup.invoker, { invokers: [], allUsers: false });
  assert.equal(writes(journal).length, 0);
  assert.equal(
    ids(journal).filter((id) => id === "cleanup-invoker-readback").length,
    0,
    "nothing was removed, nothing is read back",
  );
  assert.equal(result.cleanup.verified, true);
});

test("other members and other roles stay in the written policy", async () => {
  const { journal, result } = await go({}, (send, w) => async (request) => {
    if (request.url === SERVICE("get") && w.policy && w.policy.bindings.length === 1)
      w.policy.bindings.push(
        { role: "roles/run.invoker", members: ["allUsers", "user:a@example.com"] },
        { role: "roles/viewer", members: ["user:b@example.com"] },
      );
    return send(request);
  });
  assert.deepEqual(writes(journal)[0].json.policy.bindings, [
    { role: "roles/run.invoker", members: ["user:a@example.com"] },
    { role: "roles/viewer", members: ["user:b@example.com"] },
  ]);
  assert.equal(result.cleanup.invoker.removed, true);
});

test("the write is never re-sent: an unknown answer keeps the run open, a conflict is recorded, the delete still runs", async () => {
  const unknown = await go({}, (send) => async (request) => {
    if (request.method === "POST" && request.url.endsWith(":setIamPolicy")) {
      await send(request);
      return reply(503, { error: { code: 503, status: "UNAVAILABLE", message: "x" } });
    }
    return send(request);
  });
  assert.equal(writes(unknown.journal).length, 1);
  assert.equal(unknown.result.cleanup.invoker.removeClass, "unknown-status");
  assert.equal(unknown.result.cleanup.invoker.removed, true, "the read back shows it gone");
  assert.equal(unknown.result.closureReady, false);
  assert.equal(unknown.world.cliRuns.at(-1), "delete");
  const conflict = await go(
    {},
    (send) => async (request) =>
      request.method === "POST" && request.url.endsWith(":setIamPolicy")
        ? reply(409, { error: { code: 409, status: "ABORTED", message: "etag" } })
        : send(request),
  );
  assert.equal(conflict.result.cleanup.invoker.removeClass, "4xx");
  assert.equal(conflict.result.cleanup.invoker.removed, false);
  assert.equal(conflict.world.cliRuns.at(-1), "delete");
  assert.equal(writes(conflict.journal).length, 1);
});

test("a policy that cannot be read is recorded, nothing is written, and the cleanup goes on", async () => {
  const { result, journal, world } = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url === SERVICE("get") && request.url
        ? reply(500, { error: { code: 500, status: "INTERNAL", message: "x" } })
        : send(request),
  );
  assert.deepEqual(result.cleanup.invoker, { read: "unknown-status" });
  assert.equal(writes(journal).length, 0);
  assert.equal(world.cliRuns.at(-1), "delete");
});

test("nothing is read or written when the deploy never ran", async () => {
  const { result, journal } = await go(
    {},
    (send) => async (request) =>
      request.url.includes("serviceusage")
        ? reply(500, { error: { code: 500, status: "INTERNAL", message: "x" } })
        : send(request),
  );
  assert.equal(result.cleanup.invoker, undefined);
  assert.equal(writes(journal).length, 0);
});

test("the guard allows the policy write only on this function's service, only as a removal", () => {
  const g = createGuard(RUN, NUMBER);
  const set = (json, url = SERVICE("set")) => ({ method: "POST", url, json });
  const policy = {
    version: 1,
    etag: "e",
    bindings: [{ role: "roles/run.invoker", members: ["user:a@b.c"] }],
  };
  assert.equal(g.allow(set({ policy })), true);
  assert.equal(g.isMutation(set({ policy })), true);
  assert.equal(g.allow({ method: "GET", url: SERVICE("get") }), true);
  assert.equal(g.isMutation({ method: "GET", url: SERVICE("get") }), false);
  assert.equal(g.allow(set({ policy }, SERVICE("set").replace(FUNCTION, "another"))), false);
  assert.equal(g.allow({ method: "PUT", url: SERVICE("set"), json: { policy } }), false);
  assert.equal(g.allow(set({ policy }, SERVICE("set") + "?x=1")), false);
  assert.equal(g.allow({ method: "POST", url: SERVICE("get"), json: {} }), false);
  assert.equal(
    g.allow(set({ policy: { bindings: [{ role: "roles/run.invoker", members: ["allUsers"] }] } })),
    false,
  );
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
