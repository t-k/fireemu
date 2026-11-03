import "./storage-signed-put/test-preload.mjs";

// Packet v4 fixes: the role is kept whenever the final policy still references it, in any
// spelling (Codex delta review of v3), in the run's removal and in the standalone removal.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { roleCreateOutcome } from "./storage-signed-put/iam.mjs";
import { observe, removeSignerAccess } from "./storage-signed-put/observe.mjs";
import { ROLE_ID } from "./storage-signed-put/plan.mjs";
import {
  IAM_CONFIG,
  PRODUCTION_LIKE,
  createFakeWorld,
  createVirtualClock,
  memoryOut,
} from "./storage-signed-put/world.fake.mjs";

const RUN = "sp-0123abcd";
const ROLE_KEY = `projects/${PRODUCTION_LIKE.project}/roles/${ROLE_ID}`;
const urlOf = (entry) => new URL(entry.url).pathname;
const isSignerPolicyRead = (request) =>
  request.method === "POST" && urlOf(request).endsWith(`${PRODUCTION_LIKE.signer}:getIamPolicy`);
const roleDeletes = (world) =>
  world.log.filter((e) => e.method === "DELETE" && urlOf(e).endsWith(`/roles/${ROLE_ID}`));

// A foreign binding of the signer role that shows up in the policy after the removal wrote it.
const FOREIGN = {
  plain: { role: ROLE_KEY, members: ["user:someone@example.com"] },
  withcond: { role: `${ROLE_KEY}_withcond_0a1b2c3d`, members: ["user:someone@example.com"] },
};
const answer = (world, binding) => ({
  status: 200,
  body: Buffer.from(
    JSON.stringify({ version: 1, etag: world.iam.policy.etag, bindings: [binding] }),
  ),
});

describe("the role is kept while the final policy references it", () => {
  for (const [label, binding] of Object.entries(FOREIGN)) {
    it(`in the run's removal, for a ${label} foreign binding in the final read`, async () => {
      let reads = 0;
      const clock = createVirtualClock();
      const world = createFakeWorld({
        target: PRODUCTION_LIKE,
        clock,
        intercept: (request) =>
          isSignerPolicyRead(request) && (reads += 1) === 4 ? answer(world, binding) : undefined,
      });
      const { report } = await observe({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps: world.deps,
        out: memoryOut(),
        iam: IAM_CONFIG,
      });
      assert.equal(roleDeletes(world).length, 0, "the role must not be deleted");
      assert.equal(report.iam.bindingStillPresent, true);
      assert.equal(report.iam.roleDeleted, null);
      assert.equal(report.closureReady, false);
      assert.ok(report.unresolved.some((u) => u.reason === "created, not deleted"));
      assert.ok(report.unresolved.some((u) => u.name === "signer policy"));
    });

    it(`in the standalone removal, for a ${label} foreign binding in the final read`, async () => {
      // A run whose removal answer was unknown, leaving the binding and the role.
      const clock = createVirtualClock();
      const world = createFakeWorld({ target: PRODUCTION_LIKE, clock });
      const net = world.deps.net;
      const out = memoryOut();
      await observe({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps: {
          ...world.deps,
          net: async (request) =>
            urlOf(request).endsWith(":setIamPolicy") &&
            world.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length === 1
              ? { status: 503, headers: {}, body: Buffer.alloc(0) }
              : net(request),
        },
        out,
        iam: IAM_CONFIG,
      });
      assert.equal(roleDeletes(world).length, 0);
      let reads = 0;
      const report = await removeSignerAccess({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps: {
          ...world.deps,
          net: async (request) =>
            isSignerPolicyRead(request) && (reads += 1) === 2
              ? answer(world, binding)
              : net(request),
        },
        out: memoryOut(),
        preflight: out.saved.get("iam-preflight.json"),
        plan: out.saved.get("iam-grant-plan.json"),
      });
      assert.equal(roleDeletes(world).length, 0, "the role must not be deleted");
      assert.equal(report.bindingPresent, true);
      assert.equal(report.roleDeleted, null);
      assert.equal(report.clean, false);
    });
  }

  it("still deletes the role when the final policy holds no binding of it", async () => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    const { report } = await observe({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
      iam: IAM_CONFIG,
    });
    assert.equal(roleDeletes(world).length, 1);
    assert.equal(report.iam.roleDeleted, true);
    assert.equal(report.closureReady, true);
  });
});

const respond = (status, body = "{}") => ({ status, body: Buffer.from(body) });
const isRoleCreate = (request) => request.method === "POST" && urlOf(request).endsWith("/roles");

async function stuckRun(createFault) {
  // A run whose removal answer was unknown, so the binding (and the role, if made) remain.
  const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
  const net = world.deps.net;
  const out = memoryOut();
  const sets = () => world.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length;
  await observe({
    target: PRODUCTION_LIKE,
    runId: RUN,
    deps: {
      ...world.deps,
      net: async (request) => {
        if (isRoleCreate(request) && createFault) return createFault(request, net);
        if (urlOf(request).endsWith(":setIamPolicy") && sets() === 1) return respond(503);
        return net(request);
      },
    },
    out,
    iam: IAM_CONFIG,
  });
  return { world, out, net };
}

describe("the standalone removal deletes only a role this run made (Opus S1)", () => {
  it("reads the role create outcome from the run's journal", async () => {
    const outcome = async (fault) => roleCreateOutcome((await stuckRun(fault)).out.entries);
    assert.equal(await outcome(undefined), "created");
    assert.equal(await outcome(() => respond(409)), "refused");
    assert.equal(await outcome(() => respond(403)), "refused");
    assert.equal(await outcome((request, net) => net(request).then(() => respond(503))), "unknown");
    assert.equal(await outcome(() => "transport"), "unknown");
    assert.equal(roleCreateOutcome([]), "none");
    assert.equal(roleCreateOutcome([{ phase: "before", label: "role-create" }]), "unknown");
    assert.equal(roleCreateOutcome([{ phase: "before", label: "bucket" }]), "none");
  });

  for (const outcome of ["refused", "none"]) {
    it(`keeps the role and says so when the run's role create was ${outcome}`, async () => {
      const { world, out } = await stuckRun();
      const report = await removeSignerAccess({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps: world.deps,
        out: memoryOut(),
        preflight: out.saved.get("iam-preflight.json"),
        plan: out.saved.get("iam-grant-plan.json"),
        roleCreate: outcome,
      });
      assert.equal(roleDeletes(world).length, 0, "a role the run did not make is not deleted");
      assert.equal(report.roleDeleted, null);
      assert.equal(report.roleKept, true);
      assert.equal(report.roleCreate, outcome);
      assert.equal(report.bindingPresent, false, "the binding itself is still removed");
    });
  }

  for (const outcome of ["created", "unknown"]) {
    it(`deletes the role when the run's role create was ${outcome}`, async () => {
      const { world, out } = await stuckRun();
      const report = await removeSignerAccess({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps: world.deps,
        out: memoryOut(),
        preflight: out.saved.get("iam-preflight.json"),
        plan: out.saved.get("iam-grant-plan.json"),
        roleCreate: outcome,
      });
      assert.equal(roleDeletes(world).length, 1);
      assert.equal(report.roleDeleted, true);
      assert.equal(report.roleKept, false);
      assert.equal(report.clean, true);
    });
  }

  it("fails closed when the outcome is not given", async () => {
    const { world, out } = await stuckRun();
    const report = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
      preflight: out.saved.get("iam-preflight.json"),
      plan: out.saved.get("iam-grant-plan.json"),
    });
    assert.equal(roleDeletes(world).length, 0);
    assert.equal(report.roleKept, true);
  });
});
