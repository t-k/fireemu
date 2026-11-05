// Packet v3 fixes for the signer access (presend reviews of v2): the documented request form of
// serviceAccounts.getIamPolicy, removal that fails closed on any binding of the signer role, a
// valid etag before every policy write, and lower-case members only.

import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { GuardError, classifyRequest } from "./storage-signed-put/guard.mjs";
import {
  IamStop,
  assertGrantShape,
  assertRemovalShape,
  ourBinding,
  validateMember,
  withBinding,
  withoutBinding,
} from "./storage-signed-put/iam.mjs";
import { observe, readbackIam, removeSignerAccess } from "./storage-signed-put/observe.mjs";
import { ROLE_ID, runPrefix } from "./storage-signed-put/plan.mjs";
import {
  IAM_CONFIG,
  PRODUCTION_LIKE,
  createFakeWorld,
  createVirtualClock,
  memoryOut,
} from "./storage-signed-put/world.fake.mjs";

const RUN = "sp-0123abcd";
const ROLE_KEY = `projects/${PRODUCTION_LIKE.project}/roles/${ROLE_ID}`;
const SA = `https://iam.googleapis.com/v1/projects/${PRODUCTION_LIKE.project}/serviceAccounts/${PRODUCTION_LIKE.signer}`;
const prefix = runPrefix(RUN);
const kind = (request) => classifyRequest(PRODUCTION_LIKE, request, prefix);
const respond = (status, body = "{}") => ({ status, body: Buffer.from(body) });
const urlOf = (entry) => new URL(entry.url).pathname;

async function go({ intercept, iam, mutateDeps, setup } = {}) {
  const clock = createVirtualClock();
  const world = createFakeWorld({
    target: PRODUCTION_LIKE,
    clock,
    iam,
    intercept: intercept ? (request, log) => intercept(request, log, world) : undefined,
  });
  setup?.(world);
  const out = memoryOut();
  const deps = mutateDeps ? mutateDeps(world.deps, world) : world.deps;
  const result = await observe({ target: PRODUCTION_LIKE, runId: RUN, deps, out, iam: IAM_CONFIG });
  return { ...result, world, out };
}

describe("getIamPolicy request form (Opus M1)", () => {
  const get = (suffix = "", extra = {}) => ({
    method: "POST",
    url: `${SA}:getIamPolicy${suffix}`,
    ...extra,
  });

  it("the guard allows exactly options.requestedPolicyVersion=3 and an empty body", () => {
    assert.equal(kind(get("?options.requestedPolicyVersion=3")), "signer-get-policy");
    assert.equal(
      kind(get("?options.requestedPolicyVersion=3", { body: Buffer.alloc(0) })),
      "signer-get-policy",
    );
    for (const bad of [
      get(),
      get("?options.requestedPolicyVersion=1"),
      get("?options.requestedPolicyVersion=2"),
      get("?options.requestedPolicyVersion=4"),
      get("?options.requestedPolicyVersion=3.0"),
      get("?options.requestedPolicyVersion="),
      get("?options.requestedPolicyVersion=3&x=1"),
      get("?options.requestedPolicyVersion=3&options.requestedPolicyVersion=3"),
      get("?options%2ErequestedPolicyVersion=3&alt=json"),
      get("?requestedPolicyVersion=3"),
      get("?options.requestedPolicyVersion=3", {
        body: Buffer.from('{"options":{"requestedPolicyVersion":3}}'),
      }),
      get("?options.requestedPolicyVersion=3", { body: "{}" }),
    ]) {
      assert.throws(() => kind(bad), GuardError, bad.url + (bad.body ? " with body" : ""));
    }
    assert.throws(
      () => kind({ method: "POST", url: `${SA}:setIamPolicy?options.requestedPolicyVersion=3` }),
      GuardError,
    );
  });

  it("every signer policy read of a run carries the query and no body", async () => {
    const reads = [];
    await go({
      intercept: (request) => {
        if (
          urlOf(request).endsWith("serviceAccounts/" + PRODUCTION_LIKE.signer + ":getIamPolicy")
        ) {
          reads.push([new URL(request.url).search, request.body]);
        }
        return undefined;
      },
    });
    assert.equal(reads.length, 4, "preflight, read-back, removal read, final read");
    for (const [search, body] of reads) {
      assert.equal(search, "?options.requestedPolicyVersion=3");
      assert.ok(body === undefined || body.length === 0);
    }
  });

  it("the fake serves the version 1 view with a _withcond_ role and no condition when the form is wrong", async () => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    world.iam.policy = {
      etag: "e1",
      bindings: [
        {
          role: ROLE_KEY,
          members: [IAM_CONFIG.member],
          condition: { title: "t", expression: "e" },
        },
      ],
    };
    const read = async (suffix, body) => {
      const response = await world.deps.net({
        method: "POST",
        url: `${SA}:getIamPolicy${suffix}`,
        headers: { authorization: "Bearer fake" },
        body,
      });
      return JSON.parse(response.body.toString());
    };
    const right = await read("?options.requestedPolicyVersion=3");
    assert.deepEqual(right.bindings[0].condition, { title: "t", expression: "e" });
    assert.equal(right.bindings[0].role, ROLE_KEY);
    for (const wrong of [
      await read(""),
      await read("", Buffer.from('{"options":{"requestedPolicyVersion":3}}')),
    ]) {
      assert.equal(wrong.version, 1);
      assert.match(wrong.bindings[0].role, new RegExp(`^${ROLE_KEY}_withcond_[0-9a-f]+$`));
      assert.equal(wrong.bindings[0].condition, undefined);
    }
  });
});

describe("removal fails closed on any binding of the signer role (Opus M1.4)", () => {
  const foreign = (members = [IAM_CONFIG.member]) => ({
    role: `${ROLE_KEY}_withcond_0a1b2c`,
    members,
  });

  it("stops when the preflight policy already holds a _withcond_ form of the role", async () => {
    const { report, world } = await go({
      iam: { initialPolicy: { etag: "e0", bindings: [foreign()] } },
    });
    assert.match(report.stopped, /already holds the signer role/);
    assert.equal(
      world.log.some((e) => e.method === "POST" && urlOf(e).endsWith("/roles")),
      false,
    );
  });

  it("writes nothing and keeps the role when the removal read shows a binding it cannot match", async () => {
    let afterGrant = false;
    const { report, world } = await go({
      intercept: (request, log, w) => {
        const path = urlOf(request);
        if (path.endsWith(":setIamPolicy")) afterGrant = true;
        else if (
          afterGrant &&
          path.endsWith(":getIamPolicy") &&
          !path.includes("cloudresourcemanager")
        ) {
          const reads = log.filter(
            (e) => urlOf(e).endsWith(":getIamPolicy") && e.url.includes("serviceAccounts"),
          ).length;
          if (reads >= 3) {
            // the removal read comes back in the version 1 view
            return respond(
              200,
              JSON.stringify({ version: 1, etag: w.iam.policy.etag, bindings: [foreign()] }),
            );
          }
        }
        return undefined;
      },
    });
    const sets = world.log.filter((e) => urlOf(e).endsWith(":setIamPolicy"));
    console.log(
      "DBG",
      sets.length,
      JSON.stringify(report.unresolved),
      report.stopped,
      world.log.filter((e) => e.method === "DELETE").map((e) => e.url.slice(-40)),
    );
    assert.equal(sets.length, 1, "only the grant was written");
    assert.equal(
      world.log.filter((e) => e.method === "DELETE" && urlOf(e).includes("/roles/")).length,
      0,
    );
    assert.ok(
      report.unresolved.some((u) => /signer role|binding/.test(u.name)),
      JSON.stringify(report.unresolved),
    );
    assert.equal(report.closureReady, false);
    assert.equal(report.cleanupVerified, false);
  });

  it("A2 reads a _withcond_ binding of the role as present", async () => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    world.iam.policy = { etag: "e1", bindings: [foreign()] };
    const report = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
      preflight: { policy: { etag: "e0" } },
    });
    assert.equal(report.bindingPresent, true);
    assert.equal(report.clean, false);
  });

  it("the standalone removal refuses to write over a binding it cannot match", async () => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    world.iam.policy = { etag: "e1", bindings: [foreign()] };
    const ours = ourBinding({
      project: PRODUCTION_LIKE.project,
      member: IAM_CONFIG.member,
      runId: RUN,
      endMs: Date.UTC(2026, 10, 3, 13),
    });
    const report = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
      preflight: { policy: { etag: "e0" } },
      plan: { binding: ours },
    });
    assert.equal(report.clean, false);
    assert.match(report.error, /signer role/);
    assert.equal(world.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length, 0);
  });
});

describe("a valid etag before every policy write (Codex 3)", () => {
  const ours = ourBinding({
    project: PRODUCTION_LIKE.project,
    member: IAM_CONFIG.member,
    runId: RUN,
    endMs: Date.UTC(2026, 10, 3, 13),
  });

  it("the shape checks refuse a missing, empty or non-string etag", () => {
    for (const etag of [undefined, null, "", 0, {}, 7]) {
      const before = { version: 1, bindings: [], ...(etag === undefined ? {} : { etag }) };
      const granted = { ...withBinding(before, ours), etag: before.etag };
      assert.throws(() => assertGrantShape(before, granted, ours), GuardError, String(etag));
      const withIt = { ...withBinding({ ...before, etag: "x" }, ours) };
      const removal = { ...withoutBinding(withIt, ours), etag: withIt.etag };
      assert.doesNotThrow(() => assertRemovalShape(withIt, removal, ours));
      assert.throws(
        () => assertRemovalShape({ ...withIt, etag }, { ...removal, etag }, ours),
        GuardError,
        String(etag),
      );
    }
  });

  it("stops before any change when the preflight policy has no etag", async () => {
    const { report, world } = await go({
      intercept: (request) => {
        if (
          urlOf(request).endsWith(`${PRODUCTION_LIKE.signer}:getIamPolicy`) &&
          request.method === "POST"
        ) {
          return respond(200, JSON.stringify({ version: 1 }));
        }
        return undefined;
      },
    });
    assert.match(report.stopped, /etag/);
    assert.equal(
      world.log.some(
        (e) =>
          urlOf(e).endsWith(":setIamPolicy") ||
          (e.method === "POST" && urlOf(e).endsWith("/roles")),
      ),
      false,
    );
  });

  it("stops the removal, writing nothing, when the policy it reads has no etag", async () => {
    let reads = 0;
    const { report, world } = await go({
      intercept: (request) => {
        if (
          urlOf(request).endsWith(`${PRODUCTION_LIKE.signer}:getIamPolicy`) &&
          (reads += 1) === 3
        ) {
          return respond(200, JSON.stringify({ version: 3, bindings: [] }));
        }
        return undefined;
      },
    });
    assert.equal(world.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length, 1);
    assert.ok(
      report.unresolved.some((u) => /removal failed: .*etag/.test(u.reason)),
      JSON.stringify(report.unresolved),
    );
    assert.equal(report.closureReady, false);
  });
});

describe("member case (Opus S1)", () => {
  it("accepts only a lower-case member email", () => {
    assert.equal(validateMember("user:owner@example.com"), "user:owner@example.com");
    for (const bad of [
      "user:Owner@example.com",
      "user:owner@Example.com",
      "user:OWNER@EXAMPLE.COM",
      "user:owner@example.COM",
    ]) {
      assert.throws(() => validateMember(bad), GuardError, bad);
    }
    assert.ok(IamStop);
  });
});
