// The signer access steps of the observer against the fake IAM: the preflight that stops before
// any change, the grant, and the removal that must happen on every path, with the unknown-answer
// rules of the sandbox process.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { observe, readbackIam, removeSignerAccess } from "./storage-signed-put/observe.mjs";
import { CASES, ROLE_ID, runPrefix, staticBounds } from "./storage-signed-put/plan.mjs";
import { samePolicy } from "./storage-signed-put/iam.mjs";
import {
  IAM_CONFIG,
  PRODUCTION_LIKE,
  createFakeWorld,
  createVirtualClock,
  memoryOut,
} from "./storage-signed-put/world.fake.mjs";

const RUN = "sp-0123abcd";
const ROLE_KEY = `projects/${PRODUCTION_LIKE.project}/roles/${ROLE_ID}`;
const SA = `/v1/projects/${PRODUCTION_LIKE.project}/serviceAccounts/${PRODUCTION_LIKE.signer}`;
const OTHER = { role: "roles/viewer", members: ["user:viewer@example.com"] };

async function go({
  faults = {},
  intercept,
  iam,
  mutateDeps,
  setup,
  caps,
  iamInput = IAM_CONFIG,
} = {}) {
  const clock = createVirtualClock();
  const world = createFakeWorld({
    target: PRODUCTION_LIKE,
    clock,
    faults,
    iam,
    intercept: intercept ? (request, log) => intercept(request, log, world) : undefined,
  });
  setup?.(world);
  const out = memoryOut();
  const deps = mutateDeps ? mutateDeps(world.deps, world) : world.deps;
  const result = await observe({
    target: PRODUCTION_LIKE,
    runId: RUN,
    deps,
    out,
    caps,
    iam: iamInput,
  });
  return { ...result, world, out, clock };
}

const urlOf = (entry) => new URL(entry.url).pathname;
const sets = (world) => world.log.filter((e) => urlOf(e).endsWith(":setIamPolicy"));
const roleCreates = (world) =>
  world.log.filter((e) => e.method === "POST" && urlOf(e).endsWith("/roles"));
const roleDeletes = (world) =>
  world.log.filter((e) => e.method === "DELETE" && urlOf(e).endsWith(`/roles/${ROLE_ID}`));
const puts = (world) => world.log.filter((e) => e.method === "PUT");
const mutations = (world) => [...sets(world), ...roleCreates(world), ...roleDeletes(world)];
const unchanged = (world, initial = { etag: "etag-0" }) => samePolicy(world.iam.policy, initial);
const setNumber = (request, log) =>
  log.filter((e) => e.url === request.url && e.method === request.method).length;
const respond = (status, body = "{}") => ({ status, body: Buffer.from(body) });

describe("signer access: a clean run", () => {
  it("grants a signBlob-only role with a time condition, signs under it, and removes it all", async () => {
    const seen = [];
    const { report, world } = await go({
      intercept: (request, log, w) => {
        if (request.method === "PUT") seen.push(w.signerEnabled());
        return undefined;
      },
    });
    assert.equal(report.finished, true, report.stopped);
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
    assert.ok(seen.length > 0 && seen.every(Boolean), "every PUT was signed under the binding");
    assert.equal(world.signerEnabled(), false);
    assert.equal(unchanged(world), true);
    assert.equal(world.iam.roles.get(ROLE_KEY).deleted, true);
    assert.deepEqual(world.iam.roles.get(ROLE_KEY).includedPermissions, [
      "iam.serviceAccounts.signBlob",
    ]);
    assert.deepEqual(report.iam, {
      roleReads: 1,
      granted: true,
      signProbes: 1,
      policyEqualsPreflight: true,
      bindingStillPresent: false,
      roleDeleted: true,
      windowEnd: 'request.time < timestamp("2026-11-03T13:00:00Z")',
    });
  });

  it("changes IAM in this order only: role, binding, [recordings], binding removal, role removal", async () => {
    const { world } = await go();
    const order = world.log
      .map((e) => {
        const path = urlOf(e);
        if (e.method === "POST" && path.endsWith("/roles")) return "role-create";
        if (path.endsWith(":setIamPolicy")) return "policy-set";
        if (e.method === "DELETE" && path.includes("/roles/")) return "role-delete";
        if (e.method === "PUT") return "put";
        return null;
      })
      .filter(Boolean);
    const compact = order.filter((x, i) => x !== order[i - 1]);
    assert.deepEqual(compact, ["role-create", "policy-set", "put", "policy-set", "role-delete"]);
    const firstChange = world.log.findIndex(
      (e) => urlOf(e).endsWith("/roles") && e.method === "POST",
    );
    const reads = world.log.slice(0, firstChange).map((e) => `${e.method} ${urlOf(e)}`);
    for (const needle of [
      `${SA}:getIamPolicy`,
      `/roles/${ROLE_ID}`,
      ":getIamPolicy",
      "/iam",
      "/v1/roles/firebase.sdkAdminServiceAgent",
      "/o",
    ]) {
      assert.ok(
        reads.some((r) => r.includes(needle)),
        `${needle} was read before the first change`,
      );
    }
  });

  it("writes the binding for the given member with the window end, and the preflight policy file", async () => {
    const written = [];
    const { out } = await go({
      intercept: (request) => {
        if (new URL(request.url).pathname.endsWith(":setIamPolicy"))
          written.push(JSON.parse(Buffer.from(request.body).toString()));
        return undefined;
      },
    });
    assert.equal(written.length, 2);
    const grant = written[0].policy;
    assert.equal(grant.version, 3);
    assert.equal(grant.etag, "etag-0");
    assert.deepEqual(grant.bindings, [
      {
        role: ROLE_KEY,
        members: [IAM_CONFIG.member],
        condition: {
          title: "storage-signed-put-sp-0123abcd",
          description: "signBlob for the signed PUT observation; removed after the run",
          expression: 'request.time < timestamp("2026-11-03T13:00:00Z")',
        },
      },
    ]);
    assert.deepEqual(written[1].policy.bindings ?? [], []);
    assert.equal(written[1].policy.etag, "etag-1");
    assert.deepEqual(out.saved.get("iam-preflight.json").policy, { version: 1, etag: "etag-0" });
    assert.equal(out.saved.get("iam-grant-plan.json").binding.members[0], IAM_CONFIG.member);
  });

  it("uses the window for the end of the condition", async () => {
    const { out } = await go({ iamInput: { member: IAM_CONFIG.member, windowMinutes: 90 } });
    assert.match(
      out.saved.get("iam-grant-plan.json").binding.condition.expression,
      /2026-11-03T13:30:00Z/,
    );
  });

  it("refuses to start without valid IAM settings", async () => {
    await assert.rejects(go({ iamInput: null }), /needs the signer IAM settings/);
    await assert.rejects(
      go({ iamInput: { member: "allUsers", windowMinutes: 60 } }),
      /member must be/,
    );
    await assert.rejects(
      go({ iamInput: { member: IAM_CONFIG.member, windowMinutes: 1000 } }),
      /window must be/,
    );
  });
});

describe("signer access: the preflight stops before any change", () => {
  const stops = async (options, pattern, { verified = true } = {}) => {
    const { report, world, rows } = await go(options);
    assert.match(report.stopped, pattern);
    assert.deepEqual(mutations(world), [], "no IAM change was sent");
    assert.deepEqual(puts(world), []);
    assert.equal(rows.length, 0);
    assert.equal(report.cleanupVerified, verified, JSON.stringify(report.unresolved));
    assert.equal(report.closureReady, false);
    assert.equal(report.iam.signProbes, 0);
    assert.equal(report.iam.granted, false);
    assert.equal(report.iam.roleDeleted, null);
    assert.equal(report.iam.windowEnd, null);
    return world;
  };
  const bound = (role, extra = {}) => ({
    role,
    members: [`serviceAccount:${PRODUCTION_LIKE.signer}`],
    ...extra,
  });

  it("when the signer's policy already holds the signer role", async () => {
    const initialPolicy = {
      etag: "etag-0",
      bindings: [{ role: ROLE_KEY, members: ["user:someone@example.com"] }],
    };
    const world = await stops({ iam: { initialPolicy } }, /already holds the signer role/);
    assert.equal(world.iam.policy.etag, "etag-0");
  });

  it("when the signer role exists (live or deleted) or its read is refused", async () => {
    for (const deleted of [false, true]) {
      await stops(
        {
          setup: (w) =>
            w.iam.roles.set(ROLE_KEY, { name: ROLE_KEY, deleted, includedPermissions: [] }),
        },
        /not absent \(read answered 200\)/,
      );
    }
    await stops(
      {
        intercept: (r) =>
          r.method === "GET" && r.url.endsWith(`/roles/${ROLE_ID}`) ? respond(403) : undefined,
      },
      /not absent \(read answered 403\)/,
    );
  });

  it("when the signer account is another one, disabled, or unreadable", async () => {
    const answer =
      (body, status = 200) =>
      (r) =>
        r.method === "GET" && urlOf(r) === SA ? respond(status, JSON.stringify(body)) : undefined;
    await stops(
      { intercept: answer({ email: "other@demo-project.iam.gserviceaccount.com" }) },
      /signer service account not readable/,
    );
    await stops(
      { intercept: answer({ email: PRODUCTION_LIKE.signer, disabled: true }) },
      /signer service account not readable/,
    );
    await stops({ intercept: answer({}, 404) }, /signer service account not readable/);
  });

  it("when the signer's existing roles lack object create, get or delete, and grants nothing", async () => {
    for (const missing of [
      "storage.objects.create",
      "storage.objects.get",
      "storage.objects.delete",
    ]) {
      const permissions = [
        "storage.objects.create",
        "storage.objects.get",
        "storage.objects.delete",
      ].filter((p) => p !== missing);
      await stops(
        { iam: { predefinedRoles: { "firebase.sdkAdminServiceAgent": permissions } } },
        new RegExp(`lack ${missing.replaceAll(".", "\\.")}; nothing was granted`),
      );
    }
    await stops(
      { iam: { projectBindings: [] } },
      /\(none\) lack storage\.objects\.create, storage\.objects\.get, storage\.objects\.delete/,
    );
    await stops(
      {
        iam: {
          projectBindings: [
            bound("roles/firebase.sdkAdminServiceAgent", {
              condition: { title: "t", expression: "true" },
            }),
          ],
        },
      },
      /lack storage\.objects/,
    );
  });

  it("accepts roles held in the bucket policy or split across roles", async () => {
    const { report } = await go({
      iam: {
        projectBindings: [bound("roles/firebase.sdkAdminServiceAgent")],
        bucketBindings: [bound("roles/storage.objectViewer")],
        predefinedRoles: {
          "firebase.sdkAdminServiceAgent": ["storage.objects.create", "storage.objects.delete"],
          "storage.objectViewer": ["storage.objects.get"],
        },
      },
    });
    assert.equal(report.finished, true, report.stopped);
    assert.equal(report.iam.roleReads, 2);
    const onlyBucket = await go({
      iam: { projectBindings: [], bucketBindings: [bound("roles/firebase.sdkAdminServiceAgent")] },
    });
    assert.equal(onlyBucket.report.finished, true, onlyBucket.report.stopped);
  });

  it("when a policy or role read is refused, when too many roles are held, or a role is outside the project", async () => {
    await stops(
      { intercept: (r) => (r.url.includes("cloudresourcemanager") ? respond(403) : undefined) },
      /project policy read answered 403/,
    );
    await stops(
      { intercept: (r) => (urlOf(r).endsWith("/iam") ? respond(403) : undefined) },
      /bucket policy read answered 403/,
    );
    await stops(
      { intercept: (r) => (urlOf(r).endsWith(`${SA}:getIamPolicy`) ? respond(403) : undefined) },
      /signer policy read answered 403/,
    );
    await stops(
      { intercept: (r) => (urlOf(r).startsWith("/v1/roles/") ? respond(404) : undefined) },
      /read answered 404/,
    );
    const many = Array.from({ length: 9 }, (_, i) => bound(`roles/r${i}`));
    await stops({ iam: { projectBindings: many } }, /more than 8 to read/);
    await stops(
      { iam: { projectBindings: [bound("organizations/1/roles/x")] } },
      /outside the predefined and project roles/,
    );
    await stops(
      { iam: { projectBindings: [bound("projects/other-project/roles/x")] } },
      /outside the predefined and project roles/,
    );
  });

  it("when the run prefix is not empty, leaving IAM and the leftover alone", async () => {
    const leftover = `${runPrefix(RUN)}rec1/leftover.png`;
    const world = await stops(
      {
        setup: (w) =>
          w.objects.set(leftover, {
            name: leftover,
            generation: "1",
            body: Buffer.alloc(0),
            contentType: "x",
          }),
      },
      /prefix is not empty/,
      { verified: false },
    );
    assert.equal(world.objects.size, 1);
  });
});

describe("signer access: removal on every path", () => {
  const removed = (world) => {
    assert.equal(unchanged(world), true, JSON.stringify(world.iam.policy));
    assert.equal(world.iam.roles.get(ROLE_KEY).deleted, true);
    assert.equal(world.signerEnabled(), false);
  };

  it("after a refused positive control", async () => {
    const { report, world } = await go({
      faults: { "ok.png": respond(403, "<Error><Code>AccessDenied</Code></Error>") },
    });
    assert.match(report.stopped, /positive control ok was not accepted/);
    removed(world);
    assert.equal(report.cleanupVerified, true, JSON.stringify(report.unresolved));
  });

  it("after an unknown PUT, a signBlob that never works, an unknown signBlob and a crash in the signer", async () => {
    let n = 0;
    for (const options of [
      {
        faults: {
          "PUT /demo-bucket.firebasestorage.app/storage-signed-put/sp-0123abcd/rec1/ok-origin.png":
            respond(503),
        },
      },
      { iam: { propagationMs: 1e9 } },
      { faults: { signBlob: 503 } },
      {
        mutateDeps: (deps) => ({
          ...deps,
          sign: async (spec, meter) => {
            n += 1;
            if (n === 5) throw new Error("the signer crashed");
            return deps.sign(spec, meter);
          },
        }),
      },
    ]) {
      const { report, world } = await go(options);
      assert.equal(report.finished, false);
      removed(world);
      assert.equal(report.iam.policyEqualsPreflight, true);
      assert.equal(report.iam.roleDeleted, true);
    }
  });

  it("when the object cleanup itself fails", async () => {
    let lists = 0;
    const { report, world } = await go({
      intercept: (request) => {
        if (request.url.includes("/o?prefix=") && (lists += 1) === 2) return respond(403);
        return undefined;
      },
    });
    assert.ok(report.cleanupError);
    removed(world);
    assert.equal(report.cleanupVerified, false);
  });

  it("retries an etag conflict on a fresh read and writes only the run's removal", async () => {
    const { report, world } = await go({
      intercept: (request, log, w) => {
        if (urlOf(request).endsWith(":setIamPolicy") && setNumber(request, log) === 2)
          w.iam.policy.etag = "bumped";
        return undefined;
      },
    });
    assert.equal(sets(world).length, 3, "grant, refused removal, retried removal");
    removed(world);
    assert.equal(report.closureReady, true, JSON.stringify(report.unresolved));
  });

  it("gives up after three conflicts, keeps the role, and reports the binding", async () => {
    const { report, world } = await go({
      intercept: (request, log, w) => {
        if (urlOf(request).endsWith(":setIamPolicy") && setNumber(request, log) >= 2)
          w.iam.policy.etag = `bumped-${setNumber(request, log)}`;
        return undefined;
      },
    });
    assert.equal(sets(world).length, 4);
    assert.equal(roleDeletes(world).length, 0, "a role still bound is kept");
    assert.ok(report.unresolved.some((u) => u.name === "signer policy"));
    assert.ok(report.unresolved.some((u) => u.reason === "created, not deleted"));
    assert.equal(report.iam.bindingStillPresent, true);
    assert.equal(report.closureReady, false);
  });

  it("keeps someone else's concurrent binding and reports that the policy differs from the preflight one", async () => {
    const { report, world } = await go({
      intercept: (request, log, w) => {
        if (urlOf(request).endsWith(":setIamPolicy") && setNumber(request, log) === 2) {
          w.iam.policy.bindings = [...w.iam.policy.bindings, OTHER];
          w.iam.policy.etag = "bumped";
        }
        return undefined;
      },
    });
    assert.deepEqual(world.iam.policy.bindings, [OTHER]);
    assert.equal(report.iam.policyEqualsPreflight, false);
    assert.equal(report.iam.bindingStillPresent, false);
    assert.deepEqual(
      report.unresolved.map((u) => u.name),
      ["signer policy"],
    );
    assert.equal(world.iam.roles.get(ROLE_KEY).deleted, true);
  });

  it("never re-sends an unknown removal, keeps the role, and leaves the access to A2", async () => {
    for (const applied of [true, false]) {
      const { report, world, out } = await go({
        mutateDeps: (deps, w) => ({
          ...deps,
          net: async (request) => {
            if (
              urlOf(request).endsWith(":setIamPolicy") &&
              w.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length === 1
            ) {
              if (applied) await deps.net(request);
              return respond(503);
            }
            return deps.net(request);
          },
        }),
      });
      const attempted = out.entries.filter(
        (e) => e.phase === "before" && e.kind === "signer-set-policy",
      );
      assert.equal(attempted.length, 2, "grant and one removal attempt, never a second");
      assert.equal(roleDeletes(world).length, 0);
      assert.ok(report.unresolved.some((u) => u.reason === "unknown removal"));
      assert.equal(report.closureReady, false);
      assert.equal(report.cleanupVerified, false);
      assert.equal(world.signerEnabled(), !applied, "the binding applies until the window ends");
    }
  });

  it("reports a refused removal and still tries nothing else on it", async () => {
    const { report, world, out } = await go({
      intercept: (request, log) =>
        urlOf(request).endsWith(":setIamPolicy") && setNumber(request, log) === 2
          ? respond(403)
          : undefined,
    });
    assert.equal(sets(world).length, 2);
    assert.ok(
      report.unresolved.some((u) => /removal failed: signer removal answered 403/.test(u.reason)),
    );
    assert.match(out.saved.get("iam-failure.json").message, /signer removal answered 403/);
    assert.equal(report.closureReady, false);
  });

  it("treats an unknown or failed role delete as open, and a role still live after the delete as not deleted", async () => {
    const unknown = await go({
      intercept: (r) =>
        r.method === "DELETE" && urlOf(r).endsWith(`/roles/${ROLE_ID}`) ? respond(503) : undefined,
    });
    assert.ok(unknown.report.unresolved.some((u) => u.reason === "unknown delete"));
    assert.equal(roleDeletes(unknown.world).length, 1);
    const live = await go({
      intercept: (r, log) => {
        if (
          r.method === "GET" &&
          r.url.endsWith(`/roles/${ROLE_ID}`) &&
          log.some((e) => e.method === "DELETE")
        ) {
          return respond(200, JSON.stringify({ name: ROLE_KEY, deleted: false }));
        }
        return undefined;
      },
    });
    assert.ok(live.report.unresolved.some((u) => u.reason === "deleted, not read back as deleted"));
    assert.equal(live.report.iam.roleDeleted, false);
  });
});

describe("signer access: the grant", () => {
  it("does not delete a role it did not create when the create is refused", async () => {
    for (const status of [403, 409]) {
      const { report, world } = await go({
        intercept: (r) =>
          r.method === "POST" && urlOf(r).endsWith("/roles") ? respond(status) : undefined,
      });
      assert.match(report.stopped, new RegExp(`role create answered ${status}`));
      assert.equal(sets(world).length, 0);
      assert.equal(roleDeletes(world).length, 0);
      assert.equal(report.cleanupVerified, true, JSON.stringify(report.unresolved));
    }
  });

  it("deletes a role whose create answer was unknown only if a delete and a read settle it", async () => {
    for (const applied of [true, false]) {
      const { report, world } = await go({
        mutateDeps: (deps) => ({
          ...deps,
          net: async (request) => {
            if (request.method === "POST" && urlOf(request).endsWith("/roles")) {
              if (applied) await deps.net(request);
              return respond(503);
            }
            return deps.net(request);
          },
        }),
      });
      assert.equal(sets(world).length, 0, "no grant after an unknown role create");
      assert.equal(
        world.log.filter(
          (e) => urlOf(e).endsWith(":getIamPolicy") && !e.url.includes("cloudresourcemanager"),
        ).length,
        1,
        "no policy read after the preflight when no grant was attempted",
      );
      assert.equal(roleDeletes(world).length, 1);
      assert.equal(report.closureReady, false);
      if (applied) {
        assert.equal(world.iam.roles.get(ROLE_KEY).deleted, true);
        assert.deepEqual(report.unresolved, []);
      } else {
        assert.deepEqual(
          report.unresolved.map((u) => u.reason),
          ["unknown create, no positive read and delete"],
        );
      }
    }
  });

  it("stops on a stale etag at the grant (409) and leaves the policy as found", async () => {
    const { report, world } = await go({
      intercept: (r, log, w) => {
        if (urlOf(r).endsWith(":setIamPolicy") && setNumber(r, log) === 1)
          w.iam.policy.etag = "someone-else";
        return undefined;
      },
    });
    assert.match(report.stopped, /signer grant answered 409/);
    assert.equal(sets(world).length, 1, "nothing to remove, nothing written");
    assert.equal(roleDeletes(world).length, 1);
    assert.equal(unchanged(world), true);
    assert.equal(report.cleanupVerified, true, JSON.stringify(report.unresolved));
  });

  it("settles an unknown grant only through an own positive read, then removes it", async () => {
    for (const applied of [true, false]) {
      const { report, world } = await go({
        mutateDeps: (deps) => ({
          ...deps,
          net: async (request) => {
            if (urlOf(request).endsWith(":setIamPolicy") && !deps.__done) {
              deps.__done = true;
              if (applied) await deps.net(request);
              return respond(503);
            }
            return deps.net(request);
          },
        }),
      });
      assert.equal(report.finished, false);
      assert.equal(unchanged(world), true);
      assert.equal(world.iam.roles.get(ROLE_KEY).deleted, true);
      assert.equal(report.closureReady, false);
      assert.deepEqual(
        report.unresolved.map((u) => u.reason),
        applied ? [] : ["unknown grant, no positive read"],
      );
    }
  });

  it("stops when the policy does not read back as granted", async () => {
    let afterGrant = false;
    const { report, world } = await go({
      mutateDeps: (deps) => ({
        ...deps,
        net: async (request) => {
          const res = await deps.net(request);
          if (urlOf(request).endsWith(":setIamPolicy")) afterGrant = true;
          else if (afterGrant && urlOf(request).endsWith(":getIamPolicy") && !deps.__read) {
            deps.__read = true;
            return { ...res, body: Buffer.from(JSON.stringify({ version: 1, etag: "x" })) };
          }
          return res;
        },
      }),
    });
    assert.match(report.stopped, /does not read back as granted/);
    assert.equal(unchanged(world), true);
  });

  it("probes signBlob until the binding takes effect and counts every probe", async () => {
    const { report, world } = await go({ iam: { propagationMs: 1 } });
    // the virtual clock does not move while probing except by the probe wait
    assert.equal(report.finished, true, report.stopped);
    assert.ok(report.iam.signProbes >= 2);
    assert.ok(world.log.length > 0);
    const worst = await go({ iam: { propagationMs: 1e9 } });
    assert.equal(worst.report.requests <= staticBounds().total, true);
    assert.equal(worst.report.iam.signProbes, 12);
  });
});

describe("signer access: A2 and the standalone removal", () => {
  const afterUnknownRemoval = async () => {
    const run = await go({
      mutateDeps: (deps, w) => ({
        ...deps,
        net: async (request) => {
          if (
            urlOf(request).endsWith(":setIamPolicy") &&
            w.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length === 1
          ) {
            return respond(503);
          }
          return deps.net(request);
        },
      }),
    });
    return run;
  };

  it("reads clean after a clean run", async () => {
    const { world, out } = await go();
    const report = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: world.deps,
      out: memoryOut(),
      preflight: out.saved.get("iam-preflight.json"),
    });
    assert.deepEqual(
      [
        report.clean,
        report.policyEqualsPreflight,
        report.bindingPresent,
        report.roleState,
        report.requests,
      ],
      [true, true, false, "deleted", 2],
    );
  });

  it("reads not clean while the binding or the role remains, or when a read is unknown", async () => {
    const run = await afterUnknownRemoval();
    const preflight = run.out.saved.get("iam-preflight.json");
    const report = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: run.world.deps,
      out: memoryOut(),
      preflight,
    });
    assert.equal(report.clean, false);
    assert.equal(report.policyEqualsPreflight, false);
    assert.equal(report.bindingPresent, true);
    assert.equal(report.roleState, "live");
    const down = createFakeWorld({
      target: PRODUCTION_LIKE,
      clock: createVirtualClock(),
      faults: {},
    });
    const unreadable = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: { ...down.deps, net: async () => respond(503) },
      out: memoryOut(),
      preflight,
    });
    assert.equal(unreadable.unreadable, true);
    assert.equal(unreadable.clean, false);
    const odd = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: {
        ...down.deps,
        net: async (r) => (r.method === "GET" ? respond(403) : down.deps.net(r)),
      },
      out: memoryOut(),
      preflight,
    });
    assert.equal(odd.roleState, "unreadable");
    assert.equal(odd.clean, false);
  });

  it("removes what an unknown removal left, with the same shape checks, and reads clean afterwards", async () => {
    const run = await afterUnknownRemoval();
    const preflight = run.out.saved.get("iam-preflight.json");
    const plan = run.out.saved.get("iam-grant-plan.json");
    const out = memoryOut();
    const report = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: run.world.deps,
      out,
      preflight,
      plan,
    });
    assert.equal(report.clean, true, JSON.stringify(report));
    assert.equal(unchanged(run.world), true);
    assert.equal(run.world.iam.roles.get(ROLE_KEY).deleted, true);
    assert.deepEqual(
      [report.policyEqualsPreflight, report.bindingPresent, report.roleDeleted],
      [true, false, true],
    );
    const again = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: run.world.deps,
      out: memoryOut(),
      preflight,
      plan,
    });
    assert.equal(again.clean, true, "removing twice changes nothing more");
    const a2 = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: run.world.deps,
      out: memoryOut(),
      preflight,
    });
    assert.equal(a2.clean, true);
  });

  it("reports an unknown standalone removal and a refused one as not clean", async () => {
    const run = await afterUnknownRemoval();
    const preflight = run.out.saved.get("iam-preflight.json");
    const plan = run.out.saved.get("iam-grant-plan.json");
    for (const status of [503, 403]) {
      const deps = {
        ...run.world.deps,
        net: async (r) =>
          urlOf(r).endsWith(":setIamPolicy") ? respond(status) : run.world.deps.net(r),
      };
      const report = await removeSignerAccess({
        target: PRODUCTION_LIKE,
        runId: RUN,
        deps,
        out: memoryOut(),
        preflight,
        plan,
      });
      assert.equal(report.clean, false, String(status));
      assert.ok(report.error || report.unknownRequests.length, String(status));
    }
  });
});

describe("signer access: bounds", () => {
  it("keeps the worst case inside the caps and the run's request log inside the guard", async () => {
    const bounds = staticBounds();
    assert.ok(bounds.main <= 150 && bounds.total <= 220);
    const { report, world } = await go();
    assert.ok(report.requests <= bounds.total);
    // signer read, policy read, role read, project policy, one role definition, role create, grant,
    // read-back, then removal read, set, read-back, role delete, role read-back
    assert.equal(
      world.log.filter(
        (e) => e.url.includes("iam.googleapis.com") || e.url.includes("cloudresourcemanager"),
      ).length,
      13,
    );
    assert.equal(CASES.length, 16);
  });
});
describe("signer access: more paths", () => {
  const cleanTotal = async () => (await go()).report.requests;

  it("asks for policy version 3 on every policy read and write", async () => {
    const bodies = [];
    await go({
      intercept: (request) => {
        const path = urlOf(request);
        if (path.endsWith(":getIamPolicy"))
          bodies.push(["get", JSON.parse(Buffer.from(request.body).toString())]);
        if (path.endsWith(":setIamPolicy"))
          bodies.push(["set", JSON.parse(Buffer.from(request.body).toString()).policy.version]);
        return undefined;
      },
    });
    const gets = bodies.filter(([kind]) => kind === "get").map(([, body]) => body);
    assert.equal(gets.length, 5, "signer, project, read-back, removal read, final read");
    assert.ok(gets.every((body) => body.options.requestedPolicyVersion === 3));
    assert.deepEqual(
      bodies.filter(([kind]) => kind === "set").map(([, version]) => version),
      [3, 3],
    );
  });

  it("accepts exactly eight roles and reads each", async () => {
    const roles = Array.from({ length: 8 }, (_, i) => `roles/r${i}`);
    const predefinedRoles = Object.fromEntries(
      roles.map((r, i) => [
        r.slice(6),
        i === 0 ? ["storage.objects.create", "storage.objects.get", "storage.objects.delete"] : [],
      ]),
    );
    const { report } = await go({
      iam: {
        projectBindings: roles.map((role) => ({
          role,
          members: [`serviceAccount:${PRODUCTION_LIKE.signer}`],
        })),
        predefinedRoles,
      },
    });
    assert.equal(report.finished, true, report.stopped);
    assert.equal(report.iam.roleReads, 8);
  });

  it("stops when the grant cannot be read back or the policy cannot be read for the removal", async () => {
    let afterGrant = false;
    const { report, world } = await go({
      intercept: (request) => {
        const path = urlOf(request);
        if (path.endsWith(":setIamPolicy")) afterGrant = true;
        else if (afterGrant && path.endsWith(":getIamPolicy")) {
          afterGrant = false;
          return respond(403);
        }
        return undefined;
      },
    });
    assert.match(report.stopped, /signer policy read-back answered 403/);
    assert.equal(unchanged(world), true);
    let reads = 0;
    const second = await go({
      intercept: (request) =>
        urlOf(request).endsWith(":getIamPolicy") && (reads += 1) === 4 ? respond(403) : undefined,
    });
    assert.ok(
      second.report.unresolved.some((u) =>
        /removal failed: signer-policy-before-removal answered 403/.test(u.reason),
      ),
    );
    assert.equal(
      second.world.signerEnabled(),
      true,
      "the removal did not happen; the window bounds it",
    );
    assert.equal(second.report.closureReady, false);
  });

  it("reads nothing more about the signer's policy when no grant was attempted", async () => {
    const { world } = await go({
      intercept: (r) =>
        r.method === "POST" && urlOf(r).endsWith("/roles") ? respond(403) : undefined,
    });
    assert.equal(
      world.log.filter(
        (e) => urlOf(e).endsWith(":getIamPolicy") && !e.url.includes("cloudresourcemanager"),
      ).length,
      1,
    );
  });

  it("reports a request the guard refuses as a refusal, never as an unknown answer", async () => {
    const total = await cleanTotal();
    // The preflight reads 8 requests, so the 9th is the role create and the 10th the grant.
    for (const [main, pattern] of [
      [8, /role create/],
      [9, /signer grant/],
    ]) {
      const { report } = await go({ caps: { main, total: 220 } });
      assert.match(report.stopped, /budget exhausted/);
      assert.deepEqual(
        report.unresolved.filter((u) => /unknown/.test(u.reason)),
        [],
        pattern.source,
      );
    }
    // The removal: its policy write is the fourth request from the end, the role delete the second.
    for (const [cap, label] of [
      [total - 4, "signer-removal"],
      [total - 2, "role-delete"],
    ]) {
      const { report, out } = await go({ caps: { main: 150, total: cap } });
      assert.ok(
        report.unresolved.some((u) => /removal failed: request budget exhausted/.test(u.reason)),
        label,
      );
      assert.deepEqual(
        report.unresolved.filter((u) => /unknown/.test(u.reason)),
        [],
        label,
      );
      assert.ok(out.saved.has("iam-failure.json"));
    }
  });

  it("reports granted only for a 2xx grant, and null role state when the role was kept", async () => {
    const stale = await go({
      intercept: (r, log, w) => {
        if (urlOf(r).endsWith(":setIamPolicy") && setNumber(r, log) === 1) w.iam.policy.etag = "x";
        return undefined;
      },
    });
    assert.equal(stale.report.iam.granted, false);
    const unknown = await go({ faults: { signBlob: 503 } });
    assert.equal(unknown.report.iam.granted, true);
    const kept = await go({
      intercept: (request, log, w) => {
        if (urlOf(request).endsWith(":setIamPolicy") && setNumber(request, log) >= 2)
          w.iam.policy.etag = `b${setNumber(request, log)}`;
        return undefined;
      },
    });
    assert.equal(kept.report.iam.roleDeleted, null);
    assert.equal(kept.report.iam.policyEqualsPreflight, false);
  });
});

describe("signer access: A2 and standalone removal, more paths", () => {
  const unknownRemoval = (w) => async (request, deps) =>
    urlOf(request).endsWith(":setIamPolicy") &&
    w.log.filter((e) => urlOf(e).endsWith(":setIamPolicy")).length === 1
      ? respond(503)
      : deps.net(request);
  const stuck = async () =>
    go({
      mutateDeps: (deps, w) => ({ ...deps, net: (request) => unknownRemoval(w)(request, deps) }),
    });

  it("reads the signer role as absent, saves its report and asks for policy version 3", async () => {
    const world = createFakeWorld({ target: PRODUCTION_LIKE, clock: createVirtualClock() });
    const out = memoryOut();
    const bodies = [];
    const deps = {
      ...world.deps,
      net: async (r) => {
        if (r.body) bodies.push(JSON.parse(Buffer.from(r.body).toString()));
        return world.deps.net(r);
      },
    };
    const report = await readbackIam({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps,
      out,
      preflight: { policy: { etag: "etag-0" } },
    });
    assert.deepEqual([report.roleState, report.clean, report.requests], ["absent", true, 2]);
    assert.deepEqual(out.saved.get("a2-iam.json"), report);
    assert.deepEqual(bodies, [{ options: { requestedPolicyVersion: 3 } }]);
  });

  it("reports the standalone removal's state, saves it, and is not clean while the binding or an extra binding remains", async () => {
    const run = await stuck();
    const preflight = run.out.saved.get("iam-preflight.json");
    const plan = run.out.saved.get("iam-grant-plan.json");
    const out = memoryOut();
    const report = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: run.world.deps,
      out,
      preflight,
      plan,
    });
    assert.deepEqual(out.saved.get("iam-remove.json"), report);
    assert.equal(report.clean, true);
    assert.equal(report.requests, 5);
    // An extra binding added by someone else keeps the policy different from the preflight one.
    const other = await stuck();
    other.world.iam.policy.bindings = [...other.world.iam.policy.bindings, OTHER];
    const extra = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: other.world.deps,
      out: memoryOut(),
      preflight: other.out.saved.get("iam-preflight.json"),
      plan: other.out.saved.get("iam-grant-plan.json"),
    });
    assert.deepEqual(
      [extra.policyEqualsPreflight, extra.bindingPresent, extra.roleDeleted, extra.clean],
      [false, false, true, false],
    );
    // Three etag conflicts in a row leave the binding and keep the role.
    const third = await stuck();
    const conflicting = {
      ...third.world.deps,
      net: async (request) => {
        if (urlOf(request).endsWith(":setIamPolicy"))
          third.world.iam.policy.etag = `c${Math.random()}`;
        return third.world.deps.net(request);
      },
    };
    const kept = await removeSignerAccess({
      target: PRODUCTION_LIKE,
      runId: RUN,
      deps: conflicting,
      out: memoryOut(),
      preflight: third.out.saved.get("iam-preflight.json"),
      plan: third.out.saved.get("iam-grant-plan.json"),
    });
    assert.deepEqual([kept.bindingPresent, kept.roleDeleted, kept.clean], [true, null, false]);
  });
});
