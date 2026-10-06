import assert from "node:assert/strict";
import test from "node:test";
import * as iam from "./pubsub-production/iam.mjs";
import { plannedRequests, selectCases } from "./pubsub-production/runner.mjs";
import { createPhaseLimit } from "./pubsub-production/limits.mjs";

const principal = "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com";
const role = "roles/pubsub.subscriber";
const resource = "projects/demo-v2/subscriptions/fe0123456789ab-da-r-source";
const complete = (body) => ({ ok: true, code: "OK", status: 200, unknown: false, body });

test("v2 actual plan has228 requests22resources and approved900/1800window", () => {
  const cases = selectCases(undefined, "stream-dlq-v2");
  assert.equal(plannedRequests(cases), 228);
  assert.equal(
    cases.reduce((sum, item) => sum + item.resources, 0),
    22,
  );
  assert.equal(cases.find((item) => item.id === "dlq-grant-window").timeoutMs, 1_800_000);
  assert.equal(iam.IAM_WAIT_MS, 900_000);
  assert.equal(iam.IAM_CONVERGENCE_CLAIM, false);
  assert.equal(cases.find((item) => item.id === "rest-layout-routes").requests, 9);
});

test("policy edits preserve unrelated conditional bindings and fresh etag across generated policies", () => {
  for (let seed = 0; seed < 128; seed += 1) {
    const before = {
      version: 3,
      etag: `etag-${seed}`,
      bindings: [
        { role, members: [`user:other-${seed}@example.com`] },
        {
          role,
          members: [principal],
          condition: { title: `condition-${seed}`, expression: "false" },
        },
        { role: "roles/viewer", members: [`group:others-${seed}@example.com`] },
      ],
    };
    const saved = structuredClone(before);
    const { policy, added } = iam.addOwnBinding(before, role, principal);
    assert.equal(added, true);
    assert.deepEqual(before, saved);
    assert.equal(policy.etag, before.etag);
    assert.deepEqual(policy.bindings[1], before.bindings[1]);
    policy.etag = `fresh-${seed}`;
    policy.bindings.push({ role: "roles/editor", members: ["user:concurrent@example.com"] });
    const restored = iam.removeOwnBinding(policy, role, principal);
    assert.equal(restored.etag, policy.etag);
    assert.deepEqual(restored.bindings, [...before.bindings, policy.bindings.at(-1)]);
    assert.equal(
      iam.addOwnBinding({ ...before, bindings: [{ role, members: [principal] }] }, role, principal)
        .added,
      false,
    );
  }
  for (const bad of [
    {},
    { etag: "" },
    { etag: "x", bindings: "bad" },
    { etag: "x", bindings: [{ role, members: [42] }] },
  ])
    assert.throws(() => iam.addOwnBinding(bad, role, principal), /policy/);
});

test("grant intent is durable before set and restore uses current etag before resources delete", async () => {
  let policy = { version: 3, etag: "before", bindings: [] };
  const journal = [];
  const sent = [];
  const manager = iam.createIamOwnership({
    journal: { write: (row) => journal.push(row) },
    assertOwned: (name) => assert.equal(name, resource),
  });
  const client = {
    async getIamPolicy() {
      sent.push("get");
      return complete(structuredClone(policy));
    },
    async setIamPolicy(name, next) {
      assert.equal(name, resource);
      assert.equal(journal.at(-1).phase, sent.length === 1 ? "grant-intent" : "restore-intent");
      assert.equal(next.etag, policy.etag);
      sent.push("set");
      policy = { ...structuredClone(next), etag: `${policy.etag}-new` };
      return complete(structuredClone(policy));
    },
  };
  await manager.grant(client, resource, role, principal);
  assert.deepEqual(sent, ["get", "set", "get"]);
  policy.bindings.push({ role: "roles/viewer", members: ["user:other@example.com"] });
  const report = await manager.restore(client);
  assert.deepEqual(report.unsettled, []);
  assert.deepEqual(sent, ["get", "set", "get", "get", "set", "get"]);
  assert.deepEqual(policy.bindings, [
    { role: "roles/viewer", members: ["user:other@example.com"] },
  ]);
});

test("ambiguous grant or restore is sticky without retries and prevents closure", async () => {
  for (const status of [199, 302, 503, 499, null]) {
    const journal = [];
    let writes = 0;
    const manager = iam.createIamOwnership({
      journal: { write: (row) => journal.push(row) },
      assertOwned() {},
    });
    const client = {
      async getIamPolicy() {
        return complete({ etag: "etag", bindings: [] });
      },
      async setIamPolicy() {
        writes += 1;
        return { status, ok: false, code: "UNKNOWN", unknown: true };
      },
    };
    await assert.rejects(manager.grant(client, resource, role, principal), /grant/);
    const report = await manager.restore(client);
    assert.equal(writes, 1);
    assert.equal(report.unsettled.length, 1);
    assert.equal(journal[0].phase, "grant-intent");
  }
});

test("IAM wait uses aged monotonic time and zero requests until900seconds after last grant", async () => {
  for (const age of [0, 3_600_000]) {
    let now = age;
    const phase = createPhaseLimit(1_800_000, () => now);
    phase.remaining();
    let requests = 0;
    await iam.waitAfterLastGrant({
      grantedAt: now,
      now: () => now,
      sleep: phase.sleep(async (ms) => {
        assert.equal(requests, 0);
        now += ms;
      }),
    });
    assert.equal(now - age, 900_000);
    requests += 1;
    assert.equal(requests, 1);
    assert.equal(phase.remaining(), 900_000);
  }
});

test("IAM replay of unanswered intent never resends a grant or restoration", async () => {
  for (const phase of ["grant-intent", "restore-intent"]) {
    const replay = [
      { phase: "grant-intent", resource, role, principal },
      ...(phase === "restore-intent"
        ? [
            { phase: "grant-confirmed", resource },
            { phase, resource },
          ]
        : []),
    ];
    const manager = iam.createIamOwnership({ journal: { write() {} }, assertOwned() {}, replay });
    let calls = 0;
    const report = await manager.restore({
      async getIamPolicy() {
        calls += 1;
      },
      async setIamPolicy() {
        calls += 1;
      },
    });
    assert.equal(calls, 0);
    assert.equal(report.unsettled.length, 1);
  }
});

test("IAM restore unknown answer stays sticky after a later clean policy read", async () => {
  let policy = { etag: "start", bindings: [] };
  let restore = false;
  let sets = 0;
  const manager = iam.createIamOwnership({ journal: { write() {} }, assertOwned() {} });
  const client = {
    async getIamPolicy() {
      return complete(structuredClone(policy));
    },
    async setIamPolicy(_name, next) {
      sets += 1;
      policy = { ...next, etag: "changed" };
      return restore ? { unknown: true, ok: false, status: 503 } : complete(policy);
    },
  };
  await manager.grant(client, resource, role, principal);
  restore = true;
  assert.equal((await manager.restore(client)).unsettled.length, 1);
  assert.equal((await manager.restore(client)).unsettled.length, 1);
  assert.equal(sets, 2);
});
