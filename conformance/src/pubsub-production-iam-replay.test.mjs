import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import * as iam from "./pubsub-production/iam.mjs";
import { createRest } from "./pubsub-production/rest.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { createBudget } from "./pubsub-production/capture.mjs";

const rows = JSON.parse(
  readFileSync(new URL("./pubsub-production/fixtures/recorded-v2-iam.json", import.meta.url)),
);
const ownership = createOwnership({ project: "demo-v2", runId: "0123456789ab" });
const complete = (body) => ({ ok: true, status: 200, unknown: false, body });

function replayClient(records) {
  const pending = [...records];
  const transport = createRest({
    base: "http://127.0.0.1:1",
    budget: createBudget(records.length),
    capture: { record() {} },
    fetchImpl: async (url, request) => {
      const row = pending.shift();
      assert.ok(row, "unexpected request");
      assert.equal(new URL(url).pathname, row.request.path);
      assert.equal(request.method, row.request.method);
      if (request.method === "POST") {
        const sent = JSON.parse(request.body).policy;
        assert.equal(sent.etag, row.request.body.policy.etag);
        assert.deepEqual(sent.bindings, row.request.body.policy.bindings);
        assert.equal(sent.version, row.request.body.policy.version ?? 3);
      }
      // These are measured fixture serialization bytes, not original production bodyBytes.
      return new Response(JSON.stringify(row.response.body), { status: row.response.status });
    },
  });
  const client = createClient({
    transport,
    ownership,
    pushState: newPushState(),
    caseId: "iam-replay",
  });
  return { client, assertConsumed: () => assert.equal(pending.length, 0) };
}

test("all24 checksum-verified production IAM bodies retain their recorded policy shape", () => {
  assert.equal(rows.length, 24);
  for (const runId of ["148026092d56", "a8ed1cce53f0"]) {
    const run = rows.filter((row) => row.runId === runId);
    assert.equal(run.length, 12);
    assert.equal(run.filter((row) => row.op === "getIamPolicy").length, 8);
    assert.equal(run.filter((row) => row.op === "setIamPolicy").length, 4);
  }
  for (const row of rows) {
    assert.equal(row.response.status, 200);
    const before = structuredClone(row.response.body);
    assert.doesNotThrow(() => iam.readPolicy(before), `${row.runId}:${row.n}`);
    assert.deepEqual(iam.readPolicy(before), row.response.body, `${row.runId}:${row.n}`);
    assert.deepEqual(before, row.response.body);
    if (row.op === "setIamPolicy") assert.equal(before.version, 1);
  }
});

for (let offset = 0; offset < rows.length; offset += 3) {
  const [initial, written, readback] = rows.slice(offset, offset + 3);
  const resource = initial.request.path.slice(4).split(":")[0];
  const {
    role,
    members: [principal],
  } = written.response.body.bindings[0];
  test(`production IAM grant and recovery replay ${initial.runId} n${initial.n}-${readback.n}`, async () => {
    const journal = [];
    const manager = iam.createIamOwnership({
      journal: { write: (row) => journal.push(row) },
      assertOwned: ownership.assertOwned,
      now: () => 123,
    });
    const replay = replayClient([initial, written, readback]);
    assert.deepEqual(await manager.grant(replay.client, resource, role, principal), {
      resource,
      grantedAt: 123,
    });
    replay.assertConsumed();
    assert.equal(manager.outstanding()[0].state, "granted");
    assert.deepEqual(journal[0].before, initial.response.body);
    assert.equal(journal[0].requested.etag, initial.response.body.etag);
    assert.equal(journal[0].requested.version, 3);
    assert.deepEqual(journal[1].setAnswer.body, written.response.body);
    assert.deepEqual(journal[1].readback.body, readback.response.body);
    const recovery = iam.createIamOwnership({
      journal: { write: (row) => journal.push(row) },
      assertOwned: ownership.assertOwned,
      replay: structuredClone(journal),
    });
    // A recorded empty-policy GET exercises the already-absent proof, without claiming a recorded restore sequence or IAM convergence.
    const restored = replayClient([initial]);
    assert.deepEqual(await recovery.restore(restored.client), {
      restored: [resource],
      unsettled: [],
    });
    restored.assertConsumed();
    assert.deepEqual(recovery.outstanding(), []);
    assert.equal(journal.at(-1).proof, "already-absent");
    assert.doesNotThrow(() =>
      iam.createIamOwnership({
        journal: { write() {} },
        assertOwned: ownership.assertOwned,
        replay: structuredClone(journal),
      }),
    );
  });
  test(`production IAM post-grant GET restores exact own binding ${initial.runId} n${readback.n}`, async () => {
    const journal = [];
    const manager = iam.createIamOwnership({
      journal: { write: (row) => journal.push(row) },
      assertOwned: ownership.assertOwned,
    });
    const grant = replayClient([initial, written, readback]);
    await manager.grant(grant.client, resource, role, principal);
    grant.assertConsumed();
    // The current-policy GET is the exact recorded post-grant body. No empty-binding restore POST was observed; its success response is explicitly constructed here.
    const policy = iam.removeOwnBinding(readback.response.body, role, principal);
    const syntheticSet = {
      ...written,
      request: { ...written.request, body: { policy } },
      response: { status: 200, body: { etag: initial.response.body.etag } },
    };
    const restore = replayClient([readback, syntheticSet, initial]);
    assert.deepEqual(await manager.restore(restore.client), {
      restored: [resource],
      unsettled: [],
    });
    restore.assertConsumed();
    assert.deepEqual(journal.at(-2).before, readback.response.body);
    assert.deepEqual(journal.at(-2).requested.bindings, []);
    assert.equal(journal.at(-2).requested.etag, readback.response.body.etag);
    assert.deepEqual(manager.outstanding(), []);
    assert.doesNotThrow(() =>
      iam.createIamOwnership({
        journal: { write() {} },
        assertOwned: ownership.assertOwned,
        replay: structuredClone(journal),
      }),
    );
  });
  test(`production IAM recorded set/read bodies confirm CAS restoration ${initial.runId} n${written.n}`, async () => {
    // Only state setup is constructed: another own principal is added alongside the recorded binding.
    const own = "serviceAccount:service-123456789013@gcp-sa-pubsub.iam.gserviceaccount.com";
    const before = structuredClone(readback.response.body);
    const requested = iam.addOwnBinding(before, role, own).policy;
    const journal = [
      { phase: "grant-intent", resource, role, principal: own, before, requested },
      {
        phase: "grant-confirmed",
        resource,
        setAnswer: complete(requested),
        readback: complete(requested),
      },
    ];
    const manager = iam.createIamOwnership({
      journal: { write: (row) => journal.push(row) },
      assertOwned: ownership.assertOwned,
      replay: structuredClone(journal),
    });
    const current = { ...readback, response: { status: 200, body: requested } };
    const set = {
      ...written,
      request: { ...written.request, body: { policy: { ...before, etag: requested.etag } } },
    };
    const replay = replayClient([current, set, readback]);
    assert.deepEqual(await manager.restore(replay.client), { restored: [resource], unsettled: [] });
    replay.assertConsumed();
    assert.deepEqual(journal.at(-2).requested.bindings, before.bindings);
    assert.deepEqual(journal.at(-1).setAnswer.body, written.response.body);
    assert.doesNotThrow(() =>
      iam.createIamOwnership({
        journal: { write() {} },
        assertOwned: ownership.assertOwned,
        replay: structuredClone(journal),
      }),
    );
  });
  test(`production IAM proof near misses remain unresolved ${initial.runId} n${written.n}`, () => {
    const requested = iam.addOwnBinding(initial.response.body, role, principal).policy;
    const intent = {
      phase: "grant-intent",
      resource,
      role,
      principal,
      before: initial.response.body,
      requested,
    };
    for (const changed of [
      { status: 199 },
      { status: 302 },
      { status: 503 },
      { unknown: true },
      { ok: false },
      { body: null },
      { body: { ...written.response.body, etag: "" } },
      { body: { ...written.response.body, version: 2 } },
      { body: { ...written.response.body, bindings: [] } },
    ]) {
      for (const field of ["setAnswer", "readback"]) {
        const proof = {
          phase: "grant-confirmed",
          resource,
          setAnswer: complete(written.response.body),
          readback: complete(readback.response.body),
        };
        proof[field] = { ...proof[field], ...changed };
        assert.throws(
          () =>
            iam.createIamOwnership({
              journal: { write() {} },
              assertOwned: ownership.assertOwned,
              replay: [intent, proof],
            }),
          /proof/,
        );
      }
    }
  });
}
