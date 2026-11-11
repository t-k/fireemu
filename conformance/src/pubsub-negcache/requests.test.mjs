import assert from "node:assert/strict";
import test from "node:test";

import {
  buildRequest,
  deleteRequest,
  getRequest,
  listRequest,
  Refusal,
  setupRequests,
} from "./requests.mjs";
import { fullName, isOwned, resourceId, PROJECT } from "./names.mjs";
import { RUN_ID } from "./support.mjs";

const ctx = { runId: RUN_ID, cellId: "N2a" };
const name = (role, kind) => fullName(RUN_ID, "N2a", role, kind);

test("a subscription create carries topic, a snapshot create carries subscription", () => {
  const sub = buildRequest({ op: "putSub", target: "X", topic: "T" }, ctx);
  assert.equal(sub.method, "PUT");
  assert.deepEqual(Object.keys(sub.body), ["topic"]);
  assert.equal(sub.body.topic, fullName(RUN_ID, "N2a", "T"));
  const snap = buildRequest({ op: "putSnap", target: "Y", from: "S" }, ctx);
  assert.deepEqual(snap.body, { subscription: fullName(RUN_ID, "N2a", "S") });
  assert.ok(sub.create && snap.create);
});

test("a body name names the subscription under test, and only when asked", () => {
  const named = buildRequest({ op: "putSub", target: "W", topic: "T", bodyName: "X" }, ctx);
  assert.equal(named.body.name, name("X"));
  assert.equal(named.targets[0], name("W"));
  assert.equal(buildRequest({ op: "putSub", target: "X", topic: "T" }, ctx).body.name, undefined);
});

test("patch needs updateMask, pull needs maxMessages, seek needs a snapshot target", () => {
  const patch = buildRequest({ op: "patchSub", target: "X", labels: { k: "v" } }, ctx);
  assert.equal(patch.method, "PATCH");
  assert.equal(patch.body.updateMask, "labels");
  assert.equal(patch.body.subscription.name, name("X"));
  assert.equal(buildRequest({ op: "pullSub", target: "X" }, ctx).body.maxMessages, 1);
  const seek = buildRequest({ op: "seekSub", target: "X", snapshot: "Z" }, ctx);
  assert.equal(seek.body.snapshot, name("Z", "snapshot"));
  assert.ok(seek.path.endsWith(":seek"));
});

test("verb URLs, query strings, lists and the gRPC marker", () => {
  assert.ok(buildRequest({ op: "getIamSub", target: "X" }, ctx).path.endsWith(":getIamPolicy"));
  assert.ok(
    buildRequest({ op: "getSub", target: "X", query: "?alt=json" }, ctx).path.endsWith("?alt=json"),
  );
  assert.equal(buildRequest({ op: "grpcGetSub", target: "X" }, ctx).grpc, true);
  assert.ok(buildRequest({ op: "listSub" }, ctx).path.endsWith("/subscriptions?pageSize=100"));
  assert.ok(listRequest("snapshot", "tok en").path.endsWith("pageSize=100&pageToken=tok%20en"));
});

test("a delete is marked and targets the name; a get reads it", () => {
  const del = buildRequest({ op: "deleteSnap", target: "Y" }, ctx);
  assert.ok(del.delete && del.targets[0] === name("Y", "snapshot"));
  assert.equal(deleteRequest(name("X"), RUN_ID).method, "DELETE");
  assert.equal(getRequest(name("X"), RUN_ID).method, "GET");
});

test("a snapshot can share the id of a subscription (K1)", () => {
  const snap = buildRequest({ op: "putSnap", target: "X", from: "S" }, ctx);
  assert.ok(snap.targets[0].endsWith(`/snapshots/${resourceId(RUN_ID, "N2a", "X")}`));
});

test("names of another run, another project and other collections are refused", () => {
  assert.ok(isOwned(name("X"), RUN_ID));
  assert.ok(!isOwned(name("X"), "fedcba987654"));
  assert.ok(!isOwned(name("X").replace(PROJECT, "someone-else"), RUN_ID));
  assert.ok(!isOwned(`projects/${PROJECT}/subscriptions/unrelated`, RUN_ID));
  assert.ok(!isOwned(name("X") + "/extra", RUN_ID));
  assert.ok(!isOwned(null, RUN_ID));
  assert.ok(!isOwned(name("X"), "ABCDEF012345"));
  assert.throws(() => deleteRequest(`projects/${PROJECT}/subscriptions/other`, RUN_ID), Refusal);
  assert.throws(() => getRequest(`projects/${PROJECT}/topics/other`, RUN_ID), Refusal);
});

test("unknown ops, unknown roles and bad run ids are refused", () => {
  assert.throws(() => buildRequest({ op: "dropEverything", target: "X" }, ctx), Refusal);
  assert.throws(() => resourceId(RUN_ID, "N2a", "Q"), /unknown role/);
  assert.throws(() => resourceId("xyz", "N2a", "X"), /12 hex/);
});

test("setup creates the run's topic and source subscription, run-level names", () => {
  const [topic, sub] = setupRequests({ runId: RUN_ID });
  assert.deepEqual(topic.body, {});
  assert.equal(sub.body.topic, topic.targets[0]);
  assert.ok(topic.targets[0].includes("-nc-run-t"));
  assert.ok(sub.targets[0].includes("-nc-run-s"));
  assert.equal(resourceId(RUN_ID, "A1", "T"), resourceId(RUN_ID, "P2", "T"));
  assert.notEqual(resourceId(RUN_ID, "A1", "X"), resourceId(RUN_ID, "A2", "X"));
});

test("the id length bound is 255 and an invalid run id never owns a name", () => {
  assert.equal(resourceId(RUN_ID, "c".repeat(221), "X").length, 255);
  assert.throws(() => resourceId(RUN_ID, "c".repeat(222), "X"), /invalid resource id/);
  assert.ok(!isOwned(`projects/${PROJECT}/subscriptions/fireemu-observe-xyz-nc-a-x`, "xyz"));
  assert.ok(!isOwned(name("X"), undefined));
  assert.ok(!isOwned(123, RUN_ID));
});

test("only creates are marked create and only deletes are marked delete, across the whole program", async () => {
  const { CELLS } = await import("./program.mjs");
  for (const cell of CELLS)
    for (const step of cell.steps) {
      const request = buildRequest(step, { runId: RUN_ID, cellId: cell.id });
      assert.equal(Boolean(request.create), step.op.startsWith("put"), `${cell.id} ${step.op}`);
      assert.equal(Boolean(request.delete), step.op.startsWith("delete"), `${cell.id} ${step.op}`);
      assert.equal(request.create === true || request.create === false, true);
      assert.equal(
        request.targets.length,
        request.create || request.delete ? 1 : 0,
        `${cell.id} ${step.op}`,
      );
    }
});
