import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-corpus/wire-methods.mjs", import.meta.url);
async function moduleUnderTest() {
  assert.ok(existsSync(target), "native Pub/Sub wire mapping is missing");
  return import(target.href);
}
const topic = "projects/demo-pubsub/topics/fireemu-owned-topic";
const subscription = "projects/demo-pubsub/subscriptions/fireemu-owned-sub";
test("wire map explicitly names the native input/output messages, including non-Request types", async () => {
  const { METHODS } = await moduleUnderTest();
  assert.equal(Object.keys(METHODS).length, 21);
  assert.equal(METHODS.CreateTopic.requestType, "Topic");
  assert.equal(METHODS.CreateSubscription.requestType, "Subscription");
  assert.equal(METHODS.GetTopic.responseType, "Topic");
  assert.equal(METHODS.DeleteSubscription.responseType, "google.protobuf.Empty");
  assert.equal(METHODS.StreamingPull.requestStream, true);
  assert.equal(METHODS.StreamingPull.responseStream, true);
  for (const method of ["UpdateTopic", "DetachSubscription", "UpdateSnapshot", "SetIamPolicy"])
    assert.equal(METHODS[method], undefined);
});
test("REST and native gRPC retain the same operation and resource rather than assuming method-name messages", async () => {
  const { buildRest, buildGrpc } = await moduleUnderTest();
  const input = { name: topic, labels: { owner: "lane7" } };
  const rest = buildRest({ method: "CreateTopic", request: input }, "http://127.0.0.1:1234");
  assert.equal(rest.method, "PUT");
  assert.equal(rest.url, `http://127.0.0.1:1234/v1/${topic}`);
  assert.deepEqual(JSON.parse(rest.body), input);
  const grpc = buildGrpc({ method: "CreateTopic", request: input });
  assert.equal(grpc.path, "/google.pubsub.v1.Publisher/CreateTopic");
  assert.equal(grpc.requestType, "Topic");
  assert.equal(grpc.responseType, "Topic");
  assert.equal(grpc.routing, `name=${encodeURIComponent(topic)}`);
  assert.deepEqual(grpc.request, input);
});
test("query members stay in GET queries, field masks stay in PATCH bodies and stream has no REST path", async () => {
  const { buildRest, buildGrpc } = await moduleUnderTest();
  const list = buildRest(
    {
      method: "ListSubscriptions",
      request: { project: "projects/demo-pubsub", pageSize: 1, pageToken: "a+/=" },
    },
    "https://pubsub.googleapis.com",
  );
  assert.equal(list.method, "GET");
  assert.equal(list.body, undefined);
  const url = new URL(list.url);
  assert.equal(url.pathname, "/v1/projects/demo-pubsub/subscriptions");
  assert.equal(url.searchParams.get("pageSize"), "1");
  assert.equal(url.searchParams.get("pageToken"), "a+/=");
  const patch = buildRest(
    {
      method: "UpdateSubscription",
      request: {
        subscription: { name: subscription, ackDeadlineSeconds: 60 },
        updateMask: "ackDeadlineSeconds",
      },
    },
    "http://localhost:1234",
  );
  assert.equal(patch.method, "PATCH");
  assert.equal(new URL(patch.url).pathname, `/v1/${subscription}`);
  assert.equal(JSON.parse(patch.body).updateMask, "ackDeadlineSeconds");
  assert.equal(
    buildGrpc({ method: "UpdateSubscription", request: { subscription: { name: subscription } } })
      .routing,
    `subscription.name=${encodeURIComponent(subscription)}`,
  );
  assert.throws(() =>
    buildRest({ method: "StreamingPull", request: { subscription } }, "http://localhost:1234"),
  );
});
test("explicit REST path and native routing overrides preserve the disagreement as an observation input", async () => {
  const { buildRest, buildGrpc } = await moduleUnderTest();
  const other = topic + "-other";
  const step = { method: "CreateTopic", request: { name: topic }, resourceOverride: other };
  assert.equal(new URL(buildRest(step, "http://localhost:1234").url).pathname, `/v1/${other}`);
  assert.equal(JSON.parse(buildRest(step, "http://localhost:1234").body).name, topic);
  assert.equal(buildGrpc(step).routing, `name=${encodeURIComponent(other)}`);
  assert.equal(buildGrpc(step).request.name, topic);
});

test("malformed resource characters remain in the resource path rather than injecting query or fragment", async () => {
  const { buildRest } = await moduleUnderTest();
  const name = topic + "?pageToken=foreign#ignored";
  const result = buildRest(
    { method: "GetTopic", request: { topic: name } },
    "http://127.0.0.1:1234",
  );
  const url = new URL(result.url);
  assert.equal(url.search, "");
  assert.equal(url.hash, "");
  assert.equal(decodeURIComponent(url.pathname), `/v1/${name}`);
  for (const endpoint of [
    "https://user:secret@pubsub.googleapis.com",
    "https://pubsub.googleapis.com/path",
    "https://pubsub.googleapis.com/?q=1",
  ])
    assert.throws(() => buildRest({ method: "GetTopic", request: { topic } }, endpoint));
});
