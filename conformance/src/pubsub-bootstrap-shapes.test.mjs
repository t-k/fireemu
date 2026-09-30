import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-corpus/bootstrap-shapes.mjs", import.meta.url);
const topic = "projects/demo-pubsub-probe/topics/bootstrap-topic";
const subscription = "projects/demo-pubsub-probe/subscriptions/bootstrap-sub";
const labels = { fireemu_owner: "lane7", fireemu_run: "demo-run" };
const topicBody = { name: topic, labels };
const subscriptionBody = {
  name: subscription,
  topic,
  pushConfig: {},
  ackDeadlineSeconds: 60,
  messageRetentionDuration: "604800s",
  expirationPolicy: { ttl: "2678400s" },
  state: "ACTIVE",
};
async function classify(options) {
  assert.ok(existsSync(target), "recorded bootstrap shape classifier is missing");
  return (await import(target.href)).classifyBootstrapShape(options);
}
test("recorded REST bootstrap accepts exact topic, subscription, empty and leaf-only404 JSON shapes", async () => {
  const cases = [
    { kind: "topic", status: 200, body: topicBody, resource: topic, labels },
    { kind: "subscription", status: 200, body: subscriptionBody, resource: subscription, topic },
    { kind: "empty", status: 200, body: {} },
    ...[topic, subscription].map((resource) => ({
      kind: "missing",
      status: 404,
      resource,
      body: {
        error: {
          code: 404,
          message: `Resource not found (resource=${resource.split("/").at(-1)}).`,
          status: "NOT_FOUND",
        },
      },
    })),
  ];
  for (const input of cases)
    assert.deepEqual(await classify(input), { shape: "recorded-bootstrap-shape" });
});
test("all added, removed or changed observed subscription fields remain unknown", async () => {
  const base = { kind: "subscription", status: 200, resource: subscription, topic };
  for (const key of Object.keys(subscriptionBody)) {
    const missing = structuredClone(subscriptionBody);
    delete missing[key];
    assert.equal((await classify({ ...base, body: missing })).shape, "unknown-shape", key);
    const changed = structuredClone(subscriptionBody);
    changed[key] = null;
    assert.equal((await classify({ ...base, body: changed })).shape, "unknown-shape", key);
  }
  for (const extra of ["enableMessageOrdering", "retainAckedMessages", "futureField"])
    assert.equal(
      (await classify({ ...base, body: { ...subscriptionBody, [extra]: false } })).shape,
      "unknown-shape",
    );
  assert.equal(
    (await classify({ ...base, body: { ...subscriptionBody, pushConfig: { future: true } } }))
      .shape,
    "unknown-shape",
  );
});
test("classifier never coerces status, identities, fields or unrecorded error messages", async () => {
  for (const input of [
    { kind: "empty", status: "200", body: {} },
    { kind: "empty", status: 200, body: { topics: [], nextPageToken: "" } },
    { kind: "empty", status: 200, body: [] },
    {
      kind: "topic",
      status: 200,
      resource: topic,
      labels,
      body: { ...topicBody, name: topic + "-other" },
    },
    { kind: "topic", status: 201, resource: topic, labels, body: topicBody },
    {
      kind: "missing",
      status: 404,
      resource: topic,
      body: { error: { code: 404, status: "NOT_FOUND", message: `topic ${topic} not found` } },
    },
    { kind: "other", status: 200, body: {} },
    { kind: "topic", status: 200, body: topicBody },
  ])
    assert.equal((await classify(input)).shape, "unknown-shape");
});
test("key order does not change shape but the classifier leaves the raw input intact", async () => {
  const body = { labels: { fireemu_run: "demo-run", fireemu_owner: "lane7" }, name: topic };
  const before = JSON.stringify(body);
  assert.equal(
    (await classify({ kind: "topic", status: 200, body, resource: topic, labels })).shape,
    "recorded-bootstrap-shape",
  );
  assert.equal(JSON.stringify(body), before);
});
