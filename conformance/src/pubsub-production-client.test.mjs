import assert from "node:assert/strict";
import test from "node:test";
import {
  OPERATION_NAMES,
  PushPublishRefused,
  PushRefused,
  createClient,
  message,
  newPushState,
  restCode,
} from "./pubsub-production/client.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";

const RUN = "0123456789ab";
const own = createOwnership({ project: "demo-project", runId: RUN });
const T = own.resource("topics", "t");
const S = own.resource("subscriptions", "s");
const N = own.resource("snapshots", "n");

const fakeRest = (reply = { status: 200, body: {}, unknown: false }) => {
  const calls = [];
  return { name: "rest", calls, request: async (call) => (calls.push(call), reply) };
};
const fakeGrpc = (reply = { code: "OK", body: {}, unknown: false }) => {
  const calls = [];
  return { name: "grpc", calls, call: async (call) => (calls.push(call), reply) };
};
const rest = () => {
  const transport = fakeRest();
  return {
    transport,
    client: createClient({ transport, ownership: own, pushState: newPushState(), caseId: "c" }),
  };
};
const grpc = () => {
  const transport = fakeGrpc();
  return {
    transport,
    client: createClient({ transport, ownership: own, pushState: newPushState(), caseId: "c" }),
  };
};

test("the canonical code of a REST answer is the status the body names, or what the HTTP status means", () => {
  assert.equal(restCode(200, {}), "OK");
  assert.equal(restCode(204, null), "OK");
  assert.equal(restCode(404, { error: { status: "NOT_FOUND" } }), "NOT_FOUND");
  assert.equal(restCode(400, { error: { status: "OUT_OF_RANGE" } }), "OUT_OF_RANGE");
  for (const [status, code] of [
    [400, "INVALID_ARGUMENT"],
    [401, "UNAUTHENTICATED"],
    [403, "PERMISSION_DENIED"],
    [404, "NOT_FOUND"],
    [409, "ALREADY_EXISTS"],
    [412, "FAILED_PRECONDITION"],
    [429, "RESOURCE_EXHAUSTED"],
    [499, "CANCELLED"],
    [501, "UNIMPLEMENTED"],
    [503, "UNAVAILABLE"],
    [504, "DEADLINE_EXCEEDED"],
    [500, "INTERNAL"],
    [502, "INTERNAL"],
    [418, "UNKNOWN"],
  ])
    assert.equal(restCode(status, {}), code, String(status));
  assert.equal(
    restCode(404, { error: { status: 5 } }),
    "NOT_FOUND",
    "a status that is not text is ignored",
  );
  assert.equal(restCode(null, undefined), "UNKNOWN");
});

test("a message has base64 data, attributes and an ordering key, each only when given", () => {
  assert.deepEqual(message({ data: "hi", attributes: { a: "b" }, orderingKey: "k" }), {
    data: "aGk=",
    attributes: { a: "b" },
    orderingKey: "k",
  });
  assert.deepEqual(message({ attributes: { a: "b" } }), { attributes: { a: "b" } });
  assert.deepEqual(message({ data: Buffer.from([0, 255]) }), { data: "AP8=" });
  assert.deepEqual(message(), {});
  assert.deepEqual(message({ data: "" }), { data: "" });
});

const REST_EXPECTED = {
  createTopic: [
    [T, { labels: { a: "b" } }],
    ["PUT", `/v1/${T}`, { labels: { a: "b" } }],
  ],
  getTopic: [[T], ["GET", `/v1/${T}`, undefined]],
  listTopics: [
    ["demo-project", { pageSize: 2, pageToken: "x y" }],
    ["GET", "/v1/projects/demo-project/topics?pageSize=2&pageToken=x%20y", undefined],
  ],
  deleteTopic: [[T], ["DELETE", `/v1/${T}`, undefined]],
  publish: [
    [T, [{ data: "aGk=" }]],
    ["POST", `/v1/${T}:publish`, { messages: [{ data: "aGk=" }] }],
  ],
  listTopicSubscriptions: [
    [T, { pageSize: 1 }],
    ["GET", `/v1/${T}/subscriptions?pageSize=1`, undefined],
  ],
  listTopicSnapshots: [[T], ["GET", `/v1/${T}/snapshots`, undefined]],
  createSubscription: [
    [S, { topic: T, ackDeadlineSeconds: 30 }],
    ["PUT", `/v1/${S}`, { topic: T, ackDeadlineSeconds: 30 }],
  ],
  getSubscription: [[S], ["GET", `/v1/${S}`, undefined]],
  listSubscriptions: [
    ["demo-project"],
    ["GET", "/v1/projects/demo-project/subscriptions", undefined],
  ],
  deleteSubscription: [[S], ["DELETE", `/v1/${S}`, undefined]],
  updateSubscription: [
    [S, { ackDeadlineSeconds: 20 }, "ackDeadlineSeconds"],
    [
      "PATCH",
      `/v1/${S}`,
      { subscription: { name: S, ackDeadlineSeconds: 20 }, updateMask: "ackDeadlineSeconds" },
    ],
  ],
  modifyAckDeadline: [
    [S, ["a1"], 0],
    ["POST", `/v1/${S}:modifyAckDeadline`, { ackIds: ["a1"], ackDeadlineSeconds: 0 }],
  ],
  acknowledge: [
    [S, ["a1", "a2"]],
    ["POST", `/v1/${S}:acknowledge`, { ackIds: ["a1", "a2"] }],
  ],
  pull: [[S], ["POST", `/v1/${S}:pull`, { maxMessages: 10, returnImmediately: true }]],
  modifyPushConfig: [
    [S, {}],
    ["POST", `/v1/${S}:modifyPushConfig`, { pushConfig: {} }],
  ],
  createSnapshot: [
    [N, S, { k: "v" }],
    ["PUT", `/v1/${N}`, { subscription: S, labels: { k: "v" } }],
  ],
  getSnapshot: [[N], ["GET", `/v1/${N}`, undefined]],
  listSnapshots: [
    ["demo-project", { pageSize: 5 }],
    ["GET", "/v1/projects/demo-project/snapshots?pageSize=5", undefined],
  ],
  deleteSnapshot: [[N], ["DELETE", `/v1/${N}`, undefined]],
  getIamPolicy: [[T], ["GET", `/v1/${T}:getIamPolicy`, undefined]],
  setIamPolicy: [
    [T, { bindings: [] }],
    ["POST", `/v1/${T}:setIamPolicy`, { policy: { bindings: [] } }],
  ],
  seek: [
    [S, { snapshot: N }],
    ["POST", `/v1/${S}:seek`, { snapshot: N }],
  ],
};
const GRPC_EXPECTED = {
  createTopic: ["Publisher", "CreateTopic", { name: T, labels: { a: "b" } }],
  getTopic: ["Publisher", "GetTopic", { topic: T }],
  listTopics: [
    "Publisher",
    "ListTopics",
    { project: "projects/demo-project", pageSize: 2, pageToken: "x y" },
  ],
  deleteTopic: ["Publisher", "DeleteTopic", { topic: T }],
  publish: ["Publisher", "Publish", { topic: T, messages: [{ data: "aGk=" }] }],
  listTopicSubscriptions: ["Publisher", "ListTopicSubscriptions", { topic: T, pageSize: 1 }],
  listTopicSnapshots: ["Publisher", "ListTopicSnapshots", { topic: T }],
  createSubscription: [
    "Subscriber",
    "CreateSubscription",
    { name: S, topic: T, ackDeadlineSeconds: 30 },
  ],
  getSubscription: ["Subscriber", "GetSubscription", { subscription: S }],
  listSubscriptions: ["Subscriber", "ListSubscriptions", { project: "projects/demo-project" }],
  deleteSubscription: ["Subscriber", "DeleteSubscription", { subscription: S }],
  updateSubscription: [
    "Subscriber",
    "UpdateSubscription",
    { subscription: { name: S, ackDeadlineSeconds: 20 }, updateMask: "ackDeadlineSeconds" },
  ],
  modifyAckDeadline: [
    "Subscriber",
    "ModifyAckDeadline",
    { subscription: S, ackIds: ["a1"], ackDeadlineSeconds: 0 },
  ],
  acknowledge: ["Subscriber", "Acknowledge", { subscription: S, ackIds: ["a1", "a2"] }],
  pull: ["Subscriber", "Pull", { subscription: S, maxMessages: 10, returnImmediately: true }],
  modifyPushConfig: ["Subscriber", "ModifyPushConfig", { subscription: S, pushConfig: {} }],
  createSnapshot: [
    "Subscriber",
    "CreateSnapshot",
    { name: N, subscription: S, labels: { k: "v" } },
  ],
  getSnapshot: ["Subscriber", "GetSnapshot", { snapshot: N }],
  listSnapshots: ["Subscriber", "ListSnapshots", { project: "projects/demo-project", pageSize: 5 }],
  deleteSnapshot: ["Subscriber", "DeleteSnapshot", { snapshot: N }],
  seek: ["Subscriber", "Seek", { subscription: S, snapshot: N }],
};

test("every operation is the REST request the API documents", async () => {
  assert.deepEqual(OPERATION_NAMES.toSorted(), Object.keys(REST_EXPECTED).toSorted());
  for (const [operation, [args, [method, path, body]]] of Object.entries(REST_EXPECTED)) {
    const { transport, client } = rest();
    const reply = await client[operation](...args);
    assert.equal(transport.calls.length, 1, operation);
    assert.deepEqual(
      transport.calls[0],
      { label: { case: "c", step: "01" }, op: operation, method, path, body },
      operation,
    );
    assert.equal(reply.ok, true, operation);
    assert.equal(reply.code, "OK", operation);
    assert.equal(reply.step, "01", operation);
  }
});

test("every operation is the gRPC call of the same request", async () => {
  for (const [operation, [args]] of Object.entries(REST_EXPECTED)) {
    const { transport, client } = grpc();
    if (!(operation in GRPC_EXPECTED)) {
      // The IAM methods have no gRPC form here: they refuse before anything is sent.
      await assert.rejects(client[operation](...args), /only available over REST/);
      assert.equal(transport.calls.length, 0, operation);
      continue;
    }
    await client[operation](...args);
    const [service, method, request] = GRPC_EXPECTED[operation];
    assert.deepEqual(
      transport.calls[0],
      { label: { case: "c", step: "01" }, op: operation, service, method, request },
      operation,
    );
  }
});

test("the steps are numbered in order, and the answer is normalized on both transports", async () => {
  const transport = fakeRest({
    status: 404,
    body: { error: { status: "NOT_FOUND", message: "m" } },
    unknown: false,
  });
  const client = createClient({
    transport,
    ownership: own,
    pushState: newPushState(),
    caseId: "c",
  });
  const first = await client.getTopic(T);
  const second = await client.getTopic(T);
  assert.deepEqual([first.step, second.step, transport.calls[1].label.step], ["01", "02", "02"]);
  assert.equal(first.ok, false);
  assert.equal(first.code, "NOT_FOUND");
  assert.equal(first.status, 404);
  const grpcTransport = fakeGrpc({
    code: "NOT_FOUND",
    message: "gone",
    body: undefined,
    unknown: false,
  });
  const grpcClient = createClient({
    transport: grpcTransport,
    ownership: own,
    pushState: newPushState(),
    caseId: "g",
  });
  const reply = await grpcClient.getTopic(T);
  assert.deepEqual([reply.ok, reply.code, reply.message], [false, "NOT_FOUND", "gone"]);
  assert.equal(grpcClient.transport, "grpc");
  assert.equal(client.transport, "rest");
});

test("an operation with a token choice or a timeout passes it on and is otherwise the same", async () => {
  const { transport, client } = rest();
  await client.with({ token: "none" }).getTopic(T);
  await client.with({ token: "invalid", timeoutMs: 5 }).getTopic(T);
  await client.getTopic(T);
  assert.equal(transport.calls[0].token, "none");
  assert.deepEqual([transport.calls[1].token, transport.calls[1].timeoutMs], ["invalid", 5]);
  assert.equal(transport.calls[2].token, undefined);
  assert.deepEqual(
    transport.calls.map((call) => call.label.step),
    ["01", "02", "03"],
  );
});

test("a changing operation on a resource that is not the run's is refused before anything is sent", async () => {
  const foreign = "projects/other-project/subscriptions/fe0123456789ab-x";
  for (const [index, make] of [rest, grpc].entries()) {
    // The ownership is shared, so each transport probes a name of its own.
    const other = `projects/demo-project/topics/other-${index}`;
    const { transport, client } = make();
    const refused = [
      () => client.createTopic(other),
      () => client.deleteTopic(other),
      () => client.publish(other, []),
      () => client.createSubscription(S, { topic: other }),
      () => client.createSubscription(foreign, { topic: T }),
      () => client.deleteSubscription(foreign),
      () => client.updateSubscription(foreign, {}, "x"),
      () => client.modifyAckDeadline(foreign, [], 1),
      () => client.acknowledge(foreign, []),
      () => client.pull(foreign),
      () => client.modifyPushConfig(foreign, {}),
      () => client.createSnapshot("projects/demo-project/snapshots/other", S),
      () => client.createSnapshot(N, foreign),
      () => client.deleteSnapshot("projects/demo-project/snapshots/other"),
      () => client.seek(S, { snapshot: "projects/demo-project/snapshots/other" }),
      () => client.seek(foreign, { time: "2026-10-05T00:00:00Z" }),
    ];
    for (const [position, attempt] of refused.entries())
      await assert.rejects(attempt(), /not a resource of this run/, `refused[${position}]`);
    assert.equal(transport.calls.length, 0, `${transport.name}: nothing was sent`);
    // Reads of anything are allowed, and a registered probe may be changed.
    await client.getTopic(other);
    await client.listTopics("demo-project");
    own.registerProbe(other);
    await client.createTopic(other);
    assert.equal(transport.calls.length, 3);
  }
});

test("a topic with a push subscription is never published to, on either transport, however the push began", async () => {
  const pushState = newPushState();
  const restTransport = fakeRest();
  const grpcTransport = fakeGrpc();
  const restClient = createClient({
    transport: restTransport,
    ownership: own,
    pushState,
    caseId: "r",
  });
  const grpcClient = createClient({
    transport: grpcTransport,
    ownership: own,
    pushState,
    caseId: "g",
  });
  const pushTopic = own.resource("topics", "push-topic");
  const pushSubscription = own.resource("subscriptions", "push-sub");
  const pullTopic = own.resource("topics", "pull-topic");
  const pullSubscription = own.resource("subscriptions", "pull-sub");
  await restClient.createSubscription(pushSubscription, {
    topic: pushTopic,
    pushConfig: { pushEndpoint: "https://example.com/p" },
  });
  await assert.rejects(grpcClient.publish(pushTopic, [{}]), PushPublishRefused);
  await assert.rejects(restClient.publish(pushTopic, [{}]), /push subscription is attached/);
  // A pull subscription that is turned into a push one, by a push config or by an update, bans its topic.
  await restClient.createSubscription(pullSubscription, { topic: pullTopic });
  await grpcClient.modifyPushConfig(pullSubscription, { pushEndpoint: "https://example.com/q" });
  await assert.rejects(restClient.publish(pullTopic, [{}]), PushPublishRefused);
  assert.deepEqual([...pushState.topics].toSorted(), [pullTopic, pushTopic].toSorted());
  assert.deepEqual(
    [...pushState.subscriptions].toSorted(),
    [pullSubscription, pushSubscription].toSorted(),
  );
  // The ban counts when the push is requested, not when it was accepted.
  const refusedTopic = own.resource("topics", "refused-topic");
  const refusedSubscription = own.resource("subscriptions", "refused-sub");
  const failing = fakeRest({ status: 400, body: {}, unknown: false });
  const failingClient = createClient({
    transport: failing,
    ownership: own,
    pushState,
    caseId: "f",
  });
  await failingClient.createSubscription(refusedSubscription, {
    topic: refusedTopic,
    pushConfig: { pushEndpoint: "http://bad" },
  });
  await assert.rejects(restClient.publish(refusedTopic, [{}]), PushPublishRefused);
  // An empty push config is a pull subscription, and a subscription whose topic is unknown cannot be pushed.
  const emptyTopic = own.resource("topics", "empty-topic");
  const emptySubscription = own.resource("subscriptions", "empty-sub");
  await restClient.createSubscription(emptySubscription, { topic: emptyTopic, pushConfig: {} });
  await restClient.publish(emptyTopic, [{}]);
  await assert.rejects(
    restClient.modifyPushConfig(own.resource("subscriptions", "stray"), {
      pushEndpoint: "https://example.com/z",
    }),
    /cannot tell the topic/,
  );
  assert.equal(restTransport.calls.filter((call) => call.op === "publish").length, 1);
  assert.equal(grpcTransport.calls.filter((call) => call.op === "publish").length, 0);
});

test("an IAM policy is only changed on a resource of the run", async () => {
  const { transport, client } = rest();
  await assert.rejects(
    client.setIamPolicy("projects/demo-project/topics/other", { bindings: [] }),
    /not a resource of this run/,
  );
  await client.getIamPolicy("projects/demo-project/topics/other");
  assert.equal(transport.calls.length, 1);
});

test("the push ban also refuses a seek on a push subscription, a dead-letter topic with one, and a push on a topic with messages or retention", async () => {
  const pushState = newPushState();
  const transport = fakeRest();
  const client = createClient({ transport, ownership: own, pushState, caseId: "c" });
  const grpcClient = createClient({
    transport: fakeGrpc(),
    ownership: own,
    pushState,
    caseId: "g",
  });
  const topic = own.resource("topics", "ban-t");
  const sub = own.resource("subscriptions", "ban-s");
  await client.createSubscription(sub, {
    topic,
    pushConfig: { pushEndpoint: "https://example.com/p" },
  });
  const sent = transport.calls.length;
  // A seek on the push subscription, from either transport.
  await assert.rejects(client.seek(sub, { time: "2026-10-05T00:00:00Z" }), PushRefused);
  await assert.rejects(grpcClient.seek(sub, { time: "2026-10-05T00:00:00Z" }), PushRefused);
  // A dead-letter topic that has a push subscription would receive forwarded messages.
  const source = own.resource("subscriptions", "ban-source");
  await assert.rejects(
    client.createSubscription(source, {
      topic: own.resource("topics", "ban-other"),
      deadLetterPolicy: { deadLetterTopic: topic },
    }),
    PushRefused,
  );
  assert.equal(transport.calls.length, sent, "nothing was sent for any of them");
  // A pull subscription on a published-to topic cannot be turned into a push one, by create, update or modify.
  const published = own.resource("topics", "ban-published");
  const pullSub = own.resource("subscriptions", "ban-pull");
  await client.createSubscription(pullSub, { topic: published });
  await client.publish(published, [{}]);
  await assert.rejects(
    client.modifyPushConfig(pullSub, { pushEndpoint: "https://example.com/q" }),
    PushRefused,
  );
  await assert.rejects(
    client.updateSubscription(
      pullSub,
      { pushConfig: { pushEndpoint: "https://example.com/q" } },
      "pushConfig",
    ),
    PushRefused,
  );
  await assert.rejects(
    client.createSubscription(own.resource("subscriptions", "ban-late"), {
      topic: published,
      pushConfig: { pushEndpoint: "https://example.com/q" },
    }),
    PushRefused,
  );
  // A topic that keeps messages (retention) cannot get a push subscription either.
  const retained = own.resource("topics", "ban-retained");
  await client.createTopic(retained, { messageRetentionDuration: "3600s" });
  await assert.rejects(
    client.createSubscription(own.resource("subscriptions", "ban-ret"), {
      topic: retained,
      pushConfig: { pushEndpoint: "https://example.com/q" },
    }),
    PushRefused,
  );
  // A pull subscription on a quiet topic is still fine, and so is a seek on it.
  const quiet = own.resource("topics", "ban-quiet");
  const quietSub = own.resource("subscriptions", "ban-quiet-s");
  await client.createSubscription(quietSub, { topic: quiet });
  await client.seek(quietSub, { time: "2026-10-05T00:00:00Z" });
});
