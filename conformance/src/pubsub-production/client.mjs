// The operations of a recording, the same on both transports. A case calls `client.createTopic(...)`;
// the client sends it as a REST request or a gRPC call, normalizes the answer, and refuses before
// sending anything that would change a resource of someone else (every changing operation names a
// resource that must belong to the run) or publish to a topic that has a push subscription (a push
// subscription is created, read and deleted, and never delivered to).

import { createLedger, kindOf } from "./ledger.mjs";

const CODE_OF_STATUS = new Map([
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
]);

export class PushPublishRefused extends Error {
  constructor(topic) {
    super(`refusing to publish to ${topic}: a push subscription is attached to it`);
    this.name = "PushPublishRefused";
  }
}

/** A request that could cause a delivery to a push endpoint, refused before it is sent. */
export class PushRefused extends Error {
  constructor(what) {
    super(`refusing ${what}: it could cause a delivery to a push endpoint`);
    this.name = "PushRefused";
  }
}

/** The canonical code of a REST answer: the status the body names, or the one the HTTP status means. */
export function restCode(status, body) {
  if (status === null) return "UNKNOWN";
  if (status >= 200 && status < 300) return "OK";
  const named = body?.error?.status;
  if (typeof named === "string") return named;
  return CODE_OF_STATUS.get(status) ?? (status >= 500 ? "INTERNAL" : "UNKNOWN");
}

const encodeName = (name) => name.split("/").map(encodeURIComponent).join("/");
const query = (page = {}) => {
  const parts = [];
  if (page.pageSize !== undefined) parts.push(`pageSize=${encodeURIComponent(page.pageSize)}`);
  if (page.pageToken !== undefined) parts.push(`pageToken=${encodeURIComponent(page.pageToken)}`);
  return parts.length === 0 ? "" : `?${parts.join("&")}`;
};

/** A message to publish: `data` is text or bytes, sent base64 as both transports expect. */
export function message({ data, attributes, orderingKey } = {}) {
  const value = {};
  if (data !== undefined) value.data = Buffer.from(data).toString("base64");
  if (attributes !== undefined) value.attributes = attributes;
  if (orderingKey !== undefined) value.orderingKey = orderingKey;
  return value;
}

/** Every operation as a REST request, a gRPC call and the resources it changes (which must be owned). */
const OPERATIONS = {
  createTopic: (name, body = {}) => ({
    rest: ["PUT", `/v1/${encodeName(name)}`, body],
    grpc: ["Publisher", "CreateTopic", { name, ...body }],
    changes: [name],
    ledger: { action: "create", name },
    retains: body.messageRetentionDuration === undefined ? undefined : name,
  }),
  getTopic: (name) => ({
    rest: ["GET", `/v1/${encodeName(name)}`],
    grpc: ["Publisher", "GetTopic", { topic: name }],
  }),
  listTopics: (project, page) => ({
    rest: ["GET", `/v1/projects/${project}/topics${query(page)}`],
    grpc: ["Publisher", "ListTopics", { project: `projects/${project}`, ...page }],
  }),
  deleteTopic: (name) => ({
    rest: ["DELETE", `/v1/${encodeName(name)}`],
    grpc: ["Publisher", "DeleteTopic", { topic: name }],
    changes: [name],
    ledger: { action: "delete", name },
  }),
  publish: (topic, messages) => ({
    rest: ["POST", `/v1/${encodeName(topic)}:publish`, { messages }],
    grpc: ["Publisher", "Publish", { topic, messages }],
    changes: [topic],
    publishes: topic,
  }),
  listTopicSubscriptions: (topic, page) => ({
    rest: ["GET", `/v1/${encodeName(topic)}/subscriptions${query(page)}`],
    grpc: ["Publisher", "ListTopicSubscriptions", { topic, ...page }],
  }),
  listTopicSnapshots: (topic, page) => ({
    rest: ["GET", `/v1/${encodeName(topic)}/snapshots${query(page)}`],
    grpc: ["Publisher", "ListTopicSnapshots", { topic, ...page }],
  }),
  createSubscription: (name, body) => ({
    rest: ["PUT", `/v1/${encodeName(name)}`, body],
    grpc: ["Subscriber", "CreateSubscription", { name, ...body }],
    changes: [name, body.topic],
    ledger: { action: "create", name },
    subscription: { name, topic: body.topic, push: body.pushConfig?.pushEndpoint },
    deadLetterTopic: body.deadLetterPolicy?.deadLetterTopic,
  }),
  getSubscription: (name) => ({
    rest: ["GET", `/v1/${encodeName(name)}`],
    grpc: ["Subscriber", "GetSubscription", { subscription: name }],
  }),
  listSubscriptions: (project, page) => ({
    rest: ["GET", `/v1/projects/${project}/subscriptions${query(page)}`],
    grpc: ["Subscriber", "ListSubscriptions", { project: `projects/${project}`, ...page }],
  }),
  deleteSubscription: (name) => ({
    rest: ["DELETE", `/v1/${encodeName(name)}`],
    grpc: ["Subscriber", "DeleteSubscription", { subscription: name }],
    changes: [name],
    ledger: { action: "delete", name },
  }),
  updateSubscription: (name, subscription, updateMask) => ({
    rest: [
      "PATCH",
      `/v1/${encodeName(name)}`,
      { subscription: { name, ...subscription }, updateMask },
    ],
    grpc: [
      "Subscriber",
      "UpdateSubscription",
      { subscription: { name, ...subscription }, updateMask },
    ],
    changes: [name],
    subscription: { name, push: subscription.pushConfig?.pushEndpoint },
  }),
  modifyAckDeadline: (subscription, ackIds, ackDeadlineSeconds) => ({
    rest: [
      "POST",
      `/v1/${encodeName(subscription)}:modifyAckDeadline`,
      { ackIds, ackDeadlineSeconds },
    ],
    grpc: ["Subscriber", "ModifyAckDeadline", { subscription, ackIds, ackDeadlineSeconds }],
    changes: [subscription],
  }),
  acknowledge: (subscription, ackIds) => ({
    rest: ["POST", `/v1/${encodeName(subscription)}:acknowledge`, { ackIds }],
    grpc: ["Subscriber", "Acknowledge", { subscription, ackIds }],
    changes: [subscription],
  }),
  pull: (subscription, body = { maxMessages: 10, returnImmediately: true }) => ({
    rest: ["POST", `/v1/${encodeName(subscription)}:pull`, body],
    grpc: ["Subscriber", "Pull", { subscription, ...body }],
    changes: [subscription],
  }),
  modifyPushConfig: (subscription, pushConfig) => ({
    rest: ["POST", `/v1/${encodeName(subscription)}:modifyPushConfig`, { pushConfig }],
    grpc: ["Subscriber", "ModifyPushConfig", { subscription, pushConfig }],
    changes: [subscription],
    subscription: { name: subscription, push: pushConfig.pushEndpoint },
  }),
  createSnapshot: (name, subscription, labels) => ({
    rest: ["PUT", `/v1/${encodeName(name)}`, { subscription, ...(labels ? { labels } : {}) }],
    grpc: ["Subscriber", "CreateSnapshot", { name, subscription, ...(labels ? { labels } : {}) }],
    changes: [name, subscription],
    ledger: { action: "create", name },
  }),
  getSnapshot: (name) => ({
    rest: ["GET", `/v1/${encodeName(name)}`],
    grpc: ["Subscriber", "GetSnapshot", { snapshot: name }],
  }),
  listSnapshots: (project, page) => ({
    rest: ["GET", `/v1/projects/${project}/snapshots${query(page)}`],
    grpc: ["Subscriber", "ListSnapshots", { project: `projects/${project}`, ...page }],
  }),
  deleteSnapshot: (name) => ({
    rest: ["DELETE", `/v1/${encodeName(name)}`],
    grpc: ["Subscriber", "DeleteSnapshot", { snapshot: name }],
    changes: [name],
    ledger: { action: "delete", name },
  }),
  // The IAM methods are REST only: the google.iam protos are not part of the Pub/Sub package.
  getIamPolicy: (resource) => ({
    rest: ["GET", `/v1/${encodeName(resource)}:getIamPolicy`],
    grpc: null,
  }),
  setIamPolicy: (resource, policy) => ({
    rest: ["POST", `/v1/${encodeName(resource)}:setIamPolicy`, { policy }],
    grpc: null,
    changes: [resource],
  }),
  seek: (subscription, target) => ({
    rest: ["POST", `/v1/${encodeName(subscription)}:seek`, target],
    grpc: ["Subscriber", "Seek", { subscription, ...target }],
    changes: target.snapshot === undefined ? [subscription] : [subscription, target.snapshot],
    seeks: subscription,
  }),
};

export const OPERATION_NAMES = Object.freeze(Object.keys(OPERATIONS));

/**
 * The client of one transport. `label()` gives the capture its case and a step number; `pushState` is
 * shared by every client of the run so that the push ban holds across transports.
 */
export function createClient({ transport, ownership, pushState, caseId, ledger = createLedger() }) {
  let step = 0;
  const run = async (operation, args, options = {}) => {
    const spec = OPERATIONS[operation](...args);
    if (spec.grpc === null && transport.name !== "rest")
      throw new Error(`${operation} is only available over REST`);
    for (const name of spec.changes ?? []) if (name !== undefined) ownership.assertOwned(name);
    if (spec.publishes !== undefined) {
      if (pushState.topics.has(spec.publishes)) throw new PushPublishRefused(spec.publishes);
      pushState.published.add(spec.publishes);
    }
    if (spec.seeks !== undefined && pushState.subscriptions.has(spec.seeks))
      throw new PushRefused(`a seek on the push subscription ${spec.seeks}`);
    if (spec.deadLetterTopic !== undefined && pushState.topics.has(spec.deadLetterTopic))
      throw new PushRefused(
        `a dead-letter topic ${spec.deadLetterTopic} that has a push subscription`,
      );
    if (spec.retains !== undefined) pushState.retained.add(spec.retains);
    const subscription = spec.subscription;
    if (subscription !== undefined) {
      if (subscription.topic !== undefined)
        pushState.topicOf.set(subscription.name, subscription.topic);
      // A push subscription is known as soon as it is requested, whatever the answer: its topic is
      // never published to.
      if (typeof subscription.push === "string" && subscription.push !== "") {
        const topic = pushState.topicOf.get(subscription.name);
        if (topic === undefined)
          throw new Error(`cannot tell the topic of the push subscription ${subscription.name}`);
        // A topic that was published to, or that keeps messages, would redeliver them to the endpoint
        // (a seek, or the first delivery attempt).
        if (pushState.published.has(topic) || pushState.retained.has(topic))
          throw new PushRefused(`a push subscription on ${topic}, which has messages or retention`);
        pushState.subscriptions.add(subscription.name);
        pushState.topics.add(topic);
      }
    }
    step += 1;
    const label = { case: caseId, step: String(step).padStart(2, "0") };
    // The ledger line is written before the request is sent: a run that dies in the middle of it still
    // names what may have been created or deleted.
    const entry = spec.ledger && { ...spec.ledger, transport: transport.name };
    if (entry) ledger.sent(entry);
    let reply;
    if (transport.name === "rest") {
      const [method, path, body] = spec.rest;
      reply = await transport.request({ label, op: operation, method, path, body, ...options });
      reply = { ...reply, code: restCode(reply.status, reply.body) };
    } else {
      const [service, method, request] = spec.grpc;
      reply = await transport.call({ label, op: operation, service, method, request, ...options });
    }
    // A 2xx whose body cannot be read does not say what was done, so it is not a success.
    const result = {
      ...reply,
      ok: reply.code === "OK" && reply.unknown !== true,
      step: label.step,
    };
    if (entry) ledger.answered({ ...entry, kind: kindOf(result) });
    return result;
  };
  const methods = (options) =>
    Object.fromEntries(
      OPERATION_NAMES.map((name) => [name, (...args) => run(name, args, options)]),
    );
  return Object.freeze({
    transport: transport.name,
    ...methods(),
    /** The same operations with a token choice ("none" or "invalid") or a timeout. */
    with: (options) => methods(options),
  });
}

/** What the push subscriptions of the run have touched: the topics that must never be published to. */
export const newPushState = () => ({
  subscriptions: new Set(),
  topics: new Set(),
  topicOf: new Map(),
  published: new Set(),
  retained: new Set(),
});
