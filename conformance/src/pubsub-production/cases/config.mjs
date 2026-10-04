import { must } from "./support.mjs";

// The reply of a creation already carries the stored configuration. Only the variants named here are
// read back as well, which records that what is stored survives to a later read.
const READ_BACK = new Set(["plain", "labels", "ttl-never", "retry-valid", "dl-5", "retention-min"]);

async function createAndGet(c, key, create, get) {
  const reply = await create();
  if (reply.ok && READ_BACK.has(key)) await get();
  return reply;
}

export const topicConfig = {
  id: "topic-config",
  short: "tc",
  requests: 16,
  async run(ctx) {
    const c = ctx.client;
    const variants = [
      ["plain", {}],
      ["labels", { labels: { env: "test", ttl: "7" } }],
      ["retention-min", { messageRetentionDuration: "600s" }],
      ["retention-under-min", { messageRetentionDuration: "599s" }],
      ["retention-max", { messageRetentionDuration: "2678400s" }],
      ["retention-over-max", { messageRetentionDuration: "2678401s" }],
      ["retention-fraction", { messageRetentionDuration: "600.5s" }],
      ["storage-region", { messageStoragePolicy: { allowedPersistenceRegions: ["us-central1"] } }],
      [
        "storage-bad-region",
        { messageStoragePolicy: { allowedPersistenceRegions: ["no-such-region1"] } },
      ],
      ["label-key-upper", { labels: { Upper: "x" } }],
      ["label-value-long", { labels: { k: "v".repeat(64) } }],
    ];
    for (const [key, body] of variants) {
      const name = ctx.name("topics", key);
      await createAndGet(
        c,
        key,
        () => c.createTopic(name, body),
        () => c.getTopic(name),
      );
    }
    // An output-only or unknown field in the body.
    await c.createTopic(ctx.name("topics", "unknown-field"), { noSuchField: 1 });
  },
};

export const subscriptionConfig = {
  id: "subscription-config",
  short: "sc",
  requests: 45,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const dlTopic = ctx.name("topics", "dl");
    must(await c.createTopic(topic), "createTopic");
    must(await c.createTopic(dlTopic), "createTopic dead letter");
    const variants = [
      ["plain", {}],
      ["ack-10", { ackDeadlineSeconds: 10 }],
      ["ack-600", { ackDeadlineSeconds: 600 }],
      ["ack-9", { ackDeadlineSeconds: 9 }],
      ["ack-601", { ackDeadlineSeconds: 601 }],
      ["retain-acked", { retainAckedMessages: true }],
      ["retention-min", { messageRetentionDuration: "600s" }],
      ["retention-under-min", { messageRetentionDuration: "599s" }],
      ["retention-max", { messageRetentionDuration: "604800s" }],
      ["retention-over-max", { messageRetentionDuration: "604801s" }],
      ["ordering", { enableMessageOrdering: true }],
      ["exactly-once", { enableExactlyOnceDelivery: true }],
      ["labels", { labels: { env: "test", ttl: "7" } }],
      ["filter", { filter: 'attributes.color = "red"' }],
      ["filter-bad-syntax", { filter: "attributes.color ==" }],
      ["ttl-one-day", { expirationPolicy: { ttl: "86400s" } }],
      ["ttl-under-one-day", { expirationPolicy: { ttl: "86399s" } }],
      ["ttl-never", { expirationPolicy: {} }],
      ["retry-valid", { retryPolicy: { minimumBackoff: "10s", maximumBackoff: "600s" } }],
      ["retry-min-over-max", { retryPolicy: { minimumBackoff: "100s", maximumBackoff: "50s" } }],
      ["retry-max-over-600", { retryPolicy: { minimumBackoff: "10s", maximumBackoff: "601s" } }],
      ["output-state", { state: "RESOURCE_ERROR" }],
    ];
    for (const [key, body] of variants) {
      const name = ctx.name("subscriptions", key);
      await createAndGet(
        c,
        key,
        () => c.createSubscription(name, { topic, ...body }),
        () => c.getSubscription(name),
      );
    }
    // The dead-letter policy is only validated here; forwarding has its own case.
    const policies = [
      ["dl-5", { deadLetterTopic: dlTopic, maxDeliveryAttempts: 5 }],
      ["dl-default", { deadLetterTopic: dlTopic }],
      ["dl-4", { deadLetterTopic: dlTopic, maxDeliveryAttempts: 4 }],
      ["dl-101", { deadLetterTopic: dlTopic, maxDeliveryAttempts: 101 }],
      [
        "dl-missing-topic",
        { deadLetterTopic: ctx.name("topics", "never-created"), maxDeliveryAttempts: 5 },
      ],
      ["dl-same-topic", { deadLetterTopic: topic, maxDeliveryAttempts: 5 }],
    ];
    for (const [key, policy] of policies) {
      const name = ctx.name("subscriptions", key);
      await createAndGet(
        c,
        key,
        () => c.createSubscription(name, { topic, deadLetterPolicy: policy }),
        () => c.getSubscription(name),
      );
    }
    await c.listTopicSubscriptions(topic, { pageSize: 100 });
  },
};

export const subscriptionUpdate = {
  id: "subscription-update",
  short: "su",
  requests: 22,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const subscription = ctx.name("subscriptions", "s");
    must(await c.createTopic(topic), "createTopic");
    must(await c.createSubscription(subscription, { topic }), "createSubscription");
    const updates = [
      [{ ackDeadlineSeconds: 20 }, "ackDeadlineSeconds"],
      [{ labels: { env: "updated" } }, "labels"],
      [{ expirationPolicy: { ttl: "172800s" } }, "expirationPolicy"],
      [{ expirationPolicy: { ttl: "3600s" } }, "expirationPolicy"],
      [{ retainAckedMessages: true }, "retainAckedMessages"],
      [{ enableMessageOrdering: true }, "enableMessageOrdering"],
      [{ filter: 'attributes.color = "blue"' }, "filter"],
      [{ retryPolicy: { minimumBackoff: "20s", maximumBackoff: "300s" } }, "retryPolicy"],
      [{ ackDeadlineSeconds: 30, labels: { a: "b" } }, "ackDeadlineSeconds,labels"],
      [{ ackDeadlineSeconds: 40 }, "noSuchField"],
      [{ ackDeadlineSeconds: 40 }, ""],
      [{ ackDeadlineSeconds: 40 }, "ack_deadline_seconds"],
      [{ topic: ctx.name("topics", "other") }, "topic"],
    ];
    for (const [body, mask] of updates) {
      // Read back only what the service accepted.
      const reply = await c.updateSubscription(subscription, body, mask);
      if (reply.ok) await c.getSubscription(subscription);
    }
    await c.updateSubscription(
      ctx.name("subscriptions", "never-created"),
      { ackDeadlineSeconds: 20 },
      "ackDeadlineSeconds",
    );
  },
};
