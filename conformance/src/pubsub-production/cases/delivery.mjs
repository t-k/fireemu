import { message } from "../client.mjs";
import { ackIds, must, pullMessages } from "./support.mjs";

async function topicAndSubscription(ctx, body = {}, key = "s") {
  const topic = ctx.name("topics", `t-${key}`);
  const subscription = ctx.name("subscriptions", key);
  must(await ctx.client.createTopic(topic), "createTopic");
  must(await ctx.client.createSubscription(subscription, { topic, ...body }), "createSubscription");
  return { topic, subscription };
}

export const pullAck = {
  id: "pull-ack",
  short: "pa",
  requests: 25,
  async run(ctx) {
    const c = ctx.client;
    const { topic, subscription } = await topicAndSubscription(ctx);
    // Nothing to pull yet, and the arguments of a pull.
    await c.pull(subscription, { maxMessages: 10, returnImmediately: true });
    await c.pull(subscription, { maxMessages: 0, returnImmediately: true });
    await c.pull(subscription, { maxMessages: -1, returnImmediately: true });
    await c.pull(subscription, { returnImmediately: true });
    await c.pull(ctx.name("subscriptions", "never-created"), {
      maxMessages: 1,
      returnImmediately: true,
    });
    must(
      await c.publish(topic, [
        message({ data: "a", attributes: { n: "1" } }),
        message({ data: "b", attributes: { n: "2" } }),
        message({ data: "c", attributes: { n: "3" } }),
      ]),
      "publish",
    );
    const received = await pullMessages(ctx, subscription, 3);
    if (received.length === 0) return;
    const ids = ackIds(received);
    // Acknowledgement: the shapes it accepts and refuses.
    await c.acknowledge(subscription, []);
    await c.acknowledge(subscription, ["not-an-ack-id"]);
    await c.acknowledge(subscription, [ids[0], "not-an-ack-id"]);
    await c.acknowledge(subscription, ids);
    await c.acknowledge(subscription, ids);
    await c.acknowledge(ctx.name("subscriptions", "never-created"), ids);
    await c.pull(subscription, { maxMessages: 10, returnImmediately: true });
    // A message that was acknowledged cannot have its deadline changed.
    await c.modifyAckDeadline(subscription, [ids[0]], 30);
    await c.modifyAckDeadline(subscription, [], 30);
    await c.modifyAckDeadline(subscription, ["not-an-ack-id"], 30);
    await c.modifyAckDeadline(ctx.name("subscriptions", "never-created"), ids, 30);
  },
};

export const nackAndDeadline = {
  id: "nack-deadline",
  short: "nd",
  requests: 20,
  slow: true,
  async run(ctx) {
    const c = ctx.client;
    const { topic, subscription } = await topicAndSubscription(ctx, { ackDeadlineSeconds: 10 });
    must(
      await c.publish(topic, [message({ data: "nack me" }), message({ data: "extend me" })]),
      "publish",
    );
    let received = await pullMessages(ctx, subscription, 2);
    if (received.length === 0) return;
    // A negative acknowledgement redelivers at once; so does an expired deadline.
    await c.modifyAckDeadline(subscription, [received[0].ackId], 0);
    await c.modifyAckDeadline(subscription, [received[0].ackId], 601);
    await c.modifyAckDeadline(subscription, [received[0].ackId], -1);
    const again = await pullMessages(ctx, subscription, 1, { attempts: 3 });
    // The deadline of the other message is extended to its maximum and then let run out.
    if (received.length > 1) await c.modifyAckDeadline(subscription, [received[1].ackId], 600);
    await c.modifyAckDeadline(
      subscription,
      again.length > 0 ? [again[0].ackId] : [received[0].ackId],
      10,
    );
    await ctx.sleep(12_000);
    received = await pullMessages(ctx, subscription, 1, { attempts: 4 });
    // The ack ID of the first delivery after the deadline has run out.
    await c.acknowledge(subscription, ackIds(received));
    await c.pull(subscription, { maxMessages: 10, returnImmediately: true });
  },
};

export const filtering = {
  id: "filter",
  short: "fl",
  requests: 15,
  async run(ctx) {
    const c = ctx.client;
    const { topic, subscription } = await topicAndSubscription(ctx, {
      filter: 'attributes.color = "red"',
    });
    must(
      await c.publish(topic, [
        message({ data: "red", attributes: { color: "red" } }),
        message({ data: "blue", attributes: { color: "blue" } }),
        message({ data: "none" }),
        message({ data: "red again", attributes: { color: "red", extra: "1" } }),
      ]),
      "publish",
    );
    // Only the matching messages are delivered; the others are acknowledged by the service.
    const received = await pullMessages(ctx, subscription, 2);
    if (received.length > 0) await c.acknowledge(subscription, ackIds(received));
    await c.pull(subscription, { maxMessages: 10, returnImmediately: true });
    // A second filter form, on a subscription of the same topic.
    const second = ctx.name("subscriptions", "s2");
    await c.createSubscription(second, { topic, filter: 'hasPrefix(attributes.color, "re")' });
    await c.createSubscription(ctx.name("subscriptions", "s3"), {
      topic,
      filter: "attributes:color",
    });
    await c.createSubscription(ctx.name("subscriptions", "s4"), {
      topic,
      filter: 'NOT attributes.color = "red"',
    });
    must(
      await c.publish(topic, [message({ data: "x", attributes: { color: "red" } })]),
      "publish again",
    );
    const next = await pullMessages(ctx, second, 1, { attempts: 3 });
    if (next.length > 0) await c.acknowledge(second, ackIds(next));
  },
};

export const ordering = {
  id: "ordering",
  short: "or",
  requests: 22,
  async run(ctx) {
    const c = ctx.client;
    const { topic, subscription } = await topicAndSubscription(ctx, {
      enableMessageOrdering: true,
    });
    const unordered = ctx.name("subscriptions", "plain");
    must(await c.createSubscription(unordered, { topic }), "createSubscription plain");
    const batch = (key, prefix) =>
      Array.from({ length: 5 }, (_, i) => message({ data: `${prefix}${i}`, orderingKey: key }));
    must(await c.publish(topic, batch("k1", "a")), "publish k1");
    must(await c.publish(topic, batch("k2", "b")), "publish k2");
    must(await c.publish(topic, [message({ data: "no key" })]), "publish without key");
    // With ordering on, a pull gives the messages of a key in order and holds the later ones back
    // until the earlier ones are acknowledged.
    let received = await pullMessages(ctx, subscription, 3);
    ctx.note("ordering", { firstPull: received.map((m) => m.message?.data) });
    for (let round = 0; round < 4 && received.length > 0; round += 1) {
      await c.acknowledge(subscription, ackIds(received));
      received = await pullMessages(ctx, subscription, 1, { attempts: 2 });
    }
    // The subscription without ordering gets the same messages in no promised order.
    const plain = await pullMessages(ctx, unordered, 11, { attempts: 4 });
    if (plain.length > 0) await c.acknowledge(unordered, ackIds(plain));
    await c.pull(subscription, { maxMessages: 10, returnImmediately: true });
  },
};

export const retryPolicy = {
  id: "retry-policy",
  short: "rp",
  requests: 22,
  slow: true,
  async run(ctx) {
    const c = ctx.client;
    const { topic, subscription } = await topicAndSubscription(ctx, {
      retryPolicy: { minimumBackoff: "10s", maximumBackoff: "20s" },
    });
    must(await c.publish(topic, [message({ data: "retry" })]), "publish");
    const received = await pullMessages(ctx, subscription, 1);
    if (received.length === 0) return;
    // A negative acknowledgement waits at least the minimum backoff before the redelivery.
    await c.modifyAckDeadline(subscription, [received[0].ackId], 0);
    await c.pull(subscription, { maxMessages: 1, returnImmediately: true });
    await ctx.sleep(11_000);
    const again = await pullMessages(ctx, subscription, 1, { attempts: 4 });
    await c.modifyAckDeadline(subscription, ackIds(again), 0);
    await ctx.sleep(21_000);
    const third = await pullMessages(ctx, subscription, 1, { attempts: 4 });
    await c.acknowledge(subscription, ackIds(third));
    await c.pull(subscription, { maxMessages: 1, returnImmediately: true });
  },
};
