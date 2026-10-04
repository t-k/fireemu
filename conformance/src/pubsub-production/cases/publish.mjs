import { message } from "../client.mjs";
import {
  ackIds,
  messageSize,
  messagesOfRequestSize,
  must,
  payload,
  pullMessages,
  timeoutForBytes,
} from "./support.mjs";

export const publishWire = {
  id: "publish-wire",
  short: "pw",
  requests: 45,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const subscription = ctx.name("subscriptions", "s");
    must(await c.createTopic(topic), "createTopic");
    must(await c.createSubscription(subscription, { topic }), "createSubscription");
    await c.publish(ctx.name("topics", "never-created"), [message({ data: "x" })]);
    // The shapes of a publish request: one message, several, ids and what comes back.
    await c.publish(topic, [message({ data: "one" })]);
    await c.publish(topic, [
      message({ data: "two", attributes: { color: "red", n: "1" } }),
      message({ attributes: { only: "attributes" } }),
      message({ data: "", attributes: { k: "empty data" } }),
    ]);
    await c.publish(topic, [message({ data: "keyed", orderingKey: "k1" })]);
    await c.publish(topic, [message({ data: Buffer.from([0, 255, 128]) })]);
    await c.publish(topic, [message({ data: "ünïcödé ✓" })]);
    await c.publish(topic, []);
    await c.publish(topic, [{}]);
    await c.publish(topic, [message({ data: "" })]);
    await c.publish(topic, [message({ attributes: {} })]);
    // Attribute limits: key 256 bytes, value 1024 bytes, 100 attributes, the reserved prefix.
    const attrs = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, "v"]));
    await c.publish(topic, [message({ data: "x", attributes: { [""]: "v" } })]);
    await c.publish(topic, [message({ data: "x", attributes: { ["k".repeat(256)]: "v" } })]);
    await c.publish(topic, [message({ data: "x", attributes: { ["k".repeat(257)]: "v" } })]);
    await c.publish(topic, [message({ data: "x", attributes: { k: "v".repeat(1024) } })]);
    await c.publish(topic, [message({ data: "x", attributes: { k: "v".repeat(1025) } })]);
    await c.publish(topic, [message({ data: "x", attributes: attrs(100) })]);
    await c.publish(topic, [message({ data: "x", attributes: attrs(101) })]);
    await c.publish(topic, [message({ data: "x", attributes: { googclient_probe: "v" } })]);
    await c.publish(topic, [message({ data: "x", attributes: { goog_probe: "v" } })]);
    await c.publish(topic, [message({ data: "x", orderingKey: "k".repeat(1024) })]);
    await c.publish(topic, [message({ data: "x", orderingKey: "k".repeat(1025) })]);
    // The batch size: 1000 messages in a request, then 1001 (to a topic nobody reads, so the
    // subscription above is not flooded).
    const batchTopic = ctx.name("topics", "batch");
    must(await c.createTopic(batchTopic), "createTopic batch");
    const many = (n) => Array.from({ length: n }, () => message({ data: "m" }));
    await c.publish(batchTopic, many(1000));
    await c.publish(batchTopic, many(1001));
    // What a subscriber receives of the messages above.
    const received = await pullMessages(ctx, subscription, 1);
    if (received.length > 0) await c.acknowledge(subscription, ackIds(received));
  },
};

// Both limits are 10,000,000 bytes: a message and a whole request. Each boundary is recorded on both
// sides (accepted at the limit, refused one byte over) on a topic of its own with no subscription,
// since only the answer to the publish matters. The time limit follows the payload size; an answer
// that does not come in time is an unknown answer, recorded as such.
const LIMIT = 10_000_000;

export const publishLimits = {
  id: "publish-limits",
  short: "pl",
  requests: 12,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    must(await c.createTopic(topic), "createTopic");
    const big = c.with({ timeoutMs: timeoutForBytes(LIMIT * 1.4) });
    // The message boundary: the data is exactly LIMIT bytes, then one more.
    ctx.note("publish-limits", {
      messageDataBytes: LIMIT,
      encodedMessageBytes: messageSize(payload(LIMIT)),
    });
    await big.publish(topic, [message({ data: payload(LIMIT) })]);
    await big.publish(topic, [message({ data: payload(LIMIT + 1) })]);
    // The request boundary: two messages, the whole PublishRequest exactly LIMIT bytes, then one more.
    await big.publish(topic, messagesOfRequestSize(topic, LIMIT));
    await big.publish(topic, messagesOfRequestSize(topic, LIMIT + 1));
    // The same boundary for a message by its encoded size.
    await big.publish(topic, [
      message({ data: payload(LIMIT - (messageSize(payload(LIMIT)) - LIMIT)) }),
    ]);
    await big.publish(topic, [
      message({ data: payload(LIMIT + 1 - (messageSize(payload(LIMIT)) - LIMIT)) }),
    ]);
    await c.publish(topic, [message({ data: "after the large ones" })]);
  },
};
