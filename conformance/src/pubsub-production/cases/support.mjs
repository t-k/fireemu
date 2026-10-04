// Helpers the cases share. A case never judges an answer: it records it. It only reads an answer to
// decide the next step (an ack ID to acknowledge, a topic that must exist before a subscription).

import { protos } from "@google-cloud/pubsub";

const types = protos.google.pubsub.v1;

/** A case that cannot go on: a step it depends on did not give the answer the next step needs. */
export class CaseAbort extends Error {
  constructor(what, reply) {
    super(
      `${what} did not succeed (${reply?.code ?? "no answer"}${reply?.unknown ? ", unknown" : ""})`,
    );
    this.name = "CaseAbort";
  }
}

/** The run must stop and clean up: a precondition the operator has to fix. */
export class StopClean extends Error {
  constructor(reason) {
    super(reason);
    this.name = "StopClean";
  }
}

/** The reply, or a CaseAbort naming the step. */
export function must(reply, what) {
  if (!reply?.ok) throw new CaseAbort(what, reply);
  return reply;
}

/**
 * Pulls until `count` messages have been received (the service may answer a pull with fewer, or with
 * none, while it is still collecting them), at most `attempts` pulls. Never acknowledges.
 */
export async function pullMessages(
  ctx,
  subscription,
  count,
  { attempts = 5, immediately = false } = {},
) {
  const received = [];
  for (let attempt = 0; attempt < attempts && received.length < count; attempt += 1) {
    // A pull that waits for messages may take a while to answer.
    const client = immediately ? ctx.client : ctx.client.with({ timeoutMs: 20_000 });
    const reply = await client.pull(subscription, {
      maxMessages: Math.max(count - received.length, 1),
      returnImmediately: immediately,
    });
    if (!reply.ok) break;
    received.push(...(reply.body?.receivedMessages ?? []));
    if (immediately && received.length < count) await ctx.sleep(1000);
  }
  return received;
}

/** The ack IDs of received messages. */
export const ackIds = (messages) => messages.map((message) => message.ackId);

/** `n` bytes of a repeating pattern. */
export const payload = (n) => Buffer.alloc(n, "x");

const encodedLength = (topic, messages) =>
  types.PublishRequest.encode(types.PublishRequest.fromObject({ topic, messages })).finish().length;

/** The encoded size of one message as a PubsubMessage. */
export const messageSize = (data) =>
  types.PubsubMessage.encode(types.PubsubMessage.fromObject({ data })).finish().length;

/**
 * Messages whose PublishRequest is exactly `total` bytes: one fixed chunk, and a last message whose data
 * is adjusted until the encoding is exactly that long (a length prefix grows at the powers of 128).
 */
export function messagesOfRequestSize(topic, total, chunk = 4_000_000) {
  const fixed = { data: Buffer.alloc(chunk, "x") };
  let rest = total - chunk;
  for (let step = 0; step < 8; step += 1) {
    const messages = [fixed, { data: Buffer.alloc(rest, "y") }];
    const length = encodedLength(topic, messages);
    if (length === total) return messages.map(({ data }) => ({ data: data.toString("base64") }));
    rest += total - length;
  }
  throw new Error(`no message layout encodes to ${total} bytes`);
}

/** A time limit for a request of `bytes`: 30 s plus a second for every 100 kB. */
export const timeoutForBytes = (bytes) => 30_000 + Math.ceil(bytes / 100_000) * 1000;
