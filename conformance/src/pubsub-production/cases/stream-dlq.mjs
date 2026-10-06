import { createHash } from "node:crypto";
import { message } from "../client.mjs";
import { must, CaseAbort, StopClean } from "./support.mjs";
import { STREAM_BOUNDS } from "../stream.mjs";
import { waitAfterLastGrant } from "../iam.mjs";

export const IAM_PREREQUISITE = Object.freeze({
  finiteUpperBoundMs: null,
  source: "https://docs.cloud.google.com/iam/docs/access-change-propagation?hl=en",
  requiredRoles: [
    "roles/pubsub.subscriber on source subscription",
    "roles/pubsub.publisher on dead-letter topic",
  ],
});
const initial = (subscription) => ({
  subscription,
  streamAckDeadlineSeconds: 10,
  maxOutstandingMessages: "1",
  maxOutstandingBytes: "1024",
});
const invalidAck = "invalid-ack-for-stream-observation";
const streamCase = (id, short, mode) => ({
  id,
  short,
  requests: mode === "deadline" ? 4 : 3,
  resources: 2,
  timeoutMs: mode === "deadline" ? 120_000 : 90_000,
  transports: ["grpc"],
  async run(ctx) {
    const topic = ctx.name("topics", "stream-topic");
    const subscription = ctx.name("subscriptions", "stream-sub");
    must(await ctx.client.createTopic(topic), "create stream topic");
    must(
      await ctx.client.createSubscription(subscription, {
        topic,
        ackDeadlineSeconds: 10,
        ...(mode === "push"
          ? { pushConfig: { pushEndpoint: "https://example.invalid/pubsub-never-published" } }
          : {}),
      }),
      "create stream subscription",
    );
    const frames = [initial(subscription)];
    if (mode === "ack") frames.push({ ackIds: [invalidAck] });
    if (mode === "deadline")
      must(
        await ctx.rest.publish(topic, [message({ data: `stream-deadline-${ctx.runId}` })]),
        "publish one stream deadline identity",
      );
    if (mode === "initial") frames[0].streamAckDeadlineSeconds = 0;
    const result = await ctx.stream(
      subscription,
      frames,
      STREAM_BOUNDS.timeoutMs,
      mode === "deadline" ? { modifyDeadlineSeconds: -1 } : undefined,
    );
    ctx.note("stream-result", { mode, ...result });
    if (mode === "deadline" && !result.followUpSent)
      throw new CaseAbort("deadline followup not sent: no own ACK was received", result);
  },
});

export const deletedCursor = {
  id: "deleted-cursor",
  short: "dc",
  requests: 6,
  resources: 3,
  timeoutMs: 180_000,
  transports: ["rest"],
  async run(ctx) {
    const created = new Set();
    for (let n = 0; n < 3; n += 1) {
      const name = ctx.name("topics", `cursor-${n}`);
      created.add(name);
      must(await ctx.client.createTopic(name), "create cursor topic");
    }
    const reply = must(
      await ctx.client.listTopics(ctx.project, { pageSize: 1 }),
      "cursor first page",
    );
    const first = reply.body?.topics?.[0]?.name;
    const token = reply.body?.nextPageToken;
    if (
      !created.has(first) ||
      typeof token !== "string" ||
      token.length === 0 ||
      token.length > 4096
    )
      throw new CaseAbort(
        "cursor page did not name an own created topic and bounded opaque token",
        reply,
      );
    must(await ctx.client.deleteTopic(first), "delete first page topic");
    ctx.note("deleted-cursor", { deletedName: first, pageToken: token });
    await ctx.client.listTopics(ctx.project, { pageSize: 1, pageToken: token });
  },
};

export function observedMessageIdentity(received, expected = null) {
  const data = received.message?.data;
  const bytes = typeof data === "string" ? Buffer.from(data, "base64") : null;
  const attributes = received.message?.attributes ?? null;
  return {
    deliveryAttempt: received.deliveryAttempt ?? null,
    ackId: received.ackId ?? null,
    messageId: received.message?.messageId ?? null,
    attributes,
    dataBase64: data ?? null,
    dataBytes: bytes?.length ?? null,
    dataSha256: bytes === null ? null : createHash("sha256").update(bytes).digest("hex"),
    ...(expected === null
      ? {}
      : {
          outerDataMatchesPublished:
            bytes === null ? null : bytes.equals(Buffer.from(expected.data, "base64")),
          publishedAttributesEqualOuter:
            attributes === null
              ? null
              : Object.keys(attributes).length === Object.keys(expected.attributes).length &&
                Object.entries(expected.attributes).every(
                  ([key, value]) => attributes[key] === value,
                ),
          sourceSubscriptionExactAttributeKeys: Object.entries(attributes ?? {})
            .filter(([, value]) => value === expected.sourceSubscription)
            .map(([key]) => key),
          wrapperInterpretation: "needs-review",
        }),
  };
}
const identity = (received) => observedMessageIdentity(received);
function readMessages(reply, what) {
  must(reply, what);
  const messages = reply.body?.receivedMessages ?? [];
  if (
    !Array.isArray(messages) ||
    messages.length > 1 ||
    messages.some(
      (item) =>
        typeof item?.ackId !== "string" || !item.message || typeof item.message !== "object",
    )
  )
    throw new CaseAbort(`${what} unreadable message shape`, reply);
  return messages;
}

export const dlqNoGrant = {
  id: "dlq-no-grant",
  short: "db",
  requests: 97,
  resources: 4,
  timeoutMs: 720_000,
  transports: ["rest"],
  run: (ctx) => runDlq(ctx, false),
};

export const dlqGrantPrerequisite = {
  id: "dlq-grant-prerequisite",
  short: "da",
  requests: 0,
  resources: 0,
  timeoutMs: 1,
  transports: ["rest"],
  async run(ctx) {
    ctx.note("dlq-prerequisite", IAM_PREREQUISITE);
    throw new StopClean(
      "a finite citable IAM propagation upper bound is unavailable; A needs coordinator/owner disposition before any resources, IAM grants or publish",
    );
  },
};

export const STREAM_DLQ_CASES = Object.freeze([
  streamCase("stream-push-open", "sp", "push"),
  streamCase("stream-invalid-ack", "sa", "ack"),
  streamCase("stream-invalid-deadline", "sd", "deadline"),
  streamCase("stream-invalid-initial", "si", "initial"),
  deletedCursor,
  dlqNoGrant,
  dlqGrantPrerequisite,
]);

async function runDlq(ctx, grant) {
  const c = ctx.client;
  const topic = ctx.name("topics", "source");
  const deadTopic = ctx.name("topics", "dead");
  const source = ctx.name("subscriptions", "source");
  const sink = ctx.name("subscriptions", "sink");
  must(await c.createTopic(topic), "create source topic");
  must(await c.createTopic(deadTopic), "create dead-letter topic");
  must(
    await c.createSubscription(sink, {
      topic: deadTopic,
      ackDeadlineSeconds: 10,
      messageRetentionDuration: "600s",
    }),
    "create sink subscription",
  );
  must(
    await c.createSubscription(source, {
      topic,
      ackDeadlineSeconds: 10,
      messageRetentionDuration: "600s",
      deadLetterPolicy: { deadLetterTopic: deadTopic, maxDeliveryAttempts: 5 },
    }),
    "create source subscription",
  );
  must(await c.getSubscription(source), "read source subscription");
  if (grant) {
    if (!ctx.serviceAgent || !ctx.iam)
      throw new StopClean("A requires scoped IAM ownership and service agent");
    await ctx.iam.grant(c, source, "roles/pubsub.subscriber", ctx.serviceAgent);
    const last = await ctx.iam.grant(c, deadTopic, "roles/pubsub.publisher", ctx.serviceAgent);
    ctx.note("iam-window", {
      waitAfterGrantMs: 900_000,
      phaseMs: 1_800_000,
      requestsDuringWait: 0,
      iamConvergenceClaim: false,
    });
    await waitAfterLastGrant({
      grantedAt: last.grantedAt,
      now: ctx.monotonicNow,
      sleep: ctx.sleep,
    });
  }
  const payload = `dlq-${ctx.runId}-identity`;
  const sentMessage = message({ data: payload, attributes: { recorderRun: ctx.runId } });
  const expected = { ...sentMessage, sourceSubscription: source };
  const published = must(await c.publish(topic, [sentMessage]), "publish DLQ identity");
  ctx.note("dlq-published", {
    grant,
    messageIds: published.body?.messageIds ?? null,
    payload,
    ...expected,
    dataSha256: createHash("sha256").update(payload).digest("hex"),
  });
  // These are observation ceilings. No local count is interpreted as the service's cutoff or reset.
  for (let poll = 1; poll <= 9; poll += 1) {
    const reply = await c.pull(source, { maxMessages: 1, returnImmediately: true });
    ctx.note("dlq-source-poll", {
      poll,
      code: reply.code,
      unknown: reply.unknown,
      messages: (reply.body?.receivedMessages ?? []).map?.(identity) ?? null,
    });
    for (const item of readMessages(reply, "source pull"))
      must(await c.modifyAckDeadline(source, [item.ackId], 0), "source nack");
    if (poll < 9) await ctx.sleep(1000);
  }
  for (let poll = 1; poll <= 36; poll += 1) {
    const reply = await c.pull(sink, { maxMessages: 1, returnImmediately: true });
    ctx.note("dlq-sink-poll", {
      poll,
      code: reply.code,
      unknown: reply.unknown,
      messages: (reply.body?.receivedMessages ?? []).map?.(identity) ?? null,
    });
    for (const item of readMessages(reply, "sink pull")) {
      ctx.note("dlq-forwarded", { poll, ...observedMessageIdentity(item, expected) });
      must(await c.acknowledge(sink, [item.ackId]), "ack sink");
    }
    if (poll < 36) await ctx.sleep(5000);
  }
  const final = await c.pull(source, { maxMessages: 1, returnImmediately: true });
  ctx.note("dlq-source-final", {
    code: final.code,
    unknown: final.unknown,
    messages: (final.body?.receivedMessages ?? []).map?.(identity) ?? null,
  });
}

export const restLayoutRoutes = {
  id: "rest-layout-routes",
  short: "rl",
  requests: 9,
  resources: 3,
  timeoutMs: 180_000,
  transports: ["rest"],
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "source");
    const subscription = ctx.name("subscriptions", "source");
    const snapshot = ctx.name("snapshots", "own");
    must(await c.createTopic(topic), "layout topic");
    must(
      await c.createSubscription(subscription, { topic, retainAckedMessages: true }),
      "layout subscription",
    );
    must(
      await c.publish(topic, [message({ data: `layout-${ctx.runId}` })]),
      "layout own publication",
    );
    must(await c.createSnapshot(snapshot, subscription), "layout own snapshot");
    let ackId;
    for (let poll = 0; poll < 3 && ackId === undefined; poll += 1) {
      const received = readMessages(
        await c.pull(subscription, { maxMessages: 1, returnImmediately: true }),
        "layout Pull",
      );
      if (received.length) ackId = received[0].ackId;
    }
    if (!ackId)
      throw new CaseAbort("layout ACK/Seek unobserved: no actual own ACK from complete Pull");
    must(await c.acknowledge(subscription, [ackId]), "layout actual own ACK");
    must(await c.seek(subscription, { snapshot }), "layout own Seek");
    ctx.note("rest-layout-complete", {
      routes: ["createSubscription", "pull", "acknowledge", "seek"],
    });
  },
};
export const dlqGrantWindow = {
  id: "dlq-grant-window",
  short: "da",
  requests: 103,
  resources: 4,
  timeoutMs: 1_800_000,
  transports: ["rest"],
  run: (ctx) => runDlq(ctx, true),
};
export const STREAM_DLQ_V2_CASES = Object.freeze([
  ...STREAM_DLQ_CASES.filter((item) => item.id !== "dlq-grant-prerequisite"),
  restLayoutRoutes,
  dlqGrantWindow,
]);
