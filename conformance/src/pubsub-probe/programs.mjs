// The shared program list the Pub/Sub probe runs identically against the official Cloud
// Pub/Sub emulator and against fireemu. Every observation is normalized so that it does not
// depend on server-assigned identifiers or wall-clock timing: publish records the number of
// ids returned (not their values), pull records the sorted message payloads and attributes,
// and errors record the gRPC status code name. A step whose value differs between the two
// emulators becomes a `debt` row unless it is documented in divergences.json.

/** Maps a gRPC error to its status-code name (`NOT_FOUND`, `INVALID_ARGUMENT`, ...). */
function codeName(err) {
  // @google-cloud/pubsub surfaces the numeric gRPC code; map the ones the probe expects.
  const byNumber = {
    3: "INVALID_ARGUMENT",
    5: "NOT_FOUND",
    6: "ALREADY_EXISTS",
    9: "FAILED_PRECONDITION",
    12: "UNIMPLEMENTED",
  };
  if (err && typeof err.code === "number") return byNumber[err.code] ?? `CODE_${err.code}`;
  return "NO_ERROR";
}

async function expectError(fn) {
  try {
    await fn();
    return "NO_ERROR";
  } catch (err) {
    return codeName(err);
  }
}

/** Sorted `[data, attributes]` pairs, so message order never makes two equal runs differ. */
function normalize(messages) {
  return messages
    .map((m) => [m.data.toString(), { ...m.attributes }])
    .toSorted((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

export const PROGRAMS = [
  {
    id: "rest-resource-wire",
    area: "rest",
    async run(ctx) {
      const steps = {};
      const { project } = ctx;
      const topic = `/v1/projects/${project}/topics/rest-wire`;
      const deadTopic = `/v1/projects/${project}/topics/rest-dead`;
      const subscription = `/v1/projects/${project}/subscriptions/rest-wire`;
      const snapshot = `/v1/projects/${project}/snapshots/rest-wire`;
      const createdTopic = await ctx.rest("PUT", topic, { labels: { source: "rest" } });
      steps.topicPut = {
        status: createdTopic.status,
        name: createdTopic.body.name?.split("/").at(-1),
        label: createdTopic.body.labels?.source,
      };
      steps.topicPost = {
        rejected:
          (await ctx.rest("POST", `/v1/projects/${project}/topics/wrong-verb`)).status >= 400,
      };
      await ctx.rest("PUT", deadTopic);
      const createdSubscription = await ctx.rest("PUT", subscription, {
        topic: `projects/${project}/topics/rest-wire`,
        ackDeadlineSeconds: 20,
        enableMessageOrdering: true,
        filter: 'attributes.kind = "kept"',
        deadLetterPolicy: {
          deadLetterTopic: `projects/${project}/topics/rest-dead`,
          maxDeliveryAttempts: 5,
        },
        retryPolicy: { minimumBackoff: "1.500s", maximumBackoff: "3s" },
      });
      steps.subscriptionPut = {
        status: createdSubscription.status,
        ackDeadlineSeconds: createdSubscription.body.ackDeadlineSeconds,
        filter: createdSubscription.body.filter,
        deadLetterAttempts: createdSubscription.body.deadLetterPolicy?.maxDeliveryAttempts,
        minimumBackoff: createdSubscription.body.retryPolicy?.minimumBackoff,
      };
      const updated = await ctx.rest("PATCH", subscription, {
        subscription: {
          name: `projects/${project}/subscriptions/rest-wire`,
          ackDeadlineSeconds: 30,
        },
        updateMask: "ackDeadlineSeconds",
      });
      steps.subscriptionPatch = {
        status: updated.status,
        ackDeadlineSeconds: updated.body.ackDeadlineSeconds,
        filter: updated.body.filter,
      };
      const createdSnapshot = await ctx.rest("PUT", snapshot, {
        subscription: `projects/${project}/subscriptions/rest-wire`,
        labels: { source: "rest" },
      });
      steps.snapshotPut = {
        status: createdSnapshot.status,
        name: createdSnapshot.body.name?.split("/").at(-1),
        label: createdSnapshot.body.labels?.source,
      };
      steps.snapshotPost = {
        rejected:
          (
            await ctx.rest("POST", `/v1/projects/${project}/snapshots/wrong-verb`, {
              subscription: `projects/${project}/subscriptions/rest-wire`,
            })
          ).status >= 400,
      };
      return steps;
    },
  },
  {
    id: "topics-lifecycle",
    area: "topics",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-lifecycle");
      await t.create();
      steps.created = { ok: true };
      const [got] = await t.get();
      steps.getName = { name: got.name.split("/").slice(-2).join("/") };
      const [topics] = await ctx.pubsub.getTopics();
      steps.listed = { present: topics.some((x) => x.name.endsWith("/probe-lifecycle")) };
      steps.duplicate = { code: await expectError(() => t.create()) };
      await t.delete();
      steps.deleted = { ok: true };
      steps.getAfterDelete = { code: await expectError(() => t.get()) };
      return steps;
    },
  },
  {
    id: "topics-validation",
    area: "topics",
    async run(ctx) {
      return {
        tooShort: { code: await expectError(() => ctx.pubsub.topic("ab").create()) },
      };
    },
  },
  {
    id: "subscriptions-lifecycle",
    area: "subscriptions",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-sub-topic");
      await t.create();
      const [sub] = await t.createSubscription("probe-sub");
      steps.created = { ok: true };
      const [got] = await sub.get();
      steps.getTopic = { topic: got.metadata.topic.split("/").slice(-2).join("/") };
      const [subs] = await ctx.pubsub.getSubscriptions();
      steps.listed = { present: subs.some((x) => x.name.endsWith("/probe-sub")) };
      steps.missingTopic = {
        code: await expectError(() =>
          ctx.pubsub.topic("no-such-topic").createSubscription("orphan-sub"),
        ),
      };
      await sub.delete();
      steps.deleted = { ok: true };
      return steps;
    },
  },
  {
    id: "publish-pull-ack",
    area: "delivery",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-orders");
      await t.create();
      const [sub] = await t.createSubscription("probe-orders-sub", { ackDeadlineSeconds: 10 });
      const ids = await Promise.all([
        t.publishMessage({ data: Buffer.from("first"), attributes: { seq: "1" } }),
        t.publishMessage({ data: Buffer.from("second"), attributes: { seq: "2" } }),
      ]);
      steps.publish = { count: ids.length, nonEmptyIds: ids.every((x) => x.length > 0) };
      const received = await ctx.receive(sub, 2, "ack");
      steps.pull = { messages: normalize(received) };
      const again = await ctx.receive(sub, 1, "ack");
      steps.afterAck = { empty: again.length === 0 };
      return steps;
    },
  },
  {
    id: "subscription-filter",
    area: "delivery",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-events");
      await t.create();
      const [sub] = await t.createSubscription("probe-orders-only", {
        filter: 'attributes.type = "order"',
      });
      await t.publishMessage({ data: Buffer.from("o"), attributes: { type: "order" } });
      await t.publishMessage({ data: Buffer.from("r"), attributes: { type: "refund" } });
      const received = await ctx.receive(sub, 2, "ack");
      steps.filtered = { messages: normalize(received) };
      return steps;
    },
  },
  {
    id: "ordering-keys",
    area: "delivery",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-ordered");
      await t.create();
      const [sub] = await t.createSubscription("probe-ordered-sub", {
        enableMessageOrdering: true,
      });
      const pub = ctx.pubsub.topic("probe-ordered", { messageOrdering: true });
      for (const n of ["a", "b", "c"]) {
        await pub.publishMessage({ data: Buffer.from(n), orderingKey: "k" });
      }
      const received = await ctx.receive(sub, 3, "ack");
      steps.order = { sequence: received.map((m) => m.data.toString()).join("") };
      return steps;
    },
  },
  {
    id: "nack-redelivery",
    area: "delivery",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-retry");
      await t.create();
      const [sub] = await t.createSubscription("probe-retry-sub", { ackDeadlineSeconds: 10 });
      await t.publishMessage({ data: Buffer.from("retry-me") });
      const first = await ctx.receive(sub, 1, "nack");
      steps.firstDelivery = { received: first.length === 1 };
      const second = await ctx.receive(sub, 1, "ack");
      steps.redelivered = { received: second.length === 1 };
      return steps;
    },
  },
  {
    id: "seek-to-time",
    area: "delivery",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-seek");
      await t.create();
      const [sub] = await t.createSubscription("probe-seek-sub", { ackDeadlineSeconds: 10 });
      await t.publishMessage({ data: Buffer.from("seekable") });
      const drained = await ctx.receive(sub, 1, "ack");
      steps.drained = { received: drained.length === 1 };
      // Seek to the Unix epoch: every retained message published after it is redelivered.
      await sub.seek(new Date(0));
      const replayed = await ctx.receive(sub, 1, "ack");
      steps.replayed = { received: replayed.length >= 1 };
      return steps;
    },
  },
  {
    id: "publish-errors",
    area: "errors",
    async run(ctx) {
      const steps = {};
      const t = ctx.pubsub.topic("probe-errors");
      await t.create();
      // An empty message (no data, no attributes) is rejected by both emulators.
      steps.emptyMessage = { code: await expectError(() => t.publishMessage({})) };
      steps.missingTopic = {
        code: await expectError(() =>
          ctx.pubsub.topic("nope-not-here").publishMessage({ data: Buffer.from("x") }),
        ),
      };
      return steps;
    },
  },
];
