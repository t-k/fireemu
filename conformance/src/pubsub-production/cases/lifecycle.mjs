import { must } from "./support.mjs";

export const lifecycle = {
  id: "lifecycle",
  short: "lc",
  requests: 30,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const missing = ctx.name("topics", "never-created");
    const subscription = ctx.name("subscriptions", "s");
    await c.getTopic(topic);
    must(await c.createTopic(topic), "createTopic");
    await c.createTopic(topic);
    await c.getTopic(topic);
    await c.listTopicSubscriptions(topic);
    await c.getSubscription(subscription);
    await c.createSubscription(subscription, { topic: missing });
    must(await c.createSubscription(subscription, { topic }), "createSubscription");
    await c.createSubscription(subscription, { topic });
    await c.getSubscription(subscription);
    await c.listTopicSubscriptions(topic);
    // A topic that is deleted while a subscription is attached leaves the subscription behind.
    await c.deleteTopic(topic);
    await c.getTopic(topic);
    await c.getSubscription(subscription);
    await c.listTopicSubscriptions(topic);
    await c.createSubscription(ctx.name("subscriptions", "s-after"), { topic });
    await c.deleteSubscription(subscription);
    await c.deleteSubscription(subscription);
    await c.getSubscription(subscription);
    await c.deleteTopic(topic);
    // A name is free again once it is deleted.
    must(await c.createTopic(topic), "createTopic again");
    await c.getTopic(topic);
    await c.deleteTopic(topic);
    await c.getTopic(topic);
  },
};

// IDs the service may refuse: the reserved prefix, the length limits, the first character and the
// characters that are not allowed. Each is registered as a probe before it is sent, so that cleanup
// removes whatever the service accepted.
export const names = {
  id: "names",
  short: "nm",
  requests: 40,
  async run(ctx) {
    const c = ctx.client;
    const probes = [
      ["topics", "goog-probe"],
      ["topics", { rest: "ab", grpc: "ac" }],
      ["topics", { rest: "x1a", grpc: "x1b" }],
      ["topics", "1-leading-digit"],
      ["topics", "-leading-dash"],
      ["topics", "bad$character"],
      ["topics", "with.dot_tilde~plus+percent%25"],
      ["topics", { rest: "a".repeat(256), grpc: "b".repeat(256) }],
      ["subscriptions", "goog-probe"],
      ["subscriptions", { rest: "ab", grpc: "ac" }],
      ["subscriptions", "1-leading-digit"],
    ];
    const topic = ctx.name("topics", "n");
    must(await c.createTopic(topic), "createTopic");
    for (const [kind, id] of probes) {
      const name = ctx.probe(kind, id);
      if (kind === "topics") {
        await c.createTopic(name);
        await c.getTopic(name);
      } else {
        await c.createSubscription(name, { topic });
        await c.getSubscription(name);
      }
    }
    // The longest ID that is allowed, as an owned name.
    const longest = ctx.name("topics", "z".repeat(ctx.maxKeyLength));
    await c.createTopic(longest);
    await c.getTopic(longest);
    // Names that are not resource names at all: a read of each says how the service parses them.
    await c.getTopic(`projects/${ctx.project}/topic/x`);
    await c.getTopic(`projects/${ctx.project}/topics`);
    await c.getTopic("topics/x");
    await c.getSubscription(`projects/${ctx.project}/topics/x`);
  },
};

export const paging = {
  id: "paging",
  short: "pg",
  requests: 40,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "p");
    must(await c.createTopic(topic), "createTopic");
    for (const key of ["a", "b", "c"])
      must(
        await c.createSubscription(ctx.name("subscriptions", key), { topic }),
        `createSubscription ${key}`,
      );
    // The subscriptions of one topic: a page of two, then the rest; pages of one; every bad token or size.
    const first = await c.listTopicSubscriptions(topic, { pageSize: 2 });
    if (first.body?.nextPageToken)
      await c.listTopicSubscriptions(topic, { pageSize: 2, pageToken: first.body.nextPageToken });
    let token;
    for (let page = 0; page < 4; page += 1) {
      const reply = await c.listTopicSubscriptions(
        topic,
        token ? { pageSize: 1, pageToken: token } : { pageSize: 1 },
      );
      token = reply.body?.nextPageToken;
      if (!token) break;
    }
    await c.listTopicSubscriptions(topic, { pageSize: 0 });
    await c.listTopicSubscriptions(topic, { pageSize: -1 });
    await c.listTopicSubscriptions(topic, { pageSize: 100_000 });
    await c.listTopicSubscriptions(topic, { pageToken: "garbage" });
    // A token from a page of one used with another size, and a token of another list.
    const one = await c.listTopicSubscriptions(topic, { pageSize: 1 });
    if (one.body?.nextPageToken) {
      await c.listTopicSubscriptions(topic, { pageSize: 2, pageToken: one.body.nextPageToken });
      await c.listSubscriptions(ctx.project, { pageSize: 1, pageToken: one.body.nextPageToken });
    }
    // The project-wide lists: one small page each, and the bad tokens.
    const topics = await c.listTopics(ctx.project, { pageSize: 1 });
    if (topics.body?.nextPageToken)
      await c.listTopics(ctx.project, { pageSize: 1, pageToken: topics.body.nextPageToken });
    await c.listTopics(ctx.project, { pageSize: -1 });
    await c.listTopics(ctx.project, { pageToken: "garbage" });
    await c.listSubscriptions(ctx.project, { pageSize: 1 });
    await c.listSubscriptions(ctx.project, { pageSize: -1 });
    await c.listSnapshots(ctx.project, { pageSize: 1 });
    await c.listSnapshots(ctx.project, { pageToken: "garbage" });
    await c.listTopicSnapshots(topic, { pageSize: 1 });
    await c.listTopicSubscriptions(ctx.name("topics", "never-created"));
    await c.listTopicSnapshots(ctx.name("topics", "never-created"));
  },
};
