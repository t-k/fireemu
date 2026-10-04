import { message } from "../client.mjs";
import { must } from "./support.mjs";

export const authErrors = {
  id: "auth-errors",
  short: "ae",
  requests: 16,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const subscription = ctx.name("subscriptions", "s");
    must(await c.createTopic(topic), "createTopic");
    must(await c.createSubscription(subscription, { topic }), "createSubscription");
    for (const token of ["none", "invalid"]) {
      const t = c.with({ token });
      await t.getTopic(topic);
      await t.createTopic(ctx.name("topics", `denied-${token}`));
      await t.publish(topic, [message({ data: "denied" })]);
      // Nothing came of the refused calls.
      await c.getTopic(ctx.name("topics", `denied-${token}`));
    }
    // A project that is not the run's: reads only. The ID is one nobody owns.
    await c.getTopic("projects/fireemu-no-such-project-0/topics/x");
    await c.getSubscription("projects/fireemu-no-such-project-0/subscriptions/x");
    await c.listTopics("fireemu-no-such-project-0");
  },
};

// A push subscription is created, read, reconfigured and deleted; nothing is ever published to its
// topic, so no delivery to the endpoint happens (owner ledger 634, P1 to P6).
export const pushConfig = {
  id: "push-config",
  short: "pc",
  requests: 30,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const subscription = ctx.name("subscriptions", "s");
    must(await c.createTopic(topic), "createTopic");
    const endpoint = "https://example.com/fireemu-push-probe";
    // Not required to succeed: whatever answer comes is recorded, and the steps after it too.
    await c.createSubscription(subscription, { topic, pushConfig: { pushEndpoint: endpoint } });
    await c.getSubscription(subscription);
    await c.modifyPushConfig(subscription, {});
    await c.getSubscription(subscription);
    await c.modifyPushConfig(subscription, {
      pushEndpoint: endpoint,
      attributes: { "x-goog-version": "v1" },
    });
    await c.getSubscription(subscription);
    await c.modifyPushConfig(subscription, { pushEndpoint: "http://example.com/not-https" });
    await c.modifyPushConfig(subscription, { pushEndpoint: "not a url" });
    await c.modifyPushConfig(subscription, { pushEndpoint: endpoint, oidcToken: {} });
    await c.modifyPushConfig(subscription, {
      pushEndpoint: endpoint,
      attributes: { "x-goog-version": "v9" },
    });
    await c.updateSubscription(
      subscription,
      { pushConfig: { pushEndpoint: `${endpoint}-2` } },
      "pushConfig",
    );
    await c.getSubscription(subscription);
    await c.updateSubscription(subscription, { pushConfig: {} }, "pushConfig");
    await c.getSubscription(subscription);
    // The creation forms that are refused.
    const bad = [
      ["http", { pushEndpoint: "http://example.com/x" }],
      ["empty-endpoint-attrs", { attributes: { "x-goog-version": "v1" } }],
      ["long", { pushEndpoint: `https://example.com/${"p".repeat(4000)}` }],
    ];
    for (const [key, pushConfigBody] of bad) {
      const name = ctx.name("subscriptions", key);
      await c.createSubscription(name, { topic, pushConfig: pushConfigBody });
      await c.getSubscription(name);
    }
    // Pulling from a push subscription.
    await c.modifyPushConfig(subscription, { pushEndpoint: endpoint });
    await c.pull(subscription, { maxMessages: 1, returnImmediately: true });
    await c.deleteSubscription(subscription);
    await c.getSubscription(subscription);
  },
};
