import { message } from "../client.mjs";
import { ackIds, must, pullMessages, StopClean } from "./support.mjs";

const PUBLISHER = "roles/pubsub.publisher";
const SUBSCRIBER = "roles/pubsub.subscriber";

/**
 * Binds `member` to `role` on one resource of the run, with the policy read before and after (the
 * recording keeps both), through the resource's own IAM methods and nothing project wide. Returns the
 * reply of the first call that failed, or of setIamPolicy.
 */
async function bind(rest, resource, role, member) {
  const before = await rest.getIamPolicy(resource);
  if (!before.ok) return before;
  const policy = before.body ?? {};
  const bindings = [...(policy.bindings ?? []), { role, members: [member] }];
  const reply = await rest.setIamPolicy(resource, { ...policy, bindings });
  await rest.getIamPolicy(resource);
  return reply;
}

// The forwarding of a dead letter needs the Pub/Sub service agent of the project to publish to the
// dead-letter topic and to acknowledge on the source subscription. Both bindings are made on the run's
// own resources only. A service agent that does not exist stops the run clean: it is not created here.
export const deadLetterForwarding = {
  id: "dead-letter-forwarding",
  short: "dl",
  requests: 45,
  slow: true,
  async run(ctx) {
    const c = ctx.client;
    const production = ctx.production;
    if (production && !ctx.serviceAgent)
      throw new StopClean(
        "the service agent project number was not supplied (--service-agent-project-number)",
      );
    const member =
      ctx.serviceAgent ?? "serviceAccount:service-0@gcp-sa-pubsub.iam.gserviceaccount.com";
    const topic = ctx.name("topics", "src");
    const deadTopic = ctx.name("topics", "dead");
    const source = ctx.name("subscriptions", "src");
    const sink = ctx.name("subscriptions", "dead");
    must(await c.createTopic(topic), "createTopic");
    must(await c.createTopic(deadTopic), "createTopic dead letter");
    must(
      await c.createSubscription(sink, { topic: deadTopic, ackDeadlineSeconds: 10 }),
      "createSubscription sink",
    );
    must(
      await c.createSubscription(source, {
        topic,
        ackDeadlineSeconds: 10,
        deadLetterPolicy: { deadLetterTopic: deadTopic, maxDeliveryAttempts: 5 },
      }),
      "createSubscription source",
    );
    await c.getSubscription(source);
    const published = await bind(ctx.rest, deadTopic, PUBLISHER, member);
    if (!published.ok && production)
      throw new StopClean(`the service agent cannot be bound (${published.code}): stop and report`);
    const subscribed = await bind(ctx.rest, source, SUBSCRIBER, member);
    if (!subscribed.ok && production)
      throw new StopClean(
        `the service agent cannot be bound (${subscribed.code}): stop and report`,
      );
    must(
      await c.publish(topic, [message({ data: "dead letter", attributes: { k: "v" } })]),
      "publish",
    );
    // Five deliveries, each refused with a negative acknowledgement.
    for (let delivery = 1; delivery <= 5; delivery += 1) {
      const got = await pullMessages(ctx, source, 1, { attempts: 4 });
      if (got.length === 0) break;
      ctx.note("delivery", { delivery, attempt: got[0].deliveryAttempt ?? null });
      await c.modifyAckDeadline(source, [got[0].ackId], 0);
    }
    // The forwarding takes a while: the sink is polled for a bounded time.
    let forwarded = [];
    for (let poll = 0; poll < 12 && forwarded.length === 0; poll += 1) {
      forwarded = await pullMessages(ctx, sink, 1, { attempts: 1, immediately: true });
      if (forwarded.length === 0) await ctx.sleep(10_000);
    }
    if (forwarded.length > 0) await c.acknowledge(sink, ackIds(forwarded));
    // Nothing is left on the source.
    await c.pull(source, { maxMessages: 1, returnImmediately: true });
  },
};
