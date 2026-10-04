import { message } from "../client.mjs";
import { ackIds, must, pullMessages } from "./support.mjs";

export const snapshotSeek = {
  id: "snapshot-seek",
  short: "ss",
  requests: 50,
  async run(ctx) {
    const c = ctx.client;
    const topic = ctx.name("topics", "t");
    const subscription = ctx.name("subscriptions", "s");
    const snapshot = ctx.name("snapshots", "snap");
    must(await c.createTopic(topic), "createTopic");
    must(
      await c.createSubscription(subscription, { topic, retainAckedMessages: true }),
      "createSubscription",
    );
    // A snapshot of a subscription with nothing in it, and the arguments of the call.
    await c.createSnapshot(ctx.name("snapshots", "empty"), subscription);
    await c.createSnapshot(snapshot, ctx.name("subscriptions", "never-created"));
    await c.createSnapshot(ctx.probe("snapshots", "goog-probe"), subscription);
    await c.createSnapshot(ctx.name("snapshots", "labeled"), subscription, { env: "test" });
    must(
      await c.publish(topic, [message({ data: "before 1" }), message({ data: "before 2" })]),
      "publish before",
    );
    const before = await pullMessages(ctx, subscription, 2);
    if (before.length > 0) await c.acknowledge(subscription, ackIds(before));
    const seekTime = before[0]?.message?.publishTime;
    must(await c.createSnapshot(snapshot, subscription), "createSnapshot");
    await c.createSnapshot(snapshot, subscription);
    await c.getSnapshot(snapshot);
    await c.getSnapshot(ctx.name("snapshots", "never-created"));
    await c.listSnapshots(ctx.project, { pageSize: 1 });
    await c.listTopicSnapshots(topic);
    must(
      await c.publish(topic, [message({ data: "after 1" }), message({ data: "after 2" })]),
      "publish after",
    );
    const after = await pullMessages(ctx, subscription, 2);
    if (after.length > 0) await c.acknowledge(subscription, ackIds(after));
    // Seeking back to the snapshot makes the later messages deliverable again.
    await c.seek(subscription, { snapshot });
    const replay = await pullMessages(ctx, subscription, 2, { attempts: 3 });
    if (replay.length > 0) await c.acknowledge(subscription, ackIds(replay));
    await c.pull(subscription, { maxMessages: 10, returnImmediately: true });
    // Seeking to a time: the time of the first message, a time before everything, and the future.
    if (seekTime !== undefined) {
      await c.seek(subscription, { time: seekTime });
      const replayAll = await pullMessages(ctx, subscription, 4, { attempts: 3 });
      if (replayAll.length > 0) await c.acknowledge(subscription, ackIds(replayAll));
    }
    await c.seek(subscription, { time: "2000-01-01T00:00:00Z" });
    await c.seek(subscription, { time: "2100-01-01T00:00:00Z" });
    await c.seek(subscription, {});
    await c.seek(subscription, { snapshot: ctx.name("snapshots", "never-created") });
    await c.seek(ctx.name("subscriptions", "never-created"), { snapshot });
    await c.seek(subscription, { snapshot, time: "2000-01-01T00:00:00Z" });
    // Deletion.
    await c.deleteSnapshot(snapshot);
    await c.deleteSnapshot(snapshot);
    await c.getSnapshot(snapshot);
    await c.seek(subscription, { snapshot });
    // A subscription deleted while a snapshot of it exists.
    await c.createSnapshot(snapshot, subscription);
    await c.deleteSubscription(subscription);
    await c.getSnapshot(snapshot);
    await c.listTopicSnapshots(topic);
  },
};
