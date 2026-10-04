import { waitOperation } from "./support.mjs";

// Provider-less channel lifecycle. Production may refuse the creation; the answers are recorded either
// way (scope decision E1), and the steps that need an existing channel continue with what exists.
export const channelLifecycle = {
  id: "channel-lifecycle",
  short: "cl",
  requests: 52,
  async run(ctx) {
    const c = ctx.client;
    const name = ctx.channel("c1");
    const id = name.split("/").at(-1);
    await c.getChannel(name);
    const created = await c.createChannel(ctx.project, ctx.location, id, {});
    const settled = await waitOperation(ctx, "eventarc", created);
    await c.getChannel(name);
    await c.listChannels(ctx.project, ctx.location);
    await c.listChannels(ctx.project, ctx.location, { pageSize: 1 });
    await c.listChannels(ctx.project, ctx.location, { pageToken: "garbage" });
    await c.listChannels(ctx.project, "-", { pageSize: 5 });
    // A second creation of the same ID.
    const duplicate = await c.createChannel(ctx.project, ctx.location, id, {});
    await waitOperation(ctx, "eventarc", duplicate);
    // IDs the service may refuse: each is a probe, registered before it is sent and removed by the
    // cleanup if it was accepted.
    for (const probe of ["GOOG-Upper", "ab", "goog-probe", "1-digit-first"]) {
      const probeName = ctx.probe(probe);
      await c.createChannel(ctx.project, ctx.location, probe, {});
      await c.getChannel(probeName);
    }
    const longId = "x".repeat(64);
    ctx.probe(longId);
    await c.createChannel(ctx.project, ctx.location, longId, {});
    // A location that does not exist, and a project that is not the run's (reads only).
    const nowhere = ctx.probe("nowhere", { location: "no-such-location1", listable: false });
    await c.createChannel(ctx.project, "no-such-location1", "nowhere", {});
    await c.getChannel(nowhere);
    await c.getChannel("projects/fireemu-no-such-project-0/locations/us-central1/channels/x");
    await c.listChannels("fireemu-no-such-project-0", ctx.location);
    // Deletion of the owned channel, the operation, the read-back, and a second deletion.
    if (created.ok && settled.ok) {
      const deleted = await c.deleteChannel(name);
      await waitOperation(ctx, "eventarc", deleted);
      await c.getChannel(name);
      await c.deleteChannel(name);
    } else {
      await c.deleteChannel(name);
    }
  },
};
