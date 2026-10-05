import { cloudEvent, isRecordedNotFound, requireChannel, waitOperation } from "./support.mjs";

// What a channel answers while its own operation runs. Stage B read every operation to its end before it
// sent anything else for the channel, so the states in between were never seen. Two channels of the run:
// the first is read, listed, published to, created again and deleted while its creation runs; the second
// (created and finished) is read, listed and published to while its deletion runs, and deleted a second time.
//
// A second deletion is a deliberate probe, sent only after the first was answered 2xx and named its
// operation: after an unknown deletion nothing is sent again (the cleanup's rule). Every request that
// started an operation is settled by that operation's own reads, and by nothing else.
export const channelBusy = {
  id: "channel-busy",
  short: "bz",
  requests: 76,
  async run(ctx) {
    const c = ctx.client;
    const name = ctx.channel("a");
    const id = name.split("/").at(-1);
    const started = await c.createChannel(ctx.project, ctx.location, id);
    await c.getChannel(name);
    await c.listChannels(ctx.project, ctx.location);
    await c.publishEvents(name, { events: [cloudEvent(ctx)] });
    const again = await c.createChannel(ctx.project, ctx.location, id);
    const removed = await c.deleteChannel(name);
    for (const [reply, action] of [
      [started, "create"],
      [again, "create"],
      [removed, "delete"],
    ])
      await waitOperation(ctx, "eventarc", reply, { settle: { name, action } });
    await c.getChannel(name);

    const other = await requireChannel(ctx, "b");
    const first = await c.deleteChannel(other);
    await c.getChannel(other);
    await c.listChannels(ctx.project, ctx.location);
    await c.publishEvents(other, { events: [cloudEvent(ctx)] });
    const running = first.ok && typeof first.body?.name === "string" && first.body.done !== true;
    const second = running ? await c.deleteChannel(other) : null;
    for (const reply of [first, second])
      if (reply !== null)
        await waitOperation(ctx, "eventarc", reply, { settle: { name: other, action: "delete" } });
    for (let read = 0; read < 3; read += 1) {
      if (read > 0) await ctx.sleep(2000);
      if (isRecordedNotFound(await c.getChannel(other))) break;
    }
  },
};
