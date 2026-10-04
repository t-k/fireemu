import { createAndWait, isRecordedNotFound, waitOperation } from "./support.mjs";

/**
 * A name the service may refuse, sent as a probe: derived from the run where the rule under test allows
 * it, registered before anything is sent, and read first. It is created only after the read says it
 * cannot be there (the recorded 404, or the 400 of a name that cannot exist); a name that exists is not
 * the run's and is never created or ledgered. The creation is then followed to the end of its
 * operation, so that a 2xx alone never proves that the run created it.
 */
async function probeCreate(ctx, id, options = {}) {
  const name = ctx.probe(id, options);
  const read = await ctx.client.getChannel(name);
  const cannotExist = isRecordedNotFound(read) || (read.status === 400 && !read.unknown);
  if (!cannotExist) {
    ctx.note(read.ok ? "probe-exists" : "probe-read-unclear", { name });
    return null;
  }
  const outcome = await createAndWait(ctx, name);
  return { name, ...outcome };
}

// Provider-less channel lifecycle. Production may refuse the creation; the answers are recorded either
// way (scope decision E1), and the steps that need an existing channel continue with what exists.
export const channelLifecycle = {
  id: "channel-lifecycle",
  short: "cl",
  requests: 110,
  async run(ctx) {
    const c = ctx.client;
    const name = ctx.channel("c1");
    const id = name.split("/").at(-1);
    await c.getChannel(name);
    const { owned } = await createAndWait(ctx, name);
    await c.getChannel(name);
    await c.listChannels(ctx.project, ctx.location);
    await c.listChannels(ctx.project, ctx.location, { pageSize: 1 });
    await c.listChannels(ctx.project, ctx.location, { pageToken: "garbage" });
    await c.listChannels(ctx.project, "-", { pageSize: 5 });
    // A second creation of the same ID.
    const duplicate = await c.createChannel(ctx.project, ctx.location, id, {});
    await waitOperation(ctx, "eventarc", duplicate, { settle: { name, action: "create" } });
    // IDs the service may refuse. Each is derived from the run and read first.
    const run = ctx.ownership.runId;
    await probeCreate(ctx, `GOOG-${run.toUpperCase()}`);
    await probeCreate(ctx, `a${run[0]}`);
    await probeCreate(ctx, `goog-${run}`);
    await probeCreate(ctx, `1-${run}`);
    // 64 characters long with the run's prefix, so that it can only be this run's.
    await probeCreate(
      ctx,
      `${ctx.ownership.prefix}${"x".repeat(64 - ctx.ownership.prefix.length)}`,
    );
    // A location that does not exist cannot hold the channel: no read first, and it is never listed.
    const nowhere = ctx.probe(`nowhere-${run}`, { location: "no-such-location1", listable: false });
    const refused = await c.createChannel(ctx.project, "no-such-location1", `nowhere-${run}`, {});
    await waitOperation(ctx, "eventarc", refused, { settle: { name: nowhere, action: "create" } });
    await c.getChannel(nowhere);
    // A project that is not the run's (reads only).
    await c.getChannel("projects/fireemu-no-such-project-0/locations/us-central1/channels/x");
    await c.listChannels("fireemu-no-such-project-0", ctx.location);
    // Deletion of the owned channel, its operation, the read-back, and a second deletion. The second
    // deletion is sent only when the first was answered, its operation is done without an error and the
    // read-back is the recorded 404: after an unknown or unfinished deletion nothing is sent again.
    if (owned) {
      const deleted = await c.deleteChannel(name);
      const finished = await waitOperation(ctx, "eventarc", deleted, {
        settle: { name, action: "delete" },
      });
      const back = await c.getChannel(name);
      if (
        deleted.ok &&
        finished.body?.done === true &&
        finished.body?.error === undefined &&
        isRecordedNotFound(back)
      )
        await c.deleteChannel(name);
    }
  },
};
