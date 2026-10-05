import { createAndWait, probeCreate, settleCreation } from "./support.mjs";

// The IDs and bodies stage B did not reach: one character, a leading hyphen, a final hyphen and exactly 63
// characters (stage B: `a4` and `goog-...` were accepted; upper case, a leading digit, an underscore and
// 64 characters were refused), and the one creation that deviates from the official request on purpose
// (see `createChannelVariant`): a body that names another channel than the path's ID. Both names it may create
// are the run's own. A creation without a `channelId` is not part of the recording: production could name
// the channel itself, and a run never creates a resource it cannot name.
export const channelIds = {
  id: "channel-ids",
  short: "id",
  requests: 57,
  async run(ctx) {
    const c = ctx.client;
    const run = ctx.ownership.runId;
    // Names that cannot carry the run's prefix are probes: read first, created only after the read says
    // they cannot be there.
    await probeCreate(ctx, "a");
    await probeCreate(ctx, `-${run}`);
    // Names that can: the run's own.
    await createAndWait(ctx, ctx.channel("end-"));
    const room = 63 - ctx.channel("").split("/").at(-1).length;
    await createAndWait(ctx, ctx.channel("x".repeat(room)));
    // A body that names another owned channel than the path's ID: both may be created.
    const one = ctx.channel("mm-a");
    const other = ctx.channel("mm-b");
    const mismatch = await c.createChannelVariant(
      ctx.project,
      ctx.location,
      "name-mismatch",
      one.split("/").at(-1),
      other.split("/").at(-1),
    );
    await settleCreation(ctx, mismatch, [one, other]);
  },
};
