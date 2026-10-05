import { createAndWait, listNames, probeCreate, settleCreation } from "./support.mjs";

// The IDs and bodies stage B did not reach: one character, a leading hyphen, a final hyphen and exactly 63
// characters (stage B: `a4` and `goog-...` were accepted; upper case, a leading digit, an underscore and
// 64 characters were refused), and the two creations that deviate from the official request on purpose
// (see `createChannelVariant`): a body that names another channel than the path's ID, and a path with no
// `channelId`.
//
// A channel that cannot be named in advance cannot be removed by prefix: the creation without a `channelId`
// is bracketed by two lists of the location, and a channel that appears from it is reported (`foreign`,
// exit code 1), never touched, because it is not the run's.
export const channelIds = {
  id: "channel-ids",
  short: "id",
  requests: 76,
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
    // A path with no channelId.
    const bare = ctx.channel("nc");
    const before = await listNames(ctx, ctx.location);
    const missing = await c.createChannelVariant(
      ctx.project,
      ctx.location,
      "no-channel-id",
      bare.split("/").at(-1),
    );
    await settleCreation(ctx, missing, [bare]);
    const after = await listNames(ctx, ctx.location);
    if (before === null || after === null) {
      ctx.note("foreign-check-unavailable", { before: before !== null, after: after !== null });
      return;
    }
    const known = new Set(before);
    const appeared = after.filter((name) => !known.has(name) && !ctx.ownership.isOwned(name));
    if (appeared.length > 0) {
      ctx.foreign.push(...appeared);
      ctx.note("foreign-channel-appeared", { names: appeared });
    }
  },
};
