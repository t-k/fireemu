import { listPages, requireChannel } from "./support.mjs";

// The order of a list (stage B recorded lists of two to ten channels in an order that is neither the
// name, the creation time, the update time nor the UID). Six channels are created in an order that is not
// their name order, then listed in every way the strict surface needs: the whole list twice (is the order
// stable?), the pages of one, two and three, the page sizes a service may refuse, and a token carried
// to another location, another project and the aggregated location.
const KEYS = ["m", "c", "x", "a", "t", "f"];
const PAGE_SIZES = [0, -1, 1001, 100_000];

export const channelOrder = {
  id: "channel-order",
  short: "co",
  requests: 96,
  async run(ctx) {
    const c = ctx.client;
    for (const key of KEYS) await requireChannel(ctx, key);
    await c.listChannels(ctx.project, ctx.location);
    await c.listChannels(ctx.project, ctx.location);
    const ones = await listPages(ctx, ctx.project, ctx.location, 1, 8);
    await listPages(ctx, ctx.project, ctx.location, 2, 5);
    await listPages(ctx, ctx.project, ctx.location, 3, 4);
    for (const pageSize of PAGE_SIZES)
      await c.listChannels(ctx.project, ctx.location, { pageSize });
    await c.listChannels(ctx.project, "-", { pageSize: 100 });
    // A token of the first page of one, carried where it was not issued.
    const [pageToken] = ones;
    if (pageToken === undefined) {
      ctx.note("no-page-token", { pages: ones.length });
      return;
    }
    await c.listChannels(ctx.project, "europe-west1", { pageSize: 1, pageToken });
    await c.listChannels("fireemu-no-such-project-0", ctx.location, { pageSize: 1, pageToken });
    await c.listChannels(ctx.project, "-", { pageSize: 1, pageToken });
    await c.listChannels(ctx.project, ctx.location, { pageSize: 2, pageToken });
  },
};
