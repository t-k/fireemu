import {
  cloudEvent,
  createAndWait,
  isRecordedNotFound,
  requireChannel,
  waitOperation,
} from "./support.mjs";

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

/** The pages of a list, followed through `nextPageToken` for at most `pages` requests. */
async function listPages(ctx, project, location, pageSize, pages) {
  let pageToken;
  for (let page = 0; page < pages; page += 1) {
    const reply = await ctx.client.listChannels(project, location, {
      pageSize,
      ...(pageToken === undefined ? {} : { pageToken }),
    });
    pageToken = reply.ok ? reply.body?.nextPageToken : undefined;
    if (typeof pageToken !== "string" || pageToken === "") return;
  }
}

// What a created channel looks like to the read calls, and the rules for its name. Every step needs the
// channels of the case: a creation that is refused stops the case (`requireChannel`).
export const channelLifecycle = {
  id: "channel-lifecycle",
  short: "cl",
  requests: 134,
  async run(ctx) {
    const c = ctx.client;
    const name = await requireChannel(ctx, "c1");
    const second = await requireChannel(ctx, "c2");
    const id = name.split("/").at(-1);
    await c.getChannel(name);
    await c.getChannel(second);
    // The list with both channels, a page of one and the page it points to, a page of two, a token that
    // is not one, the aggregated location `-`, a second real location and a well-formed one that is not.
    await c.listChannels(ctx.project, ctx.location);
    await listPages(ctx, ctx.project, ctx.location, 1, 3);
    await c.listChannels(ctx.project, ctx.location, { pageSize: 2 });
    await c.listChannels(ctx.project, ctx.location, { pageToken: "garbage" });
    await c.listChannels(ctx.project, "-", { pageSize: 5 });
    await c.listChannels(ctx.project, "europe-west1");
    await c.listChannels(ctx.project, "us-east99");
    await c.getChannel(`projects/${ctx.project}/locations/europe-west1/channels/${id}`);
    // The project number in the path (given at run time, only when it differs from the ID).
    if (ctx.projectNumber !== null) {
      await c.listChannels(ctx.projectNumber, ctx.location);
      await c.getChannel(name.replace(`projects/${ctx.project}/`, `projects/${ctx.projectNumber}/`));
    }
    // A second creation of the same ID.
    const duplicate = await c.createChannel(ctx.project, ctx.location, id);
    await waitOperation(ctx, "eventarc", duplicate, { settle: { name, action: "create" } });
    // IDs the service may refuse. Each is derived from the run and read first.
    const run = ctx.ownership.runId;
    await probeCreate(ctx, `GOOG-${run.toUpperCase()}`);
    await probeCreate(ctx, `a${run[0]}`);
    await probeCreate(ctx, `goog-${run}`);
    await probeCreate(ctx, `1-${run}`);
    await probeCreate(ctx, `bad_${run}`);
    // 64 characters long with the run's prefix, so that it can only be this run's.
    await probeCreate(
      ctx,
      `${ctx.ownership.prefix}${"x".repeat(64 - ctx.ownership.prefix.length)}`,
    );
    // A location that does not exist cannot hold the channel: no read first, and it is never listed.
    const nowhere = ctx.probe(`nowhere-${run}`, { location: "no-such-location1", listable: false });
    const refused = await c.createChannel(ctx.project, "no-such-location1", `nowhere-${run}`);
    await waitOperation(ctx, "eventarc", refused, { settle: { name: nowhere, action: "create" } });
    await c.getChannel(nowhere);
    // A project that is not the run's (reads only: the recorder changes nothing outside its project).
    await c.getChannel("projects/fireemu-no-such-project-0/locations/us-central1/channels/x");
    await c.listChannels("fireemu-no-such-project-0", ctx.location);
  },
};

// Deletion: its operation, the read-back, the list without the channel, a second deletion, and a publish
// to the name after the deletion (whether production answers 404 at once).
export const channelDelete = {
  id: "channel-delete",
  short: "cd",
  requests: 41,
  async run(ctx) {
    const c = ctx.client;
    const name = await requireChannel(ctx, "d1");
    await requireChannel(ctx, "d2");
    const deleted = await c.deleteChannel(name);
    const finished = await waitOperation(ctx, "eventarc", deleted, {
      settle: { name, action: "delete" },
    });
    const back = await c.getChannel(name);
    await c.listChannels(ctx.project, ctx.location);
    // Immediately after the deletion, and again once the read-back said 404.
    await c.publishEvents(name, { events: [cloudEvent(ctx)] });
    if (
      deleted.ok &&
      finished.body?.done === true &&
      finished.body?.error === undefined &&
      isRecordedNotFound(back)
    )
      await c.deleteChannel(name);
  },
};
