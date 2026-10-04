import { cloudEvent, defaultChannelAbsent, waitOperation } from "./support.mjs";

/** The names of the enabled services, read a page at a time (at most 3 pages), and whether the read was complete. */
async function enabledServices(ctx) {
  const names = [];
  let pageToken;
  for (let page = 0; page < 3; page += 1) {
    const reply = await ctx.client.listEnabledServices(pageToken ? { pageToken } : {});
    if (!reply.ok) return { names, complete: false };
    for (const item of reply.body?.services ?? []) names.push(item.config?.name ?? item.name);
    pageToken = reply.body?.nextPageToken;
    if (!pageToken) return { names, complete: true };
  }
  return { names, complete: false };
}

// The publishing API is disabled in the sandbox until this case enables it. While it is disabled, the
// answers of a publish and of the channel calls are recorded once; then the API is enabled and left
// enabled (the owner's decision), which is a change to the project that the send's change log names.
export const serviceState = {
  id: "service-state",
  short: "sv",
  requests: 26,
  async run(ctx) {
    const c = ctx.client;
    const before = await c.getService();
    const disabled = before.body?.state === "DISABLED";
    ctx.note("service-state", {
      before: before.body?.state ?? null,
      disabledStateRecorded: disabled,
    });
    if (disabled) {
      // The publish answers while the API is disabled: an owned channel that was never created, and the
      // default channel (only if it does not exist, so that nothing reaches a real channel).
      const never = ctx.channel("never-created");
      await c.publishEvents(never, { events: [cloudEvent(ctx)] });
      if (await defaultChannelAbsent(ctx))
        await c.publishEvents(ctx.publishTarget("firebase"), { events: [cloudEvent(ctx)] });
      // The Eventarc API itself is enabled: its calls while the publishing API is disabled.
      await c.getChannel(never);
      await c.listChannels(ctx.project, ctx.location, { pageSize: 10 });
      const listedBefore = await enabledServices(ctx);
      const enabled = await c.enableService();
      await waitOperation(ctx, "usage", enabled);
      await c.getService();
      const listedAfter = await enabledServices(ctx);
      // What the enabling turned on besides the publishing API (a dependency of it).
      ctx.note("enabled-services", {
        before: listedBefore.names.length,
        after: listedAfter.names.length,
        added: listedAfter.names.filter((name) => !listedBefore.names.includes(name)),
        complete: listedBefore.complete && listedAfter.complete,
      });
    }
    // The state after, and the first publish with the API enabled (an owned channel that was never created).
    await c.publishEvents(ctx.channel("never-created"), { events: [cloudEvent(ctx)] });
  },
};
