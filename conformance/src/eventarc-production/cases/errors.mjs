import { cloudEvent, createOwnedChannel } from "./support.mjs";

// Credentials and the answers of a missing channel, a malformed event and a wrong project or location.
export const authErrors = {
  id: "auth-errors",
  short: "ae",
  requests: 14,
  async run(ctx) {
    const c = ctx.client;
    const channel = (await createOwnedChannel(ctx, "auth")) ?? ctx.channel("auth-absent");
    for (const token of ["none", "invalid"]) {
      const t = c.with({ token });
      await t.listChannels(ctx.project, ctx.location);
      await t.publishEvents(channel, { events: [cloudEvent(ctx)] });
    }
    await c
      .with({ token: "none" })
      .createChannel(ctx.project, ctx.location, `${channel.split("/").at(-1)}-x`, {});
    // A channel of the run that does not exist, a location that is not one, a project that is not the run's.
    await c.publishEvents(ctx.channel("never-created"), { events: [cloudEvent(ctx)] });
    const nowhere = ctx.probe("nowhere-pub", { location: "no-such-location1", listable: false });
    await c.publishEvents(nowhere, { events: [cloudEvent(ctx)] });
    await c.getChannel(`projects/fireemu-no-such-project-0/locations/${ctx.location}/channels/x`);
  },
};
