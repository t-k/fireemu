import { cloudEvent, requireReadyChannel } from "./support.mjs";

// Credentials and the answers of a missing channel, a malformed event and a wrong project or location.
// The token-format probes first: strict decides by shape (a `ya29.`-prefixed token or a three-part JWT is
// accepted as a credential, anything else is refused with the recorded 401), so each shape that production
// might treat differently is sent once to a read and once to a publish.
const TOKEN_PROBES = ["none", "invalid", "ya29-garbage", "jwt-garbage", "jwt-expired-unsigned"];
/** A scope that no Eventarc call needs: a real token of this scope tells a wrong scope from a bad token. */
const NARROW_SCOPE = "https://www.googleapis.com/auth/userinfo.email";

export const authErrors = {
  id: "auth-errors",
  short: "ae",
  requests: 36,
  async run(ctx) {
    const c = ctx.client;
    const channel = await requireReadyChannel(ctx, "auth");
    for (const token of TOKEN_PROBES) {
      const t = c.with({ token });
      await t.listChannels(ctx.project, ctx.location);
      await t.publishEvents(channel, { events: [cloudEvent(ctx)] });
    }
    // The recorded token again, for a second record of the same refusal.
    const again = c.with({ token: "invalid" });
    await again.getChannel(channel);
    // A real token of the wrong scope (skipped, with a note, when gcloud cannot print one).
    const bearer = await ctx.scopedToken(NARROW_SCOPE);
    if (bearer === null) ctx.note("wrong-scope-skipped", { scope: NARROW_SCOPE });
    else {
      const t = c.with({ token: { label: "wrong-scope", bearer } });
      await t.listChannels(ctx.project, ctx.location);
      await t.publishEvents(channel, { events: [cloudEvent(ctx)] });
    }
    // The quota project of the call: one that does not exist.
    const other = c.with({ quotaProject: "fireemu-no-such-project-0" });
    await other.listChannels(ctx.project, ctx.location);
    await other.publishEvents(channel, { events: [cloudEvent(ctx)] });
    await c
      .with({ token: "none" })
      .createChannel(ctx.project, ctx.location, `${channel.split("/").at(-1)}-x`);
    // A channel of the run that does not exist, a location that is not one, a project that is not the run's.
    await c.publishEvents(ctx.channel("never-created"), { events: [cloudEvent(ctx)] });
    const nowhere = ctx.probe("nowhere-pub", { location: "no-such-location1", listable: false });
    await c.publishEvents(nowhere, { events: [cloudEvent(ctx)] });
    await c.getChannel(`projects/fireemu-no-such-project-0/locations/${ctx.location}/channels/x`);
  },
};
