import { StopClean, isRecordedNotFound } from "./support.mjs";

// What stage B needs of the project before anything is created: the publishing API is enabled (stage A
// enabled it and left it enabled; this recording never changes a service). The default channel is read, so
// that the recording says whether production created it in the meantime.
export const preconditions = {
  id: "preconditions",
  short: "pr",
  requests: 3,
  async run(ctx) {
    const c = ctx.client;
    const service = await c.getService();
    const state = service.body?.state ?? null;
    ctx.note("service-state", { state });
    if (state !== "ENABLED")
      throw new StopClean(
        `the publishing API is ${String(state)}: stage B does not enable it, nothing was created`,
      );
    const channel = await c.getChannel(
      `projects/${ctx.project}/locations/${ctx.location}/channels/firebase`,
    );
    ctx.note("default-channel", { absent: isRecordedNotFound(channel), status: channel.status });
  },
};
