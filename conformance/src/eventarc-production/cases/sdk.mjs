import { defaultChannelAbsent, requireChannel } from "./support.mjs";

// The Admin SDK publish. `ctx.sdk.publish` reports whether the SDK threw and how many requests it sent;
// the requests themselves are in the capture (op sdk.publishEvents), recorded as the SDK built them.
export const adminSdkPublish = {
  id: "admin-sdk-publish",
  short: "sd",
  requests: 24,
  async run(ctx) {
    const channel = await requireChannel(ctx, "sdk");
    const relative = channel.replace(`projects/${ctx.project}/`, "");
    const source = `//fireemu/recorder/${ctx.ownership.runId}`;
    const record = async (name, spec) => {
      const outcome = await ctx.sdk.publish(spec);
      ctx.note("sdk-outcome", { name, ...outcome });
      return outcome;
    };
    const object = (extra = {}) => ({
      type: "fireemu.recorder.v1.sdk",
      data: { probe: true },
      ...extra,
    });
    await record("full-channel", { channel, events: object({ source }) });
    await record("relative-channel", { channel: relative, events: object({ source }) });
    await record("multiple-events", {
      channel,
      events: [object({ source }), object({ source, data: "text" })],
    });
    await record("generated-metadata", { channel, events: object(), source });
    await record("caller-metadata", {
      channel,
      events: object({
        source,
        id: `${ctx.ownership.prefix}sdk-id`,
        time: "2026-10-05T01:02:03.000Z",
        subject: "sdk-subject",
        datacontenttype: "application/json",
        custom: "extension",
      }),
    });
    // The default channel is only used while it does not exist, so that nothing reaches a real channel.
    if (await defaultChannelAbsent(ctx)) {
      // Only now may a publish name the default channel (it is not the run's, and is never deleted).
      ctx.publishTarget("firebase");
      await record("default-channel", { events: object({ source }) });
    }
    // The SDK filters by allowed event types itself: nothing is sent for a type that is not in the list.
    await record("allowed-event-types", {
      channel,
      channelOptions: { allowedEventTypes: ["fireemu.recorder.v1.other"] },
      events: object({ source }),
    });
    // Refusals before anything is sent.
    await record("missing-source", { channel, events: object() });
    await record("missing-data", { channel, events: { type: "t", source } });
    await record("bad-time", { channel, events: object({ source, time: "yesterday" }) });
    await record("non-string-extension", { channel, events: object({ source, custom: 5 }) });
    await record("number-data", { channel, events: object({ source, data: 5 }) });
    await record("bad-channel-name", { channel: "not/a/channel", events: object({ source }) });
  },
};
