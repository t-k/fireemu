// Helpers the cases share. A case never judges an answer: it records it. It only reads an answer to
// decide the next step (the operation to poll, whether a channel exists before something is published to it).

export { CaseAbort, StopClean, must } from "../../pubsub-production/cases/support.mjs";

export const CE_TYPE = "type.googleapis.com/io.cloudevents.v1.CloudEvent";

/** The attribute `time` (a timestamp) and `datacontenttype` (a string) every event of the recorder carries. */
export const baseAttributes = (
  contentType = "application/json",
  time = new Date().toISOString(),
) => ({
  time: { ceTimestamp: time },
  datacontenttype: { ceString: contentType },
});

let counter = 0;

/** A CloudEvent in the proto JSON the publishing API takes, with the run's own id, source and type. */
export function cloudEvent(ctx, overrides = {}) {
  counter += 1;
  const { attributes, ...rest } = overrides;
  return {
    "@type": CE_TYPE,
    id: `${ctx.ownership.prefix}evt-${counter}`,
    source: `//fireemu/recorder/${ctx.ownership.runId}`,
    specVersion: "1.0",
    type: "fireemu.recorder.v1.probe",
    attributes: attributes ?? baseAttributes(),
    textData: '{"probe":true}',
    ...rest,
  };
}

/** A copy of an event without the named top-level members. */
export const without = (event, ...names) =>
  Object.fromEntries(Object.entries(event).filter(([name]) => !names.includes(name)));

/** The same event with one attribute removed. */
export const withoutAttribute = (event, name) => ({
  ...event,
  attributes: Object.fromEntries(Object.entries(event.attributes).filter(([key]) => key !== name)),
});

/**
 * Polls the operation a reply names until it is done, at most `attempts` reads. Every read is a step of
 * the capture. Returns the last read (or the reply itself when it names no operation).
 */
export async function waitOperation(ctx, host, reply, { attempts = 8 } = {}) {
  const name = reply?.body?.name;
  if (!reply?.ok || typeof name !== "string" || reply.body?.done === true) return reply;
  let last = reply;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await ctx.sleep(2000);
    last = await ctx.client.getOperation(host, name);
    if (!last.ok || last.body?.done === true) return last;
  }
  return last;
}

/** Creates an owned channel and waits for the creation; returns the channel name, or null if it was refused. */
export async function createOwnedChannel(ctx, key, body = {}) {
  const name = ctx.channel(key);
  const id = name.split("/").at(-1);
  const created = await ctx.client.createChannel(ctx.project, ctx.location, id, body);
  const settled = await waitOperation(ctx, "eventarc", created);
  return created.ok && settled.ok && settled.body?.error === undefined ? name : null;
}

/** True when the default channel does not exist, so that a publish to it cannot reach a real channel. */
export async function defaultChannelAbsent(ctx) {
  const reply = await ctx.client.getChannel(
    `projects/${ctx.project}/locations/${ctx.location}/channels/firebase`,
  );
  return reply.code === "NOT_FOUND";
}
