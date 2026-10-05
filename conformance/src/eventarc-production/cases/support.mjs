// Helpers the cases share. A case never judges an answer: it records it. It only reads an answer to
// decide the next step (the operation to poll, whether a channel exists before something is published to it).

import { CaseAbort } from "../../pubsub-production/cases/support.mjs";
import { isRecordedNotFound } from "../client.mjs";

export { CaseAbort, StopClean, must } from "../../pubsub-production/cases/support.mjs";
export { isRecordedNotFound };

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
 * the capture. Returns the last read (or the reply itself when it names no operation). With `settle`
 * (`{ name, action }`), the result is written into the ledger as what the operation says of that
 * channel: the 2xx that started it does not prove that the run created (or removed) it.
 */
/** The reads of one operation: the bound every case ceiling is derived from (with `READY_READS`). */
export const OPERATION_READS_MAX = 10;

export async function waitOperation(
  ctx,
  host,
  reply,
  { attempts = OPERATION_READS_MAX, settle } = {},
) {
  const name = reply?.body?.name;
  let last = reply;
  const finished = () => !last?.ok || last.body?.done === true;
  if (reply?.ok && typeof name === "string" && reply.body?.done !== true) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (attempt > 0) await ctx.sleep(2000);
      last = await ctx.client.getOperation(host, name);
      if (finished()) break;
    }
  }
  if (settle !== undefined && reply?.ok)
    ctx.client.settleOperation(settle.name, settle.action, last, name);
  return last;
}

/**
 * Creates the channel `name` and waits for its operation, writing the outcome into the ledger.
 * Returns `{ created, settled, owned }`: `owned` is true only when the operation is done without an
 * error (a 2xx alone does not prove that this run created the channel). The body is built by the client.
 */
export async function createAndWait(ctx, name) {
  const id = name.split("/").at(-1);
  const location = name.split("/")[3];
  const created = await ctx.client.createChannel(ctx.project, location, id);
  const settled = await waitOperation(ctx, "eventarc", created, {
    settle: { name, action: "create" },
  });
  const owned =
    created.ok && settled.ok && settled.body?.done === true && settled.body?.error === undefined;
  return { created, settled, owned };
}

/**
 * Creates an owned channel and returns its name. A case that needs the channel stops here, with the
 * reason, when the creation was refused or is not confirmed by its operation: its dependent steps are
 * skipped explicitly and nothing is sent to a name that may not exist (stage A went on and published to
 * a name it had never created).
 */
export async function requireChannel(ctx, key) {
  const name = ctx.channel(key);
  const { created, owned } = await createAndWait(ctx, name);
  if (!owned) {
    ctx.note("channel-not-confirmed", { name, status: created.status });
    throw new CaseAbort(
      `the creation of ${key}`,
      created.ok ? { code: "its operation did not finish without an error" } : created,
    );
  }
  return name;
}

/** The reads of the channel's state before a publish: the first, and at most four more, three seconds apart. */
export const READY_READS = 5;
export const READY_WAIT_MS = 3000;

/**
 * Creates an owned channel (see `requireChannel`) and reads it until its `state` says ACTIVE, so that the
 * publishes that follow are not sent to a channel that is still being set up. The reads stop at once when
 * the read is not a 2xx or the channel has no `state`, and after the last read whatever the state is: the
 * case goes on and the capture says what it was (`channel-state`).
 */
export async function requireReadyChannel(ctx, key) {
  const name = await requireChannel(ctx, key);
  let state = null;
  for (let read = 0; read < READY_READS; read += 1) {
    if (read > 0) await ctx.sleep(READY_WAIT_MS);
    const reply = await ctx.client.getChannel(name);
    state = reply.ok && typeof reply.body?.state === "string" ? reply.body.state : null;
    if (state === null || state === "ACTIVE") break;
  }
  ctx.note("channel-state", { name, state });
  return name;
}

/** True when the default channel is known not to exist (the recorded 404), so a publish to it reaches nothing. */
export async function defaultChannelAbsent(ctx) {
  const reply = await ctx.client.getChannel(
    `projects/${ctx.project}/locations/${ctx.location}/channels/firebase`,
  );
  return isRecordedNotFound(reply);
}
