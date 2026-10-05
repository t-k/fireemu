import { StopClean, createAndWait, isRecordedNotFound, waitOperation } from "./support.mjs";

// The first creation of a channel with a name (stage A never got one: its body had none). Everything
// stage B records depends on this answer, so the case stops the whole run, cleanly, when the creation is
// refused, is not confirmed by its operation, or cannot be read back: nothing else is created.
//
// The deletion follows the same rules as the recorder's cleanup: its operation is polled, the channel is
// read back, and the second deletion is sent only when the first was answered, finished without an error
// and the read-back is the recorded 404 (after an unknown or unfinished deletion nothing is sent again).
export const createProbe = {
  id: "create-probe",
  short: "cp",
  requests: 31,
  async run(ctx) {
    const c = ctx.client;
    const name = ctx.channel("p1");
    await c.getChannel(name);
    const { created, owned } = await createAndWait(ctx, name);
    if (!owned) {
      ctx.note("create-probe-refused", { status: created.status });
      throw new StopClean(
        "the first creation with a name was refused or is not confirmed by its operation: nothing else is created",
      );
    }
    const read = await c.getChannel(name);
    if (!read.ok)
      throw new StopClean("the created channel could not be read: nothing else is created");
    await c.listChannels(ctx.project, ctx.location);
    await c.listChannels(ctx.project, ctx.location, { pageSize: 1 });
    const deleted = await c.deleteChannel(name);
    const finished = await waitOperation(ctx, "eventarc", deleted, {
      settle: { name, action: "delete" },
    });
    const back = await c.getChannel(name);
    if (
      deleted.ok &&
      finished.body?.done === true &&
      finished.body?.error === undefined &&
      isRecordedNotFound(back)
    )
      await c.deleteChannel(name);
  },
};
