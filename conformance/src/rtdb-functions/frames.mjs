// What the CV14 recorder and its fixture agree on: the handlers, the instance, the run prefix and the
// frame marker. The fixture (fixtures/) is deployed on its own, so it repeats these literals; the fixture
// test checks that both sides agree.

export const FRAME_MARKER = "CV14_FRAME ";
export const INSTANCE = "fireemu-q-rtdb2";
export const LOCATION = "us-central1";
/** The run prefix: fixed, because the instance is DELETED before and after the run. */
export const PREFIX = "cv14-rtdb";
export const ITEM_PATH = `/${PREFIX}/items/{id}`;

/** [name, generation, event] of the eight handlers: created, updated, deleted and written, on each generation. */
export const FIXTURE_HANDLERS = [
  ["rtdbCreatedV1", 1, "create"],
  ["rtdbUpdatedV1", 1, "update"],
  ["rtdbDeletedV1", 1, "delete"],
  ["rtdbWrittenV1", 1, "write"],
  ["rtdbCreatedV2", 2, "create"],
  ["rtdbUpdatedV2", 2, "update"],
  ["rtdbDeletedV2", 2, "delete"],
  ["rtdbWrittenV2", 2, "write"],
].map(([name, generation, event]) => Object.freeze({ name, generation, event }));
