// What the kinds recorder and its fixture (fixtures-kinds/) agree on: the handlers, the nested pattern,
// the run prefix and the recorded-member table. The fixture is deployed on its own, so it repeats these
// literals; kinds-fixtures.test.mjs checks that both sides agree.
//
// The recorder reuses the CV14 and breadth machinery. The frame marker is the breadth one, the handlers
// are new (fresh names: a deleted function name can stay unusable for days on some services), and the
// members a frame may carry beyond the named ones are the shapes CV14 recorded for the same event type.

import { FRAME_MARKER } from "./breadth-frames.mjs";
import { isRecordedMember as cv14Member } from "./frames.mjs";

export { FRAME_MARKER };
export { NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS } from "./frames.mjs";
export const INSTANCE = "fireemu-q-rtdb2";
export const LOCATION = "us-central1";
export const PREFIX = "k9-rtdb";
export const CODEBASE = "rtdb-kinds-oracle";
export const ITEM_PATH = `/${PREFIX}/{group}/items/{id}`;
export const GROUP_PATH = `/${PREFIX}/{group}`;
/**
 * The instance the optional any-instance handler names: none, which the 2nd gen SDK turns into `*`
 * (lib/v2/providers/database.js getOpts). It matches the one instance; no second instance is created.
 */
export const ANY_INSTANCE = "*";

/**
 * In deploy order. `event` is the CV14 vocabulary (create, update, delete, write); `level` says whether the
 * handler watches the item pattern or its group (the ancestor of the item pattern). The six kind handlers
 * are required: a refused deploy of one stops the run. The glob and the group handler are optional: a
 * definite refusal of either lets the run continue without them, an unknown deploy stops everything.
 */
export const FIXTURE_HANDLERS = [
  ["k9CreatedV2", 2, "create", "item", true],
  ["k9UpdatedV2", 2, "update", "item", true],
  ["k9DeletedV2", 2, "delete", "item", true],
  ["k9CreatedV1", 1, "create", "item", true],
  ["k9UpdatedV1", 1, "update", "item", true],
  ["k9DeletedV1", 1, "delete", "item", true],
  ["k9AnyWrittenV2", 2, "write", "item", false],
  ["k9GroupWrittenV2", 2, "write", "group", false],
].map(([name, generation, event, level, required]) =>
  Object.freeze({ name, generation, event, level, required }),
);

const CV14_NAME = { create: "Created", update: "Updated", delete: "Deleted", write: "Written" };
const BY_NAME = new Map(FIXTURE_HANDLERS.map((handler) => [handler.name, handler]));

/**
 * Whether `value` (as the fixture printed it in `extras`) is the recorded shape of `member` for this
 * handler: the shape CV14 recorded on the same event type and generation, and nothing else.
 */
export function isRecordedMember(handler, generation, member, value) {
  const entry = BY_NAME.get(handler);
  if (!entry || entry.generation !== generation) return false;
  return cv14Member(`rtdb${CV14_NAME[entry.event]}V${generation}`, generation, member, value);
}
