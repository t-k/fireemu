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

/**
 * The members of a 1st gen context and of a 2nd gen CloudEvent that the fixture names and prints as
 * values. The fixture lists every other member by name and type (`extras`, `contextKeys`, `eventKeys`);
 * the judge treats any such member as something nobody has seen before, and the run is then not called
 * recorded. Kept equal to fixtures/frames.js by fixtures.test.mjs.
 *
 * No RTDB trigger event has been recorded (the stage 1 recording is of an HTTP function's deploy), so a
 * member is named only when the pinned firebase-functions 7.3.2 source builds it, for the generation that
 * source builds it for. Naming a member only stops the "unnamed member" reason: its value is printed and
 * kept in full, and nothing is taken as matching because of it.
 *
 * Beyond the FUNCTIONS-EVENTS set:
 * - 1st gen `auth`: lib/v1/cloud-functions.js:29-36 sets it for a database trigger whose auth type is not
 *   ADMIN (`_makeAuth`, 134-141: null for UNAUTHENTICATED) and deletes it for ADMIN.
 * - 2nd gen `firebaseDatabaseHost`, `instance`, `ref`, `location`: lib/v2/providers/database.d.ts:35-43
 *   (DatabaseEvent) and lib/v2/providers/database.js:106-117 and 122-137.
 * Not named from the SDK, for want of a source that builds them: a 1st gen `domain` (the SDK only reads it
 * from the raw context, v1/providers/database.js:140), a 1st gen `auth` token member, anything else.
 * Those the production run of 2026-10-27 showed are named below, from that recording and nothing else.
 */
export const NAMED_CONTEXT_MEMBERS = Object.freeze([
  "eventId",
  "timestamp",
  "eventType",
  "resource",
  "params",
  "authType",
  "authId",
  "auth",
]);
export const NAMED_EVENT_MEMBERS = Object.freeze([
  "id",
  "time",
  "type",
  "source",
  "subject",
  "specversion",
  "datacontenttype",
  "params",
  "authType",
  "authId",
  "data",
  "firebaseDatabaseHost",
  "instance",
  "ref",
  "location",
]);

/**
 * The members the production recording showed beyond the ones above (recorded/production-rtdb-triggers.json,
 * the run of CV14-RTDB-TRIGGERS-20261027-02: 28 frames, 8 handlers, 9 writes). A member is named only for
 * the generation and event type it was recorded on, with the shape it was recorded in, and each entry
 * cites the first recorded frame (frame number in the fixture, handler, delivery sequence number, step):
 * - 1st gen `domain` in the context, "firebaseio.com" in all 14 frames, the four event types.
 * - 2nd gen `context` (eventId, eventType, params, resource, timestamp) and `traceparent` (a W3C
 *   traceparent) on all four event types; `change` (after, before) on updated and written; `snapshot`
 *   (_data, _path, app, instance) on created and deleted.
 * Nothing else is named: a member on another event type, another generation or in another shape, and any
 * other member, still makes the run need review.
 */
const TRACEPARENT = /^00-[0-9a-f]{32}-[0-9a-f]{16}-0[0-3]$/u;
const objectOf = (...keys) => Object.freeze({ kind: "object", keys: Object.freeze(keys) });
const recorded = (generation, event, member, shape, frame, handler, step) =>
  Object.freeze({
    generation,
    event,
    member,
    shape,
    source: `recorded/production-rtdb-triggers.json frame ${frame} (${handler} seq 1, step ${step})`,
  });
const DOMAIN = Object.freeze({ kind: "value", value: "firebaseio.com" });
const CONTEXT = objectOf("eventId", "eventType", "params", "resource", "timestamp");
const CHANGE = objectOf("after", "before");
const SNAPSHOT = objectOf("_data", "_path", "app", "instance");
const TRACE = Object.freeze({ kind: "traceparent" });
export const RECORDED_MEMBERS = Object.freeze([
  recorded(1, "create", "domain", DOMAIN, 4, "rtdbCreatedV1", "s1"),
  recorded(1, "update", "domain", DOMAIN, 8, "rtdbUpdatedV1", "s2"),
  recorded(1, "delete", "domain", DOMAIN, 12, "rtdbDeletedV1", "s4"),
  recorded(1, "write", "domain", DOMAIN, 3, "rtdbWrittenV1", "s1"),
  recorded(2, "create", "context", CONTEXT, 2, "rtdbCreatedV2", "s1"),
  recorded(2, "update", "context", CONTEXT, 7, "rtdbUpdatedV2", "s2"),
  recorded(2, "delete", "context", CONTEXT, 10, "rtdbDeletedV2", "s4"),
  recorded(2, "write", "context", CONTEXT, 1, "rtdbWrittenV2", "s1"),
  recorded(2, "create", "traceparent", TRACE, 2, "rtdbCreatedV2", "s1"),
  recorded(2, "update", "traceparent", TRACE, 7, "rtdbUpdatedV2", "s2"),
  recorded(2, "delete", "traceparent", TRACE, 10, "rtdbDeletedV2", "s4"),
  recorded(2, "write", "traceparent", TRACE, 1, "rtdbWrittenV2", "s1"),
  recorded(2, "update", "change", CHANGE, 7, "rtdbUpdatedV2", "s2"),
  recorded(2, "write", "change", CHANGE, 1, "rtdbWrittenV2", "s1"),
  recorded(2, "create", "snapshot", SNAPSHOT, 2, "rtdbCreatedV2", "s1"),
  recorded(2, "delete", "snapshot", SNAPSHOT, 10, "rtdbDeletedV2", "s4"),
]);

const EVENT_OF = new Map(FIXTURE_HANDLERS.map((handler) => [handler.name, handler.event]));

/** Whether `value` (as the fixture printed it in `extras`) is the recorded shape of `member` for this handler. */
export function isRecordedMember(handler, generation, member, value) {
  const entry = RECORDED_MEMBERS.find(
    (e) => e.generation === generation && e.event === EVENT_OF.get(handler) && e.member === member,
  );
  if (entry === undefined) return false;
  const { shape } = entry;
  if (shape.kind === "value") return value === shape.value;
  if (shape.kind === "traceparent") return typeof value === "string" && TRACEPARENT.test(value);
  return (
    value !== null &&
    typeof value === "object" &&
    value.type === "object" &&
    Array.isArray(value.keys) &&
    value.keys.length === shape.keys.length &&
    shape.keys.every((key, index) => value.keys[index] === key)
  );
}
