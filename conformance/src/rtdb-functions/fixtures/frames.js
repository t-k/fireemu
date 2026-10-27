// Prints one typed frame per event on stdout (Cloud Logging carries it back to the recorder). The
// first production observation of an RTDB trigger event: every member of the context or event outside
// the named ones is listed by name and type, so a member the framework adds is not lost. Values are
// metadata only (a string of at most 256 characters, a number, a boolean or null as is; anything else
// is reduced to its type and size or key names), so nothing but the event's own data is printed in full.
const MARKER = "CV14_FRAME ";
let counter = 0;

// Members named by the fixture. Each one beyond the FUNCTIONS-EVENTS set cites the pinned firebase-functions
// 7.3.2 source that builds it, and only for the generation that source builds it for:
//   1st gen `auth`: lib/v1/cloud-functions.js:29-36 and 134-141 (set for a database trigger whose auth type
//     is not ADMIN: null for UNAUTHENTICATED, deleted for ADMIN).
//   2nd gen `firebaseDatabaseHost`, `instance`, `ref`, `location`: lib/v2/providers/database.d.ts:35-43
//     (DatabaseEvent) and lib/v2/providers/database.js:106-117 and 122-137 (the event spread with the
//     host member renamed), used again at database.js:107, 153 and 247.
// Every other member of a context or an event is listed by name and type, never named.
const CONTEXT_MEMBERS = new Set(["eventId", "timestamp", "eventType", "resource", "params", "authType", "authId", "auth"]);
const EVENT_MEMBERS = new Set([
  "id", "time", "type", "source", "subject", "specversion", "datacontenttype", "params", "authType", "authId", "data",
  "firebaseDatabaseHost", "instance", "ref", "location",
]);

function describeMember(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.length <= 256 ? value : { type: "string", length: value.length };
  if (Array.isArray(value)) return { type: "array", length: value.length };
  if (typeof value === "object") return { type: "object", keys: Object.keys(value).sort().slice(0, 32) };
  return { type: typeof value };
}

function otherMembers(source, named) {
  const out = {};
  for (const key of Object.keys(source).sort()) {
    if (!named.has(key)) out[key] = describeMember(source[key]);
  }
  return out;
}

function snapshot(value) {
  if (!value) return null;
  const exists = typeof value.exists === "function" ? value.exists() : null;
  return { exists, key: value.key ?? null, value: exists === false ? null : value.val() };
}

function data(value) {
  if (!value) return null;
  if ("before" in value && "after" in value) return { before: snapshot(value.before), after: snapshot(value.after) };
  return snapshot(value);
}

function v1Context(context) {
  return {
    eventId: context.eventId,
    timestamp: context.timestamp,
    eventType: context.eventType,
    resource: context.resource,
    params: context.params,
    authType: context.authType ?? null,
    authId: context.authId ?? null,
    auth: "auth" in context ? describeMember(context.auth) : undefined,
    contextKeys: Object.keys(context).sort(),
    extras: otherMembers(context, CONTEXT_MEMBERS),
  };
}

function v2Event(event) {
  return {
    id: event.id,
    time: event.time,
    type: event.type,
    source: event.source,
    subject: event.subject ?? null,
    specversion: event.specversion ?? null,
    datacontenttype: event.datacontenttype ?? null,
    params: event.params ?? null,
    authType: event.authType ?? null,
    authId: event.authId ?? null,
    data: data(event.data),
    firebaseDatabaseHost: describeMember(event.firebaseDatabaseHost ?? null),
    instance: describeMember(event.instance ?? null),
    ref: describeMember(event.ref ?? null),
    location: describeMember(event.location ?? null),
    eventKeys: Object.keys(event).sort(),
    extras: otherMembers(event, EVENT_MEMBERS),
  };
}

function report(frame) {
  counter += 1;
  console.log(`${MARKER}${JSON.stringify({ ...frame, seq: counter, receivedAt: new Date().toISOString() })}`);
  return Promise.resolve();
}

module.exports = { MARKER, CONTEXT_MEMBERS, EVENT_MEMBERS, data, report, v1Context, v2Event };
