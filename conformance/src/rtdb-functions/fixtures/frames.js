// Prints one typed frame per event on stdout (Cloud Logging carries it back to the recorder). The
// first production observation of an RTDB trigger event: every member of the context or event outside
// the named ones is listed by name and type, so a member the framework adds is not lost. Values are
// metadata only (a string of at most 256 characters, a number, a boolean or null as is; anything else
// is reduced to its type and size or key names), so nothing but the event's own data is printed in full.
const MARKER = "CV14_FRAME ";
let counter = 0;

const CONTEXT_MEMBERS = new Set(["eventId", "timestamp", "eventType", "resource", "params", "authType", "authId"]);
const EVENT_MEMBERS = new Set([
  "id", "time", "type", "source", "subject", "specversion", "datacontenttype", "params", "authType", "authId", "data",
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
