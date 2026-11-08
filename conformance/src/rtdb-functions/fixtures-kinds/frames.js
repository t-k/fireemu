// Prints one typed frame per event on stdout (Cloud Logging carries it back to the recorder). Same
// projection as the breadth fixture, with three additions for the kinds recording:
//   - a snapshot carries the node's priority (`getPriority()`), because `val()` drops it;
//   - every string above 256 characters inside a value is reduced to its length, so a large write
//     never makes a log entry that Cloud Logging would truncate (the model reduces the same way);
//   - a 1st gen `auth` carries the value of each custom claim named `k9*` (an allow-listed prefix of
//     the claims the run sets on its own user), besides the token key names.
// Values outside a snapshot are metadata only (a string of at most 256 characters, a number, a boolean
// or null as is; anything else is reduced to its type and size or key names).
const MARKER = "G9_FRAME ";
const STRING_LIMIT = 256;
const CLAIM_PREFIX = "k9";
let counter = 0;

// Members named by the fixture; every other member of a context or an event is listed by name and type.
const CONTEXT_MEMBERS = new Set([
  "eventId",
  "timestamp",
  "eventType",
  "resource",
  "params",
  "authType",
  "authId",
  "auth",
]);
const EVENT_MEMBERS = new Set([
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

function describeMember(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string")
    return value.length <= STRING_LIMIT ? value : { type: "string", length: value.length };
  if (Array.isArray(value)) return { type: "array", length: value.length };
  if (typeof value === "object")
    return { type: "object", keys: Object.keys(value).sort().slice(0, 32) };
  return { type: typeof value };
}

function otherMembers(source, named) {
  const out = {};
  for (const key of Object.keys(source).sort()) {
    if (!named.has(key)) out[key] = describeMember(source[key]);
  }
  return out;
}

/** Strings above the limit become `{type: "string", length}`; the rest of a value is kept as is. */
function reduce(value) {
  if (typeof value === "string")
    return value.length <= STRING_LIMIT ? value : { type: "string", length: value.length };
  if (Array.isArray(value)) return value.map(reduce);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, reduce(item)]));
  return value;
}

function snapshot(value) {
  if (!value) return null;
  const exists = typeof value.exists === "function" ? value.exists() : null;
  return {
    exists,
    key: value.key ?? null,
    value: exists === false ? null : reduce(value.val()),
    priority:
      exists === false || typeof value.getPriority !== "function" ? null : value.getPriority(),
  };
}

function data(value) {
  if (!value) return null;
  if ("before" in value && "after" in value)
    return { before: snapshot(value.before), after: snapshot(value.after) };
  return snapshot(value);
}

function claims(token) {
  const out = {};
  for (const key of Object.keys(token ?? {}).sort())
    if (key.startsWith(CLAIM_PREFIX)) out[key] = describeMember(token[key]);
  return out;
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
    auth:
      "auth" in context
        ? context.auth == null
          ? null
          : {
              uid: context.auth.uid ?? null,
              tokenKeys: Object.keys(context.auth.token ?? {}).sort(),
              signInProvider: context.auth.token?.firebase?.sign_in_provider ?? null,
              emailVerified: context.auth.token?.email_verified ?? null,
              claims: claims(context.auth.token),
            }
        : undefined,
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
  console.log(
    `${MARKER}${JSON.stringify({ ...frame, seq: counter, receivedAt: new Date().toISOString() })}`,
  );
  return Promise.resolve();
}

module.exports = {
  MARKER,
  CONTEXT_MEMBERS,
  EVENT_MEMBERS,
  data,
  reduce,
  report,
  v1Context,
  v2Event,
};
