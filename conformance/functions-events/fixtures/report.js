const net = require("node:net");

function snapshot(value) {
  if (!value) return null;
  return {
    exists: value.exists,
    id: value.id,
    path: value.ref?.path ?? null,
    data: value.exists ? value.data() : null,
    createTime: value.createTime ?? null,
    updateTime: value.updateTime ?? null,
  };
}

function firestoreData(value) {
  if (!value) return null;
  if ("before" in value && "after" in value) {
    return { before: snapshot(value.before), after: snapshot(value.after) };
  }
  return snapshot(value);
}

// The delivery probe (FE_EVENTS_CAPTURE_MODE=stdout) also lists which members the framework put on the
// context and the CloudEvent, so a member outside the named ones is not lost. Other capture modes keep
// their frame bytes. Values are metadata only: a string of at most 256 characters, a number, a boolean or
// null is printed as is; a longer string, an array or an object is reduced to its type and size or key
// names, so a token inside an object is never printed.
const CONTEXT_MEMBERS = new Set(["eventId", "timestamp", "eventType", "resource", "params", "authType", "authId"]);
const EVENT_MEMBERS = new Set([
  "id", "time", "type", "source", "subject", "specversion", "datacontenttype", "params", "authType", "authId", "data",
]);

function probeListing() {
  return process.env.FE_EVENTS_CAPTURE_MODE === "stdout";
}

function describeMember(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") {
    return value.length <= 256 ? value : { type: "string", length: value.length };
  }
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

function v1Context(context) {
  const printed = {
    eventId: context.eventId,
    timestamp: context.timestamp,
    eventType: context.eventType,
    resource: context.resource,
    params: context.params,
    authType: context.authType ?? null,
    authId: context.authId ?? null,
  };
  if (probeListing()) {
    printed.contextKeys = Object.keys(context).sort();
    printed.contextExtras = otherMembers(context, CONTEXT_MEMBERS);
  }
  return printed;
}

function v2Event(event, data) {
  const printed = {
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
    data,
  };
  if (probeListing()) {
    printed.eventKeys = Object.keys(event).sort();
    printed.extensionAttributes = otherMembers(event, EVENT_MEMBERS);
  }
  return printed;
}

function report(frame) {
  if (process.env.FE_EVENTS_CAPTURE_MODE === "reject-canary") {
    return Promise.reject(new Error("canary capture rejects events"));
  }
  const encoded = `${JSON.stringify(frame)}\n`;
  if (process.env.FE_EVENTS_CAPTURE_MODE === "stdout") {
    console.log(`FE_EVENTS_FRAME ${encoded.trimEnd()}`);
    return Promise.resolve();
  }
  const path = process.env.FE_EVENTS_CAPTURE_SOCKET;
  if (!path || process.env.FE_EVENTS_CAPTURE_MODE !== "socket") {
    return Promise.reject(new Error("event capture transport is not configured"));
  }
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path });
    let answered = false;
    let response = "";
    const fail = (error) => {
      if (answered) return;
      answered = true;
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(10_000, () => fail(new Error("event capture ack timed out")));
    socket.on("error", fail);
    socket.on("connect", () => socket.write(encoded));
    socket.on("data", (chunk) => {
      response += chunk.toString("utf8");
      if (response.length > 256) return fail(new Error("event capture ack exceeded limit"));
      if (!response.includes("\n")) return;
      if (response.trim() !== '{"ok":true}') {
        return fail(new Error("event capture rejected frame"));
      }
      answered = true;
      socket.end();
      resolve();
    });
    socket.on("end", () => {
      if (!answered) fail(new Error("event capture closed before ack"));
    });
  });
}

module.exports = { firestoreData, report, snapshot, v1Context, v2Event };
