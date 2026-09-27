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
    readTime: value.readTime ?? null,
  };
}

function firestoreData(value) {
  if (!value) return null;
  if ("before" in value && "after" in value) {
    return { before: snapshot(value.before), after: snapshot(value.after) };
  }
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
  };
}

function v2Event(event, data) {
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
    data,
  };
}

function report(frame) {
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
