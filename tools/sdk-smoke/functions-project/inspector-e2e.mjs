import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createConnection } from "node:net";

const inspectorPort = Number(process.argv[2]);
const control = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;
const functionsHost = process.env.FIREEMU_FUNCTIONS_HOST;
const project = process.env.GOOGLE_CLOUD_PROJECT;
const loggingHost = process.env.FIREBASE_LOGGING_EMULATOR_HOST;

assert.ok(Number.isInteger(inspectorPort), "the inspector port argument is required");
assert.ok(control, "FIREEMU_CONTROL_URL is required");
assert.ok(controlToken, "FIREEMU_CONTROL_TOKEN is required");
assert.ok(functionsHost, "FIREEMU_FUNCTIONS_HOST is required");
assert.ok(project, "GOOGLE_CLOUD_PROJECT is required");
assert.ok(loggingHost, "FIREBASE_LOGGING_EMULATOR_HOST is required");

async function loggingHistory() {
  const [host, port] = loggingHost.split(":");
  const socket = createConnection({ host, port: Number(port) });
  socket.setTimeout(5_000, () => socket.destroy(new Error("Logging WebSocket timed out")));
  const key = randomBytes(16).toString("base64");
  let buffer = Buffer.alloc(0);
  let upgraded = false;
  const frames = [];
  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!upgraded) {
        const end = buffer.indexOf("\r\n\r\n");
        if (end < 0) return;
        assert.match(buffer.subarray(0, end).toString("utf8"), /^HTTP\/1\.1 101 /);
        buffer = buffer.subarray(end + 4);
        upgraded = true;
        setTimeout(() => {
          socket.destroy();
          resolve(frames);
        }, 500);
      }
      while (buffer.length >= 2) {
        const lengthCode = buffer[1] & 0x7f;
        let offset = 2;
        let length = lengthCode;
        if (lengthCode === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          offset = 4;
        } else if (lengthCode === 127) {
          if (buffer.length < 10) return;
          length = Number(buffer.readBigUInt64BE(2));
          offset = 10;
        }
        if (buffer.length < offset + length) return;
        frames.push(JSON.parse(buffer.subarray(offset, offset + length).toString("utf8")));
        buffer = buffer.subarray(offset + length);
      }
    });
    socket.write(
      `GET / HTTP/1.1\r\nHost: ${loggingHost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
    );
  });
}

const signal = AbortSignal.timeout(10_000);
const targets = await fetch(`http://127.0.0.1:${inspectorPort}/json/list`, { signal });
assert.equal(targets.status, 200);
const targetList = await targets.json();
assert.ok(Array.isArray(targetList) && targetList.length > 0, "Node inspector has no targets");
assert.match(targetList[0].webSocketDebuggerUrl, /^ws:\/\/127\.0\.0\.1:/);

const controlHeaders = {
  authorization: `Bearer ${controlToken}`,
  "content-type": "application/json",
};
const runs = ["alpha", "beta"].map((name) =>
  fetch(`${control}sessions/default/functions/${name}:run`, {
    method: "POST",
    headers: controlHeaders,
    body: "{}",
    signal,
  }),
);
runs.push(
  fetch(`http://${functionsHost}/${project}/us-central1/http`, {
    method: "POST",
    signal,
  }),
);
// Debug mode disables the deployed function timeout so breakpoints do not kill the runtime.
runs.push(
  fetch(`http://${functionsHost}/${project}/us-central1/slowHttp`, {
    method: "POST",
    signal,
  }),
);
const responses = await Promise.all(runs);
for (const response of responses) assert.equal(response.status, 200);

const idle = await fetch(`${control}sessions/default:awaitIdle`, {
  method: "POST",
  headers: controlHeaders,
  body: JSON.stringify({ timeoutSeconds: 5 }),
  signal,
});
assert.equal(idle.status, 200);
const history = await loggingHistory();
assert.ok(history.length > 0, "Logging history is empty");
for (const frame of history) {
  assert.doesNotMatch(frame.message || "", /Debugger listening on ws:\/\//);
}
