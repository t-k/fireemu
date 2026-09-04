import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createConnection } from "node:net";

const loggingHost = process.env.FIREBASE_LOGGING_EMULATOR_HOST;
const control = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;
assert.ok(loggingHost, "FIREBASE_LOGGING_EMULATOR_HOST is required");
assert.ok(control, "FIREEMU_CONTROL_URL is required");
assert.ok(controlToken, "FIREEMU_CONTROL_TOKEN is required");

const [host, portText] = loggingHost.split(":");
const port = Number(portText);
const frames = [];
const waiters = [];
let buffer = Buffer.alloc(0);
let upgraded = false;

function dispatch(value) {
  frames.push(value);
  for (let index = waiters.length - 1; index >= 0; index -= 1) {
    const waiter = waiters[index];
    if (waiter.predicate(value)) {
      waiters.splice(index, 1);
      waiter.resolve(value);
    }
  }
}

function parseFrames() {
  while (buffer.length >= 2) {
    const opcode = buffer[0] & 0x0f;
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
    const payload = buffer.subarray(offset, offset + length);
    buffer = buffer.subarray(offset + length);
    if (opcode === 1) dispatch(JSON.parse(payload.toString("utf8")));
  }
}

const socket = createConnection({ host, port });
socket.setTimeout(10_000, () => socket.destroy(new Error("Logging WebSocket timed out")));
const websocketKey = randomBytes(16).toString("base64");
const upgradedPromise = new Promise((resolve, reject) => {
  socket.once("error", reject);
  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    if (!upgraded) {
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return;
      const head = buffer.subarray(0, end).toString("utf8");
      assert.match(head, /^HTTP\/1\.1 101 /);
      const expectedAccept = createHash("sha1")
        .update(`${websocketKey}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
        .digest("base64");
      const acceptLine = head
        .split("\r\n")
        .find((line) => line.toLowerCase().startsWith("sec-websocket-accept:"));
      assert.equal(acceptLine?.split(":").slice(1).join(":").trim(), expectedAccept);
      buffer = buffer.subarray(end + 4);
      upgraded = true;
      resolve();
    }
    parseFrames();
  });
});

function waitFor(predicate) {
  const existing = frames.find(predicate);
  if (existing) return Promise.resolve(existing);
  return new Promise((resolve, reject) => waiters.push({ predicate, resolve, reject }));
}

let frameTimeout;
try {
  socket.write(
    `GET / HTTP/1.1\r\nHost: ${loggingHost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${websocketKey}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
  );
  await upgradedPromise;

  const headers = {
    authorization: `Bearer ${controlToken}`,
    "content-type": "application/json",
  };
  const controlSignal = AbortSignal.timeout(10_000);
  const [alphaRun, betaRun] = await Promise.all(
    ["alpha", "beta"].map((name) =>
      fetch(`${control}sessions/default/functions/${name}:run`, {
        method: "POST",
        headers,
        body: "{}",
        signal: controlSignal,
      }),
    ),
  );
  assert.equal(alphaRun.status, 200);
  assert.equal(betaRun.status, 200);
  const idle = await fetch(`${control}sessions/default:awaitIdle`, {
    method: "POST",
    headers,
    body: JSON.stringify({ timeoutSeconds: 5 }),
    signal: controlSignal,
  });
  assert.equal(idle.status, 200);

  frameTimeout = setTimeout(() => {
    const error = new Error("function log frames did not arrive within 10 seconds");
    for (const waiter of waiters.splice(0)) waiter.reject(error);
    socket.destroy(error);
  }, 10_000);

  const alphaFrame = await waitFor((frame) => frame.message.includes("alpha structured"));
  assert.equal(alphaFrame.level, "warn");
  assert.equal(alphaFrame.data.metadata.emulator.name, "functions");
  assert.equal(alphaFrame.data.metadata.function.name, "alpha");
  assert.equal(alphaFrame.data.metadata.type, "USER");

  const betaFrame = await waitFor((frame) => frame.message === "beta done");
  assert.equal(betaFrame.level, "info");
  assert.equal(betaFrame.data.metadata.emulator.name, "functions");
  assert.equal(betaFrame.data.metadata.function.name, "beta");
  assert.equal(betaFrame.data.metadata.type, "USER");
} finally {
  clearTimeout(frameTimeout);
  socket.destroy();
}
