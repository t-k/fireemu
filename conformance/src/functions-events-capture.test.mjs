import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, rm } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { createRequire } from "node:module";
import {
  CaptureSink,
  exportPublicFrames,
  publicEventTypes,
  publicHandlerNames,
} from "./functions-events/capture.mjs";

const require = createRequire(import.meta.url);
const { report } = require("../functions-events/fixtures/report.js");
const opened = [];

async function makeSink(options = {}) {
  const privateDir = await mkdtemp(join(tmpdir(), "fe-events-"));
  const sink = await CaptureSink.open({
    privateDir,
    allowedHandlers: ["fsCreatedV2"],
    ...options,
  });
  opened.push({ sink, privateDir });
  return sink;
}

function sendRaw(path, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path });
    let answer = "";
    socket.on("error", reject);
    socket.on("connect", () => socket.write(payload));
    socket.on("data", (chunk) => {
      answer += chunk.toString("utf8");
      if (answer.includes("\n")) {
        socket.end();
        resolve(JSON.parse(answer.trim()));
      }
    });
  });
}

afterEach(async () => {
  delete process.env.FE_EVENTS_CAPTURE_SOCKET;
  delete process.env.FE_EVENTS_CAPTURE_MODE;
  for (const { sink, privateDir } of opened.splice(0)) {
    await sink.close();
    await rm(privateDir, { recursive: true, force: true });
  }
});

const frame = (overrides = {}) => ({
  handler: "fsCreatedV2",
  generation: 2,
  source: "firestore",
  event: {
    id: "raw-event-id",
    time: "2026-09-27T00:00:00Z",
    type: "google.cloud.firestore.document.v1.created",
    source: "//firestore.googleapis.com/projects/demo-conformance/databases/(default)",
    subject: "documents/fe_events_primary/doc-1",
    data: { value: "alpha" },
  },
  ...overrides,
});

test("the fixture receives ack only after a private raw frame is persisted", async () => {
  const sink = await makeSink();
  process.env.FE_EVENTS_CAPTURE_SOCKET = sink.socketPath;
  process.env.FE_EVENTS_CAPTURE_MODE = "socket";
  await report(frame());
  const raw = await readFile(sink.rawPath, "utf8");
  assert.match(raw, /raw-event-id/);
  assert.equal((await stat(sink.rawPath)).mode & 0o777, 0o600);
  assert.equal((await stat(sink.privateDir)).mode & 0o777, 0o700);
  assert.deepEqual(
    sink.since(0).map((item) => item.sequence),
    [1],
  );
  assert.equal((await sink.barrier()).cursor, 1);
  assert.equal((await sink.barrier()).lossCount, 0);
});

test("unknown, malformed, and oversized frames are retained or marked as loss", async () => {
  const sink = await makeSink({ maxFrameBytes: 512 });
  const unknown = await sendRaw(
    sink.socketPath,
    `${JSON.stringify(frame({ handler: "unexpected" }))}\n`,
  );
  assert.equal(unknown.ok, false);
  assert.equal(sink.since(0).length, 1);
  assert.equal(sink.since(0)[0].frame.handler, "unexpected");
  const malformed = await sendRaw(sink.socketPath, "{bad-json}\n");
  assert.equal(malformed.ok, false);
  const oversized = await sendRaw(
    sink.socketPath,
    `${JSON.stringify(frame({ padding: "x".repeat(1000) }))}\n`,
  );
  assert.equal(oversized.ok, false);
  assert.equal((await sink.barrier()).lossCount, 2);
  assert.equal((await sink.barrier()).issueCount, 3);
});

test("frame count and aggregate byte limits stop capture without silent drops", async () => {
  const sink = await makeSink({ maxFrames: 1, maxRunBytes: 1000 });
  assert.deepEqual(await sendRaw(sink.socketPath, `${JSON.stringify(frame())}\n`), { ok: true });
  assert.equal((await sendRaw(sink.socketPath, `${JSON.stringify(frame())}\n`)).ok, false);
  assert.equal((await sink.barrier()).lossCount, 1);
  const limited = await makeSink({ maxRunBytes: 10 });
  assert.equal((await sendRaw(limited.socketPath, `${JSON.stringify(frame())}\n`)).ok, false);
  assert.equal((await limited.barrier()).lossCount, 1);
});

test("a frame arriving after a cursor barrier remains visible", async () => {
  const sink = await makeSink();
  const before = await sink.barrier();
  assert.equal(before.cursor, 0);
  assert.deepEqual(await sendRaw(sink.socketPath, `${JSON.stringify(frame())}\n`), { ok: true });
  assert.equal(sink.since(before.cursor).length, 1);
  assert.equal((await sink.barrier()).cursor, 1);
});

test("a public projection removes nested secrets and normalizes variable values", () => {
  const secretFrame = frame({
    event: {
      ...frame().event,
      id: "secret-id-token",
      time: "2026-09-27T12:34:56Z",
      data: { apiKey: "secret-api-key", nested: { idToken: "secret-id-token" } },
    },
  });
  const projected = exportPublicFrames([{ sequence: 1, frame: secretFrame }]);
  const text = JSON.stringify(projected);
  assert.doesNotMatch(text, /secret-id-token|secret-api-key|2026-09-27/);
  assert.deepEqual(projected[0], {
    sequence: 1,
    handler: "fsCreatedV2",
    generation: 2,
    source: "firestore",
    eventType: "google.cloud.firestore.document.v1.created",
    eventId: "<present>",
    eventTime: "<present>",
    resource: "<private>",
    payload: "<private>",
  });
});

test("a public projection rejects secrets placed in metadata fields", () => {
  const malicious = frame({
    handler: "token-in-handler",
    source: "key-in-source",
    generation: "token-in-generation",
    event: {
      ...frame().event,
      type: "token-in-event-type",
      id: "token-in-id",
      data: { opaque: "token-in-data" },
    },
  });
  const projected = exportPublicFrames([{ sequence: "token-in-sequence", frame: malicious }]);
  assert.doesNotMatch(JSON.stringify(projected), /token-in-|key-in-/);
  assert.equal(projected[0].handler, "<invalid>");
  assert.equal(projected[0].eventType, "<invalid>");
});

test("the public allowlists match every fixed handler and SDK event type", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../functions-events/programs.json", import.meta.url)),
  );
  const names = new Set(
    manifest.programs.flatMap((program) => Object.values(program.handlerExports)),
  );
  assert.deepEqual(publicHandlerNames, names);
  process.env.GCLOUD_PROJECT = "demo-conformance";
  const fixture = require("../functions-events/fixtures/index.js");
  const types = new Set(
    Object.values(fixture).map((handler) => handler.__endpoint.eventTrigger.eventType),
  );
  assert.deepEqual(publicEventTypes, types);
});
