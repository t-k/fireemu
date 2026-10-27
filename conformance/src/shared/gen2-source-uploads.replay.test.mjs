// Replay of the two `firebase deploy --debug` lines recorded in production by the stage 1 probe
// (2026-10-26, firebase-tools 15.28.2, project fireemu-oracle-query, region us-central1): the
// generateUploadUrl answer and the status of the upload's PUT. The recorded file is the probe's own
// lines-masked.txt with the project number replaced by the fixture number and the signed upload URL
// removed (the raw receipt line was 958 bytes with the URL, the PUT line 194 bytes with the real
// project number).

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { maskProbeLine } from "../../functions-http/upload-probe.mjs";
import {
  FAKE_BUCKET,
  FAKE_PROJECT_NUMBER,
  FAKE_REGION,
  SECRET_MARKER,
  createFakeGcs,
} from "./gen2-source-uploads.fake.mjs";
import {
  createReceiptScanner,
  openSourceUploads,
  redactUploadSecrets,
  uploadEventFromLine,
  uploadEventsFromCliOutput,
} from "./gen2-source-uploads.mjs";

const RECORDED = readFileSync(
  new URL("./fixtures/gen2-debug-lines.2026-10-26.txt", import.meta.url),
  "utf8",
);
const [RECEIPT_LINE, PUT_LINE] = RECORDED.trimEnd().split("\n");
const OBJECT = "514cacbe-3258-46fd-9a02-54b7485b11c1.zip";

test("the recorded generateUploadUrl line is a receipt for the derived bucket", () => {
  assert.deepEqual(uploadEventFromLine(RECEIPT_LINE), {
    type: "receipt",
    bucket: FAKE_BUCKET,
    object: OBJECT,
  });
});

test("the recorded PUT line is the 200 status of the same object", () => {
  assert.deepEqual(uploadEventFromLine(PUT_LINE), {
    type: "put-status",
    bucket: FAKE_BUCKET,
    object: OBJECT,
    status: 200,
  });
});

test("the recorded lines parse the same in a whole output and in a stream of any chunk size", () => {
  const output = [
    "i  functions: preparing",
    RECEIPT_LINE,
    "+  other",
    PUT_LINE,
    "+  Deploy complete!",
  ].join("\n");
  const expected = uploadEventsFromCliOutput(output);
  assert.equal(expected.length, 2);
  for (const size of [1, 7, 64, 500, 100_000]) {
    const seen = [];
    const scanner = createReceiptScanner((event) => seen.push(event));
    for (let i = 0; i < output.length; i += size) scanner.feed(output.slice(i, i + size));
    scanner.flush();
    assert.deepEqual(seen, expected, `chunk size ${size}`);
  }
});

test("with the real signed URL in the uploadUrl field the line still parses and is redacted", () => {
  const signed = `https://storage.googleapis.com/${FAKE_BUCKET}/${OBJECT}?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=${SECRET_MARKER}&X-Goog-Signature=${SECRET_MARKER}`;
  const real = RECEIPT_LINE.replace("[REDACTED UPLOAD URL]", signed);
  assert.deepEqual(uploadEventFromLine(real), uploadEventFromLine(RECEIPT_LINE));
  assert.ok(!redactUploadSecrets(real).includes(SECRET_MARKER));
  const masked = maskProbeLine(real, FAKE_PROJECT_NUMBER);
  assert.ok(!masked.includes(SECRET_MARKER));
  assert.equal(
    masked,
    RECEIPT_LINE,
    "masking a real-shaped line gives back the recorded fixture line",
  );
  assert.equal(maskProbeLine(PUT_LINE, FAKE_PROJECT_NUMBER), PUT_LINE);
});

test("a number of the real length is masked with the fixture number, whatever its length", () => {
  for (const number of ["1234567890123", "987654321098", "9876543210"]) {
    const line = RECEIPT_LINE.replaceAll(FAKE_PROJECT_NUMBER, number);
    assert.ok(line.includes(number));
    assert.equal(maskProbeLine(line, number), RECEIPT_LINE, number);
  }
});

test("replayed through the helper, the recorded forms give a confirmed create that is deleted by generation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gen2-replay-"));
  try {
    const world = createFakeGcs();
    const uploads = openSourceUploads({
      ledgerPath: join(dir, "l.jsonl"),
      runId: "run-replay",
      projectNumber: FAKE_PROJECT_NUMBER,
      region: FAKE_REGION,
      send: (method, url) => world.send(method, url),
      requestsLeft: () => 100,
    });
    const deploy = await uploads.beginDeploy("replay:http");
    world.put(OBJECT);
    const scanner = createReceiptScanner((event) => deploy.observe(event));
    scanner.feed(`${RECORDED}`);
    scanner.flush();
    const result = await deploy.finish({ cliExited: true, exitCode: 0 });
    assert.deepEqual(result.reasons, []);
    assert.ok(!world.objects.has(OBJECT));
    const deletes = world.requests.filter((request) => request.method === "DELETE");
    assert.equal(deletes.length, 1);
    assert.match(deletes[0].url, /ifGenerationMatch=\d+$/);
    const report = uploads.report();
    assert.equal(report.closureReady, true);
    assert.equal(report.a2Required, false, "a confirmed create needs no A2 read-back");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the recorded fixture checks its own privacy: the fixture number is its only long digit run and no credential marker is in it", () => {
  const longRuns = RECORDED.match(/\d{9,}/gu) ?? [];
  assert.ok(longRuns.length > 0);
  assert.ok(
    longRuns.every((run) => run === FAKE_PROJECT_NUMBER),
    `digit runs: ${longRuns.join(", ")}`,
  );
  for (const marker of [
    "X-Goog-",
    "Signature=",
    "GoogleAccessId",
    "ya29.",
    "AIza",
    "eyJ",
    "Bearer",
    "@",
  ]) {
    assert.ok(!RECORDED.includes(marker), marker);
  }
  const body = JSON.parse(RECEIPT_LINE.slice(RECEIPT_LINE.indexOf("{")));
  assert.equal(body.uploadUrl, "[REDACTED UPLOAD URL]");
  assert.deepEqual(Object.keys(body).toSorted(), ["storageSource", "uploadUrl"]);
  assert.deepEqual(Object.keys(body.storageSource).toSorted(), ["bucket", "object"]);
});
