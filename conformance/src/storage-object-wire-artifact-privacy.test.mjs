import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createProductionWireAttempt } from "./storage-object/production-wire-capture.mjs";
import { createProductionCaptureProfile } from "./storage-object/production-capture-coverage.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const requestWire = Buffer.from("GET / HTTP/1.1\r\n\r\n");
const responseWire = Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}");
const url = "https://storage.googleapis.com/storage/v1/b/example.appspot.com/o/owned%2Fobject";
const cases = [
  ["request commitment", hash(requestWire), "create"],
  ["intent boundary", "HTTP_PLAINTEXT_COMMITMENT_AND_SANITIZED_BODY", "create"],
  ["response commitment", hash(responseWire), "finish"],
  ["result reason", "WIRE_TRUNCATED", "finish"],
  ["serialization newline", "\n", "create"],
];
function fixture(recording, secret, action, discovered = false) {
  const directory = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-wire-final-")));
  fs.chmodSync(directory, 0o700);
  const registry = createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  registry.register(discovered ? "SYNTHETIC_UNRELATED_CREDENTIAL" : secret);
  const responseBody = discovered
    ? Buffer.from(JSON.stringify({ name: "owned/object", downloadTokens: [secret] }))
    : Buffer.from("{}");
  const actualResponseWire = discovered
    ? Buffer.concat([
        Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"),
        responseBody,
      ])
    : responseWire;
  let attempt;
  const create = () => {
    attempt = createProductionWireAttempt({
      directory,
      sequence: 1,
      request: { url, method: "GET", headers: [], body: Buffer.alloc(0), wire: requestWire },
      metadata: { operationId: `r${recording}/p1/${"a".repeat(64)}`, phase: "subject" },
      policy: {
        secretRegistry: registry,
        captureProfile: createProductionCaptureProfile({
          kind: "storage",
          objectName: "owned/object",
          method: "GET",
          url,
          sessionPhase: null,
        }),
        expectedBucket: "example.appspot.com",
        expectedObjectNames: ["owned/object"],
      },
    });
    return attempt;
  };
  const finish = () => {
    attempt.appendResponse(actualResponseWire);
    attempt.finish({
      complete: secret !== "WIRE_TRUNCATED",
      reason: secret === "WIRE_TRUNCATED" ? "WIRE_TRUNCATED" : null,
      status: 200,
      finishConfirmed: true,
      socketReportedWrittenBytes: requestWire.length,
      requestReservedBytes: requestWire.length,
      responseObservedBytes: actualResponseWire.length,
      rawResponseHeaders: ["Content-Type", "application/json"],
      responseBodyBase64: responseBody.toString("base64"),
    });
  };
  try {
    action({ create, finish, directory, registry });
  } finally {
    if (attempt && !attempt.snapshot().closed) {
      try {
        finish();
      } catch {
        /* The fixed failure has already been observed by the test. */
      }
    }
    registry.close();
    fs.rmSync(directory, { recursive: true });
  }
}
for (const recording of [1, 2]) {
  for (const [label, secret, phase] of cases) {
    test(`recording ${recording} withholds a generated ${label} credential copy before persistence`, () => {
      fixture(recording, secret, ({ create, finish, directory, registry }) => {
        if (phase === "create") assert.throws(create, /production wire capture/);
        else {
          create();
          assert.throws(finish, /production wire capture/);
        }
        assert.equal(registry.snapshot().closed, true);
        for (const name of fs.readdirSync(directory)) {
          const saved = fs.readFileSync(join(directory, name), "utf8");
          assert.equal(
            saved.includes(secret),
            false,
            `${name} contains an unchecked credential copy`,
          );
        }
      });
    });
  }
  test(`recording ${recording} discovers a response credential before writing generated wire metadata`, () => {
    const secret = "sequence";
    fixture(
      recording,
      secret,
      ({ create, finish, directory, registry }) => {
        create();
        assert.throws(finish, /production wire capture/);
        for (const name of fs.readdirSync(directory))
          assert.equal(fs.readFileSync(join(directory, name), "utf8").includes(secret), false);
        assert.equal(registry.snapshot().closed, true);
      },
      true,
    );
  });
  test(`recording ${recording} retains safe wire commitments and complete persistence`, () => {
    fixture(recording, "SYNTHETIC_UNRELATED_CREDENTIAL", ({ create, finish, directory }) => {
      const attempt = create();
      finish();
      const request = JSON.parse(fs.readFileSync(attempt.files.request, "utf8"));
      const response = JSON.parse(fs.readFileSync(attempt.files.response, "utf8"));
      const result = JSON.parse(fs.readFileSync(attempt.files.result, "utf8"));
      assert.equal(request.requestWire.sha256, hash(requestWire));
      assert.equal(response.responseWire.sha256, hash(responseWire));
      assert.equal(result.complete, true);
      assert.equal(fs.readdirSync(directory).length, 4);
    });
  });
}
