import assert from "node:assert/strict";
import test from "node:test";
import {
  mkdtempSync,
  readFileSync,
  chmodSync,
  statSync,
  rmSync,
  symlinkSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPrivateWireAttempt } from "./storage-object/private-wire-capture.mjs";

const withDirectory = (fn) => {
  const directory = mkdtempSync(join(tmpdir(), "storage-wire-test-"));
  try {
    fn(directory);
  } finally {
    rmSync(directory, { recursive: true });
  }
};

test("exact private request/response bytes and receipts are exclusive and mode600", () =>
  withDirectory((directory) => {
    const request = Buffer.from(
      "GET /?key=synthetic-key HTTP/1.1\r\nAuthorization: Bearer synthetic-token\r\n\r\n",
    );
    const receipt = createPrivateWireAttempt({
      directory,
      sequence: 1,
      request,
      metadata: { operationId: "test/write" },
    });
    receipt.appendResponse(Buffer.from("HTTP/1.1 200 OK\r\n\r\n"));
    receipt.appendResponse(Buffer.from("synthetic-private-response"));
    receipt.finish({ status: 200, complete: true });
    assert.deepEqual(readFileSync(receipt.files.request), request);
    assert.equal(
      readFileSync(receipt.files.response, "utf8"),
      "HTTP/1.1 200 OK\r\n\r\nsynthetic-private-response",
    );
    assert.equal(JSON.parse(readFileSync(receipt.files.result)).status, 200);
    for (const file of Object.values(receipt.files))
      assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.throws(
      () => createPrivateWireAttempt({ directory, sequence: 1, request, metadata: {} }),
      /private wire capture/,
    );
    assert.deepEqual(readFileSync(receipt.files.request), request);
    assert.throws(() => receipt.appendResponse(Buffer.from("late")), /closed/);
  }));

test("world-readable and symlink directories reject before capture files", () =>
  withDirectory((directory) => {
    chmodSync(directory, 0o755);
    assert.throws(
      () =>
        createPrivateWireAttempt({
          directory,
          sequence: 1,
          request: Buffer.from("x"),
          metadata: {},
        }),
      /private wire capture/,
    );
    assert.deepEqual(readdirSync(directory), []);
    chmodSync(directory, 0o700);
    const link = join(directory, "link");
    symlinkSync(directory, link);
    assert.throws(
      () =>
        createPrivateWireAttempt({
          directory: link,
          sequence: 1,
          request: Buffer.from("x"),
          metadata: {},
        }),
      /private wire capture/,
    );
    assert.deepEqual(readdirSync(directory), ["link"]);
  }));

test("an unsuccessful attempt retains its raw prefix and fixed reason", () =>
  withDirectory((directory) => {
    const attempt = createPrivateWireAttempt({
      directory,
      sequence: 1,
      request: Buffer.from("x"),
      metadata: {},
    });
    attempt.appendResponse(Buffer.from("HTTP/1.1 200"));
    attempt.finish({ complete: false, reason: "WIRE_TRUNCATED", responseObservedBytes: 12 });
    assert.equal(readFileSync(attempt.files.response, "utf8"), "HTTP/1.1 200");
    assert.equal(JSON.parse(readFileSync(attempt.files.result)).reason, "WIRE_TRUNCATED");
  }));
