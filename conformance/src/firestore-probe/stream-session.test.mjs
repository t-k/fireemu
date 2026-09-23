import assert from "node:assert/strict";
import { test } from "node:test";

import {
  projectStreamResponse,
  projectStreamStatus,
  terminalComplete,
  validateStreamRecipes,
  validateStreamTarget,
} from "./stream-session.mjs";

const recipes = [
  {
    id: "writes/write-stream-transaction",
    transport: "saved-reference",
    source: "spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json",
  },
  {
    id: "writes/write-stream-terminal/trailing-metadata",
    transport: "grpc",
    action: "invalid-empty-write-after-handshake",
    maxFrames: 2,
  },
  {
    id: "writes/write-stream-terminal/half-close",
    transport: "grpc",
    action: "half-close-after-handshake",
    maxFrames: 1,
  },
];

test("only the two fixed sandbox stream recipes are live", () => {
  assert.equal(validateStreamRecipes(recipes).live.length, 2);
  assert.throws(
    () => validateStreamRecipes([{ ...recipes[1], action: "write-arbitrary-document" }]),
    /unsupported stream recipe/,
  );
  assert.throws(
    () => validateStreamRecipes([{ ...recipes[1], maxFrames: 3 }]),
    /unsupported stream recipe/,
  );
});

test("a clean half-close completes on status plus end without a close event", () => {
  assert.equal(
    terminalComplete({
      status: { code: 0 },
      sawEnd: true,
      sawClose: false,
      sentFrames: 1,
      expectedFrames: 1,
    }),
    true,
  );
  assert.equal(
    terminalComplete({
      status: { code: 0 },
      sawEnd: false,
      sawClose: false,
      sentFrames: 1,
      expectedFrames: 1,
    }),
    false,
  );
  assert.equal(
    terminalComplete({
      status: { code: 0 },
      sawEnd: true,
      sawClose: false,
      sentFrames: 0,
      expectedFrames: 1,
    }),
    false,
  );
});

test("stream response projection records shape but no opaque stream credential", () => {
  const projected = projectStreamResponse({
    streamId: "opaque-id",
    streamToken: Buffer.from("secret-token"),
    writeResults: [],
  });
  assert.deepEqual(projected, {
    streamId: "nonempty-string",
    streamToken: "nonempty-bytes",
    writeResults: [],
  });
  assert.ok(!JSON.stringify(projected).includes("secret-token"));
});

test("gRPC status keeps duplicate and binary trailers without transport date", () => {
  const metadata = {
    getMap: () => ({
      date: "Wed, 23 Sep 2026 00:00:00 GMT",
      "grpc-status-details-bin": Buffer.from([0, 255]),
      "x-debug-tracking-id": "volatile-123;o=0",
    }),
    get: (key) =>
      key === "grpc-status-details-bin"
        ? [Buffer.from([0, 255]), Buffer.alloc(0)]
        : key === "x-debug-tracking-id"
          ? ["volatile-123;o=0"]
          : ["Wed, 23 Sep 2026 00:00:00 GMT"],
  };
  assert.deepEqual(projectStreamStatus({ code: 3, details: "invalid write", metadata }), {
    code: 3,
    details: "invalid write",
    trailers: [
      { key: "grpc-status-details-bin", kind: "binary", valueBase64: "AP8=" },
      { key: "grpc-status-details-bin", kind: "binary", valueBase64: "" },
      { key: "x-debug-tracking-id", kind: "ascii", value: "nonempty-volatile-id" },
    ],
  });
});

test("stream connection is fixed to the sandbox project and transport", () => {
  assert.deepEqual(
    validateStreamTarget({ target: "production", projectId: "fireemu-oracle-sbx" }),
    {
      host: "firestore.googleapis.com",
      port: 443,
      tls: true,
    },
  );
  assert.throws(
    () => validateStreamTarget({ target: "production", projectId: "fireemu-35fe6" }),
    /sandbox project/,
  );
  assert.throws(
    () =>
      validateStreamTarget({
        target: "local",
        projectId: "fireemu-oracle-sbx",
        host: "remote.example",
        port: 8080,
      }),
    /loopback/,
  );
});
