import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalWireTransport } from "./storage-object/local-wire-transport.mjs";

const pinned = { skip: process.version !== "v24.14.0" };
const make = (directory, delta = {}) =>
  createLocalWireTransport({
    origins: ["http://127.0.0.1:9999"],
    captureDirectory: directory,
    limits: {
      maxRequestBytes: 100000,
      maxResponseBytes: 100000,
      maxPerResponseWireBytes: 20000,
      responseReadUnitBytes: 8192,
    },
    onByteReserve: async () => {},
    ...delta,
  });
const request = { operationId: "test/write", accountingPhase: "subject" };

test(
  "close waits for a pending durable reservation and leaves no active dispatch",
  pinned,
  async () => {
    const directory = mkdtempSync(join(tmpdir(), "storage-wire-close-"));
    let release;
    const transport = make(directory, {
      onByteReserve: () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    });
    try {
      const sending = transport.fetch("http://127.0.0.1:9999/x", request);
      let closed = false;
      const closing = transport.close().then(() => {
        closed = true;
      });
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(closed, false);
      release();
      await assert.rejects(sending, /WIRE_ABORTED_BEFORE_DISPATCH/);
      await closing;
      assert.equal(transport.snapshot().busy, false);
      assert.equal(transport.snapshot().closed, true);
    } finally {
      release?.();
      await transport.close();
      rmSync(directory, { recursive: true });
    }
  },
);

test(
  "an insufficient next-response reservation creates no request capture or network socket",
  pinned,
  async () => {
    const directory = mkdtempSync(join(tmpdir(), "storage-wire-budget-"));
    let persisted = 0;
    const transport = make(directory, {
      limits: {
        maxRequestBytes: 10000,
        maxResponseBytes: 100,
        maxPerResponseWireBytes: 20000,
        responseReadUnitBytes: 8192,
      },
      onByteReserve: async () => persisted++,
    });
    try {
      await assert.rejects(
        transport.fetch("http://127.0.0.1:9999/x", request),
        /WIRE_RESPONSE_CAP_EXHAUSTED/,
      );
      assert.equal(persisted, 0);
      assert.deepEqual(readdirSync(directory), []);
      assert.equal(transport.snapshot().attempts, 0);
    } finally {
      await transport.close();
      rmSync(directory, { recursive: true });
    }
  },
);

test("durable callback errors cannot expose token-like error messages", pinned, async () => {
  const directory = mkdtempSync(join(tmpdir(), "storage-wire-error-"));
  const transport = make(directory, {
    onByteReserve: async () => {
      throw new Error("synthetic-secret-token");
    },
  });
  try {
    await assert.rejects(
      transport.fetch("http://127.0.0.1:9999/x", request),
      (error) => error.message === "WIRE_PREDISPATCH_OR_CAPTURE_FAILED",
    );
    assert.deepEqual(readdirSync(directory), []);
  } finally {
    await transport.close();
    rmSync(directory, { recursive: true });
  }
});

test(
  "the credential check runs after durable request capture and before socket creation",
  pinned,
  async () => {
    const directory = mkdtempSync(join(tmpdir(), "storage-wire-credential-"));
    const transport = make(directory);
    let checked = false;
    try {
      await assert.rejects(
        transport.fetch("http://127.0.0.1:9999/x", {
          ...request,
          headers: { authorization: "Firebase synthetic-private-token" },
          verifyBeforeDispatch: () => {
            checked = true;
            assert.match(
              readFileSync(join(directory, "000001-request.bin"), "utf8"),
              /synthetic-private-token/,
            );
            throw new Error("expired synthetic-private-token");
          },
        }),
        /WIRE_PREDISPATCH_REJECTED/,
      );
      assert.equal(checked, true);
      assert.equal(transport.snapshot().responseObservedBytes, 0);
      assert.equal(
        JSON.parse(readFileSync(join(directory, "000001-result.json"))).finishConfirmed,
        false,
      );
    } finally {
      await transport.close();
      rmSync(directory, { recursive: true });
    }
  },
);
