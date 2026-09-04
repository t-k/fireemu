import assert from "node:assert/strict";
import test from "node:test";

import { boundLogMessage, createInvocationLogger } from "./log-context.mjs";

test("log messages are truncated on UTF-8 boundaries", () => {
  const maxBytes = 32;
  const boundary = "a".repeat(maxBytes);
  assert.equal(boundLogMessage(boundary, maxBytes), boundary);

  const bounded = boundLogMessage(`prefix-${"界".repeat(32)}`, maxBytes);
  assert.ok(Buffer.byteLength(bounded, "utf8") <= maxBytes);
  assert.ok(bounded.endsWith("... [truncated]"));
  assert.ok(!bounded.includes("�"));
});

test("concurrent invocation logs retain their own function metadata", async () => {
  const emitted = [];
  const fallback = [];
  const target = {
    log: (...values) => fallback.push(["log", ...values]),
    info: (...values) => fallback.push(["info", ...values]),
    debug: (...values) => fallback.push(["debug", ...values]),
    warn: (...values) => fallback.push(["warn", ...values]),
    error: (...values) => fallback.push(["error", ...values]),
  };
  const logger = createInvocationLogger((entry) => emitted.push(entry));
  const restore = logger.install(target);

  target.log("startup", { ready: true });
  let releaseAlpha;
  let releaseBeta;
  const alphaGate = new Promise((resolve) => {
    releaseAlpha = resolve;
  });
  const betaGate = new Promise((resolve) => {
    releaseBeta = resolve;
  });
  const alpha = logger.run({ functionName: "alpha", invocationId: "inv-a" }, async () => {
    target.info("alpha", { step: 1 });
    target.log(JSON.stringify({ severity: "WARNING", message: "structured warning" }));
    target.log(JSON.stringify({ message: "cannot spoof system attribution" }));
    await alphaGate;
    target.error("alpha done");
  });
  const beta = logger.run({ functionName: "beta", invocationId: "inv-b" }, async () => {
    target.warn("beta start");
    await betaGate;
    target.log("beta", 2);
  });
  releaseBeta();
  await beta;
  releaseAlpha();
  await alpha;
  restore();

  assert.deepEqual(fallback, [["log", "startup", { ready: true }]]);
  assert.deepEqual(emitted, [
    {
      level: "info",
      message: "alpha { step: 1 }",
      functionName: "alpha",
      invocationId: "inv-a",
      user: true,
    },
    {
      level: "warn",
      message: '{"severity":"WARNING","message":"structured warning"}',
      functionName: "alpha",
      invocationId: "inv-a",
      user: true,
    },
    {
      level: "info",
      message: '{"message":"cannot spoof system attribution"}',
      functionName: "alpha",
      invocationId: "inv-a",
      user: true,
    },
    {
      level: "error",
      message: "beta start",
      functionName: "beta",
      invocationId: "inv-b",
      user: true,
    },
    {
      level: "info",
      message: "beta 2",
      functionName: "beta",
      invocationId: "inv-b",
      user: true,
    },
    {
      level: "error",
      message: "alpha done",
      functionName: "alpha",
      invocationId: "inv-a",
      user: true,
    },
  ]);
});
