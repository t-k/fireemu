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
  assert.equal(boundLogMessage("before\ud800after"), "before�after");
  assert.equal(boundLogMessage("before\udfffafter"), "before�after");
  assert.equal(boundLogMessage("before🚀after"), "before🚀after");
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
    target.log(
      JSON.stringify({
        severity: "WARNING",
        message: "structured warning",
        trace: "projects/demo/traces/abc",
        labels: { payment: "delayed", attempts: [1, 2] },
        metadata: { spoofed: true },
      }),
    );
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
      level: "warning",
      message: "structured warning",
      functionName: "alpha",
      invocationId: "inv-a",
      user: true,
      fields: {
        trace: "projects/demo/traces/abc",
        labels: { payment: "delayed", attempts: [1, 2] },
        metadata: { spoofed: true },
      },
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

test("structured logger severities and fields retain the production representation", () => {
  const emitted = [];
  const target = Object.fromEntries(
    ["log", "info", "debug", "warn", "error"].map((method) => [method, () => {}]),
  );
  const logger = createInvocationLogger((entry) => emitted.push(entry));
  const restore = logger.install(target);

  logger.run({ functionName: "audit", invocationId: "inv-severity" }, () => {
    for (const severity of [
      "DEBUG",
      "INFO",
      "NOTICE",
      "WARNING",
      "ERROR",
      "CRITICAL",
      "ALERT",
      "EMERGENCY",
    ]) {
      target.log(JSON.stringify({ severity, message: `${severity} message`, code: 47 }));
    }
    target.log(JSON.stringify({ severity: "EMERGENCY", audit: { committed: false } }));
  });
  restore();

  assert.deepEqual(
    emitted.slice(0, 8).map(({ level, message, fields }) => ({ level, message, fields })),
    ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"].map(
      (level) => ({ level, message: `${level.toUpperCase()} message`, fields: { code: 47 } }),
    ),
  );
  assert.deepEqual(emitted[8], {
    level: "emergency",
    message: "",
    functionName: "audit",
    invocationId: "inv-severity",
    user: true,
    fields: { audit: { committed: false } },
  });
});

test("non-structured and unsafe JSON stays bounded plain output", () => {
  const emitted = [];
  const target = Object.fromEntries(
    ["log", "info", "debug", "warn", "error"].map((method) => [method, () => {}]),
  );
  const logger = createInvocationLogger((entry) => emitted.push(entry));
  const restore = logger.install(target);

  logger.run({ functionName: "audit", invocationId: "inv-fallback" }, () => {
    target.log("plain\ud800value");
    target.log("multiple", "value\udfff");
    target.log('[{"severity":"WARNING"}]');
    target.log('{"severity":"DEFAULT","message":"unknown"}');
    target.log('{not-json');
    target.log('{"severity":"WARNING"}', "second argument");
    let nested = { value: true };
    for (let index = 0; index < 65; index += 1) nested = { nested };
    target.log(JSON.stringify({ severity: "WARNING", message: "too deep", nested }));
    target.log(
      JSON.stringify({ severity: "WARNING", message: "too large", detail: "x".repeat(300_000) }),
    );
    target.log('{"severity":"WARNING","message":"bad surrogate","value":"\\ud800"}');
    target.log('{"severity":"WARNING","message":"bad key","\\udfff":"value"}');
    target.log('{"severity":"NOTICE","message":"paired","value":"\\ud83d\\ude80"}');
  });
  restore();

  assert.deepEqual(
    emitted.slice(2, 6).map(({ level, fields }) => ({ level, fields })),
    [
      { level: "info", fields: undefined },
      { level: "info", fields: undefined },
      { level: "info", fields: undefined },
      { level: "info", fields: undefined },
    ],
  );
  assert.equal(emitted[0].message, "plain�value");
  assert.equal(emitted[1].message, "multiple value�");
  assert.equal(emitted[6].level, "info");
  assert.equal(emitted[6].fields, undefined);
  assert.equal(emitted[7].level, "info");
  assert.equal(emitted[7].fields, undefined);
  assert.ok(Buffer.byteLength(emitted[7].message, "utf8") <= 256 * 1024);
  assert.ok(emitted[7].message.endsWith("... [truncated]"));
  assert.equal(emitted[8].level, "info");
  assert.equal(emitted[8].fields, undefined);
  assert.equal(emitted[9].level, "info");
  assert.equal(emitted[9].fields, undefined);
  assert.equal(emitted[10].level, "notice");
  assert.deepEqual(emitted[10].fields, { value: "🚀" });
});
