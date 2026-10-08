import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { createHash } from "node:crypto";
import * as wModule from "./w.mjs";
import { spawnSync, execFileSync } from "node:child_process";
import {
  wManifest,
  wBody,
  wAcceptance,
  recordW,
  wAdmission,
  wCreateRefusal,
  W_A2_RULING,
} from "./w.mjs";
import { hProductionAnswer } from "./h-production.mjs";
import { readWJournal, main } from "./w-run.mjs";

const manifest = (stage = "w0", prerequisite) =>
  wManifest({
    project: "fireemu-oracle-events",
    runId: "adbcfeadbcfe",
    stage,
    prerequisite,
  });
const native = (status, body, host) => {
  const text = JSON.stringify(body, null, 2);
  const bytes = Buffer.from(
    `${host === "usage" ? text.replace(/[<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`) : text}\n`,
  );
  return { status, body, bodyBase64: bytes.toString("base64"), bodyBytes: bytes.length };
};
const corpus = ["stage-c-replay", "h1-preflight", "h-readiness", "h-lists", "v7-replay"].flatMap(
  (name) => JSON.parse(readFileSync(new URL(`./fixtures/h-fe/${name}.json`, import.meta.url))),
);
const template = (predicate) => structuredClone(corpus.find(predicate).body);

test("W family reaches every ladder point and adjacent bytes below the ceiling", () => {
  const m = manifest();
  for (const size of [65536, ...m.ladder, m.ceiling]) {
    const a = wBody(m, 1, size);
    assert.equal(Buffer.byteLength(a.raw), size);
    assert.equal(a.body.events.length, 100);
    assert.ok(a.anyBytes.every((n) => n < 450000));
    assert.equal(new Set(a.body.events.map((e) => e.id)).size, 100);
    assert.ok(a.body.events.every((e) => typeof JSON.parse(e.textData) === "string"));
    assert.equal(wBody(m, 2, size).requestBytes, a.requestBytes);
  }
  const a = wBody(m, 3, 65536),
    b = wBody(m, 3, 65536, 2);
  assert.deepEqual(JSON.parse(a.raw), JSON.parse(b.raw));
  assert.equal(b.httpBytes, a.httpBytes + 2);
  assert.equal(b.requestBytes, a.requestBytes);
  assert.throws(() => wBody(m, 1, m.ceiling + 1), /ceiling/);
  assert.throws(() => wBody(m, 1, m.ceiling, 1), /ceiling/);
  assert.throws(() => wBody(m, 21, 65536), /recipe/);
  assert.throws(
    () => wBody({ ...m, ceiling: 60 * 1024 * 1024 }, 1, 45 * 1024 * 1024),
    /individual Any/,
  );
});

test("W accepts native recorded-layout 400 and 413 refusals without guessing message wording", () => {
  const spec = {
    host: "publishing",
    method: "POST",
    path: `/v1/${manifest().channel}:publishEvents`,
  };
  const refusals = corpus.filter(
    (r) =>
      r.status === 400 &&
      ["No events provided.", "Too many events."].includes(r.body.error?.message),
  );
  assert.ok(refusals.length > 0);
  for (const row of refusals) {
    assert.equal(wAcceptance(row, spec), false);
    for (const status of [400, 413]) {
      const body = structuredClone(row.body);
      body.error.code = status;
      body.error.status = status === 413 ? "RESOURCE_EXHAUSTED" : "INVALID_ARGUMENT";
      body.error.message = "Payload rejected by the service.";
      body.error.details[0].fieldViolations[0].description = "Observed service detail.";
      assert.equal(wAcceptance(native(status, body), spec), false);
      const answer = native(status, body);
      const badLayout = {
        ...answer,
        bodyBase64: Buffer.from(
          Buffer.from(answer.bodyBase64, "base64").toString().replace("  ", "\t "),
        ).toString("base64"),
      };
      assert.equal(wAcceptance(badLayout, spec), null);
      assert.equal(wAcceptance({ ...answer, bodyBytes: 1 }, spec), null);
      assert.equal(wAcceptance({ ...answer, headers: { "content-length": "1" } }, spec), null);
      assert.equal(wAcceptance({ ...answer, bodySha256: "0".repeat(64) }, spec), null);
      assert.equal(wAcceptance({ ...answer, unknown: true }, spec), null);
      assert.equal(wAcceptance(answer, { ...spec, host: "eventarc" }), null);
      assert.equal(wAcceptance(answer, { ...spec, method: "GET" }), null);
      assert.equal(wAcceptance(answer, { ...spec, path: "/v1/foreign:publishEvents" }), null);
      for (const edit of [
        (b) => {
          b.error.code = 429;
        },
        (b) => {
          delete b.error.details;
        },
        (b) => {
          b.error.details[0]["@type"] = "foreign";
        },
        (b) => {
          b.error.details[0].fieldViolations[0].field = "events[0]";
        },
        (b) => {
          b.error.message = 1;
        },
        (b) => {
          b.extra = true;
        },
      ]) {
        const changed = structuredClone(body);
        edit(changed);
        assert.equal(wAcceptance(native(status, changed), spec), null);
      }
      for (const rejected of [200, 403, 429, 503])
        assert.equal(wAcceptance(native(rejected, body), spec), null);
    }
  }
  assert.equal(wAcceptance(native(413, { raw: "<html>too large</html>" }), spec), null);
  assert.equal(wAcceptance(native(200, {}), spec), true);
  assert.equal(wAcceptance({ ...native(200, {}), bodyBytes: 2 }, spec), null);
});

// Original W0 capture line 16: the public-safe native response has no details field.
const nativeSizeRefusal = {
  error: {
    code: 400,
    message: "Request payload size exceeds the limit: 10485760 bytes.",
    status: "INVALID_ARGUMENT",
  },
};

test("W recognizes the exact W0 native size refusal and base64-parts fallback", () => {
  const spec = {
    host: "publishing",
    method: "POST",
    path: `/v1/${manifest().channel}:publishEvents`,
  };
  const answer = native(400, nativeSizeRefusal);
  const bytes = Buffer.from(answer.bodyBase64, "base64");
  const bodySha256 = createHash("sha256").update(bytes).digest("hex");
  assert.equal(answer.bodyBytes, 145);
  assert.equal(bodySha256, "81e20f3b3dd1632f2778afb47bf7ebb6b03be6d6ef17fc938312dab8e8ca8d5d");
  answer.bodySha256 = bodySha256;
  answer.headers = { "content-length": "145" };
  assert.equal(wAcceptance(answer, spec), false);
  const { bodyBase64, ...parts } = answer;
  assert.equal(
    wAcceptance(
      { ...parts, bodyBase64Parts: [bodyBase64.slice(0, 20), bodyBase64.slice(20)] },
      spec,
    ),
    false,
  );
});

test("W native size refusal rejects scope, status, envelope and native-byte near misses", () => {
  const spec = {
    host: "publishing",
    method: "POST",
    path: `/v1/${manifest().channel}:publishEvents`,
  };
  const answer = native(400, nativeSizeRefusal);
  assert.equal(wAcceptance(native(413, nativeSizeRefusal), spec), null);
  for (const changed of [
    { ...spec, host: "eventarc" },
    { ...spec, method: "GET" },
    { ...spec, path: spec.path.replace("fireemu-oracle-events", "foreign") },
    { ...spec, path: spec.path.replace("us-central1", "us-east1") },
    { ...spec, path: spec.path.replace("-w:", "-foreign:") },
  ])
    assert.equal(wAcceptance(answer, changed), null, JSON.stringify(changed));
  for (const status of [199, 200, 302, 400, 403, 413, 429, 503]) {
    const body = structuredClone(nativeSizeRefusal);
    if (status === 400) body.error.code = "400";
    else body.error.code = status;
    assert.equal(wAcceptance(native(status, body), spec), null, String(status));
  }
  const bodies = [
    null,
    {},
    { error: null },
    { error: { ...nativeSizeRefusal.error, code: 413 } },
    { error: { ...nativeSizeRefusal.error, status: "RESOURCE_EXHAUSTED" } },
    { error: { ...nativeSizeRefusal.error, status: null } },
    { error: { ...nativeSizeRefusal.error, message: 10485760 } },
    { ...nativeSizeRefusal, extra: true },
    { error: { ...nativeSizeRefusal.error, extra: true } },
    { error: { ...nativeSizeRefusal.error, details: null } },
    { error: { ...nativeSizeRefusal.error, details: [] } },
    { error: { status: "INVALID_ARGUMENT", code: 400, message: nativeSizeRefusal.error.message } },
  ];
  for (const message of [
    "Payload rejected by the service.",
    "Too many events.",
    "Quota exceeded.",
    "Permission denied.",
    "Event payload size exceeds the limit: 10485760 bytes.",
    "Request payload size exceeds the limit: 10485761 bytes.",
    "Request payload size exceeds the limit: 10485760 bytes",
    `${nativeSizeRefusal.error.message} Retry later.`,
  ])
    bodies.push({ error: { ...nativeSizeRefusal.error, message } });
  for (const body of bodies)
    assert.equal(wAcceptance(native(400, body), spec), null, JSON.stringify(body));
  const raw = Buffer.from(answer.bodyBase64, "base64").toString();
  const wrongRaw = (text) => {
    const bytes = Buffer.from(text);
    return {
      ...answer,
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
      headers: { "content-length": String(bytes.length) },
      bodySha256: createHash("sha256").update(bytes).digest("hex"),
    };
  };
  for (const changed of [
    { ...answer, unknown: true },
    { ...answer, bodyBytes: 144 },
    { ...answer, headers: { "content-length": "144" } },
    { ...answer, bodySha256: "0".repeat(64) },
    wrongRaw(JSON.stringify(answer.body)),
    wrongRaw(raw.replace(/  /g, "\t")),
    wrongRaw(raw.slice(0, -1)),
    wrongRaw(raw.replace("10485760", "10485761")),
  ])
    assert.equal(wAcceptance(changed, spec), null);
});

test("W native size refusal admits only the recorded literal across generated near misses", () => {
  const spec = {
    host: "publishing",
    method: "POST",
    path: `/v1/${manifest().channel}:publishEvents`,
  };
  const message = nativeSizeRefusal.error.message;
  for (let i = 0; i <= message.length; i++) {
    for (const suffix of ["0", "x", " ", "\n"]) {
      const changed = message.slice(0, i) + suffix + message.slice(i);
      const body = { error: { ...nativeSizeRefusal.error, message: changed } };
      assert.equal(wAcceptance(native(400, body), spec), null, JSON.stringify(changed));
    }
    if (i < message.length) {
      const changed = message.slice(0, i) + message.slice(i + 1);
      const body = { error: { ...nativeSizeRefusal.error, message: changed } };
      assert.equal(wAcceptance(native(400, body), spec), null, JSON.stringify(changed));
    }
  }
  for (let i = 0; i < 128; i++) {
    const body = { error: { ...nativeSizeRefusal.error, [`extra${i}`]: i } };
    assert.equal(wAcceptance(native(400, body), spec), null);
    body.error = { ...nativeSizeRefusal.error, code: 399 - i };
    assert.equal(wAcceptance(native(400, body), spec), null);
    body.error = { ...nativeSizeRefusal.error, status: `INVALID_ARGUMENT${i}` };
    assert.equal(wAcceptance(native(400, body), spec), null);
  }
});

// W0 3ba6db4cb8e0 capture n17 reports an opaque internal measurement, not recipe bytes.
const requestSizeRefusal = {
  error: {
    code: 400,
    message:
      "The value for request_size is too large. You passed 10476337 in the request, but the maximum value is 10000000.",
    status: "INVALID_ARGUMENT",
  },
};

test("W request_size recognizes the actual n17 native refusal without equating its metric to recipe bytes", () => {
  const m = wManifest({ project: "fireemu-oracle-events", runId: "3ba6db4cb8e0", stage: "w0" });
  const spec = { host: "publishing", method: "POST", path: `/v1/${m.channel}:publishEvents` };
  const answer = native(400, requestSizeRefusal);
  answer.bodySha256 = createHash("sha256")
    .update(Buffer.from(answer.bodyBase64, "base64"))
    .digest("hex");
  answer.headers = { "content-length": "201" };
  assert.equal(answer.bodyBytes, 201);
  assert.equal(
    answer.bodySha256,
    "35a2305226a86caf533f4cf9d22b06b89043ffa257985eec70615a6d464b0782",
  );
  const recipe = wBody(m, 8, 10485760);
  assert.equal(recipe.httpBytes, 10485760);
  assert.equal(recipe.requestBytes, 10475028);
  assert.notEqual(10476337, recipe.httpBytes);
  assert.notEqual(10476337, recipe.requestBytes);
  assert.equal(wAcceptance(answer, spec), false);
});

test("W request_size bounds the observed grammar and rejects envelope, scope and raw near misses", () => {
  const spec = {
    host: "publishing",
    method: "POST",
    path: `/v1/${manifest().channel}:publishEvents`,
  };
  const withMessage = (message) => ({ error: { ...requestSizeRefusal.error, message } });
  const message = (passed) =>
    `The value for request_size is too large. You passed ${passed} in the request, but the maximum value is 10000000.`;
  // These parser examples are synthetic; only 10476337 has production evidence.
  for (const passed of [10000001, 10476337, 12345678, 99999999])
    assert.equal(
      wAcceptance(native(400, withMessage(message(passed))), spec),
      false,
      String(passed),
    );
  for (let i = 1; i <= 32; i++) {
    const passed = 10000000 + i * 271829;
    assert.equal(wAcceptance(native(400, withMessage(message(passed))), spec), false);
    for (const malformed of [`0${passed}`, `${passed}.0`, `+${passed}`, `${passed}x`])
      assert.equal(wAcceptance(native(400, withMessage(message(malformed))), spec), null);
  }
  for (const passed of [
    "0",
    "9999999",
    "10000000",
    "010476337",
    "100000000",
    "+10476337",
    "-10476337",
    "1.0476337e7",
    "10476337.0",
    "10476337 ",
  ])
    assert.equal(wAcceptance(native(400, withMessage(message(passed))), spec), null, passed);
  for (const changed of [
    message(10476337).replace("request_size", "events_size"),
    message(10476337).replace("The value for request_size is too large.", "Payload rejected."),
    message(10476337).replace("request_size", "event_size"),
    message(10476337).replace("10000000.", "10000001."),
    message(10476337).replace("10000000.", "9999999."),
    message(10476337).slice(0, -1),
    `${message(10476337)} Retry later.`,
    `${message(10476337)}\n`,
    "The value for request_size is too large.",
    "Payload rejected by the service.",
  ])
    assert.equal(wAcceptance(native(400, withMessage(changed)), spec), null, changed);
  const answer = native(400, requestSizeRefusal);
  for (const status of [200, 404, 413, 429, 500, 503])
    assert.equal(wAcceptance(native(status, requestSizeRefusal), spec), null, String(status));
  for (const changed of [
    { ...spec, host: "eventarc" },
    { ...spec, method: "GET" },
    { ...spec, path: "/v1/foreign:publishEvents" },
  ])
    assert.equal(wAcceptance(answer, changed), null);
  for (const body of [
    { error: { ...requestSizeRefusal.error, code: "400" } },
    { error: { ...requestSizeRefusal.error, code: 413 } },
    { error: { ...requestSizeRefusal.error, status: "RESOURCE_EXHAUSTED" } },
    { error: { ...requestSizeRefusal.error, message: null } },
    { error: { ...requestSizeRefusal.error, message: [requestSizeRefusal.error.message] } },
    { ...requestSizeRefusal, extra: true },
    { error: { ...requestSizeRefusal.error, extra: true } },
    ...[null, [], [{}]].map((details) => ({ error: { ...requestSizeRefusal.error, details } })),
    { error: { status: "INVALID_ARGUMENT", code: 400, message: requestSizeRefusal.error.message } },
  ])
    assert.equal(wAcceptance(native(400, body), spec), null, JSON.stringify(body));
  const raw = Buffer.from(answer.bodyBase64, "base64").toString();
  const rawAnswer = (text) => {
    const bytes = Buffer.from(text);
    return {
      ...answer,
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
      bodySha256: createHash("sha256").update(bytes).digest("hex"),
      headers: { "content-length": String(bytes.length) },
    };
  };
  for (const changed of [
    { ...answer, unknown: true },
    { ...answer, bodyBytes: 200 },
    { ...answer, headers: { "content-length": "200" } },
    { ...answer, bodySha256: "0".repeat(64) },
    rawAnswer(JSON.stringify(answer.body)),
    rawAnswer(raw.replace(/  /g, "\t")),
    rawAnswer(raw.slice(0, -1)),
    rawAnswer(raw.replace("10476337", "10476338")),
  ])
    assert.equal(wAcceptance(changed, spec), null);
});

// Resource answers use recorded bodies and the real production judge; only instance values change.
async function replay(stage = "w0", mode = "normal", prerequisite, defer = false, createReply) {
  const m = manifest(stage, prerequisite),
    calls = [],
    notes = [];
  const resourceMode = mode
    .replace(/^(shape|upper)-/, "")
    .replace(/^badrequest-(400|413)-(arbitrary|numeric|payload)-/, "");
  let clock = 0,
    present = false,
    topicPresent = false;
  const topic = `projects/${m.project}/topics/w-managed`,
    operations = new Map();
  const operation = (action) => {
    const body = template((r) => r.sequence === (action === "create" ? 4 : 11) && r.path);
    body.name = `${m.parent}/operations/w-${action}`;
    body.metadata.target = m.channel;
    operations.set(body.name, { action, body });
    return body;
  };
  const transports = Object.fromEntries(
    ["usage", "eventarc", "pubsub", "publishing"].map((host) => [
      host,
      {
        request: async (spec) => {
          calls.push({ host, ...spec });
          let status = 200,
            body;
          if (host === "publishing") {
            if (mode.startsWith("upper-")) {
              if (spec.recipe.purpose.endsWith("control"))
                return mode === `upper-${spec.recipe.purpose}-refused`
                  ? native(400, nativeSizeRefusal)
                  : native(200, {});
              const generic = /^upper-badrequest-(400|413)-(arbitrary|numeric|payload)(?:-|$)/.exec(
                mode,
              );
              if (generic) {
                const refusal = template(
                  (r) => r.status === 400 && r.body.error?.message === "No events provided.",
                );
                refusal.error.code = Number(generic[1]);
                refusal.error.status =
                  generic[1] === "400" ? "INVALID_ARGUMENT" : "RESOURCE_EXHAUSTED";
                refusal.error.message =
                  generic[2] === "numeric"
                    ? requestSizeRefusal.error.message
                    : generic[2] === "payload"
                      ? nativeSizeRefusal.error.message
                      : "Payload rejected by the service.";
                refusal.error.details[0].fieldViolations[0].description = refusal.error.message;
                return native(Number(generic[1]), refusal);
              }
              if (mode === "upper-unknown") return { unknown: true, status: 503, body: {} };
              if (mode === "upper-unclassified")
                return native(418, { error: { message: "unclassified" } });
              return native(400, nativeSizeRefusal);
            }
            if (mode.startsWith("shape")) {
              if (mode === "shape-unknown" && spec.recipe.purpose === "T0")
                return { unknown: true, status: 503, body: {} };
              if (spec.recipe.purpose.endsWith("control"))
                return mode === `shape-${spec.recipe.purpose}-refused`
                  ? native(400, nativeSizeRefusal)
                  : native(200, {});
              if (mode === "shape-counter-success") return native(200, {});
              if (mode === "shape-unmeasured") return native(400, nativeSizeRefusal);
              const generic = /^shape-detailed-(400|413)-(1000000[01])$/.exec(mode);
              if (generic) {
                const refusal = template(
                  (r) => r.status === 400 && r.body.error?.message === "No events provided.",
                );
                refusal.error.code = Number(generic[1]);
                refusal.error.status =
                  generic[1] === "400" ? "INVALID_ARGUMENT" : "RESOURCE_EXHAUSTED";
                refusal.error.message = `The value for request_size is too large. You passed ${generic[2]} in the request, but the maximum value is 10000000.`;
                refusal.error.details[0].fieldViolations[0].description = refusal.error.message;
                return native(Number(generic[1]), refusal);
              }
              if (mode === "shape-detail-free-boundary")
                return native(400, {
                  error: {
                    code: 400,
                    message:
                      "The value for request_size is too large. You passed 10000000 in the request, but the maximum value is 10000000.",
                    status: "INVALID_ARGUMENT",
                  },
                });
              return native(400, {
                error: {
                  code: 400,
                  message: `The value for request_size is too large. You passed ${shapeWire(spec.body.events, topic).pubsub.length + (mode === "shape-mismatch" ? 1 : 0)} in the request, but the maximum value is 10000000.`,
                  status: "INVALID_ARGUMENT",
                },
              });
            }
            if (mode === "unknown-publish") return { unknown: true, status: 503, body: {} };
            const size = Buffer.byteLength(spec.rawBody);
            const accepted =
              mode === "all-accepted" ||
              (mode === "logical" ? spec.recipe.httpBytes - spec.recipe.whitespace : size) <=
                (mode === "native-size" || mode === "request-size" ? 10485760 : 1500000);
            if (accepted) body = {};
            else {
              status = 400;
              body = template(
                (r) => r.status === 400 && r.body.error?.message === "No events provided.",
              );
              body.error.message = "Payload rejected by the service.";
              body.error.details[0].fieldViolations[0].description = body.error.message;
              if (mode === "native-size") body = structuredClone(nativeSizeRefusal);
              // A synthetic threshold and opaque variable measurement exercise mixed refusal families.
              if (mode === "request-size") {
                body = structuredClone(size > 12582912 ? nativeSizeRefusal : requestSizeRefusal);
                if (size <= 12582912)
                  body.error.message = body.error.message.replace(
                    "10476337",
                    String(10000000 + size - 10485760),
                  );
              }
            }
          } else if (host === "usage") {
            body = template(
              (r) =>
                Array.isArray(r.body.services) &&
                r.body.services.some((s) => s.config?.name === "eventarcpublishing.googleapis.com"),
            );
            if (resourceMode === "api-disabled")
              body.services = body.services.filter(
                (s) => s.config.name !== "eventarcpublishing.googleapis.com",
              );
          } else if (spec.path.includes("/topics?"))
            body = topicPresent ? { topics: [{ name: topic }] } : {};
          else if (spec.path.endsWith("/triggers"))
            body =
              resourceMode === "dependent" && present
                ? { triggers: [{ name: `${m.parent}/triggers/foreign`, channel: m.channel }] }
                : {};
          else if (spec.path.includes("/operations/")) {
            const own = operations.get(spec.path.slice(4));
            if (resourceMode === "pending-delete" && own.action === "delete") {
              body = template((r) => r.case === "channel-operation-not-done");
              body.name = own.body.name;
              body.metadata.target = m.channel;
            } else {
              body = template((r) => r.sequence === 13 && r.path);
              body.name = own.body.name;
              body.metadata.target = m.channel;
              body.metadata.verb = own.action;
              if (own.action === "delete") {
                present = false;
                topicPresent = resourceMode === "topic-left";
              }
              if (resourceMode === "wrong-target") body.metadata.target += "-foreign";
            }
          } else if (spec.method === "POST") {
            if (createReply) return structuredClone(createReply);
            present = true;
            topicPresent = true;
            if (resourceMode === "unknown-create") return { unknown: true, status: 503, body: {} };
            body = operation("create");
          } else if (spec.method === "DELETE") {
            if (resourceMode === "unknown-delete") return { unknown: true, status: 503, body: {} };
            body = operation("delete");
          } else if (present && resourceMode !== "unknown-create") {
            body = template(
              (r) =>
                r.status === 200 &&
                r.method === "GET" &&
                (r.path ?? r.url).includes("/channels/") &&
                r.body.pubsubTopic,
            );
            body.name = m.channel;
            body.pubsubTopic = topic;
          } else {
            status = 404;
            body = template(
              (r) =>
                r.status === 404 && r.method === "GET" && (r.path ?? r.url).includes("/channels/"),
            );
          }
          const answer = native(status, body, host);
          if (host !== "publishing")
            assert.equal(
              hProductionAnswer(answer, { ...spec, host }),
              true,
              `${host} ${spec.method} ${spec.path}`,
            );
          return answer;
        },
      },
    ]),
  );
  if (defer) return { transports, calls };
  const result = await recordW({
    manifest: m,
    transports,
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    note: (kind, value) => notes.push({ kind, value: structuredClone(value) }),
  });
  return { result, calls, notes };
}

test("W0 discovers an interval through real resource judges and cleans its exact channel", async () => {
  const { result, calls } = await replay();
  assert.equal(result.stopped, null);
  assert.equal(result.cleanupReady, true);
  assert.ok(result.boundary.refused - result.boundary.accepted <= 4096);
  assert.equal(calls.filter((c) => c.method === "DELETE").length, 1);
  assert.ok(result.counts.publish <= 20);
  assert.equal(result.publishes[0].accepted, true);
  assert.equal(result.evidenceComplete, true);
  for (const p of result.publishes.filter((item) => item.accepted === false))
    assert.equal(p.observation, "Payload rejected by the service.");
  for (const call of calls)
    assert.equal(
      call.timeoutMs,
      30_000 + Math.ceil(((call.recipe?.httpBytes ?? 0) * 8 * 1000) / 2_000_000),
    );
});

// Independent byte encoders follow the public CloudEvent and Pub/Sub field numbers.
function shapeWire(events, topic, channel = manifest().channel) {
  const varint = (value) => {
    const bytes = [];
    do {
      bytes.push((value % 128) | (value >= 128 ? 128 : 0));
      value = Math.floor(value / 128);
    } while (value);
    return Buffer.from(bytes);
  };
  const field = (tag, bytes) => {
    bytes = Buffer.from(bytes);
    return Buffer.concat([varint(tag * 8 + 2), varint(bytes.length), bytes]);
  };
  const ce = [field(1, channel)],
    pubsub = [field(1, topic)],
    anyBytes = [];
  for (const event of events) {
    const encoded = [
      field(1, event.id),
      field(2, event.source),
      field(3, event.specVersion),
      field(4, event.type),
    ];
    const attributes = {
      "ce-id": event.id,
      "ce-source": event.source,
      "ce-specversion": event.specVersion,
      "ce-type": event.type,
    };
    for (const [key, value] of Object.entries(event.attributes)) {
      let inner, text;
      if (value.ceString !== undefined) {
        inner = field(3, value.ceString);
        text = value.ceString;
      } else if (value.ceInteger !== undefined) {
        inner = Buffer.concat([varint(2 * 8), varint(value.ceInteger)]);
        text = String(value.ceInteger);
      } else {
        const seconds = Date.parse(value.ceTimestamp) / 1000;
        inner = field(7, seconds ? Buffer.concat([varint(8), varint(seconds)]) : Buffer.alloc(0));
        text = value.ceTimestamp;
      }
      encoded.push(field(5, Buffer.concat([field(1, key), field(2, inner)])));
      attributes[`ce-${key}`] = text;
    }
    encoded.push(field(7, event.textData));
    const any = Buffer.concat([field(1, event["@type"]), field(2, Buffer.concat(encoded))]);
    anyBytes.push(any.length);
    ce.push(field(2, any));
    const message = [field(1, event.textData)];
    for (const [key, value] of Object.entries(attributes))
      message.push(field(2, Buffer.concat([field(1, key), field(2, value)])));
    pubsub.push(field(2, Buffer.concat(message)));
  }
  return { ce: Buffer.concat(ce), pubsub: Buffer.concat(pubsub), anyBytes };
}

test("W shape fixes three public-safe recipes and reconstructs their exact byte metrics", () => {
  const m = manifest("w-shape");
  assert.deepEqual(m.limits, { preflight: 16, setup: 12, publish: 5, cleanup: 38 });
  const topic = `projects/${m.project}/topics/${"t".repeat(49)}`;
  assert.equal(Buffer.byteLength(topic), 87);
  for (const [index, shape] of ["N99", "T0", "I0"].entries()) {
    const built = wModule.wShapeBody(m, index + 2, shape, topic);
    const wire = shapeWire(built.body.events, topic);
    assert.equal(wire.ce.length, 10081812);
    assert.equal(built.requestBytes, wire.ce.length);
    assert.equal(built.predictedRequestSize, wire.pubsub.length);
    assert.equal(built.predictedRequestSize, [10083108, 10083721, 10083321][index]);
    assert.deepEqual(built.anyBytes, wire.anyBytes);
    assert.ok(built.anyBytes.every((n) => n < 450000));
    assert.ok(built.httpBytes <= m.ceiling);
    assert.equal(built.httpBytes, Buffer.byteLength(built.raw));
    assert.deepEqual(JSON.parse(built.raw), built.body);
    assert.equal(built.sha256, createHash("sha256").update(built.raw).digest("hex"));
    assert.deepEqual(wModule.wShapeBody(m, index + 2, shape, topic), built);
    const events = built.body.events;
    assert.equal(events.length, shape === "N99" ? 99 : 100);
    assert.equal(new Set(events.map((e) => e.id)).size, events.length);
    assert.ok(events.every((e) => typeof JSON.parse(e.textData) === "string"));
    assert.ok(
      events.every(
        (e) =>
          e.attributes.time.ceTimestamp ===
          (shape === "T0" ? "1970-01-01T00:00:00Z" : "2026-10-07T00:00:00Z"),
      ),
    );
    assert.ok(
      events.every(
        (e) =>
          JSON.stringify(Object.keys(e.attributes)) ===
          (shape === "I0" ? '["datacontenttype","time","probe"]' : '["datacontenttype","time"]'),
      ),
    );
    if (shape === "I0") assert.ok(events.every((e) => e.attributes.probe.ceInteger === 0));
  }
  for (const args of [
    [m, 1, "N99", topic],
    [m, 2, "T0", topic],
    [m, 2, "foreign", topic],
    [manifest(), 2, "N99", topic],
    [m, 2, "N99", "projects/foreign/topics/t"],
    [{ ...m, ceiling: 65536 }, 2, "N99", topic],
  ])
    assert.throws(() => wModule.wShapeBody(...args), /shape|ceiling/);
  assert.throws(() => manifest("w-shape", { accepted: 1, refused: 2 }), /shape/);
});

test("W shape obtains the actual topic then sends only controls and the three counters", async () => {
  const { result, calls } = await replay("w-shape", "shape");
  assert.equal(result.stopped, null);
  assert.equal(result.evidenceComplete, true);
  assert.equal(result.cleanupReady, true);
  assert.equal(result.boundary, null);
  assert.equal(result.layer, null);
  assert.equal(result.counts.publish, 5);
  assert.deepEqual(
    result.publishes.map((p) => p.purpose),
    ["before-control", "N99", "T0", "I0", "after-control"],
  );
  assert.deepEqual(
    result.publishes.map((p) => p.accepted),
    [true, false, false, false, true],
  );
  for (const call of calls.filter((c) => c.host === "publishing")) {
    const { raw, body, ...recipe } = call.recipe.shape
      ? wModule.wShapeBody(result.manifest, call.recipe.sequence, call.recipe.shape, result.topic)
      : wBody(result.manifest, call.recipe.sequence, 65536);
    assert.equal(raw, call.rawBody);
    assert.deepEqual(body, call.body);
    for (const [key, value] of Object.entries(recipe)) assert.deepEqual(call.recipe[key], value);
  }
  for (const p of result.publishes.slice(1, 4)) {
    assert.equal(p.observedRequestSize, p.predictedRequestSize);
    assert.equal(p.predictionMatches, true);
  }
  assert.equal(calls.filter((c) => c.method === "DELETE").length, 1);
});

test("W shape generated fixed-width identities and topic varint boundaries match independent encodings", () => {
  for (const [index, topicWidth] of [87, 127, 128, 129].entries()) {
    const m = wManifest({
      project: manifest().project,
      runId: (index + 1).toString(16).padStart(12, "0"),
      stage: "w-shape",
    });
    const prefix = `projects/${m.project}/topics/`;
    const topic = prefix + "t".repeat(topicWidth - Buffer.byteLength(prefix));
    for (const [ordinal, shape] of ["N99", "T0", "I0"].entries()) {
      const built = wModule.wShapeBody(m, ordinal + 2, shape, topic);
      const wire = shapeWire(built.body.events, topic, m.channel);
      assert.equal(built.requestBytes, wire.ce.length);
      assert.equal(built.predictedRequestSize, wire.pubsub.length);
      assert.equal(wire.ce.length, 10081812);
      assert.deepEqual(built.anyBytes, wire.anyBytes);
      assert.ok(
        built.body.events.every(
          (event) =>
            event.id.startsWith(m.runId) && event.source === m.source && event.type === m.type,
        ),
      );
    }
  }
});

test("W shape preserves mismatched measurements and stops on unknown or unmeasured answers with cleanup", async () => {
  const mismatch = await replay("w-shape", "shape-mismatch");
  assert.equal(mismatch.result.evidenceComplete, true);
  assert.ok(
    mismatch.result.publishes
      .slice(1, 4)
      .every(
        (p) =>
          p.observedRequestSize === p.predictedRequestSize + 1 && p.predictionMatches === false,
      ),
  );
  for (const [mode, count] of [
    ["shape-unknown", 3],
    ["shape-unmeasured", 2],
    ["shape-counter-success", 2],
  ]) {
    const { result, calls } = await replay("w-shape", mode);
    assert.equal(result.evidenceComplete, false);
    assert.equal(result.counts.publish, count);
    assert.equal(result.cleanupReady, true);
    assert.match(result.stopped, /needs-review/);
    assert.equal(calls.filter((c) => c.method === "DELETE").length, 1);
  }
});

test("W shape measurements reject generic detailed refusals and the maximum boundary", async () => {
  for (const mode of [
    "shape-detailed-400-10000001",
    "shape-detailed-413-10000001",
    "shape-detailed-400-10000000",
    "shape-detailed-413-10000000",
    "shape-detail-free-boundary",
  ]) {
    const { result, calls } = await replay("w-shape", mode);
    const counter = result.publishes[1];
    const spec = calls.find((c) => c.recipe?.purpose === "N99");
    assert.equal(
      wAcceptance(counter.answer, spec),
      mode === "shape-detail-free-boundary" ? null : false,
    );
    assert.equal(result.evidenceComplete, false, mode);
    assert.equal(result.counts.publish, 2, mode);
    assert.equal(result.cleanupReady, true, mode);
    assert.equal(result.closureReady, false, mode);
    assert.match(result.stopped, /needs-review/, mode);
    assert.equal(counter.observedRequestSize, undefined, mode);
    assert.equal(counter.predictionMatches, undefined, mode);
    assert.deepEqual(
      result.publishes.map((p) => p.purpose),
      ["before-control", "N99"],
      mode,
    );
    assert.equal(calls.filter((c) => c.method === "DELETE").length, 1, mode);
    const bytes = Buffer.from(counter.answer.bodyBase64, "base64");
    assert.equal(bytes.length, counter.answer.bodyBytes, mode);
    assert.equal(bytes.toString(), `${JSON.stringify(counter.answer.body, null, 2)}\n`, mode);
  }
});

test("W shape keeps control, lifecycle and cleanup obligations without retries", async () => {
  for (const [mode, count, closed] of [
    ["shape-before-control-refused", 1, true],
    ["shape-after-control-refused", 5, true],
    ["shape-api-disabled", 0, true],
    ["shape-unknown-create", 0, false],
    ["shape-dependent", 5, false],
    ["shape-topic-left", 5, false],
    ["shape-unknown-delete", 5, false],
    ["shape-pending-delete", 5, false],
  ]) {
    const { result, calls } = await replay("w-shape", mode);
    assert.equal(result.counts.publish, count, mode);
    assert.equal(result.cleanupReady, closed, mode);
    assert.ok(calls.filter((c) => c.method === "DELETE").length <= 1, mode);
    assert.equal(
      result.evidenceComplete,
      count === 5 && mode !== "shape-after-control-refused",
      mode,
    );
    if (mode === "shape-api-disabled") assert.notEqual(result.closureReady, true, mode);
    else assert.equal(result.closureReady, false, mode);
    if (mode === "shape-api-disabled")
      assert.equal(calls.filter((c) => c.method === "POST").length, 0);
  }
});

for (const stage of ["w-shape", "w-upper-counter"])
  test(`W ${stage} default entry requires frozen admission before credentials, network or runtime writes`, () => {
    const root = resolve("target/codex-out/w-ready/test-work");
    mkdirSync(root, { recursive: true });
    const dir = mkdtempSync(join(root, "shape-entry-"));
    try {
      const m = manifest(stage);
      const checkout = resolve(
        dirname(new URL("./w-run.mjs", import.meta.url).pathname),
        "../../..",
      );
      const config = {
        ...m,
        sourceCommit: execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
          encoding: "utf8",
        }).trim(),
        reserveUsd: 0.05,
        packetReserveUsd: 0.15,
        parentBudgetUsd: 14,
        out: join(dir, "out"),
        sandboxLedger: join(dir, "ledger.jsonl"),
        lockDir: join(dir, "locks"),
        ownerLedger: join(dir, "owner.md"),
        packetDir: dir,
      };
      const descriptor = {
        status: "frozen",
        sourceCommit: config.sourceCommit,
        executions: [{ stage: m.stage, runId: m.runId }],
        sourceHashes: {},
        artifactHashes: {},
        envelopeBodies: { [m.stage]: "unadmitted-shape" },
      };
      const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
      for (const name of ["w.mjs", "w-run.mjs"]) {
        const path = new URL(name, import.meta.url).pathname;
        descriptor.sourceHashes[path] = hash(readFileSync(path));
      }
      for (const name of ["eventarc-packet-w.md", "w-checklist.md", "w-mutation-report.md"]) {
        writeFileSync(join(dir, name), name);
        descriptor.artifactHashes[name] = hash(name);
      }
      const descriptorBytes = JSON.stringify(descriptor);
      writeFileSync(join(dir, "w-descriptor.json"), descriptorBytes);
      writeFileSync(config.ownerLedger, `${W_A2_RULING}\n`);
      const input = join(dir, "input.json");
      writeFileSync(input, JSON.stringify(config));
      const preload = `
      import fs from "node:fs";
      import child from "node:child_process";
      import { syncBuiltinESMExports } from "node:module";
      const counts = { wire: 0, credential: 0, runtimeWrite: 0 };
      const read = fs.readFileSync;
      fs.readFileSync = function(path, ...args) {
        if (/application_default_credentials|\\/.config\\/gcloud\\//.test(String(path))) {
          counts.credential++; throw new Error("credential denied");
        }
        return read.call(this, path, ...args);
      };
      const open = fs.openSync;
      fs.openSync = function(path, flags, ...args) {
        if (flags === "r" || flags === 0) return open.call(this, path, flags, ...args);
        counts.runtimeWrite++; throw new Error("runtime open denied");
      };
      for (const name of ["mkdirSync", "writeFileSync", "appendFileSync", "unlinkSync"])
        fs[name] = () => { counts.runtimeWrite++; throw new Error("runtime write denied"); };
      child.execFile = () => { counts.credential++; throw new Error("credential execution denied"); };
      const exec = child.execFileSync;
      child.execFileSync = (file, args, options) => {
        if (file === "git" && JSON.stringify(args) === '["rev-parse","HEAD"]')
          return exec(file, args, options);
        counts.credential++; throw new Error("child execution denied");
      };
      globalThis.fetch = () => { counts.wire++; throw new Error("wire denied"); };
      syncBuiltinESMExports();
      process.on("exit", () => process.stdout.write(JSON.stringify(counts) + "\\n"));
    `;
      const run = spawnSync(
        process.execPath,
        [
          "--import",
          `data:text/javascript,${encodeURIComponent(preload)}`,
          new URL("./w-run.mjs", import.meta.url).pathname,
          "--config",
          input,
        ],
        {
          env: { PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin` },
          cwd: checkout,
          timeout: 10000,
          encoding: "utf8",
        },
      );
      assert.equal(run.status, 2, run.stderr);
      assert.match(run.stderr, /exact E\/V admission absent/);
      assert.deepEqual(JSON.parse(run.stdout), { wire: 0, credential: 0, runtimeWrite: 0 });
      const vBody = `decision=APPROVE; envelopeId=EVENTARC-W-${config.runId}; packetSha256=${descriptor.artifactHashes["eventarc-packet-w.md"]}; checklistSha256=${descriptor.artifactHashes["w-checklist.md"]}; mutationSha256=${descriptor.artifactHashes["w-mutation-report.md"]}; descriptorSha256=${hash(descriptorBytes)}; sourceCommit=${config.sourceCommit}`;
      writeFileSync(
        config.ownerLedger,
        `${W_A2_RULING}\n- 2026-10-08 | EVENTARC-PACKET-W envelope | ${descriptor.envelopeBodies[m.stage]} | offline test | test-only.md\n- 2026-10-08 | EVENTARC-PACKET-W | ${vBody} | offline test | test-only.md\n`,
      );
      const args = [
        "--import",
        `data:text/javascript,${encodeURIComponent(preload)}`,
        new URL("./w-run.mjs", import.meta.url).pathname,
        "--config",
        input,
      ];
      const options = {
        env: { PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin` },
        cwd: checkout,
        timeout: 10000,
        encoding: "utf8",
      };
      const admitted = spawnSync(process.execPath, args, options);
      assert.equal(admitted.status, 3, admitted.stderr);
      assert.match(admitted.stderr, /runtime write denied/);
      assert.deepEqual(JSON.parse(admitted.stdout), { wire: 0, credential: 0, runtimeWrite: 1 });
      const a2 = spawnSync(process.execPath, [...args, "--a2"], options);
      assert.equal(a2.status, 2, a2.stderr);
      assert.match(a2.stderr, /shape A2 requires a separate ruling/);
      assert.deepEqual(JSON.parse(a2.stdout), { wire: 0, credential: 0, runtimeWrite: 0 });
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

test("W native size refusal reaches staged bisection with bounded monotone publications", async () => {
  const zero = await replay("w0", "native-size");
  const one = await replay("w1", "native-size", zero.result.boundary);
  const two = await replay("w2", "native-size", one.result.boundary);
  assert.ok(zero.result.boundary.refused - zero.result.boundary.accepted <= 4096);
  assert.deepEqual(one.result.boundary, { accepted: 10485760, refused: 10485761 });
  assert.deepEqual(two.result.boundary, one.result.boundary);
  for (const [stage, limit] of [
    [zero, 20],
    [one, 18],
    [two, 6],
  ]) {
    const { result, calls } = stage;
    assert.equal(result.stopped, null);
    assert.equal(result.evidenceComplete, true);
    assert.equal(result.cleanupReady, true);
    assert.ok(result.counts.publish <= limit);
    assert.ok(calls.length <= 16 + 12 + limit + 38);
    assert.equal(calls.filter((c) => c.method === "DELETE").length, 1);
    assert.equal(result.publishes[0].accepted, true);
    if (stage !== zero) assert.equal(result.publishes.at(-1).accepted, true);
    for (const publication of result.publishes) {
      assert.equal(publication.accepted, publication.httpBytes <= 10485760);
      if (publication.accepted === false)
        assert.equal(publication.observation, nativeSizeRefusal.error.message);
    }
  }
  assert.equal(one.result.layer, "http-body-dependent");
  assert.equal(two.result.layer, one.result.layer);
});

test("W request_size mixed refusal replay completes synthetic W0 bounded bisection", async () => {
  const { result, calls } = await replay("w0", "request-size");
  assert.equal(result.stopped, null);
  assert.equal(result.evidenceComplete, true);
  assert.equal(result.cleanupReady, true);
  assert.ok(result.boundary.refused - result.boundary.accepted <= 4096);
  assert.ok(result.counts.publish <= 20);
  assert.ok(calls.length <= 16 + 12 + 20 + 38);
  assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
  assert.equal(result.publishes[0].accepted, true);
  const refused = result.publishes.filter((p) => p.accepted === false);
  assert.ok(refused.some((p) => p.observation === nativeSizeRefusal.error.message));
  assert.ok(refused.some((p) => p.observation.startsWith("The value for request_size")));
  assert.equal(result.layer, null);
});

test("W recorded C and D CREATE refusals settle failed with no open writes in main cleanup and A2", async () => {
  const refusals = corpus.filter((r) => r.case === "channel-create-refusal");
  assert.deepEqual(
    refusals.map((r) => r.run),
    ["eventarc-stage-c-20261005-r1", "eventarc-packet-d-20261006-r1"],
  );
  for (const refusal of refusals) {
    const world = await replay("w0", "normal", undefined, true, refusal);
    const result = await recordW({
      manifest: manifest(),
      transports: world.transports,
      now: () => 0,
      sleep: async () => {},
      note: () => {},
    });
    assert.equal(result.writes[0].state, "failed", refusal.run);
    assert.equal(result.writes[0].operation, undefined);
    assert.equal(result.cleanupReady, true);
    assert.equal(result.cleanupError, undefined);
    assert.equal(result.writes.filter((w) => ["unknown", "pending"].includes(w.state)).length, 0);
    assert.equal(result.topic, undefined);
    assert.equal(result.publishes.length, 0);
    assert.deepEqual(
      world.calls.filter((c) => c.method !== "GET").map((c) => c.method),
      ["POST"],
    );
    const a2 = await recordW({
      manifest: manifest(),
      recording: { ...result, cleanupReady: false },
      transports: world.transports,
      now: () => 600_000,
      sleep: async () => {},
      note: () => {},
    });
    assert.equal(a2.cleanupReady, true);
    assert.equal(a2.writes[0].state, "failed");
    assert.equal(world.calls.filter((c) => c.method === "POST").length, 1);
    assert.equal(world.calls.filter((c) => c.method === "DELETE").length, 0);
  }
});

test("W incomplete, non-native and unjudged CREATE refusals remain unknown after absence", async () => {
  const m = manifest(),
    refusal = corpus.find((r) => r.case === "channel-create-refusal");
  const spec = {
    host: "eventarc",
    method: "POST",
    path: `/v1/${m.parent}/channels?channelId=${m.channel.split("/").at(-1)}`,
    body: { name: m.channel },
  };
  assert.equal(wCreateRefusal(refusal, spec), true);
  assert.equal(wCreateRefusal(refusal, { ...spec, method: "DELETE" }), false);
  assert.equal(wCreateRefusal(refusal, { ...spec, host: "publishing" }), false);
  assert.equal(wCreateRefusal(refusal, { ...spec, path: `/v1/${m.parent}/triggers` }), false);
  const changed = [
    { ...refusal, unknown: true },
    { ...refusal, status: 503 },
    { ...refusal, bodyBytes: 1 },
    { ...refusal, bodySha256: "0".repeat(64) },
    { ...refusal, bodyBase64: Buffer.from(JSON.stringify(refusal.body)).toString("base64") },
  ];
  for (const edit of [
    (b) => {
      b.name = `${m.parent}/operations/unjudged`;
    },
    (b) => {
      b.error.code = 403;
    },
    (b) => {
      b.error.status = "PERMISSION_DENIED";
    },
    (b) => {
      b.error.message = "";
    },
    (b) => {
      b.error.message = 5;
    },
    (b) => {
      delete b.error.details;
    },
    (b) => {
      b.error.details.pop();
    },
    (b) => {
      b.error.details[0].fieldViolations[0].field = "foreign";
    },
    (b) => {
      b.error.details[0].fieldViolations[0].extra = true;
    },
    (b) => {
      b.error.details[1].requestId = 5;
    },
    (b) => {
      b.error.details[1].requestId = "";
    },
    (b) => {
      b.error.details[3].requestId = "a".repeat(16);
    },
    (b) => {
      b.error.details[3]["@type"] = "foreign";
    },
  ]) {
    const body = structuredClone(refusal.body);
    edit(body);
    changed.push(native(400, body));
  }
  for (const reply of changed) {
    assert.equal(wCreateRefusal(reply, spec), false);
    const { result, calls } = await replay("w0", "normal", undefined, false, reply);
    assert.equal(result.writes[0].state, "unknown");
    assert.equal(result.cleanupReady, false);
    assert.match(result.cleanupError, /unknown CREATE/);
    assert.equal(calls.filter((c) => c.method === "DELETE").length, 0);
  }
});

test("W refused CREATE settlement in A2 requires absence, baseline ownership and complete clean lists", async () => {
  const refusal = corpus.find((r) => r.case === "channel-create-refusal");
  const { result } = await replay("w0", "normal", undefined, false, refusal);
  for (const failure of [
    "baseline",
    "dependent",
    "foreign-trigger",
    "foreign-topic",
    "unjudged-absence",
    "present",
    "topic-obligation",
    "failed-operation",
    "incomplete-list",
  ]) {
    const m = manifest();
    const world = await replay("w0", "normal", undefined, true, refusal);
    const recording = structuredClone(result);
    recording.cleanupReady = false;
    if (failure === "baseline") recording.baselineAbsent = false;
    if (failure === "topic-obligation") recording.topic = `projects/${m.project}/topics/own`;
    if (failure === "failed-operation")
      recording.writes[0].operation = `${m.parent}/operations/failed`;
    const request = world.transports.eventarc.request;
    world.transports.eventarc.request = async (spec) => {
      if (failure === "unjudged-absence" && spec.path.includes("/channels/"))
        return native(404, {});
      if (failure === "present" && spec.path.includes("/channels/")) {
        const body = template((r) => r.method === "GET" && r.body.pubsubTopic);
        body.name = m.channel;
        body.pubsubTopic = `projects/${m.project}/topics/own`;
        return native(200, body);
      }
      if (spec.path.endsWith("/triggers")) {
        if (["dependent", "foreign-trigger"].includes(failure))
          return native(200, {
            triggers: [
              {
                name: `${m.parent}/triggers/foreign`,
                ...(failure === "dependent" ? { channel: m.channel } : {}),
              },
            ],
          });
        if (failure === "incomplete-list") return native(200, { nextPageToken: "not-exhausted" });
      }
      return request(spec);
    };
    if (failure === "foreign-topic")
      world.transports.pubsub.request = async () =>
        native(200, { topics: [{ name: `projects/${m.project}/topics/foreign` }] });
    const a2 = await recordW({
      manifest: m,
      recording,
      transports: world.transports,
      now: () => 600_000,
      sleep: async () => {},
      note: () => {},
    });
    assert.equal(a2.cleanupReady, false, failure);
    assert.equal(a2.writes[0].state, "failed");
    assert.equal(world.calls.filter((c) => c.method !== "GET").length, 0);
    if (failure === "dependent") {
      const recovered = await recordW({
        manifest: m,
        recording: a2,
        transports: (await replay("w0", "normal", undefined, true, refusal)).transports,
        now: () => 1_200_000,
        sleep: async () => {},
        note: () => {},
      });
      assert.equal(recovered.cleanupReady, true);
      assert.equal(recovered.cleanupError, undefined);
    }
  }
});

test("W1 and W2 confirm adjacent bytes and distinguish HTTP and logical dependence", async () => {
  const prerequisite = { accepted: 1499900, refused: 1500100 };
  for (const mode of ["normal", "logical"]) {
    const one = await replay("w1", mode, prerequisite);
    assert.equal(one.result.stopped, null);
    assert.deepEqual(one.result.boundary, { accepted: 1500000, refused: 1500001 });
    assert.equal(
      one.result.layer,
      mode === "normal" ? "http-body-dependent" : "logical-request-dependent",
    );
    assert.ok(one.result.counts.publish <= 18);
    const confirmed = one.calls.find((c) => c.recipe?.purpose === "accepted-confirmation");
    for (const variant of one.calls.filter((c) => c.recipe?.whitespace)) {
      assert.deepEqual(JSON.parse(variant.rawBody), JSON.parse(confirmed.rawBody));
      assert.equal(variant.recipe.requestBytes, confirmed.recipe.requestBytes);
    }
    const two = await replay("w2", mode, one.result.boundary);
    assert.equal(two.result.stopped, null);
    assert.equal(two.result.counts.publish, 6);
    assert.equal(two.result.cleanupReady, true);
  }
});

test("W A2 polls only its own prior DELETE and preserves unknown CREATE and topic obligations", async () => {
  for (const outcome of [
    "done",
    "pending",
    "foreign-target",
    "foreign-name",
    "channel-present",
    "topic-present",
    "unknown-create",
    "unknown-delete",
  ]) {
    const m = manifest(),
      channel = m.channel,
      topic = `projects/${m.project}/topics/managed-w`,
      operation = `${m.parent}/operations/own-delete`;
    const recording = {
      manifest: m,
      startedAt: 0,
      lastRequestAt: 0,
      baselineAbsent: true,
      baselineTopics: [],
      baselineTriggers: [],
      topic,
      stopped: null,
      evidenceComplete: true,
      cleanupReady: false,
      writes: [
        {
          name: channel,
          action: "create",
          state: outcome === "unknown-create" ? "unknown" : "confirmed",
        },
        {
          name: channel,
          action: "delete",
          state: "pending",
          ...(outcome === "unknown-delete" ? {} : { operation }),
        },
      ],
    };
    const calls = [];
    let clock = 600_000;
    const result = await recordW({
      manifest: m,
      recording,
      now: () => clock,
      sleep: async (ms) => {
        clock += ms;
      },
      note: () => {},
      transports: Object.fromEntries(
        ["eventarc", "pubsub"].map((host) => [
          host,
          {
            request: async (spec) => {
              calls.push(spec);
              assert.equal(spec.method, "GET");
              let body,
                status = 200;
              if (spec.path.includes("/operations/")) {
                body = template((r) =>
                  outcome === "pending"
                    ? r.case === "channel-operation-not-done"
                    : r.sequence === 13 && r.path,
                );
                body.name = outcome === "foreign-name" ? operation + "-foreign" : operation;
                body.metadata.target =
                  outcome === "foreign-target" ? channel + "-foreign" : channel;
              } else if (spec.path.includes("/channels/")) {
                status = outcome === "channel-present" ? 200 : 404;
                body = template(
                  (r) =>
                    r.status === status &&
                    r.method === "GET" &&
                    (r.path ?? r.url).includes("/channels/") &&
                    (status === 404 || r.body.pubsubTopic),
                );
                if (status === 200) {
                  body.name = channel;
                  body.pubsubTopic = topic;
                }
              } else
                body =
                  outcome === "topic-present" && spec.path.includes("/topics?")
                    ? { topics: [{ name: topic }] }
                    : {};
              const answer = native(status, body);
              assert.equal(hProductionAnswer(answer, { ...spec, host }), true);
              return answer;
            },
          },
        ]),
      ),
    });
    assert.equal(result.cleanupReady, outcome === "done", outcome);
    assert.ok(result.counts.cleanup <= 38);
    assert.equal(calls.filter((c) => c.method === "DELETE").length, 0);
    if (outcome === "unknown-create") assert.equal(calls.length, 1);
  }
});

test("W A2 requires spacing, exhaustive pages and its own bounded deadline", async () => {
  const m = manifest();
  const recording = {
    manifest: m,
    startedAt: 0,
    lastRequestAt: 0,
    baselineAbsent: true,
    baselineTopics: [],
    baselineTriggers: [],
    topic: `projects/${m.project}/topics/managed`,
    writes: [{ action: "create", name: m.channel, state: "confirmed" }],
    publishes: [],
    stopped: null,
    evidenceComplete: true,
  };
  await assert.rejects(
    recordW({ manifest: m, recording, now: () => 599_999, note: () => {} }),
    /ten minutes/,
  );
  let calls = 0;
  const late = await recordW({
    manifest: m,
    recording: {
      ...recording,
      writes: [...recording.writes, { action: "delete", name: m.channel, state: "confirmed" }],
    },
    now: () => m.wallMs,
    note: () => {},
    sleep: async () => {},
    transports: Object.fromEntries(
      ["eventarc", "pubsub"].map((host) => [
        host,
        {
          request: async (spec) => {
            calls++;
            return spec.path.includes("/channels/")
              ? native(
                  404,
                  template(
                    (r) =>
                      r.status === 404 &&
                      r.method === "GET" &&
                      (r.path ?? r.url).includes("/channels/"),
                  ),
                )
              : native(200, {});
          },
        },
      ]),
    ),
  });
  assert.equal(calls, 4);
  assert.equal(late.cleanupReady, true);
  calls = 0;
  let clock = m.wallMs;
  const expired = await recordW({
    manifest: m,
    recording,
    now: () => clock,
    note: () => {},
    sleep: async () => {},
    transports: {
      eventarc: {
        request: async () => {
          calls++;
          clock += 45 * 60_000;
          return native(
            404,
            template(
              (r) =>
                r.status === 404 && r.method === "GET" && (r.path ?? r.url).includes("/channels/"),
            ),
          );
        },
      },
    },
  });
  assert.equal(calls, 1);
  assert.match(expired.cleanupError, /wall/);
  const spent = await recordW({
    manifest: m,
    recording: { ...recording, a2Requests: 38 },
    now: () => 600_000,
    note: () => {},
    sleep: async () => {},
    transports: {},
  });
  assert.equal(spent.cleanupReady, false);
  assert.match(spent.cleanupError, /ceiling/);
  assert.equal(spent.counts.cleanup, 0);
  calls = 0;
  const incomplete = await recordW({
    manifest: m,
    now: () => 0,
    note: () => {},
    sleep: async () => {},
    transports: {
      usage: {
        request: async () => {
          calls++;
          return native(200, { services: [], nextPageToken: "still-more" });
        },
      },
    },
  });
  assert.equal(calls, 1);
  assert.match(incomplete.stopped, /needs-review/);
  assert.equal(incomplete.writes.length, 0);
});

test("W publication upload budget reserves cleanup and refuses dispatch beyond the wall", async () => {
  const m = manifest();
  assert.equal(m.wallMs, 150 * 60_000);
  const world = await replay("w0", "normal", undefined, true);
  let clock = 0;
  const request = world.transports.eventarc.request;
  world.transports.eventarc.request = async (spec) => {
    const answer = await request(spec);
    if (spec.method === "GET" && answer.status === 200 && answer.body.pubsubTopic)
      clock = m.wallMs - 5 * 60_000 - 60_000;
    return answer;
  };
  const result = await recordW({
    manifest: m,
    transports: world.transports,
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    note: () => {},
  });
  assert.match(result.stopped, /publish.*wall/);
  assert.equal(result.counts.publish, 0);
  assert.equal(world.calls.filter((c) => c.host === "publishing").length, 0);
  assert.equal(result.cleanupReady, true);
});

test("W refuses changed W2 boundaries and inconsistent whitespace layers", async () => {
  const moved = await replay("w2", "normal", {
    accepted: 1500001,
    refused: 1500002,
    layer: "http-body-dependent",
  });
  assert.match(moved.result.stopped, /boundary changed/);
  const layer = await replay("w2", "logical", {
    accepted: 1500000,
    refused: 1500001,
    layer: "http-body-dependent",
  });
  assert.match(layer.result.stopped, /layer changed/);
  assert.equal(layer.result.evidenceComplete, false);
});

test("W journal recovery keeps unanswered intents and latest A2 spacing", () => {
  const root = resolve("target/codex-out/w-ready/test-work");
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, "journal-"));
  try {
    const runId = manifest().runId,
      state = {
        manifest: manifest(),
        writes: [{ name: manifest().channel, action: "delete", state: "unknown" }],
      };
    const own = join(dir, `issued-${runId}.jsonl`);
    writeFileSync(
      own,
      JSON.stringify({ at: 0, kind: "w-state", value: state }) +
        "\n" +
        JSON.stringify({ at: 100, kind: "request" }) +
        "\n{",
    );
    writeFileSync(
      join(dir, `issued-${runId}-a2-20261007T010000Z.jsonl`),
      JSON.stringify({ at: 200, kind: "answer" }) + "\n",
    );
    const recovered = readWJournal(own);
    assert.equal(recovered.writes[0].state, "unknown");
    assert.equal(recovered.lastRequestAt, 200);
    assert.throws(() => readWJournal(join(dir, "other.jsonl")), /original/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("W entry fails before credentials or writes for unfrozen and wrongly pinned input", async () => {
  const root = resolve("target/codex-out/w-ready/test-work");
  mkdirSync(root, { recursive: true });
  const dir = mkdtempSync(join(root, "entry-"));
  try {
    const config = {
      project: manifest().project,
      stage: "w0",
      runId: manifest().runId,
      sourceCommit: "a".repeat(40),
      reserveUsd: 0.05,
      packetReserveUsd: 0.15,
      parentBudgetUsd: 14,
      out: join(dir, "out"),
      sandboxLedger: join(dir, "ledger.jsonl"),
      lockDir: join(dir, "locks"),
      ownerLedger: join(dir, "owner.md"),
      packetDir: dir,
    };
    const input = join(dir, "input.json");
    writeFileSync(input, JSON.stringify(config));
    const descriptor = {
      status: "ready",
      sourceCommit: config.sourceCommit,
      executions: [{ stage: "w0", runId: config.runId }],
      sourceHashes: {},
      artifactHashes: {},
    };
    writeFileSync(join(dir, "w-descriptor.json"), JSON.stringify(descriptor));
    const env = {
        PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin`,
      },
      errors = [];
    const io = { stdout: { write: () => {} }, stderr: { write: (text) => errors.push(text) } };
    const deps = {
      head: () => config.sourceCommit,
      execToken: () => {
        throw new Error("credentials must not run");
      },
    };
    assert.equal(await main(["--config", input], env, io, deps), 2);
    assert.match(errors.pop(), /not coordinator-frozen/);
    descriptor.status = "frozen";
    descriptor.sourceHashes[input] = "b".repeat(64);
    writeFileSync(join(dir, "w-descriptor.json"), JSON.stringify(descriptor));
    assert.equal(await main(["--config", input], env, io, deps), 2);
    assert.match(errors.pop(), /source changed/);
    assert.equal(await main(["--config", input], { PATH: "/usr/bin" }, io, deps), 2);
    assert.match(errors.pop(), /Node 24/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("W entry records exact emitted bytes with real judges and gates E, V, ruling and revocation", async () => {
  const root = resolve("target/codex-out/w-ready/test-work");
  mkdirSync(root, { recursive: true });
  for (const failure of [
    null,
    "missing-e",
    "duplicate-v",
    "ruling-changed",
    "revoked",
    "artifact-changed",
    "outbound-wall",
    "summary-exists",
  ]) {
    const dir = mkdtempSync(join(root, "entry-replay-"));
    try {
      const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
      const config = {
        project: manifest().project,
        stage: "w0",
        runId: manifest().runId,
        sourceCommit: "a".repeat(40),
        reserveUsd: 0.05,
        packetReserveUsd: 0.15,
        parentBudgetUsd: 14,
        out: join(dir, "out"),
        sandboxLedger: join(dir, "ledger.jsonl"),
        lockDir: join(dir, "locks"),
        ownerLedger: join(dir, "owner.md"),
        packetDir: dir,
      };
      const artifacts = Object.fromEntries(
        ["eventarc-packet-w.md", "w-checklist.md", "w-mutation-report.md"].map((name) => {
          writeFileSync(join(dir, name), name);
          return [name, hash(name)];
        }),
      );
      const source = new URL("./w.mjs", import.meta.url).pathname;
      const descriptor = {
        status: "frozen",
        sourceCommit: config.sourceCommit,
        executions: [{ stage: config.stage, runId: config.runId }],
        sourceHashes: { [source]: hash(readFileSync(source)) },
        artifactHashes: artifacts,
        envelopeBodies: { w0: `envelopeId=EVENTARC-W-${config.runId}; reserveUsd=0.05` },
      };
      const descriptorBytes = JSON.stringify(descriptor);
      writeFileSync(join(dir, "w-descriptor.json"), descriptorBytes);
      const vBody = `decision=APPROVE; envelopeId=EVENTARC-W-${config.runId}; packetSha256=${artifacts["eventarc-packet-w.md"]}; checklistSha256=${artifacts["w-checklist.md"]}; mutationSha256=${artifacts["w-mutation-report.md"]}; descriptorSha256=${hash(descriptorBytes)}; sourceCommit=${config.sourceCommit}`;
      const e = `- 2026-10-07 | EVENTARC-PACKET-W envelope | ${descriptor.envelopeBodies.w0} | coordinator | private-review.md`;
      const v = `- 2026-10-07 | EVENTARC-PACKET-W | ${vBody} | coordinator | private-review.md`;
      const lines = [
        failure === "ruling-changed" ? W_A2_RULING + "changed" : W_A2_RULING,
        ...(failure === "missing-e" ? [] : [e]),
        v,
        ...(failure === "duplicate-v" ? [v] : []),
        ...(failure === "revoked"
          ? [
              `- 2026-10-07 | EVENTARC-PACKET-W envelope | REVOKED envelopeId=EVENTARC-W-${config.runId} | coordinator | private-review.md`,
            ]
          : []),
      ];
      writeFileSync(config.ownerLedger, lines.join("\n") + "\n");
      if (failure === "artifact-changed") writeFileSync(join(dir, "w-checklist.md"), "changed");
      const input = join(dir, "input.json");
      writeFileSync(input, JSON.stringify(config));
      const world = await replay("w0", "normal", undefined, true);
      if (failure === "summary-exists") {
        mkdirSync(config.out, { recursive: true });
        writeFileSync(join(config.out, "summary.json"), "existing");
      }
      let clock = 0;
      let credentials = 0,
        requests = 0;
      const output = [],
        errors = [],
        io = {
          stdout: { write: (text) => output.push(text) },
          stderr: { write: (text) => errors.push(text) },
        };
      const code = await main(
        ["--config", input],
        { PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin` },
        io,
        {
          head: () => config.sourceCommit,
          now: () => clock,
          sleep: async () => {},
          execToken: async () => {
            credentials++;
            if (failure === "outbound-wall") clock = manifest().wallMs;
            return "offline-not-a-real-credential";
          },
          fetchImpl: async (address, options) => {
            requests++;
            assert.equal(options.redirect, "manual");
            assert.equal(options.headers["accept-encoding"], "identity");
            assert.equal(options.headers["x-goog-user-project"], config.project);
            const url = new URL(address),
              host = {
                "serviceusage.googleapis.com": "usage",
                "eventarc.googleapis.com": "eventarc",
                "pubsub.googleapis.com": "pubsub",
                "eventarcpublishing.googleapis.com": "publishing",
              }[url.hostname];
            const spec = {
              method: options.method,
              path: url.pathname + url.search,
              ...(options.body === undefined ? {} : { body: JSON.parse(options.body) }),
              ...(host === "publishing"
                ? {
                    rawBody: options.body,
                    recipe: { httpBytes: Buffer.byteLength(options.body), whitespace: 0 },
                  }
                : {}),
            };
            const answer = await world.transports[host].request(spec);
            return new Response(Buffer.from(answer.bodyBase64, "base64"), {
              status: answer.status,
              headers: { "content-type": "application/json" },
            });
          },
        },
      );
      assert.equal(
        code,
        failure === null ? 0 : ["outbound-wall", "summary-exists"].includes(failure) ? 3 : 2,
        errors.join(""),
      );
      assert.equal(
        credentials,
        [null, "outbound-wall", "summary-exists"].includes(failure) ? 1 : 0,
      );
      if (failure === null) {
        assert.ok(requests <= 86);
        const rows = readFileSync(config.sandboxLedger, "utf8").trim().split("\n").map(JSON.parse);
        assert.deepEqual(
          rows.map((r) => r.event),
          ["started", "finished"],
        );
        assert.ok(
          rows.every(
            (r) =>
              r.taskId === "PUBSUB-EVENTARC" &&
              r.envelopeId === `EVENTARC-W-${config.runId}` &&
              r.runId === config.runId &&
              r.mode === "w0",
          ),
        );
        assert.equal(rows[0].reserveUsd, 0.05);
        assert.equal(rows[1].requests, requests);
        assert.equal(rows[1].sandboxAtBaseline, true);
        assert.equal(rows[1].lockRetained, false);
        assert.equal(rows[1].outcome, "recorded");
        const recovered = readWJournal(join(config.out, `issued-${config.runId}.jsonl`));
        assert.equal(recovered.cleanupReady, true);
        const a2Requests = requests;
        const codeA2 = await main(
          ["--config", input, "--a2"],
          { PATH: `${dirname(process.execPath)}:/etc/profiles/per-user/tk/bin:/usr/bin:/bin` },
          io,
          {
            head: () => config.sourceCommit,
            now: () => manifest().wallMs + 600_000,
            sleep: async () => {},
            execToken: async () => "offline-not-a-real-credential",
            fetchImpl: async (address, options) => {
              requests++;
              assert.equal(options.method, "GET");
              const url = new URL(address);
              const answer = await world.transports[
                url.hostname === "pubsub.googleapis.com" ? "pubsub" : "eventarc"
              ].request({ method: options.method, path: url.pathname + url.search });
              return new Response(Buffer.from(answer.bodyBase64, "base64"), {
                status: answer.status,
              });
            },
          },
        );
        assert.equal(codeA2, 0, errors.join(""));
        const a2Rows = readFileSync(config.sandboxLedger, "utf8")
          .trim()
          .split("\n")
          .map(JSON.parse)
          .slice(2);
        assert.deepEqual(
          a2Rows.map((r) => r.event),
          ["started", "finished"],
        );
        assert.ok(a2Rows.every((r) => r.mode === "a2" && r.estimatedUsd === 0));
        assert.equal(a2Rows[0].reserveUsd, 0);
        assert.equal(a2Rows[1].requests, requests - a2Requests);
        assert.equal(a2Rows[1].sandboxAtBaseline, true);
        assert.equal(a2Rows[1].lockRetained, false);
        const captures = readFileSync(join(config.out, `capture-${config.runId}.jsonl`), "utf8");
        assert.doesNotMatch(captures, /offline-not-a-real-credential|authorization/i);
        const entries = captures
          .trim()
          .split("\n")
          .map(JSON.parse)
          .filter((r) => r.case === "w-publish");
        assert.equal(entries.length, recovered.publishes.length);
        for (let i = 0; i < entries.length; i++) {
          assert.equal(entries[i].requestBytes, recovered.publishes[i].httpBytes);
          assert.equal(entries[i].requestSha256, recovered.publishes[i].sha256);
        }
      } else if (["outbound-wall", "summary-exists"].includes(failure)) {
        const rows = readFileSync(config.sandboxLedger, "utf8").trim().split("\n").map(JSON.parse);
        assert.deepEqual(
          rows.map((r) => r.event),
          ["started", "finished"],
        );
        assert.equal(rows[1].requests, failure === "outbound-wall" ? 1 : requests);
        assert.equal(rows[1].lockRetained, failure === "summary-exists");
        assert.equal(rows[1].sandboxAtBaseline, failure === "outbound-wall");
        assert.equal(
          rows[1].outcome,
          failure === "outbound-wall" ? "stopped-for-review" : "needs-recovery",
        );
        if (failure === "outbound-wall") assert.equal(requests, 0);
        else assert.ok(requests > 0);
      } else assert.equal(requests, 0);
    } finally {
      rmSync(dir, { recursive: true });
    }
  }
});

test("W stops on unknowns, unavailable APIs, incomplete cleanup and unobserved boundaries", async () => {
  for (const mode of [
    "unknown-publish",
    "api-disabled",
    "unknown-create",
    "unknown-delete",
    "pending-delete",
    "wrong-target",
    "dependent",
    "topic-left",
    "all-accepted",
  ]) {
    const { result, calls } = await replay("w0", mode);
    assert.equal(
      result.cleanupReady,
      ["unknown-publish", "all-accepted", "api-disabled"].includes(mode),
      mode,
    );
    assert.ok(calls.filter((c) => c.method === "DELETE").length <= 1);
    if (mode === "api-disabled") assert.equal(calls.filter((c) => c.method === "POST").length, 0);
    if (mode === "unknown-publish") assert.equal(result.counts.publish, 1);
    if (mode === "all-accepted") {
      assert.equal(result.boundary, null);
      assert.equal(result.counts.publish, 8);
      const largest = calls.find((c) => c.recipe?.httpBytes === manifest().ceiling - 2);
      assert.equal(largest.timeoutMs, 197773);
    }
    if (mode === "unknown-create")
      assert.equal(calls.filter((c) => c.method === "DELETE").length, 0);
  }
});

test("W prerequisites and admission bind the checkpoint with a ledger-compatible line", () => {
  assert.throws(() => manifest("w1"), /prerequisite/);
  assert.throws(() => manifest("w1", { accepted: 1048576, refused: 2097152 }), /interval/);
  assert.throws(() => manifest("w2", { accepted: 1048576, refused: 1048578 }), /adjacent/);
  const line = wAdmission({
    stage: "w1",
    runId: "adbcfeadbcfe",
    sourceCommit: "a".repeat(40),
    checkpointSha256: "b".repeat(64),
    date: "2026-10-07",
  });
  assert.equal(line.split(" | ").length, 5);
  assert.match(line, /checkpoint=b{64}; decision=APPROVE/);
});

test("W upper counters separate HTTP, CE and mapped request metrics", () => {
  const m = manifest("w-upper-counter");
  assert.equal(m.limits.publish, 4);
  assert.throws(() => manifest("w-upper-counter", {}), /independent/);
  for (const width of [9, 127, 128]) {
    const topic = `projects/${m.project}/topics/${"t".repeat(width)}`;
    const http = wModule.wUpperBody(m, 2, "Hplus1", topic);
    const logical = wModule.wUpperBody(m, 3, "logical-counter", topic);
    const base = wBody(m, 2, 10485760);
    assert.equal(http.httpBytes, 10485761);
    assert.equal(http.raw, base.raw + " ");
    assert.deepEqual(http.body, base.body);
    for (const built of [http, logical]) {
      const wire = shapeWire(built.body.events, topic);
      assert.equal(built.requestBytes, wire.ce.length);
      assert.equal(built.predictedRequestSize, wire.pubsub.length);
      assert.deepEqual(built.anyBytes, wire.anyBytes);
      assert.ok(built.anyBytes.every((n) => n < 450000));
      assert.equal(built.sha256, createHash("sha256").update(built.raw).digest("hex"));
    }
    assert.ok(http.requestBytes < 10485760);
    assert.ok(http.predictedRequestSize < 10485760);
    assert.equal(logical.requestBytes, 10485200);
    assert.ok(logical.predictedRequestSize > 10485760);
  }
  assert.throws(() => wModule.wUpperBody(m, 3, "Hplus1", "projects/x/topics/t"), /recipe|topic/);
});

test("W upper recorder sends four fixed observations and keeps accepted counters native", async () => {
  const { result, calls } = await replay("w-upper-counter", "all-accepted");
  assert.equal(result.stopped, null);
  assert.equal(result.cleanupReady, true);
  assert.equal(result.evidenceComplete, true);
  const publishes = calls.filter((c) => c.host === "publishing");
  assert.deepEqual(
    publishes.map((c) => c.recipe.purpose),
    ["before-control", "Hplus1", "logical-counter", "after-control"],
  );
  assert.deepEqual(
    publishes.map((c) => c.recipe.sequence),
    [1, 2, 3, 4],
  );
  assert.ok(result.publishes.every((p) => p.answer.status === 200 && p.accepted === true));
  assert.equal(result.boundary, null);
  assert.equal(result.layer, null);
});

test("W upper recorder retains either known refusal without choosing an upper metric", async () => {
  for (const mode of ["native-size", "request-size"]) {
    const { result } = await replay("w-upper-counter", mode);
    assert.equal(result.stopped, null, mode);
    assert.equal(result.evidenceComplete, true, mode);
    assert.equal(result.cleanupReady, true, mode);
    assert.equal(result.publishes.length, 4, mode);
    if (mode === "request-size")
      assert.ok(
        result.publishes.slice(1, 3).every((p) => Number.isSafeInteger(p.observedRequestSize)),
      );
    else assert.ok(result.publishes.every((p) => p.observedRequestSize === undefined));
    assert.ok(
      result.publishes.slice(1, 3).every((p) => p.accepted === false && p.answer.bodyBase64),
    );
    assert.equal(result.layer, null);
    assert.equal(result.boundary, null);
  }
});

test("W upper recorder stops unknown publication and preserves incomplete cleanup evidence", async () => {
  const { result } = await replay("w-upper-counter", "unknown-publish");
  assert.match(result.stopped, /needs-review/);
  assert.equal(result.publishes.length, 1);
  assert.equal(result.evidenceComplete, false);
  assert.equal(result.cleanupReady, true);
});

test("W upper recorder keeps lifecycle, control and unknown-counter stops bounded", async () => {
  for (const [mode, count, cleanup, complete] of [
    ["upper-before-control-refused", 1, true, false],
    ["upper-after-control-refused", 4, true, false],
    ["upper-unknown", 2, true, false],
    ["upper-unclassified", 2, true, false],
    ["upper-api-disabled", 0, true, false],
    ["upper-unknown-create", 0, false, false],
    ["upper-dependent", 4, false, true],
    ["upper-topic-left", 4, false, true],
    ["upper-unknown-delete", 4, false, true],
    ["upper-pending-delete", 4, false, true],
  ]) {
    const { result } = await replay("w-upper-counter", mode);
    assert.equal(result.publishes.length, count, mode);
    assert.equal(result.cleanupReady, cleanup, mode);
    assert.equal(result.evidenceComplete, complete, mode);
    assert.ok(result.counts.publish <= 4, mode);
  }
});

test("W upper counters stop recorded BadRequest layouts outside the two native refusal families", async () => {
  for (const status of [400, 413]) {
    for (const reason of ["arbitrary", "numeric", "payload"]) {
      const { result } = await replay("w-upper-counter", `upper-badrequest-${status}-${reason}`);
      assert.match(result.stopped, /needs-review/);
      assert.equal(result.publishes.length, 2);
      assert.equal(result.evidenceComplete, false);
      assert.equal(result.cleanupReady, true);
      const counter = result.publishes[1];
      assert.equal(counter.accepted, null);
      assert.equal(counter.observedRequestSize, undefined);
      assert.equal(counter.answer.status, status);
      assert.equal(
        counter.answer.body.error.details[0]["@type"],
        "type.googleapis.com/google.rpc.BadRequest",
      );
      assert.deepEqual(
        JSON.parse(Buffer.from(counter.answer.bodyBase64, "base64")),
        counter.answer.body,
      );
    }
  }
  for (const resource of ["dependent", "topic-left", "unknown-delete"]) {
    const { result } = await replay(
      "w-upper-counter",
      `upper-badrequest-400-arbitrary-${resource}`,
    );
    assert.equal(result.publishes.length, 2, resource);
    assert.equal(result.evidenceComplete, false, resource);
    assert.equal(result.cleanupReady, false, resource);
    assert.equal(result.publishes[1].accepted, null, resource);
  }
});
