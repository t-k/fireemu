import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS } from "./fs-query-index/corpus.mjs";
import { scanFixture } from "./fs-query-index/fixture-scan.mjs";
import {
  RECORDED_PROJECT,
  decodeStatusDetail,
  shiftInstant,
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  guardGrpcRequest,
  guardRestRequest,
  isTransient,
  normalizeGrpcResponse,
  normalizeIndexLink,
  normalizeRestResponse,
  normalizeStep,
  projectGrpcMessage,
  resolveValue,
  toGrpcMessage,
  validateCorpus,
} from "./fs-query-index/harness.mjs";
import {
  classify,
  estimatedUsd,
  indexKey,
  renormalize,
  selectPrograms,
} from "./fs-query-index/run.mjs";

const started = Date.parse("2026-09-24T00:00:00Z");
const production = () =>
  createContext({
    run: "1",
    startedMs: started,
    target: {
      kind: "production",
      token: "ya29.secret-token-value",
      quotaProject: SANDBOX_PROJECT,
    },
  });
const local = () =>
  createContext({
    run: "1",
    startedMs: started,
    target: {
      kind: "local",
      origin: "http://127.0.0.1:9999",
      grpcHost: "127.0.0.1",
      grpcPort: 9999,
    },
  });

test("the corpus passes its own validation and stays under the request cap", () => {
  const requests = validateCorpus(PROGRAMS);
  assert.ok(requests > 500, `corpus has ${requests} recorded requests`);
});

test("validation refuses unreviewed methods, absolute paths and duplicate ids", () => {
  const program = (steps, extra = {}) => [{ id: "fs-query-index/x/y", steps, ...extra }];
  assert.throws(() => validateCorpus(program([{ id: "a", rpc: "delete" }])), /not reviewed/);
  assert.throws(
    () => validateCorpus(program([{ id: "a", rpc: "commit", transport: "grpc" }])),
    /not reviewed/,
  );
  assert.throws(
    () => validateCorpus(program([{ id: "a", rpc: "runQuery", parent: "/x" }])),
    /relative/,
  );
  assert.throws(
    () => validateCorpus(program([{ id: "a", rpc: "runQuery", parent: "a/../b" }])),
    /relative/,
  );
  assert.throws(
    () => validateCorpus(program([{ id: "a", rpc: "runQuery", path: "v1/projects/x" }])),
    /under/,
  );
  assert.throws(
    () =>
      validateCorpus(
        program([
          { id: "a", rpc: "runQuery" },
          { id: "a", rpc: "runQuery" },
        ]),
      ),
    /duplicate step/,
  );
  assert.throws(() => validateCorpus([{ id: "other/x", steps: [] }]), /program id/);
  assert.throws(() => validateCorpus(program([], { seed: [["/abs", {}]] })), /relative/);
});

test("production requests carry the quota project and only reach the sandbox database", () => {
  const ctx = production();
  const request = buildRestRequest(
    { id: "a", rpc: "runQuery", parent: "qroot/r1", body: {} },
    ctx,
    new Map(),
  );
  assert.equal(
    request.url,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents/qroot/r1:runQuery`,
  );
  assert.equal(request.init.headers["x-goog-user-project"], SANDBOX_PROJECT);
  assert.equal(request.init.headers.authorization, "Bearer ya29.secret-token-value");
  guardRestRequest(request, ctx);
  const elsewhere = (url, body = "{}") => ({
    url,
    init: {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    },
  });
  const base = `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases`;
  assert.throws(
    () => guardRestRequest(elsewhere(`${base}/other/documents:runQuery`), ctx),
    /outside/,
  );
  assert.throws(
    () => guardRestRequest(elsewhere(`${base}/(default)/documents/a/../b:runQuery`), ctx),
    /canonical/,
  );
  assert.throws(
    () => guardRestRequest(elsewhere(`${base}/(default)/documents/%2e%2e:runQuery`), ctx),
    /canonical/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        elsewhere(
          "https://firestore.googleapis.com/v1/projects/fireemu-35fe6/databases/(default)/documents:runQuery",
        ),
        ctx,
      ),
    /outside/,
  );
  assert.throws(
    () => guardRestRequest(elsewhere("https://example.com/v1/x"), ctx),
    /left the target/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        elsewhere(
          `${base}/(default)/documents:runQuery`,
          JSON.stringify({ v: "projects/fireemu-35fe6/databases/(default)" }),
        ),
        ctx,
      ),
    /another project/,
  );
  // The emulator reset route is never reachable in production, even for the harness.
  assert.throws(
    () =>
      guardRestRequest(
        elsewhere(
          `https://firestore.googleapis.com/emulator/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents`,
        ),
        ctx,
        { harness: true },
      ),
    /outside/,
  );
});

test("gRPC requests are scoped to the sandbox database", () => {
  const ctx = production();
  const built = buildGrpcRequest(
    {
      id: "a",
      rpc: "runQuery",
      body: {
        structuredQuery: {
          limit: 3,
          findNearest: { limit: 2, distanceThreshold: "NaN" },
        },
      },
    },
    ctx,
    new Map(),
  );
  assert.equal(built.method, "RunQuery");
  assert.equal(built.request.parent, `projects/${SANDBOX_PROJECT}/databases/(default)/documents`);
  assert.deepEqual(built.request.structuredQuery.limit, { value: 3 });
  assert.ok(Number.isNaN(built.request.structuredQuery.findNearest.distanceThreshold.value));
  guardGrpcRequest(built, ctx);
  assert.throws(
    () =>
      guardGrpcRequest(
        { request: { parent: "projects/other/databases/(default)/documents" } },
        ctx,
      ),
    /outside/,
  );
  assert.throws(
    () =>
      guardGrpcRequest(
        {
          request: {
            parent: `projects/${SANDBOX_PROJECT}/databases/named/documents`,
          },
        },
        ctx,
      ),
    /outside/,
  );
});

test("REST JSON converts to gRPC message form", () => {
  assert.deepEqual(toGrpcMessage({ readTime: "2026-09-24T00:00:01.5Z" }), {
    readTime: {
      seconds: String(Date.parse("2026-09-24T00:00:01Z") / 1000),
      nanos: 500_000_000,
    },
  });
  assert.deepEqual(toGrpcMessage({ doubleValue: "-Infinity" }), {
    doubleValue: -Infinity,
  });
  assert.deepEqual(toGrpcMessage({ bytesValue: "AQI=" }).bytesValue, Buffer.from([1, 2]));
  assert.deepEqual(toGrpcMessage({ count: { upTo: "3" } }), {
    count: { upTo: { value: "3" } },
  });
  assert.equal(
    toGrpcMessage({ timestampValue: "2020-01-01T00:00:00.000001Z" }).timestampValue.nanos,
    1000,
  );
});

test("resolveValue follows earlier raw responses and fails loudly when they are missing", () => {
  const ctx = local();
  const raw = new Map([["w", { commitTime: "t" }]]);
  assert.deepEqual(resolveValue({ readTime: { $from: "w", path: "commitTime" } }, ctx, raw), {
    readTime: "t",
  });
  assert.throws(() => resolveValue({ $from: "x", path: "y" }, ctx, raw), /recorded nothing/);
  assert.equal(
    resolveValue("{docs}/a", ctx, raw),
    `projects/${SANDBOX_PROJECT}/databases/(default)/documents/a`,
  );
});

test("normalization masks only run-window times, durations and opaque tokens", () => {
  const ctx = production();
  const recorded = normalizeRestResponse(
    200,
    JSON.stringify([
      {
        document: {
          name: `projects/${SANDBOX_PROJECT}/databases/(default)/documents/qn/d1`,
          createTime: "2026-09-24T00:00:01.123456Z",
          fields: { t: { timestampValue: "2020-01-01T00:00:00Z" } },
        },
        readTime: "2026-09-24T00:00:02Z",
        explainMetrics: { executionStats: { executionDuration: "0.012477s" } },
      },
      { nextPageToken: "abc", transaction: "dHg=" },
    ]),
    ctx,
  );
  assert.deepEqual(recorded.body, [
    {
      document: {
        name: `projects/${RECORDED_PROJECT}/databases/(default)/documents/qn/d1`,
        createTime: "<t1>",
        fields: { t: { timestampValue: "2020-01-01T00:00:00Z" } },
      },
      readTime: "<t2>",
      explainMetrics: { executionStats: { executionDuration: "<duration>" } },
    },
    { nextPageToken: "<page-token>", transaction: "<transaction>" },
  ]);
  assert.throws(
    () => normalizeRestResponse(200, JSON.stringify({ executionDuration: "fast" }), ctx),
    /unexpected executionDuration/,
  );
  assert.deepEqual(normalizeRestResponse(400, "<html>", ctx), {
    status: 400,
    nonJson: "<html>",
  });
});

test("a missing-index link keeps its encoded index with the project replaced", () => {
  const ctx = production();
  // The link production returned for (q ASC, z ASC) on flt during exploration.
  const blob =
    "ClBwcm9qZWN0cy9maXJlZW11LW9yYWNsZS1xdWVyeS9kYXRhYmFzZXMvKGRlZmF1bHQpL2NvbGxlY3Rpb25Hcm91cHMvZmx0L2luZGV4ZXMvXxABGgUKAXEQARoFCgF6EAEaDAoIX19uYW1lX18QAQ";
  const text = `You can create it here: https://console.firebase.google.com/v1/r/project/${SANDBOX_PROJECT}/firestore/indexes?create_composite=${blob}`;
  const out = normalizeRestResponse(400, JSON.stringify({ error: { message: text } }), ctx).body
    .error.message;
  assert.ok(!out.includes(SANDBOX_PROJECT));
  const encoded = /create_composite=([A-Za-z0-9_-]+)/.exec(out)[1];
  const decoded = Buffer.from(encoded, "base64url").toString("latin1");
  assert.ok(
    decoded.includes(`projects/${RECORDED_PROJECT}/databases/(default)/collectionGroups/flt`),
  );
  assert.equal(normalizeIndexLink("no link", ctx), "no link");
  assert.doesNotThrow(() => scanFixture(out, [SANDBOX_PROJECT]));
  assert.throws(() => scanFixture(text, [SANDBOX_PROJECT]), /private value/);
});

test("the fixture scan finds the project in every base64 alignment and access tokens", () => {
  for (const prefix of ["", "a", "ab", "abc"]) {
    const encoded = Buffer.from(`${prefix}projects/${SANDBOX_PROJECT}/x`).toString("base64url");
    assert.throws(() => scanFixture(encoded, [SANDBOX_PROJECT]), /private value/, prefix);
  }
  assert.throws(() => scanFixture("ya29.a0AfB_byC1234567890", []), /access token/);
  assert.doesNotThrow(() => scanFixture("demo-fs-query-index", [SANDBOX_PROJECT]));
});

test("gRPC messages project to their REST JSON shape", () => {
  const projected = projectGrpcMessage({
    document: {
      name: "a",
      fields: {
        n: { integerValue: "0", valueType: "integerValue" },
        b: { booleanValue: false, valueType: "booleanValue" },
        z: { nullValue: "NULL_VALUE", valueType: "nullValue" },
        d: { doubleValue: Number.NaN, valueType: "doubleValue" },
        m: { mapValue: { fields: {} }, valueType: "mapValue" },
        a: { arrayValue: { values: [] }, valueType: "arrayValue" },
      },
      createTime: { seconds: "1790000000", nanos: 5000 },
      updateTime: null,
    },
    transaction: { type: "Buffer", data: [] },
    readTime: { seconds: "1790000000", nanos: 0 },
    skippedResults: 0,
    done: true,
    continuationSelector: "done",
    explainMetrics: {
      planSummary: null,
      executionStats: {
        resultsReturned: "0",
        executionDuration: { seconds: "0", nanos: 1_200_000 },
        debugStats: {
          fields: { a: { stringValue: "1", kind: "stringValue" } },
        },
      },
    },
  });
  assert.deepEqual(projected, {
    document: {
      name: "a",
      fields: {
        n: { integerValue: "0" },
        b: { booleanValue: false },
        z: { nullValue: null },
        d: { doubleValue: "NaN" },
        m: { mapValue: {} },
        a: { arrayValue: {} },
      },
      createTime: "2026-09-21T14:13:20.000005Z",
    },
    readTime: "2026-09-21T14:13:20Z",
    done: true,
    explainMetrics: {
      executionStats: { executionDuration: "0.0012s", debugStats: { a: "1" } },
    },
  });
  const status = normalizeGrpcResponse(
    {
      messages: [],
      code: 9,
      details: `The query requires an index for ${SANDBOX_PROJECT}`,
      errorDetails: [],
    },
    production(),
  );
  assert.deepEqual(status, {
    transport: "grpc",
    code: 9,
    message: `The query requires an index for ${RECORDED_PROJECT}`,
    messages: [],
  });
});

test("transient answers are indeterminate; a repeated production 5xx is behavior", () => {
  assert.equal(isTransient({ status: 503 }), true);
  assert.equal(isTransient({ status: 0 }), true);
  assert.equal(isTransient({ status: 429 }), true);
  assert.equal(
    isTransient({
      status: 400,
      body: [{ error: { status: "INVALID_ARGUMENT" } }],
    }),
    false,
  );
  assert.equal(
    isTransient({
      status: 200,
      body: [{ error: { status: "RESOURCE_EXHAUSTED" } }],
    }),
    true,
  );
  assert.equal(isTransient({ transport: "grpc", code: 14 }), true);
  assert.equal(isTransient({ transport: "grpc", code: 3 }), false);
  assert.equal(isTransient({ status: -1, dependencyTransient: false }), false);
  const ok = { status: 200, body: [] };
  assert.equal(classify({ stale: true, production: ok, fireemu: ok }), "STALE_FIXTURE");
  assert.equal(classify({ production: undefined, fireemu: ok }), "MISSING_FIXTURE");
  assert.equal(classify({ production: ok, fireemu: undefined }), "MISSING");
  assert.equal(classify({ production: ok, fireemu: ok }), "MATCH");
  assert.equal(classify({ production: ok, fireemu: { status: 400 } }), "MISMATCH");
  assert.equal(
    classify({
      production: ok,
      alternative: { status: 201 },
      fireemu: { status: 201 },
    }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(classify({ production: ok, fireemu: { status: 503 } }), "MISMATCH");
  assert.equal(classify({ production: { status: 429 }, fireemu: ok }), "INDETERMINATE");
  assert.equal(classify({ production: { status: 500 }, fireemu: { status: 500 } }), "MATCH");
  assert.equal(classify({ production: { status: 500 }, fireemu: { status: 200 } }), "MISMATCH");
});

test("index keys ignore an implied trailing __name__ only", () => {
  const a = [{ fieldPath: "a", order: "ASCENDING" }];
  assert.equal(
    indexKey("g", "COLLECTION", a),
    indexKey("g", "COLLECTION", [...a, { fieldPath: "__name__", order: "ASCENDING" }]),
  );
  assert.notEqual(
    indexKey("g", "COLLECTION", a),
    indexKey("g", "COLLECTION", [...a, { fieldPath: "__name__", order: "DESCENDING" }]),
  );
  assert.notEqual(indexKey("g", "COLLECTION", a), indexKey("g", "COLLECTION_GROUP", a));
  // Production lists the implied __name__ before a trailing vector field.
  const vector = { fieldPath: "emb", vectorConfig: { dimension: 3, flat: {} } };
  const name = { fieldPath: "__name__", order: "ASCENDING" };
  assert.equal(indexKey("v", "COLLECTION", [vector]), indexKey("v", "COLLECTION", [name, vector]));
  assert.equal(
    indexKey("v", "COLLECTION", [a[0], vector]),
    indexKey("v", "COLLECTION", [a[0], name, vector]),
  );
  const only = [{ fieldPath: "__name__", order: "DESCENDING" }];
  assert.equal(indexKey("ord", "COLLECTION", only), "ord|COLLECTION|__name__:DESCENDING");
});

test("program selection by prefix and by exact id", () => {
  const programs = [{ id: "fs-query-index/a/b" }, { id: "fs-query-index/a/bc" }];
  assert.equal(selectPrograms(programs, "fs-query-index/a/b", false).length, 2);
  assert.equal(selectPrograms(programs, "fs-query-index/a/b", true).length, 1);
  assert.throws(() => selectPrograms(programs, "none", false), /no program/);
});

test("the fixture scan refuses the project number, numeric project names and addresses", () => {
  const number = "123456789012";
  for (const prefix of ["", "a", "ab"]) {
    const encoded = Buffer.from(`${prefix}consumer projects/${number}`).toString("base64");
    assert.throws(() => scanFixture(encoded, [number]), /private value/, prefix);
  }
  const quota = JSON.stringify({
    error: { details: [{ metadata: { consumer: `projects/${number}` } }] },
  });
  assert.throws(() => scanFixture(quota, []), /numeric project name/);
  assert.throws(() => scanFixture('"owner@example.com"', []), /email/);
  assert.doesNotThrow(() => scanFixture('{"@type":"type.googleapis.com/google.rpc.Help"}', []));
});

test("negative zero survives request serialization and the recorded form", () => {
  const ctx = production();
  const request = buildRestRequest(
    { id: "a", rpc: "runQuery", body: { v: { doubleValue: "-0" } } },
    ctx,
    new Map(),
  );
  assert.equal(request.init.body, '{"v":{"doubleValue":"-0"}}');
  assert.ok(Object.is(toGrpcMessage({ doubleValue: "-0" }).doubleValue, -0));
  const recorded = normalizeRestResponse(200, '{"doubleValue":-0}', ctx);
  assert.equal(JSON.parse(JSON.stringify(recorded)).body.doubleValue, "-0");
  assert.equal(normalizeRestResponse(200, '{"doubleValue":0}', ctx).body.doubleValue, 0);
});

test("run-window instants are numbered per step; requested instants keep a program anchor", () => {
  const ctx = production();
  const anchors = new Map();
  const write = normalizeStep(
    {
      transport: "rest",
      response: { status: 200, text: '{"commitTime":"2026-09-24T00:00:05Z"}' },
    },
    ctx,
    anchors,
  );
  assert.equal(write.body.commitTime, "<t1>");
  const echoed = normalizeStep(
    {
      transport: "rest",
      request: { readTime: "2026-09-24T00:00:05Z" },
      response: {
        status: 200,
        text: '[{"readTime":"2026-09-24T00:00:05Z"},{"readTime":"2026-09-24T00:00:09Z"}]',
      },
    },
    ctx,
    anchors,
  );
  assert.deepEqual(echoed.body, [{ readTime: "<r1>" }, { readTime: "<t1>" }]);
  // A later step numbers its own instants from 1 again, whatever came before.
  const later = normalizeStep(
    {
      transport: "rest",
      response: { status: 200, text: '[{"readTime":"2026-09-24T00:00:11Z"}]' },
    },
    ctx,
    anchors,
  );
  assert.deepEqual(later.body, [{ readTime: "<t1>" }]);
  // The same instant spelled with a different number of fraction digits is the same symbol: a
  // shifted request trims trailing zeros, the server answers with six digits.
  const spelled = normalizeStep(
    {
      transport: "rest",
      request: { readTime: "2026-09-24T00:00:07.12345Z" },
      response: {
        status: 200,
        text: '[{"readTime":"2026-09-24T00:00:07.123450Z"},{"readTime":"2026-09-24T00:00:08.100Z"},{"readTime":"2026-09-24T00:00:08.1Z"}]',
      },
    },
    ctx,
    anchors,
  );
  assert.deepEqual(spelled.body, [
    { readTime: "<r2>" },
    { readTime: "<t1>" },
    { readTime: "<t1>" },
  ]);
  // Symbols are numbered in sorted key order, whatever order the server sent the keys in.
  const a = normalizeRestResponse(
    200,
    '{"u":"2026-09-24T00:00:01Z","c":"2026-09-24T00:00:02Z"}',
    ctx,
  );
  const b = normalizeRestResponse(
    200,
    '{"c":"2026-09-24T00:00:02Z","u":"2026-09-24T00:00:01Z"}',
    ctx,
  );
  assert.deepEqual(a.body, b.body);
  assert.deepEqual(a.body, { c: "<t1>", u: "<t2>" });
  // Times an hour before the run are still masked; seeded times are not.
  assert.equal(normalizeRestResponse(200, '"2026-09-23T23:00:00Z"', ctx).body, "<t1>");
  assert.equal(
    normalizeRestResponse(200, '"2020-01-01T00:00:00Z"', ctx).body,
    "2020-01-01T00:00:00Z",
  );
});

test("chained instants shift with nanosecond precision and empty chains fail", () => {
  assert.equal(shiftInstant("2026-09-24T00:00:05.123456Z", 0, 1), "2026-09-24T00:00:05.123456001Z");
  assert.equal(
    shiftInstant("2026-09-24T00:00:05.123456Z", 0, -1000),
    "2026-09-24T00:00:05.123455Z",
  );
  assert.equal(shiftInstant("2026-09-24T00:00:05Z", -3660), "2026-09-23T22:59:05Z");
  assert.equal(shiftInstant("2026-09-24T00:00:00.000001Z", 0, -1000), "2026-09-24T00:00:00Z");
  const ctx = local();
  const raw = new Map([["w", { commitTime: "2026-09-24T00:00:05Z", nextPageToken: "" }]]);
  assert.equal(
    resolveValue({ $time: { $from: "w", path: "commitTime", addSeconds: 1 } }, ctx, raw),
    "2026-09-24T00:00:06Z",
  );
  assert.throws(
    () => resolveValue({ $from: "w", path: "nextPageToken" }, ctx, raw),
    /recorded nothing/,
  );
});

test("guards refuse writes and scopes outside the sandbox database", () => {
  const ctx = production();
  const commit = (writes) =>
    buildRestRequest({ id: "c", rpc: "commit", body: { writes } }, ctx, new Map());
  const docs = `projects/${SANDBOX_PROJECT}/databases/(default)/documents`;
  guardRestRequest(commit([{ update: { name: `${docs}/qt/t1`, fields: {} } }]), ctx);
  assert.throws(
    () =>
      guardRestRequest(
        commit([
          {
            update: {
              name: `projects/${SANDBOX_PROJECT}/databases/cfg-x/documents/a/b`,
            },
          },
        ]),
        ctx,
      ),
    /outside the sandbox database/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        commit([
          {
            delete: `projects/${SANDBOX_PROJECT}/databases/cfg-x/documents/a/b`,
          },
        ]),
        ctx,
      ),
    /outside the sandbox database/,
  );
  assert.throws(() => guardRestRequest(commit([{ delete: `${docs}/a/../../x` }]), ctx), /outside/);
  assert.throws(
    () =>
      guardRestRequest(
        buildRestRequest(
          { id: "c", rpc: "commit", body: { transaction: "dA==", writes: [] } },
          ctx,
          new Map(),
        ),
        ctx,
      ),
    /transaction/,
  );
  // A reference value to another database is a compared value, not a target.
  const other = {
    referenceValue: `projects/${SANDBOX_PROJECT}/databases/other-db/documents/qn/d1`,
  };
  guardRestRequest(
    buildRestRequest({ id: "q", rpc: "runQuery", body: { v: other } }, ctx, new Map()),
    ctx,
  );
  assert.throws(() => guardGrpcRequest({ request: { parent: `${docs}X` } }, ctx), /outside/);
  assert.throws(() => guardGrpcRequest({ request: { parent: `${docs}/a/..` } }, ctx), /outside/);
  assert.throws(
    () =>
      guardGrpcRequest(
        {
          request: {
            parent: docs,
            database: `projects/${SANDBOX_PROJECT}/databases/(default)`,
          },
        },
        ctx,
      ),
    /outside/,
  );
  assert.throws(
    () =>
      validateCorpus([
        {
          id: "fs-query-index/x/y",
          steps: [
            {
              id: "a",
              rpc: "runQuery",
              transport: "grpc",
              body: { parent: docs },
            },
          ],
        },
      ]),
    /own scope/,
  );
});

test("gRPC conversion keeps null, and Struct values project to plain JSON", () => {
  assert.deepEqual(toGrpcMessage({ value: { nullValue: null } }), {
    value: { nullValue: "NULL_VALUE" },
  });
  const struct = {
    fields: {
      properties: { stringValue: "(a ASC)", kind: "stringValue" },
      zero: { numberValue: 0, kind: "numberValue" },
      no: { boolValue: false, kind: "boolValue" },
      nothing: { nullValue: "NULL_VALUE", kind: "nullValue" },
    },
  };
  assert.deepEqual(projectGrpcMessage({ planSummary: { indexesUsed: [struct] } }), {
    planSummary: {
      indexesUsed: [{ properties: "(a ASC)", zero: 0, no: false, nothing: null }],
    },
  });
});

test("status details decode ErrorInfo and Help", () => {
  const field = (number, bytes) =>
    Buffer.concat([Buffer.from([(number << 3) | 2, bytes.length]), bytes]);
  const str = (value) => Buffer.from(value);
  const errorInfo = Buffer.concat([
    field(1, str("PIPELINE_REQUIRES_ENTERPRISE_EDITION")),
    field(2, str("firestore.googleapis.com")),
    field(3, Buffer.concat([field(1, str("k")), field(2, str("v"))])),
  ]);
  assert.deepEqual(
    decodeStatusDetail({
      typeUrl: "type.googleapis.com/google.rpc.ErrorInfo",
      bytes: errorInfo.toString("base64"),
    }),
    {
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      reason: "PIPELINE_REQUIRES_ENTERPRISE_EDITION",
      domain: "firestore.googleapis.com",
      metadata: { k: "v" },
    },
  );
  const help = field(1, Buffer.concat([field(1, str("Learn more")), field(2, str("https://x"))]));
  assert.deepEqual(
    decodeStatusDetail({
      typeUrl: "type.googleapis.com/google.rpc.Help",
      bytes: help.toString("base64"),
    }),
    {
      "@type": "type.googleapis.com/google.rpc.Help",
      links: [{ description: "Learn more", url: "https://x" }],
    },
  );
  assert.deepEqual(decodeStatusDetail({ typeUrl: "t/other", bytes: "AQ==" }), {
    "@type": "t/other",
    bytes: "AQ==",
  });
});

test("the cost estimate stays under the per-task budget", () => {
  const usd = estimatedUsd(PROGRAMS, 2);
  assert.ok(usd > 0.01 && usd < 10, `estimate ${usd}`);
});

test("answers echoing a requested read time share its symbol; embedded times are masked", () => {
  const ctx = production();
  const answer = normalizeStep(
    {
      transport: "rest",
      request: { readTime: "2026-09-23T23:00:00.000001Z" },
      response: {
        status: 400,
        text: JSON.stringify({
          error: { message: "read at 2026-09-23T23:00:00.000001Z is too old" },
        }),
      },
    },
    ctx,
    new Map(),
  );
  assert.equal(answer.body.error.message, "read at <r1> is too old");
  const withNumber = createContext({
    run: "1",
    startedMs: started,
    target: {
      kind: "production",
      token: "t",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: "123456789012",
    },
  });
  assert.equal(
    normalizeRestResponse(429, '{"consumer":"projects/123456789012"}', withNumber).body.consumer,
    "projects/<project-number>",
  );
  assert.throws(() => scanFixture("project_number: 123456789012", []), /numeric project name/);
});

test("guards refuse transforms of other databases and transactions", () => {
  const ctx = production();
  const commit = (body) => buildRestRequest({ id: "c", rpc: "commit", body }, ctx, new Map());
  assert.throws(
    () =>
      guardRestRequest(
        commit({
          writes: [
            {
              transform: {
                document: `projects/${SANDBOX_PROJECT}/databases/cfg-x/documents/a/b`,
              },
            },
          ],
        }),
        ctx,
      ),
    /outside the sandbox database/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        buildRestRequest(
          { id: "q", rpc: "runQuery", body: { newTransaction: {} } },
          ctx,
          new Map(),
        ),
        ctx,
      ),
    /transaction/,
  );
});

test("a saved raw recording normalizes again to the same rows", () => {
  const program = {
    id: "fs-query-index/x/y",
    steps: [
      { id: "w", rpc: "commit" },
      { id: "q", rpc: "runQuery" },
      { id: "u", rpc: "runQuery" },
    ],
  };
  const raw = {
    w: {
      transport: "rest",
      response: { status: 200, text: '{"commitTime":"2026-09-24T00:00:05Z"}' },
    },
    q: {
      transport: "rest",
      request: { readTime: "2026-09-24T00:00:05Z" },
      response: { status: 200, text: '[{"readTime":"2026-09-24T00:00:05Z"}]' },
    },
  };
  const unresolved = { status: -1, unresolved: "step x recorded nothing at y" };
  const recording = {
    context: { run: "7", startedMs: started },
    results: { [program.id]: { steps: { u: unresolved }, raw } },
  };
  const again = renormalize(recording, [program]).results[program.id].steps;
  assert.deepEqual(again, {
    w: { status: 200, body: { commitTime: "<t1>" } },
    q: { status: 200, body: [{ readTime: "<r1>" }] },
    u: unresolved,
  });
});

test("approved divergences remove only what their decision names", async () => {
  const { approvedDivergence } = await import("./fs-query-index/divergences.mjs");
  const inequality = "fs-query-index/query-limits/not-in-and-inequalities#inequality-fields-11";
  const refusal = (message) => ({
    status: 400,
    body: [{ error: { code: 400, message, status: "INVALID_ARGUMENT" } }],
  });
  assert.equal(
    approvedDivergence(
      inequality,
      refusal("fields: [f1, f0]. more"),
      refusal("fields: [f0, f1]. more"),
    ),
    "S4",
  );
  // Another field, or other text, is still a mismatch; so is an unlisted row.
  assert.equal(
    approvedDivergence(inequality, refusal("fields: [f1, f0]."), refusal("fields: [f0, f2].")),
    undefined,
  );
  assert.equal(
    approvedDivergence(inequality, refusal("fields: [f1, f0]."), refusal("Fields: [f0, f1].")),
    undefined,
  );
  assert.equal(
    approvedDivergence(
      "fs-query-index/query-limits/not-in-and-inequalities#inequality-fields-10",
      refusal("[b, a]"),
      refusal("[a, b]"),
    ),
    undefined,
  );
  const merge = "fs-query-index/explain/merge-order#larger-earlier-field-analyze";
  const explain = (members, entries, docs = "1") => ({
    status: 200,
    body: [
      {
        explainMetrics: {
          executionStats: {
            debugStats: { documents_scanned: docs, index_entries_scanned: entries },
          },
          planSummary: { indexesUsed: members.map((properties) => ({ properties })) },
        },
      },
    ],
  });
  // larger-earlier-field: `b == 2` has 2 entries and `a == 0` has 7 (with c) in its seed, so
  // any walk that returns one document reads between 2 and 9 entries.
  const [A, B, C] = ["a", "b", "c"].map((field) => `(${field} ASC, c ASC, __name__ ASC)`);
  // Members in another order, and the walk's entry count that follows from it.
  assert.equal(approvedDivergence(merge, explain([B, A], "5"), explain([A, B], "6")), "S4");
  // Another member, another document count, or the same order with another entry count.
  assert.equal(approvedDivergence(merge, explain([B, A], "5"), explain([A, C], "5")), undefined);
  assert.equal(
    approvedDivergence(merge, explain([B, A], "5"), explain([A, B], "5", "2")),
    undefined,
  );
  assert.equal(approvedDivergence(merge, explain([B, A], "5"), explain([B, A], "6")), undefined);
  // An entry count outside what any join order reads is not.
  assert.equal(approvedDivergence(merge, explain([B, A], "5"), explain([A, B], "10")), undefined);
  assert.equal(approvedDivergence(merge, explain([B, A], "5"), explain([A, B], "1")), undefined);
  assert.equal(approvedDivergence(merge, explain([B, A], "5"), explain([A, B], "9")), "S4");
  const docs = "projects/demo-fs-query-index/databases/(default)/documents";
  const partition = "fs-query-index/partition-query/large-group#count-2";
  const cursors = (...keys) => ({
    status: 200,
    body: { partitions: keys.map((key) => ({ values: [{ referenceValue: key }] })) },
  });
  const sample = (parent, id) => `${docs}/qroot/r${parent}/qp/d${String(id).padStart(5, "0")}`;
  assert.equal(
    approvedDivergence(
      partition,
      cursors(sample(1, 550), sample(1, 892)),
      cursors(sample(0, 855), sample(2, 17)),
    ),
    "S5",
  );
  // Fewer cursors, a cursor carrying before, or one in another group or database is not.
  assert.equal(
    approvedDivergence(partition, cursors(sample(1, 550), sample(1, 892)), cursors(sample(0, 855))),
    undefined,
  );
  assert.equal(
    approvedDivergence(partition, cursors(sample(1, 550), sample(1, 892)), {
      status: 200,
      body: {
        partitions: [
          { before: true, values: [{ referenceValue: sample(0, 855) }] },
          { values: [{ referenceValue: sample(0, 900) }] },
        ],
      },
    }),
    undefined,
  );
  assert.equal(
    approvedDivergence(
      partition,
      cursors(sample(1, 550), sample(1, 892)),
      cursors(sample(0, 855), `${docs}/qroot/r0/other/d00001`),
    ),
    undefined,
  );
  const everything = "fs-query-index/partition-query/large-group#count-64";
  const many = (count) => cursors(...Array.from({ length: count }, (_, i) => sample(i % 3, i)));
  assert.equal(approvedDivergence(everything, many(14), many(20)), "S5");
  // Fewer than the largest count answered in full, as many as requested, or no cursor at all.
  assert.equal(approvedDivergence(everything, many(14), many(7)), undefined);
  assert.equal(approvedDivergence(everything, many(14), many(64)), undefined);
  // More samples than a group of 2,000 plausibly has, on either side.
  assert.equal(approvedDivergence(everything, many(14), many(28)), undefined);
  assert.equal(approvedDivergence(everything, many(40), many(20)), undefined);
  assert.equal(approvedDivergence(everything, many(14), { status: 200, body: {} }), undefined);
});

test("partition cursors must nest and ranges must add up across rows", async () => {
  const { crossRowChecks, RANGE_ROWS } = await import("./fs-query-index/divergences.mjs");
  const docs = "projects/demo-fs-query-index/databases/(default)/documents";
  const key = (id) => `${docs}/qroot/r0/qp/d${String(id).padStart(5, "0")}`;
  const cursors = (...ids) => ({
    status: 200,
    body: { partitions: ids.map((id) => ({ values: [{ referenceValue: key(id) }] })) },
  });
  const count = (n) => ({
    status: 200,
    body: [{ result: { aggregateFields: { c: { integerValue: String(n) } } } }],
  });
  const counted = (step, ids) => ({
    row: `fs-query-index/partition-query/large-group#${step}`,
    status: "DIVERGENCE_APPROVED",
    production: cursors(1),
    fireemu: cursors(...ids),
  });
  const ranges = (production, fireemu) =>
    RANGE_ROWS.map((row, i) => ({
      row,
      status: "DIVERGENCE_APPROVED",
      production: count(production[i]),
      fireemu: count(fireemu[i]),
    }));
  const good = [
    counted("count-1", [5]),
    counted("count-2", [5, 9]),
    counted("count-3", [2, 5, 9]),
    counted("count-8", [1, 2, 3, 4, 5, 6, 7, 9]),
    counted("count-64", [1, 2, 3, 4, 5, 6, 7, 8, 9]),
  ];
  let checked = crossRowChecks([...good, ...ranges([850, 114, 218, 818], [285, 417, 78, 1220])]);
  assert.deepEqual([...checked.demote], []);
  assert.deepEqual(checked.rangeTotals, { production: "2000", fireemu: "2000" });
  // Ranges that do not add up are demoted.
  checked = crossRowChecks([...good, ...ranges([850, 114, 218, 818], [285, 417, 78, 1219])]);
  assert.deepEqual([...checked.demote].toSorted(), RANGE_ROWS.toSorted());
  // Cursors out of key order, or a count that drops a cursor of a smaller one, are demoted.
  for (const broken of [[counted("count-2", [9, 5])], [counted("count-2", [5, 7])]]) {
    const rows = good.map((row) => broken.find((b) => b.row === row.row) ?? row);
    assert.equal(crossRowChecks(rows).demote.size, 5);
  }
});
