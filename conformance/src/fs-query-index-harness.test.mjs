import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS } from "./fs-query-index/corpus.mjs";
import { scanFixture } from "./fs-query-index/fixture-scan.mjs";
import {
  RECORDED_PROJECT,
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
  projectGrpcMessage,
  resolveValue,
  toGrpcMessage,
  validateCorpus,
} from "./fs-query-index/harness.mjs";
import { classify, indexKey, selectPrograms } from "./fs-query-index/run.mjs";

const started = Date.parse("2026-09-24T00:00:00Z");
const production = () =>
  createContext({
    run: "1",
    startedMs: started,
    target: { kind: "production", token: "ya29.secret-token-value", quotaProject: SANDBOX_PROJECT },
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
    init: { method: "POST", headers: { "content-type": "application/json" }, body },
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
      body: { structuredQuery: { limit: 3, findNearest: { limit: 2, distanceThreshold: "NaN" } } },
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
        { request: { parent: `projects/${SANDBOX_PROJECT}/databases/named/documents` } },
        ctx,
      ),
    /outside/,
  );
});

test("REST JSON converts to gRPC message form", () => {
  assert.deepEqual(toGrpcMessage({ readTime: "2026-09-24T00:00:01.5Z" }), {
    readTime: { seconds: String(Date.parse("2026-09-24T00:00:01Z") / 1000), nanos: 500_000_000 },
  });
  assert.deepEqual(toGrpcMessage({ doubleValue: "-Infinity" }), { doubleValue: -Infinity });
  assert.deepEqual(toGrpcMessage({ bytesValue: "AQI=" }).bytesValue, Buffer.from([1, 2]));
  assert.deepEqual(toGrpcMessage({ count: { upTo: "3" } }), { count: { upTo: { value: "3" } } });
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
        createTime: "<run-time>",
        fields: { t: { timestampValue: "2020-01-01T00:00:00Z" } },
      },
      readTime: "<run-time>",
      explainMetrics: { executionStats: { executionDuration: "<duration>" } },
    },
    { nextPageToken: "<page-token>", transaction: "<transaction>" },
  ]);
  assert.throws(
    () => normalizeRestResponse(200, JSON.stringify({ executionDuration: "fast" }), ctx),
    /unexpected executionDuration/,
  );
  assert.deepEqual(normalizeRestResponse(400, "<html>", ctx), { status: 400, nonJson: "<html>" });
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
        debugStats: { fields: { a: { stringValue: "1", kind: "stringValue" } } },
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
    explainMetrics: { executionStats: { executionDuration: "0.0012s", debugStats: { a: "1" } } },
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
    isTransient({ status: 400, body: [{ error: { status: "INVALID_ARGUMENT" } }] }),
    false,
  );
  assert.equal(
    isTransient({ status: 200, body: [{ error: { status: "RESOURCE_EXHAUSTED" } }] }),
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
    classify({ production: ok, alternative: { status: 201 }, fireemu: { status: 201 } }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(classify({ production: ok, fireemu: { status: 503 } }), "INDETERMINATE");
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
