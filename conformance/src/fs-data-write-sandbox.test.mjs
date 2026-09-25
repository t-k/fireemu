import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareSandboxArtifact,
  compareRecordings,
  freezeSandboxFixture,
  validateSandboxCorpus,
} from "./fs-data-write-sandbox.mjs";

test("artifact comparison distinguishes production error reasons as well as status and code", () => {
  const production = {
    programs: {
      "writes/control": {
        steps: {
          read: { status: 400, code: "INVALID_ARGUMENT", message: "production detail" },
          write: { status: 200, code: "OK", body: { fields: { b: 2, a: 1 } } },
        },
      },
    },
    streams: { "writes/stream": { status: { code: 0 }, events: [{ type: "end" }] } },
  };
  const local = {
    "writes/control": {
      steps: {
        read: { status: 400, code: "INVALID_ARGUMENT", message: "local detail" },
        write: { status: 200, code: "OK", body: { fields: { a: 1, b: 2 } } },
      },
    },
  };
  assert.deepEqual(compareSandboxArtifact(production, local, production.streams), [
    "writes/control#read",
  ]);
  local["writes/control"].steps.write.body.fields.a = 3;
  assert.deepEqual(compareSandboxArtifact(production, local, production.streams), [
    "writes/control#read",
    "writes/control#write",
  ]);
  local["writes/control"].steps.write.body.fields.a = 1;
  assert.deepEqual(
    compareSandboxArtifact(production, local, {
      "writes/stream": { status: { code: 3 }, events: [{ type: "end" }] },
    }),
    ["writes/control#read", "writes/stream#grpc"],
  );
});

test("stream comparison preserves stable content-disposition and excludes only volatile tracking IDs", () => {
  const productionTrailers = [
    { key: "content-disposition", kind: "ascii", value: "attachment" },
    { key: "x-debug-tracking-id", kind: "ascii", value: "production-id" },
  ];
  const terminal = (code, trailers, eventType = "status") => ({
    status: { code, details: "", trailers },
    events: [
      { type: "data", value: { streamId: "handshake", streamToken: "token", writeResults: [] } },
      { type: eventType, value: { code, details: "", trailers } },
      { type: "end" },
    ],
    sentFrames: 1,
  });
  const production = { streams: { "writes/stream": terminal(0, productionTrailers) } };
  const local = { "writes/stream": terminal(0, []) };

  assert.deepEqual(compareSandboxArtifact(production, {}, local), ["writes/stream#grpc"]);
  const stableLocal = [
    { key: "content-disposition", kind: "ascii", value: "attachment" },
    { key: "x-debug-tracking-id", kind: "ascii", value: "local-id" },
  ];
  assert.deepEqual(
    compareSandboxArtifact(production, {}, { "writes/stream": terminal(0, stableLocal) }),
    [],
  );
  assert.deepEqual(production.streams["writes/stream"].status.trailers, productionTrailers);
  assert.deepEqual(compareSandboxArtifact(production, {}, { "writes/stream": terminal(3, []) }), [
    "writes/stream#grpc",
  ]);
  assert.deepEqual(
    compareSandboxArtifact(production, {}, { "writes/stream": terminal(0, [], "error") }),
    ["writes/stream#grpc"],
  );
  const changedData = terminal(0, []);
  changedData.events[0].value.streamToken = "different-token";
  assert.deepEqual(compareSandboxArtifact(production, {}, { "writes/stream": changedData }), [
    "writes/stream#grpc",
  ]);
  const changedDetails = terminal(0, []);
  changedDetails.status.details = "different detail";
  assert.deepEqual(compareSandboxArtifact(production, {}, { "writes/stream": changedDetails }), [
    "writes/stream#grpc",
  ]);
  const missingEnd = terminal(0, []);
  missingEnd.events.pop();
  assert.deepEqual(compareSandboxArtifact(production, {}, { "writes/stream": missingEnd }), [
    "writes/stream#grpc",
  ]);
  assert.deepEqual(
    compareSandboxArtifact(
      production,
      {},
      {
        "writes/stream": terminal(0, [
          { key: "grpc-status-details-bin", kind: "binary", value: "x" },
        ]),
      },
    ),
    ["writes/stream#grpc"],
  );
});

test("artifact comparison ignores only BatchGet response ordering", () => {
  const response = (name) => ({
    missing: `projects/demo-firestore-probe/databases/(default)/documents/c/${name}`,
  });
  const production = {
    programs: {
      "writes/readback": {
        steps: { get: { status: 200, code: "OK", body: [response("b"), response("a")] } },
      },
      "writes/ordered": {
        steps: { list: { status: 200, code: "OK", body: [response("b"), response("a")] } },
      },
    },
  };
  const local = {
    "writes/readback": {
      steps: { get: { status: 200, code: "OK", body: [response("a"), response("b")] } },
    },
    "writes/ordered": {
      steps: { list: { status: 200, code: "OK", body: [response("a"), response("b")] } },
    },
  };
  const recipes = {
    restPrograms: [
      {
        id: "writes/readback",
        steps: [
          {
            id: "get",
            method: "POST",
            path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:batchGet",
          },
        ],
      },
      {
        id: "writes/ordered",
        steps: [
          {
            id: "list",
            method: "POST",
            path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:runQuery",
          },
        ],
      },
    ],
  };
  assert.deepEqual(compareSandboxArtifact(production, local, {}, recipes), ["writes/ordered#list"]);
  const unicodeProduction = {
    programs: {
      "writes/readback": {
        steps: { get: { status: 200, code: "OK", body: [response("é"), response("e\u0301")] } },
      },
    },
  };
  const unicodeLocal = {
    "writes/readback": {
      steps: { get: { status: 200, code: "OK", body: [response("e\u0301"), response("é")] } },
    },
  };
  assert.deepEqual(compareSandboxArtifact(unicodeProduction, unicodeLocal, {}, recipes), []);
});

const step = {
  id: "read",
  method: "GET",
  path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents/c/x",
};
const corpus = {
  schemaVersion: 1,
  restPrograms: [{ id: "writes/control", area: "writes", steps: [step] }],
  streamRecipes: [],
  restRequestCount: 1,
};

test("sandbox corpus refuses a route, method, or header outside its bounded project", () => {
  assert.equal(validateSandboxCorpus(corpus).requestCount, 1);
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            ...corpus.restPrograms[0],
            steps: [{ ...step, path: step.path.replace("fireemu-oracle-sbx", "fireemu-35fe6") }],
          },
        ],
      }),
    /sandbox project/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [{ ...corpus.restPrograms[0], steps: [{ ...step, method: "DELETE" }] }],
      }),
    /method/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            ...corpus.restPrograms[0],
            steps: [{ ...step, headers: { authorization: "Bearer secret" } }],
          },
        ],
      }),
    /headers/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          { ...corpus.restPrograms[0], steps: [{ ...step, path: `${step.path}/../../other` }] },
        ],
      }),
    /path traversal/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            ...corpus.restPrograms[0],
            steps: [
              {
                ...step,
                body: { documents: ["projects/fireemu-35fe6/databases/(default)/documents/c/x"] },
              },
            ],
          },
        ],
      }),
    /request body escaped/,
  );
});

test("DELETE is accepted only for bounded near-limit REST route recipes", () => {
  const base = "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents";
  const routeProgram = (route) => {
    const count = 12_112;
    const collection = `del${route.replaceAll("-", "")}${count}DELETE_RUN_ID`.padEnd(979, "c");
    const resource = `projects/fireemu-oracle-sbx/databases/(default)/documents/${collection}/d`;
    return {
      id: `writes/limits/near-limit-delete-refusal/${route}/${count}`,
      area: "writes",
      steps: [
        {
          id: "seed",
          method: "POST",
          path: `${base}:commit`,
          body: {
            writes: [
              {
                update: {
                  name: resource,
                  fields: {
                    a: {
                      arrayValue: {
                        values: Array.from({ length: count }, (_, index) => ({
                          integerValue: String(index),
                        })),
                      },
                    },
                  },
                },
              },
            ],
          },
        },
        { id: "before-delete", method: "GET", path: `/v1/${resource}` },
        route === "rest"
          ? { id: "delete", method: "DELETE", path: `/v1/${resource}` }
          : {
              id: "delete",
              method: "POST",
              path: `${base}:${route === "commit" ? "commit" : "batchWrite"}`,
              body: { writes: [{ delete: resource }] },
            },
        {
          id: "after-delete",
          method: "POST",
          path: `${base}:batchGet`,
          body: { documents: [resource] },
        },
        {
          id: "group-after-delete",
          method: "POST",
          path: `${base}:runQuery`,
          body: {
            structuredQuery: {
              from: [
                {
                  collectionId: resource.split("/documents/")[1].split("/")[0],
                  allDescendants: true,
                },
              ],
              select: { fields: [{ fieldPath: "__name__" }] },
              limit: 2,
            },
          },
        },
      ],
    };
  };
  const corpusFor = (route) => {
    const program = routeProgram(route);
    return { ...corpus, restPrograms: [program], restRequestCount: program.steps.length };
  };
  for (const route of ["rest", "commit", "batch-write"]) {
    assert.equal(validateSandboxCorpus(corpusFor(route)).requestCount, 5);
  }
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpusFor("rest"),
        restPrograms: [{ ...routeProgram("rest"), id: "writes/unbounded-delete" }],
      }),
    /unsupported sandbox method/,
  );
});

test("WebChannel byte probes are limited to the fixed sandbox unknown-session route", () => {
  const channel = {
    id: "writes/limits/webchannel-request-bytes/10485760",
    area: "writes",
    steps: [
      {
        id: "unknown-session",
        method: "POST",
        path: "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8&RID=1&SID=missing-fireemu-byte-probe&AID=0",
        webchannelBodyBytes: 10_485_760,
      },
    ],
  };
  const channelCorpus = { ...corpus, restPrograms: [channel], restRequestCount: 1 };
  assert.equal(validateSandboxCorpus(channelCorpus).requestCount, 1);
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...channelCorpus,
        restPrograms: [
          {
            ...channel,
            steps: [
              {
                ...channel.steps[0],
                path: channel.steps[0].path.replace("fireemu-oracle-sbx", "fireemu-35fe6"),
              },
            ],
          },
        ],
      }),
    /sandbox WebChannel route/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...channelCorpus,
        restPrograms: [
          { ...channel, steps: [{ ...channel.steps[0], webchannelBodyBytes: 10_485_762 }] },
        ],
      }),
    /WebChannel body size/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...channelCorpus,
        restPrograms: [{ ...channel, steps: [{ ...channel.steps[0], method: "GET" }] }],
      }),
    /sandbox WebChannel route/,
  );
});

test("two recordings must agree row by row before a fixture can be frozen", () => {
  const first = { "writes/control": { steps: { read: { status: 404, code: "NOT_FOUND" } } } };
  const second = { "writes/control": { steps: { read: { code: "NOT_FOUND", status: 404 } } } };
  assert.deepEqual(compareRecordings(first, second), []);
  second["writes/control"].steps.read.status = 200;
  assert.deepEqual(compareRecordings(first, second), ["writes/control#read"]);
  assert.throws(
    () =>
      freezeSandboxFixture({
        corpus,
        first,
        second,
        recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
        harnessRevision: "a".repeat(40),
        sdkVersions: { firebaseAdmin: "14.3.2" },
        credentialToken: "private-test-token",
      }),
    /nondeterministic/,
  );
  const unavailable = { "writes/control": { steps: { read: { status: 0, code: "no-response" } } } };
  assert.throws(
    () =>
      freezeSandboxFixture({
        corpus,
        first: unavailable,
        second: unavailable,
        recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
        harnessRevision: "a".repeat(40),
        sdkVersions: { firebaseAdmin: "14.3.2" },
        credentialToken: "private-test-token",
      }),
    /failed observation/,
  );
});

test("fixture binds recipe and time while omitting the real project and token", () => {
  const observed = { "writes/control": { steps: { read: { status: 404, code: "NOT_FOUND" } } } };
  const fixture = freezeSandboxFixture({
    corpus,
    first: observed,
    second: observed,
    recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
    harnessRevision: "a".repeat(40),
    sdkVersions: { firebaseAdmin: "14.3.2" },
    credentialToken: "private-test-token",
  });
  assert.match(fixture.evidence.corpusSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(fixture.evidence.recordedAt, ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"]);
  assert.equal(fixture.evidence.project, "demo-firestore-probe");
  assert.deepEqual(fixture.programs, observed);
  assert.ok(!JSON.stringify(fixture).includes("fireemu-oracle-sbx"));
});

test("fixture refuses an OAuth bearer echoed into a REST error body", () => {
  const token = "private-test-token";
  const observed = {
    "writes/control": {
      steps: {
        read: { status: 400, code: "INVALID_ARGUMENT", body: { error: { message: token } } },
      },
    },
  };
  assert.throws(
    () =>
      freezeSandboxFixture({
        corpus,
        first: observed,
        second: observed,
        recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
        harnessRevision: "a".repeat(40),
        sdkVersions: { firebaseAdmin: "14.3.2" },
        credentialToken: token,
      }),
    /credential/,
  );
});

test("fixture accepts a unary gRPC byte probe, which has a status and no stream events", () => {
  const unary = {
    id: "writes/limits/grpc-unary-request-bytes/10485760",
    transport: "grpc",
    action: "get-document-transaction-bytes",
    wireBytes: 10485760,
    maxFrames: 1,
  };
  const withUnary = { ...corpus, streamRecipes: [unary] };
  const rest = { "writes/control": { steps: { read: { status: 404, code: "NOT_FOUND" } } } };
  const options = {
    corpus: withUnary,
    first: rest,
    second: rest,
    recordedAt: ["2026-09-25T00:00:00Z", "2026-09-25T00:01:00Z"],
    harnessRevision: "a".repeat(40),
    sdkVersions: { firebaseAdmin: "14.3.0" },
    credentialToken: "private-test-token",
  };
  // The shape the production unary child records (stream-session.mjs).
  const observed = {
    [unary.id]: {
      sentFrames: 1,
      status: { code: 3, details: "Invalid transaction.", trailers: [] },
      wireBytes: 10485760,
    },
  };
  const frozen = freezeSandboxFixture({
    ...options,
    firstStream: observed,
    secondStream: observed,
  });
  assert.equal(frozen.streams[unary.id].status.code, 3);
  // A unary result still needs an integer status and the exact wire size it was asked for.
  for (const broken of [
    { ...observed[unary.id], status: {} },
    { ...observed[unary.id], wireBytes: 10485761 },
  ]) {
    const recording = { [unary.id]: broken };
    assert.throws(
      () => freezeSandboxFixture({ ...options, firstStream: recording, secondStream: recording }),
      /incomplete stream recording/,
    );
  }
  // A stream recipe still needs its events.
  const stream = {
    ...unary,
    id: "writes/limits/grpc-stream-request-bytes/10485760",
    action: "write-stream-token-bytes",
  };
  const streamResult = { [stream.id]: { sentFrames: 1, status: { code: 0 }, wireBytes: 10485760 } };
  assert.throws(
    () =>
      freezeSandboxFixture({
        ...options,
        corpus: { ...corpus, streamRecipes: [stream] },
        firstStream: streamResult,
        secondStream: streamResult,
      }),
    /incomplete stream recording/,
  );
});

test("fixture cannot omit or hide drift in live gRPC stream observations", () => {
  const withStream = {
    ...corpus,
    streamRecipes: [
      {
        id: "writes/write-stream-terminal/half-close",
        transport: "grpc",
        action: "half-close-after-handshake",
        maxFrames: 1,
      },
    ],
  };
  const rest = { "writes/control": { steps: { read: { status: 404, code: "NOT_FOUND" } } } };
  const options = {
    corpus: withStream,
    first: rest,
    second: rest,
    recordedAt: ["2026-09-23T00:00:00Z", "2026-09-23T00:01:00Z"],
    harnessRevision: "a".repeat(40),
    sdkVersions: { firebaseAdmin: "14.3.0" },
    credentialToken: "private-test-token",
  };
  assert.throws(() => freezeSandboxFixture(options), /stream recording/);
  const firstStream = {
    "writes/write-stream-terminal/half-close": { status: { code: 0 }, events: [{ type: "end" }] },
  };
  const secondStream = {
    "writes/write-stream-terminal/half-close": { status: { code: 3 }, events: [{ type: "end" }] },
  };
  assert.throws(
    () => freezeSandboxFixture({ ...options, firstStream, secondStream }),
    /nondeterministic stream/,
  );
  assert.ok(
    freezeSandboxFixture({ ...options, firstStream, secondStream: firstStream }).evidence
      .streamRecordingDigests.length === 2,
  );
});
