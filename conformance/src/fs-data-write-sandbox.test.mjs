import assert from "node:assert/strict";
import { test } from "node:test";

import {
  compareSandboxArtifact,
  compareRecordings,
  freezeSandboxFixture,
  validateSandboxCorpus,
} from "./fs-data-write-sandbox.mjs";
import { webchannelSessionProgram } from "./firestore-probe/webchannel-request-bytes.mjs";

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

test("valid-session WebChannel programs must equal their fixed four-step shape", () => {
  const program = webchannelSessionProgram(11_534_337);
  const sessionCorpus = { ...corpus, restPrograms: [program], restRequestCount: 4 };
  assert.equal(validateSandboxCorpus(sessionCorpus).requestCount, 4);
  const altered = (change) => ({
    ...sessionCorpus,
    restPrograms: [change(structuredClone(program))],
  });
  for (const change of [
    (value) => ({ ...value, id: "writes/limits/webchannel-request-bytes/11534338" }),
    (value) => {
      value.steps[2].webchannelBodyBytes = 11_534_336;
      return value;
    },
    (value) => {
      value.steps[0].path = value.steps[0].path.replace("fireemu-oracle-sbx", "fireemu-35fe6");
      return value;
    },
    (value) => {
      value.steps[3].method = "POST";
      return value;
    },
    (value) => {
      value.steps[1].body = { database: "x" };
      return value;
    },
    (value) => {
      value.steps.reverse();
      return value;
    },
  ]) {
    assert.throws(() => validateSandboxCorpus(altered(change)), /sandbox WebChannel/);
  }
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...sessionCorpus,
        restPrograms: [{ ...program, steps: program.steps.slice(0, 3) }],
        restRequestCount: 3,
      }),
    /sandbox WebChannel/,
  );
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [
          {
            id: program.id,
            area: "writes",
            steps: [
              {
                id: "read",
                method: "GET",
                path: "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents/a/b",
              },
            ],
          },
        ],
        restRequestCount: 1,
      }),
    /sandbox WebChannel/,
  );
  // A session step outside its program is refused too.
  assert.throws(
    () =>
      validateSandboxCorpus({
        ...corpus,
        restPrograms: [{ id: "writes/other", area: "writes", steps: [program.steps[0]] }],
        restRequestCount: 1,
      }),
    /sandbox WebChannel/,
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

test("an eleven-mebibyte body is stored compact and padded to its exact size before sending", async () => {
  const { padJsonBody, PADDED_BODY_SIZES } = await import("./fs-data-write-sandbox.mjs");
  const body = '{"documents":["x"]}';
  for (const size of PADDED_BODY_SIZES) {
    const padded = padJsonBody(body, size);
    assert.equal(Buffer.byteLength(padded), size);
    assert.deepEqual(JSON.parse(padded), JSON.parse(body));
    assert.ok(padded.startsWith(body.slice(0, -1)) && padded.endsWith(" }"));
  }
  assert.throws(() => padJsonBody(body, 10_485_760), /invalid padded/);
  assert.throws(() => padJsonBody('{"a":1', 11_534_336), /invalid padded/);
  assert.throws(() => padJsonBody("[1]", 11_534_336), /invalid padded/);
});

test("a dropped connection is a complete answer only on a WebChannel measured body", async () => {
  const { assertCompleteRecording } = await import("./fs-data-write-sandbox.mjs");
  const program = webchannelSessionProgram(16_777_217);
  const sessionCorpus = { ...corpus, restPrograms: [program], restRequestCount: 4 };
  const ok = (body) => ({ status: 200, code: "OK", body });
  const recording = (boundary, control = ok("forward-ack")) => ({
    [program.id]: {
      steps: {
        handshake: ok("session-opened"),
        control,
        boundary,
        terminate: ok("session-terminated"),
      },
    },
  });
  const reset = (message) => ({ status: 0, code: "connection-reset", message });
  for (const phase of ["reset-before-response", "reset-during-response"]) {
    assertCompleteRecording(sessionCorpus, recording(reset(phase)), {});
  }
  for (const [label, rows] of [
    ["unknown phase", recording(reset("reset-somewhere"))],
    ["reset on the control", recording(ok("forward-ack"), reset("reset-before-response"))],
    ["untyped failure", recording({ status: 0, code: "probe-error", message: "fetch failed" })],
  ]) {
    assert.throws(
      () => assertCompleteRecording(sessionCorpus, rows, {}),
      /failed observation/,
      label,
    );
  }
  // A reset is frozen only when both recordings answered the same way.
  const frozen = freezeSandboxFixture({
    corpus: sessionCorpus,
    first: recording(reset("reset-before-response")),
    second: recording(reset("reset-before-response")),
    recordedAt: ["2026-09-27T00:00:00Z", "2026-09-27T00:10:00Z"],
    harnessRevision: "a".repeat(40),
    sdkVersions: {},
    credentialToken: "token-for-leak-check",
  });
  assert.deepEqual(frozen.programs[program.id].steps.boundary, reset("reset-before-response"));
  for (const second of [
    recording(reset("reset-during-response")),
    recording({ status: 400, code: "INVALID_ARGUMENT", message: "Request payload size" }),
  ]) {
    assert.throws(
      () =>
        freezeSandboxFixture({
          corpus: sessionCorpus,
          first: recording(reset("reset-before-response")),
          second,
          recordedAt: ["2026-09-27T00:00:00Z", "2026-09-27T00:10:00Z"],
          harnessRevision: "a".repeat(40),
          sdkVersions: {},
          credentialToken: "token-for-leak-check",
        }),
      /nondeterministic/,
    );
  }
});
