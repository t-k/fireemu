import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS } from "./fs-list/corpus.mjs";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  guardGrpcRequest,
  guardRestRequest,
  normalizeStep,
  projectGrpcMessage,
  validateCorpus,
} from "./fs-query-index/harness.mjs";
import { LANES, selectLane } from "./fs-query-index/lanes.mjs";
import { estimatedUsd, renormalize, withRecordingLock } from "./fs-query-index/run.mjs";

const started = Date.parse("2026-09-24T00:00:00Z");
const production = () =>
  createContext({
    run: "1",
    startedMs: started,
    target: { kind: "production", token: "ya29.secret", quotaProject: SANDBOX_PROJECT },
  });
const docs = `projects/${SANDBOX_PROJECT}/databases/(default)/documents`;

test("the list corpus validates only under its own lane and stays within budget", () => {
  const requests = validateCorpus(PROGRAMS, "fs-data-write-list");
  assert.ok(requests > 100, `corpus has ${requests} recorded requests`);
  assert.throws(() => validateCorpus(PROGRAMS), /program id must be fs-query-index/);
  assert.ok(estimatedUsd(PROGRAMS, 2) < 1);
  for (const program of PROGRAMS) assert.match(program.id, /^fs-data-write-list\//);
});

test("lanes select their own corpus, fixture and ledger task", () => {
  assert.equal(selectLane("fs-data-write-list").taskId, "FS-DATA-WRITE-LIST");
  assert.equal(selectLane("fs-query-index").fixture, "fs-query-index-production.json");
  assert.throws(() => selectLane("fs-other"), /unknown sandbox lane/);
  assert.notEqual(LANES["fs-data-write-list"].fixture, LANES["fs-query-index"].fixture);
});

test("a REST listDocuments step is a GET with ordered, repeatable, chained parameters", () => {
  const ctx = production();
  const raw = new Map([["first", { nextPageToken: "tok/en+=" }]]);
  const request = buildRestRequest(
    {
      id: "a",
      rpc: "listDocuments",
      parent: "lst/d01",
      collectionId: "sub",
      query: [
        ["mask.fieldPaths", "a"],
        ["mask.fieldPaths", "m.p"],
        ["pageToken", { $from: "first", path: "nextPageToken" }],
        ["orderBy", "a desc, b"],
      ],
    },
    ctx,
    raw,
  );
  assert.equal(request.init.method, "GET");
  assert.equal(request.init.body, undefined);
  assert.equal(
    request.url,
    `https://firestore.googleapis.com/v1/${docs}/lst/d01/sub?mask.fieldPaths=a&mask.fieldPaths=m.p&pageToken=tok%2Fen%2B%3D&orderBy=a%20desc%2C%20b`,
  );
  guardRestRequest(request, ctx);
  const plain = buildRestRequest({ id: "b", rpc: "listDocuments", collectionId: "lst" }, ctx, raw);
  assert.equal(plain.url, `https://firestore.googleapis.com/v1/${docs}/lst`);
  guardRestRequest(plain, ctx);
});

test("the guard allows query parameters only on a GET and only reviewed ones", () => {
  const ctx = production();
  const headers = { authorization: "Bearer x" };
  const get = (query) => ({
    url: `https://firestore.googleapis.com/v1/${docs}/lst?${query}`,
    init: { method: "GET", headers },
  });
  guardRestRequest(get("pageSize=2&showMissing=true&readTime=2099-01-01T00%3A00%3A00Z"), ctx);
  assert.throws(() => guardRestRequest(get("key=x"), ctx), /not reviewed/);
  assert.throws(() => guardRestRequest(get("$alt=json"), ctx), /not reviewed/);
  assert.throws(
    () => guardRestRequest(get("pageToken=projects%2Fother%2Fdatabases"), ctx),
    /another project/,
  );
  assert.throws(() => guardRestRequest(get("pageSize=1?x"), ctx), /not canonical/);
  assert.throws(
    () =>
      guardRestRequest(
        {
          url: `https://firestore.googleapis.com/v1/${docs}:runQuery?pageSize=1`,
          init: { method: "POST", headers },
        },
        ctx,
      ),
    /only a GET/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        {
          url: `https://firestore.googleapis.com/v1/projects/other/databases/(default)/documents/lst?pageSize=1`,
          init: { method: "GET", headers },
        },
        ctx,
      ),
    /outside the sandbox/,
  );
});

test("validation refuses list steps that could leave the reviewed shape", () => {
  const program = (step) => [{ id: "fs-data-write-list/x/y", steps: [{ id: "a", ...step }] }];
  const lane = "fs-data-write-list";
  assert.throws(
    () => validateCorpus(program({ rpc: "runQuery", query: [["pageSize", "1"]] }), lane),
    /only a REST listDocuments step takes a query/,
  );
  assert.throws(
    () =>
      validateCorpus(
        program({ rpc: "listDocuments", transport: "grpc", query: [["pageSize", "1"]] }),
        lane,
      ),
    /only a REST listDocuments step takes a query/,
  );
  assert.throws(
    () =>
      validateCorpus(
        program({ rpc: "listDocuments", collectionId: "lst", query: [["key", "x"]] }),
        lane,
      ),
    /not reviewed/,
  );
  for (const collectionId of [undefined, "", "a/b", "..%2F", "a?b"]) {
    assert.throws(
      () => validateCorpus(program({ rpc: "listDocuments", collectionId }), lane),
      /names one collection/,
    );
  }
  assert.throws(
    () =>
      validateCorpus(
        program({ rpc: "listDocuments", transport: "grpc", body: { parent: "x" } }),
        lane,
      ),
    /must not set its own scope/,
  );
});

test("gRPC list requests are scoped to the step parent and convert their read time", () => {
  const ctx = production();
  const built = buildGrpcRequest(
    {
      id: "a",
      rpc: "listDocuments",
      transport: "grpc",
      parent: "lst/d01",
      body: { collectionId: "sub", readTime: "2099-01-01T00:00:00Z", mask: { fieldPaths: ["a"] } },
    },
    ctx,
    new Map(),
  );
  assert.equal(built.method, "ListDocuments");
  assert.equal(built.stream, false);
  assert.deepEqual(built.request, {
    parent: `${docs}/lst/d01`,
    collectionId: "sub",
    readTime: { seconds: "4070908800", nanos: 0 },
    mask: { fieldPaths: ["a"] },
  });
  guardGrpcRequest(built, ctx);
  const ids = buildGrpcRequest(
    { id: "b", rpc: "listCollectionIds", transport: "grpc", body: { pageSize: 2 } },
    ctx,
    new Map(),
  );
  assert.equal(ids.method, "ListCollectionIds");
  assert.deepEqual(ids.request, { parent: docs, pageSize: 2 });
  guardGrpcRequest(ids, ctx);
});

test("validation keeps dot segments, foreign methods and chained transactions out", () => {
  const program = (step) => [{ id: "fs-data-write-list/x/y", steps: [{ id: "a", ...step }] }];
  const lane = "fs-data-write-list";
  for (const collectionId of [".", ".."]) {
    assert.throws(
      () => validateCorpus(program({ rpc: "listDocuments", collectionId }), lane),
      /names one collection/,
    );
  }
  for (const step of [
    { rpc: "listCollectionIds", path: "v1/{docs}:beginTransaction" },
    { rpc: "runQuery", path: "v1/{docs}/a/b:batchWrite" },
    { rpc: "listDocuments", collectionId: "lst", path: "v1/{docs}/lst" },
    { rpc: "get", path: "v1/{docs}/lst/d" },
  ]) {
    assert.throws(() => validateCorpus(program(step), lane), /must end in :/, JSON.stringify(step));
  }
  validateCorpus(
    program({ rpc: "listCollectionIds", path: "v1/{docs}/lst:listCollectionIds" }),
    lane,
  );
  assert.throws(
    () =>
      validateCorpus(
        program({
          rpc: "listDocuments",
          collectionId: "lst",
          query: [["transaction", { $from: "b", path: "transaction" }]],
        }),
        lane,
      ),
    /must be a literal/,
  );
});

test("the guard refuses resource and system parameters in a list query", () => {
  const ctx = production();
  for (const key of ["parent", "collectionId", "fields", "access_token", "prettyPrint", "alt"]) {
    assert.throws(
      () =>
        guardRestRequest(
          {
            url: `https://firestore.googleapis.com/v1/${docs}/lst?${key}=x`,
            init: { method: "GET", headers: {} },
          },
          ctx,
        ),
      /not reviewed/,
      key,
    );
  }
});

const listRaw = (query, response) => ({
  transport: "rest",
  request: query,
  response: { status: 400, text: JSON.stringify(response) },
});

test("a list answer echoing a requested read time or page token records their symbols", () => {
  const ctx = production();
  const readTime = "2026-09-24T00:10:00.123456Z";
  const token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
  const recorded = normalizeStep(
    listRaw(
      [
        ["readTime", readTime],
        ["pageToken", token],
        ["pageSize", "garbage-literal"],
      ],
      { error: { message: `token ${token} at ${readTime} is stale; garbage-literal` } },
    ),
    ctx,
    new Map(),
  );
  assert.equal(recorded.body.error.message, "token <page-token> at <r1> is stale; garbage-literal");
  // A short literal token is corpus text, not a server token, and stays.
  const literal = normalizeStep(
    listRaw([["pageToken", "garbage"]], { error: { message: "garbage" } }),
    ctx,
    new Map(),
  );
  assert.equal(literal.body.error.message, "garbage");
  // A gRPC body token is registered the same way.
  const grpcRow = normalizeStep(
    {
      transport: "grpc",
      request: { pageToken: token },
      response: { messages: [], code: 3, details: `bad ${token}`, errorDetails: [] },
    },
    ctx,
    new Map(),
  );
  assert.equal(grpcRow.message, "bad <page-token>");
});

test("a saved list recording normalizes again to the same rows", () => {
  const ctx = production();
  const program = PROGRAMS.find((p) => p.id.endsWith("/list-documents/read-time"));
  const step = program.steps.find((s) => s.id === "at-write-1");
  const readTime = "2026-09-24T00:10:00.123456Z";
  const raw = {
    transport: "rest",
    request: [["readTime", readTime]],
    response: {
      status: 200,
      text: JSON.stringify({
        documents: [
          {
            name: `${docs}/lsr/r1`,
            createTime: readTime,
            updateTime: readTime,
          },
        ],
      }),
    },
  };
  const row = normalizeStep(raw, ctx, new Map());
  assert.equal(
    row.body.documents[0].name,
    `projects/${RECORDED_PROJECT}/databases/(default)/documents/lsr/r1`,
  );
  assert.equal(row.body.documents[0].createTime, "<r1>");
  const recording = {
    context: { run: "1", startedMs: started },
    results: { [program.id]: { steps: { [step.id]: { stale: true } }, raw: { [step.id]: raw } } },
  };
  const again = renormalize(recording, [program]);
  assert.deepEqual(again.results[program.id].steps[step.id], row);
});

test("list answers over gRPC project to the REST shape, missing documents included", () => {
  const projected = projectGrpcMessage({
    documents: [
      { name: `${docs}/lst/missing1`, fields: {}, createTime: null, updateTime: null },
      {
        name: `${docs}/lst/d05`,
        fields: {},
        createTime: { seconds: "1790000000", nanos: 5000 },
        updateTime: { seconds: "1790000000", nanos: 5000 },
      },
    ],
    nextPageToken: "",
  });
  assert.deepEqual(projected, {
    documents: [
      { name: `${docs}/lst/missing1` },
      {
        name: `${docs}/lst/d05`,
        createTime: "2026-09-21T14:13:20.000005Z",
        updateTime: "2026-09-21T14:13:20.000005Z",
      },
    ],
  });
});

test("a recording holds an exclusive lock that the other lane cannot take", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fireemu-lock-"));
  const ledger = join(dir, "ledger.jsonl");
  try {
    let inner;
    const outer = await withRecordingLock(ledger, "fs-query-index", async () => {
      inner = await withRecordingLock(ledger, "fs-data-write-list", async () => "ran").catch(
        (error) => error,
      );
      return "outer";
    });
    assert.equal(outer, "outer");
    assert.match(String(inner?.message), /another recording holds .*fs-query-index pid/);
    assert.deepEqual(await readdir(dir), []);
    await assert.rejects(
      withRecordingLock(ledger, "fs-query-index", async () => {
        throw new Error("boom");
      }),
      /boom/,
    );
    assert.deepEqual(await readdir(dir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
