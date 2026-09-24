import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS } from "./fs-list/corpus.mjs";
import {
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-query-index/harness.mjs";
import { LANES, selectLane } from "./fs-query-index/lanes.mjs";
import { estimatedUsd } from "./fs-query-index/run.mjs";

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
