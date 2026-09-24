import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS, validateCorpus } from "./fs-rules/corpus.mjs";
import {
  buildFirestoreGrpc,
  buildFirestoreRest,
  createContext,
  guardFirestoreRequest,
  guardGrpcRequest,
  isTransient,
  normalizeGrpc,
  normalizeRest,
  SANDBOX_PROJECT,
} from "./fs-rules/harness.mjs";
import { markerOf, RULESET_IDS, rulesetSource } from "./fs-rules/rulesets.mjs";
import { classify, recentAbort } from "./fs-rules/run.mjs";

const production = () =>
  createContext({
    run: "1790000000000",
    startedMs: Date.parse("2026-09-24T12:00:00Z"),
    target: {
      kind: "production",
      adminToken: "ya29.owner",
      apiKey: "AIzaFsrKey",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: "637500000000",
    },
  });

const local = () =>
  createContext({
    run: "1790000000000",
    target: {
      kind: "local",
      firestoreOrigin: "http://127.0.0.1:9000",
      authOrigin: "http://127.0.0.1:9099",
      grpcHost: "127.0.0.1",
      grpcPort: 9000,
    },
  });

const principals = new Map([
  ["a", { uid: "Zq3aUidOfPrincipalA000000001" }],
  ["b", { uid: "Zq3bUidOfPrincipalB000000002" }],
]);

test("a production context must be the sandbox with owner credentials and its number", () => {
  assert.throws(
    () =>
      createContext({
        run: "1790000000000",
        target: {
          kind: "production",
          apiKey: "k",
          quotaProject: SANDBOX_PROJECT,
          projectNumber: "1",
        },
      }),
    /owner access token/,
  );
  assert.throws(
    () =>
      createContext({
        run: "1790000000000",
        target: {
          kind: "production",
          adminToken: "t",
          apiKey: "k",
          quotaProject: "other",
          projectNumber: "637500000000",
        },
      }),
    /quota project/,
  );
  assert.throws(
    () =>
      createContext({
        run: "1790000000000",
        target: {
          kind: "local",
          firestoreOrigin: "http://10.0.0.1:9000",
          authOrigin: "http://127.0.0.1:1",
          grpcHost: "127.0.0.1",
          grpcPort: 1,
        },
      }),
    /loopback/,
  );
  assert.deepEqual(production().databases, { named: "fsr-00000000-a", bare: "fsr-00000000-b" });
});

test("REST requests carry the principal's bearer only, and address the run's databases", () => {
  const ctx = production();
  const request = buildFirestoreRest(
    { id: "s", rpc: "get", doc: "fsr-own/UID(a)/items/x" },
    ctx,
    new Map(),
    principals,
    "Bearer id-token",
  );
  assert.equal(
    request.url,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents/fsr-own/Zq3aUidOfPrincipalA000000001/items/x`,
  );
  assert.deepEqual(request.init.headers, { authorization: "Bearer id-token" });
  assert.doesNotThrow(() => guardFirestoreRequest(request, ctx));
  const unauthenticated = buildFirestoreRest(
    { id: "s", rpc: "get", doc: "x/y" },
    ctx,
    new Map(),
    principals,
    undefined,
  );
  assert.deepEqual(unauthenticated.init.headers, {});
  const named = buildFirestoreRest(
    { id: "s", rpc: "commit", database: "named", body: {} },
    ctx,
    new Map(),
    principals,
    undefined,
  );
  assert.match(named.url, /databases\/fsr-00000000-a\/documents:commit$/);
  assert.doesNotThrow(() => guardFirestoreRequest(named, ctx));
});

test("the request guard refuses other hosts, projects, databases and non-canonical paths", () => {
  const ctx = production();
  const other = (url) => () => guardFirestoreRequest({ url, init: {} }, ctx);
  assert.throws(
    other("https://example.com/v1/projects/fireemu-oracle-idp/databases/(default)/documents/x/y"),
    /left the Firestore target/,
  );
  assert.throws(
    other(
      "https://firestore.googleapis.com/v1/projects/fireemu-35fe6/databases/(default)/documents/x/y",
    ),
    /not a document path/,
  );
  assert.throws(
    other(
      "https://firestore.googleapis.com/v1/projects/fireemu-oracle-idp/databases/other/documents/x/y",
    ),
    /not a document path/,
  );
  assert.throws(
    other(
      "https://firestore.googleapis.com/v1/projects/fireemu-oracle-idp/databases/(default)/documents/x/../../other",
    ),
    /not canonical/,
  );
  assert.throws(
    other("https://firestore.googleapis.com/v1/projects/fireemu-oracle-idp/databases"),
    /not a document path/,
  );
  assert.throws(
    () =>
      guardGrpcRequest(
        { request: { name: "projects/fireemu-35fe6/databases/(default)/documents/x/y" } },
        ctx,
      ),
    /another database/,
  );
});

test("gRPC requests use the REST shape of the same step", () => {
  const ctx = local();
  const built = buildFirestoreGrpc(
    {
      id: "s",
      rpc: "runQuery",
      parent: "fsr-own/UID(a)",
      body: { structuredQuery: { from: [{ collectionId: "items" }], limit: 2 } },
    },
    ctx,
    new Map(),
    principals,
  );
  assert.equal(built.method, "RunQuery");
  assert.equal(built.stream, true);
  assert.equal(
    built.request.parent,
    `projects/${SANDBOX_PROJECT}/databases/(default)/documents/fsr-own/Zq3aUidOfPrincipalA000000001`,
  );
  assert.deepEqual(built.request.structuredQuery.limit, { value: 2 });
  assert.match(built.routing, /^parent=/);
});

test("normalization masks uids, the project, its number, the API key, databases and run times", () => {
  const ctx = production();
  const recorded = normalizeRest(
    200,
    JSON.stringify({
      name: `projects/${SANDBOX_PROJECT}/databases/fsr-00000000-a/documents/fsr-own/Zq3aUidOfPrincipalA000000001/items/x`,
      fields: { owner: { stringValue: "Zq3bUidOfPrincipalB000000002" } },
      updateTime: "2026-09-24T12:01:02.123456Z",
      note: "project 637500000000 key AIzaFsrKey run 1790000000000",
      transaction: "Eg0KC2Zvbw==",
      old: "2020-01-01T00:00:00Z",
    }),
    ctx,
    principals,
  );
  assert.deepEqual(recorded, {
    status: 200,
    body: {
      name: "projects/demo-fs-rules/databases/<database:named>/documents/fsr-own/<uid:a>/items/x",
      fields: { owner: { stringValue: "<uid:b>" } },
      updateTime: "<run-time>",
      note: "project <project-number> key <api-key> run <run>",
      transaction: "<transaction>",
      old: "2020-01-01T00:00:00Z",
    },
  });
  assert.deepEqual(normalizeRest(403, "<html>", ctx, principals), { status: 403, nonJson: true });
  assert.deepEqual(
    normalizeGrpc(
      { code: 7, details: "Missing or insufficient permissions.", messages: [] },
      ctx,
      principals,
    ),
    { grpc: 7, details: "Missing or insufficient permissions." },
  );
});

test("transport failures, 5xx, 429, unsettled publications and gRPC UNAVAILABLE say nothing", () => {
  assert.equal(isTransient({ status: 0, transport: "ECONNRESET" }), true);
  assert.equal(isTransient({ status: 503 }), true);
  assert.equal(isTransient({ status: 429 }), true);
  assert.equal(isTransient({ status: 403, publication: "unsettled" }), true);
  assert.equal(isTransient({ grpc: 14, details: "" }), true);
  assert.equal(isTransient({ grpc: 7, details: "" }), false);
  assert.equal(isTransient({ status: 403 }), false);
  assert.equal(isTransient({ status: -1, dependencyTransient: false }), false);
});

test("classification needs a current fixture and a determinate answer on both sides", () => {
  const denied = { status: 403, body: { error: { status: "PERMISSION_DENIED" } } };
  const allowed = { status: 404, body: {} };
  assert.equal(classify({ stale: true, production: denied, fireemu: denied }), "STALE_FIXTURE");
  assert.equal(classify({ production: undefined, fireemu: denied }), "MISSING_FIXTURE");
  assert.equal(classify({ production: denied, fireemu: undefined }), "MISSING");
  assert.equal(classify({ production: denied, fireemu: denied }), "MATCH");
  assert.equal(classify({ production: denied, fireemu: allowed }), "MISMATCH");
  assert.equal(
    classify({ production: denied, alternative: allowed, fireemu: allowed }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(classify({ production: { status: 500 }, fireemu: denied }), "INDETERMINATE");
});

test("the corpus is valid, waits only in its last program and stays within the request cap", () => {
  const requests = validateCorpus(PROGRAMS);
  assert.ok(requests > 900, `${requests} recorded requests`);
  assert.equal(PROGRAMS.at(-1).id, "fs-rules/expiry/around-exp");
  assert.equal(PROGRAMS[0].id, "fs-rules/publication/no-release");
  const waiting = { ...PROGRAMS.at(-1), id: "fs-rules/expiry/early" };
  assert.throws(() => validateCorpus([waiting, PROGRAMS[0]]), /only the last program may wait/);
  const stranger = {
    id: "fs-rules/x/y",
    ruleset: "main",
    steps: [{ id: "s", as: "mallory", rpc: "get", doc: "x/y" }],
  };
  assert.throws(() => validateCorpus([stranger]), /unknown principal mallory/);
  const absolute = {
    id: "fs-rules/x/y",
    ruleset: "main",
    steps: [{ id: "s", as: "a", rpc: "get", doc: "/x/y" }],
  };
  assert.throws(() => validateCorpus([absolute]), /path must be relative/);
  const mail = {
    id: "fs-rules/x/y",
    ruleset: "main",
    steps: [{ id: "s", as: "a", rpc: "commit", body: { note: "someone@gmail.com" } }],
  };
  assert.throws(() => validateCorpus([mail]), /example.com/);
});

test("every ruleset carries its own marker, and a changed source changes the label", () => {
  const labels = RULESET_IDS.map(markerOf);
  assert.equal(new Set(labels).size, labels.length);
  for (const id of RULESET_IDS) {
    assert.ok(rulesetSource(id).includes(`allow get: if label == '${markerOf(id)}';`));
    assert.ok(rulesetSource(id).startsWith("rules_version = '2';"));
  }
  // `main` and `alt` differ only in the publication rule and the marker.
  const main = rulesetSource("main").replace(markerOf("main"), "L").split("\n");
  const alt = rulesetSource("alt").replace(markerOf("alt"), "L").split("\n");
  assert.equal(main.length, alt.length);
  const differing = main.flatMap((line, i) => (line === alt[i] ? [] : [[line, alt[i]]]));
  assert.deepEqual(differing, [
    ["      allow get: if request.auth != null;", "      allow get: if false;"],
  ]);
});

test("a run is refused within an hour of the task's last aborted run", () => {
  const now = Date.parse("2026-09-24T12:00:00Z");
  const line = (ts, outcome, taskId = "FS-RULES-SANDBOX") =>
    JSON.stringify({ ts, outcome, taskId });
  assert.ok(recentAbort([line("2026-09-24T11:30:00Z", "aborted-fatal")].join("\n"), now));
  assert.equal(recentAbort([line("2026-09-24T10:30:00Z", "aborted")].join("\n"), now), undefined);
  assert.equal(recentAbort([line("2026-09-24T11:30:00Z", "recorded")].join("\n"), now), undefined);
  assert.equal(
    recentAbort([line("2026-09-24T11:30:00Z", "aborted", "OTHER")].join("\n"), now),
    undefined,
  );
});
