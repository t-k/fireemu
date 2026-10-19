import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PROGRAMS,
  PROBE_DOC,
  SELECT_EXPRESSIONS,
  STATIC_REFUSALS,
  WHERE_CONDITIONS,
} from "./fs-ent-pipeline/corpus.mjs";
import {
  DATABASE,
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-query-index/harness.mjs";
import { LANES, selectLane } from "./fs-query-index/lanes.mjs";

const lane = LANES["fs-ent-pipeline"];

const production = (database = lane.database) =>
  createContext({
    run: "1",
    startedMs: Date.parse("2026-10-20T00:00:00Z"),
    database,
    target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
  });

test("the pipeline lane records into the named Enterprise database without an index file", () => {
  assert.equal(selectLane("fs-ent-pipeline"), lane);
  assert.equal(lane.database, "entpipe1");
  assert.equal(lane.edition, "ENTERPRISE");
  assert.equal(lane.indexes, null);
  assert.equal(lane.taskId, "FS-ENT-ORACLE");
  // The other lanes keep (default).
  assert.equal(LANES["fs-query-index"].database, undefined);
  assert.equal(LANES["fs-data-write-list"].database, undefined);
});

test("contexts name their database and refuse any other", () => {
  assert.equal(databaseName(production()), `projects/${SANDBOX_PROJECT}/databases/entpipe1`);
  assert.equal(
    databaseName(production(DATABASE)),
    `projects/${SANDBOX_PROJECT}/databases/(default)`,
  );
  assert.equal(
    databaseName(
      createContext({
        run: "1",
        target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
      }),
    ),
    `projects/${SANDBOX_PROJECT}/databases/(default)`,
  );
  for (const database of ["entpipe2", "", "(default)/x"]) {
    assert.throws(() => production(database), /not a sandbox database/, database);
  }
});

test("the corpus validates, stays within its budget and only reads pipelines or writes its own collection", () => {
  const requests = validateCorpus(PROGRAMS, "fs-ent-pipeline");
  assert.equal(requests, 162);
  const rpcs = new Set(PROGRAMS.flatMap((p) => p.steps.map((s) => s.rpc)));
  assert.deepEqual([...rpcs].toSorted(), ["commit", "executePipeline"]);
  // The only writes are the order program's single-document commits into `ord`.
  for (const program of PROGRAMS) {
    for (const step of program.steps.filter((s) => s.rpc === "commit")) {
      assert.equal(program.id, "fs-ent-pipeline/results/order");
      assert.equal(step.body.writes.length, 1);
      assert.match(step.body.writes[0].update.name, /^\{docs\}\/ord\/[a-z]+$/);
    }
  }
  const labels = (pairs) => pairs.map(([label]) => label);
  for (const pairs of [SELECT_EXPRESSIONS, WHERE_CONDITIONS, STATIC_REFUSALS]) {
    assert.equal(new Set(labels(pairs)).size, pairs.length);
    for (const label of labels(pairs)) assert.match(label, /^[a-z0-9-]+$/);
  }
  // The probe document never holds a run-window time and never sets `x`.
  assert.equal(PROBE_DOC.x, undefined);
  assert.equal(PROBE_DOC.ts.timestampValue.startsWith("2020-"), true);
});

test("every step stays in the named database on both transports", () => {
  for (const ctx of [production()]) {
    for (const program of PROGRAMS) {
      for (const step of program.steps) {
        if ((step.transport ?? "rest") === "grpc") {
          const built = buildGrpcRequest(step, ctx, new Map());
          guardGrpcRequest(built, ctx);
          assert.equal(built.request.database, databaseName(ctx), step.id);
        } else {
          const built = buildRestRequest(step, ctx, new Map());
          guardRestRequest(built, ctx);
          assert.ok(
            built.url.startsWith(
              `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/entpipe1/documents`,
            ),
            built.url,
          );
        }
      }
    }
  }
});

test("a request built for the named database is refused in (default) and the reverse", () => {
  const step = PROGRAMS[0].steps[0];
  const named = buildRestRequest(step, production(), new Map());
  assert.throws(
    () => guardRestRequest(named, production(DATABASE)),
    /outside the sandbox database/,
  );
  const fallback = buildRestRequest(step, production(DATABASE), new Map());
  assert.throws(() => guardRestRequest(fallback, production()), /outside the sandbox database/);
  const grpcStep = PROGRAMS.find((p) => p.id.endsWith("metadata")).steps.find(
    (s) => s.transport === "grpc",
  );
  const grpcNamed = buildGrpcRequest(grpcStep, production(), new Map());
  assert.throws(() => guardGrpcRequest(grpcNamed, production(DATABASE)), /outside the sandbox/);
});
