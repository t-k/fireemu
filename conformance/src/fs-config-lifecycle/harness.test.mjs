import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS } from "./corpus.mjs";
import {
  buildRestRequest,
  collapseTrace,
  createContext,
  databaseId,
  filterDatabaseList,
  guardRestRequest,
  normalizeRestResponse,
  programSymbols,
  traceAgrees,
  validateCorpus,
} from "./harness.mjs";

const production = () =>
  createContext({
    run: "1790223596",
    startedMs: Date.parse("2026-09-24T05:00:00Z"),
    target: {
      kind: "production",
      token: "ya29.token",
      quotaProject: "fireemu-oracle-query",
      projectNumber: "1049549757969",
      bucket: "fireemu-oracle-query-cfg-1790223596",
    },
  });
const program = { id: "fs-config/test/case", ordinal: 3, slug: "test-case", databases: ["a"] };

const request = (path, method = "GET", body) => ({
  url: `https://firestore.googleapis.com/${path}`,
  init: {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    ...(body ? { body: JSON.stringify(body) } : {}),
  },
});

test("database ids have one length on both sides and name the program", () => {
  const ctx = production();
  assert.equal(databaseId(ctx, program, "a"), "cfg1790223596-03a");
});

test("the guard admits only program databases, uncreated ids and a read of (default)", () => {
  const ctx = production();
  const own = databaseId(ctx, program, "a");
  const ok = (r) => guardRestRequest(r, ctx, program);
  ok(request(`v1/projects/fireemu-oracle-query/databases/${own}/documents/c/d`));
  ok(request("v1/projects/fireemu-oracle-query/databases/(default)"));
  ok(request("v1/projects/fireemu-oracle-query/databases/nonexist-cfg/documents/c/d"));
  ok(request(`v1/projects/fireemu-oracle-query/databases?databaseId=${own}`, "POST", {}));
  ok(request("v1/projects/fireemu-no-such-project-0924/databases"));
  ok(request("v1/projects/fireemu-oracle-query/locations/us-central1"));
  const refused = (r, pattern) => assert.throws(() => guardRestRequest(r, ctx, program), pattern);
  refused(
    request("v1/projects/fireemu-oracle-query/databases/(default)/documents/c/d"),
    /\(default\)/,
  );
  refused(request("v1/projects/fireemu-oracle-query/databases/(default)", "DELETE"), /\(default\)/);
  refused(
    request("v1/projects/fireemu-oracle-query/databases/other-db/documents/c"),
    /does not own/,
  );
  refused(
    request("v1/projects/fireemu-oracle-query/databases?databaseId=other-db", "POST", {}),
    /does not own/,
  );
  refused(request("v1/projects/fireemu-oracle-sbx/databases"), /another project/);
  refused(request("v1/projects/fireemu-no-such-project-0924/databases", "POST", {}), /only read/);
  refused(
    request("v1/projects/fireemu-oracle-query/databases:restore", "POST", {}),
    /restore|unexpected/,
  );
  refused(
    request(`v1/projects/fireemu-oracle-query/databases/${own}/backupSchedules`, "POST", {}),
    /out of scope/,
  );
  refused(
    request(`v1/projects/fireemu-oracle-query/databases/${own}:exportDocuments`, "POST", {
      outputUriPrefix: "gs://someone-else/x",
    }),
    /another bucket/,
  );
  refused(
    request(`v1/projects/fireemu-oracle-query/databases/${own}/documents:commit`, "POST", {
      writes: [
        { update: { name: "projects/fireemu-oracle-query/databases/(default)/documents/c/d" } },
      ],
    }),
    /foreign database/,
  );
  refused(request("v1/projects/fireemu-oracle-query/databases/x/..%2f"), /canonical/);
});

test("storage requests stay in the run bucket; only the harness creates it", () => {
  const ctx = production();
  const storage = (path, method = "GET", query = "") => ({
    url: `https://storage.googleapis.com/${path}${query}`,
    init: { method, headers: {} },
  });
  guardRestRequest(storage(`storage/v1/b/${ctx.bucket}/o`), ctx, program);
  assert.throws(
    () => guardRestRequest(storage("storage/v1/b/other/o"), ctx, program),
    /run bucket/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        storage("storage/v1/b", "POST", "?project=fireemu-oracle-query"),
        ctx,
        program,
      ),
    /harness/,
  );
  guardRestRequest(storage("storage/v1/b", "POST", "?project=fireemu-oracle-query"), ctx, program, {
    harness: true,
  });
});

test("a built request carries the quota project and resolves placeholders", () => {
  const ctx = production();
  const built = buildRestRequest(
    {
      path: "v1/{project}/databases/{db:a}:exportDocuments",
      method: "POST",
      body: { outputUriPrefix: "{prefix}/all" },
    },
    ctx,
    program,
    new Map(),
  );
  assert.equal(
    built.url,
    "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/cfg1790223596-03a:exportDocuments",
  );
  assert.equal(built.init.headers["x-goog-user-project"], "fireemu-oracle-query");
  assert.deepEqual(JSON.parse(built.init.body), {
    outputUriPrefix: "gs://fireemu-oracle-query-cfg-1790223596/test-case/all",
  });
});

test("normalization replaces every private or run-specific value with a stable symbol", () => {
  const ctx = production();
  const symbols = programSymbols(ctx, program);
  const own = databaseId(ctx, program, "a");
  const body = {
    name: `projects/fireemu-oracle-query/databases/${own}/operations/AbC_123-xyz`,
    metadata: {
      index: `projects/fireemu-oracle-query/databases/${own}/collectionGroups/items/indexes/CICAgOjXh4EK`,
      startTime: "2026-09-24T05:01:02.123456Z",
    },
    response: {
      uid: "07f4f5c6-8514-4bf3-96a9-2e8d44b64e96",
      name: "projects/fireemu-oracle-query/databases/07f4f5c6-8514-4bf3-96a9-2e8d44b64e96",
      etag: "IO6i87axhpcDMJLX8raxhpcD",
      createTime: "2026-09-24T05:01:02.123456Z",
      old: "2020-01-01T00:00:00Z",
    },
    note: "Please retry in 262 seconds. consumer projects/1049549757969",
  };
  const recorded = normalizeRestResponse(200, JSON.stringify(body), ctx, program, symbols);
  assert.deepEqual(recorded.body, {
    metadata: {
      index: "projects/demo-fs-config/databases/<db:a>/collectionGroups/items/indexes/<index1>",
      startTime: "<t1>",
    },
    name: "projects/demo-fs-config/databases/<db:a>/operations/<op1>",
    note: "Please retry in <n> seconds. consumer projects/<project-number>",
    response: {
      createTime: "<t1>",
      etag: "<etag>",
      name: "projects/demo-fs-config/databases/<uid1>",
      old: "2020-01-01T00:00:00Z",
      uid: "<uid1>",
    },
  });
  // Program-wide symbols: a later answer naming the same operation keeps its symbol.
  const again = normalizeRestResponse(
    200,
    JSON.stringify({ name: body.name, other: `projects/x/databases/${own}/operations/Other` }),
    ctx,
    program,
    symbols,
  );
  assert.equal(again.body.name, "projects/demo-fs-config/databases/<db:a>/operations/<op1>");
  assert.equal(again.body.other, "projects/x/databases/<db:a>/operations/<op2>");
});

test("list answers keep (default) and this program's databases only", () => {
  const ctx = production();
  const own = databaseId(ctx, program, "a");
  const body = {
    databases: [
      { name: "projects/p/databases/(default)" },
      { name: `projects/p/databases/${own}` },
      { name: "projects/p/databases/someone-else" },
      { name: "projects/p/databases/0000-uid", previousId: own },
      { name: "projects/p/databases/1111-uid", previousId: "someone-else" },
    ],
  };
  assert.deepEqual(
    filterDatabaseList(body, ctx, program).databases.map((d) => d.name),
    [
      "projects/p/databases/(default)",
      `projects/p/databases/${own}`,
      "projects/p/databases/0000-uid",
    ],
  );
});

test("a poll trace agrees when fireemu skips a transitional state but not when it invents one", () => {
  const creating = { status: 200, body: { state: "CREATING" } };
  const ready = { status: 200, body: { state: "READY" } };
  const error = { status: 400, body: {} };
  const prod = { trace: collapseTrace([creating, creating, ready]), settled: ready };
  assert.deepEqual(prod.trace, [creating, ready]);
  assert.ok(traceAgrees(prod, { trace: [ready], settled: ready }));
  assert.ok(traceAgrees(prod, { trace: [creating, ready], settled: ready }));
  assert.ok(!traceAgrees(prod, { trace: [error, ready], settled: ready }));
  assert.ok(!traceAgrees(prod, { trace: [ready, creating], settled: creating }));
  assert.ok(!traceAgrees(prod, { trace: [creating], settled: creating }));
});

test("the corpus validates and every program owns distinct database ids", () => {
  assert.ok(validateCorpus(PROGRAMS) > 0);
  const ctx = production();
  const ids = PROGRAMS.flatMap((p) => (p.databases ?? []).map((l) => databaseId(ctx, p, l)));
  assert.equal(ids.length, new Set(ids).size);
  for (const id of ids) assert.match(id, /^[a-z][a-z0-9-]{3,62}$/);
});

test("only the (default) lifecycle program in the bisection project may change (default)", async () => {
  const { BISECT_PROJECT } = await import("./harness.mjs");
  const bisect = createContext({
    run: "1790223596",
    project: BISECT_PROJECT,
    target: { kind: "production", token: "t", quotaProject: BISECT_PROJECT, bucket: "b-cfg" },
  });
  const lifecycle = PROGRAMS.find((p) => p.id === "fs-config/default-database/lifecycle");
  const del = request(`v1/projects/${BISECT_PROJECT}/databases/(default)`, "DELETE");
  guardRestRequest(del, bisect, lifecycle);
  guardRestRequest(
    request(`v1/projects/${BISECT_PROJECT}/databases?databaseId=(default)`, "POST", {}),
    bisect,
    lifecycle,
  );
  // Any other program, or the lifecycle program against the query sandbox, is refused.
  assert.throws(() => guardRestRequest(del, bisect, program), /runs only against/);
  assert.throws(
    () =>
      guardRestRequest(
        request("v1/projects/fireemu-oracle-query/databases/(default)", "DELETE"),
        production(),
        lifecycle,
      ),
    /runs only against/,
  );
  const ordinary = { ...program, project: BISECT_PROJECT };
  assert.throws(() => guardRestRequest(del, bisect, ordinary), /\(default\)/);
});

test("an export capture is normalized with same-length placeholders and restores exactly", async () => {
  const { crc32c, maskCrc, normalizeCapture, restoreCapture, capturePairs } =
    await import("./exports.mjs");
  const ctx = production();
  const record = (payload) => {
    const header = Buffer.alloc(7);
    header.writeUInt16LE(payload.length, 4);
    header[6] = 1;
    const out = Buffer.concat([header, payload]);
    out.writeUInt32LE(maskCrc(crc32c(out.subarray(6))), 0);
    return out;
  };
  const own = databaseId(ctx, program, "a");
  const output = record(
    Buffer.from(
      `key fireemu-oracle-query ${own} ref projects/fireemu-oracle-query/databases/${own}`,
    ),
  );
  const files = {
    "all/all_namespaces/all_kinds/output-0": output,
    "all/x.export_metadata": Buffer.from("plain"),
  };
  const pairs = capturePairs(ctx, program);
  const capture = normalizeCapture(files, pairs);
  const text = Buffer.from(
    capture.files["all/all_namespaces/all_kinds/output-0"],
    "base64",
  ).toString("latin1");
  assert.ok(!text.includes("fireemu-oracle-query") && !text.includes(own));
  assert.ok(text.includes("demo-fs-config-00000") && text.includes("cfg0000000000-00a"));
  const restored = restoreCapture(
    capture,
    pairs.map(([a, b]) => [b, a]),
    { verifyOriginals: true },
  );
  assert.deepEqual(restored["all/all_namespaces/all_kinds/output-0"], output);
  assert.throws(
    () => normalizeCapture({ "all/y.export_metadata": Buffer.from("fireemu-oracle-query") }, pairs),
    /carries/,
  );
});
