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
      projectNumber: "123456789012",
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
  const refused = (r, pattern) => assert.throws(() => guardRestRequest(r, ctx, program), pattern);
  ok(request(`v1/projects/fireemu-oracle-query/databases/${own}/documents/c/d`));
  ok(request("v1/projects/fireemu-oracle-query/databases/(default)"));
  ok(request("v1/projects/fireemu-oracle-query/databases/Bad_Id/documents/c/d"));
  refused(request("v1/projects/fireemu-oracle-query/databases/Bad_Id", "DELETE"), /only read/);
  refused(
    request(
      `v1/projects/fireemu-oracle-query/databases/${own}?updateMask=pointInTimeRecoveryEnablement`,
      "PATCH",
      {},
    ),
    /point-in-time/,
  );
  ok(request(`v1/projects/fireemu-oracle-query/databases?databaseId=${own}`, "POST", {}));
  ok(request("v1/projects/fireemu-no-such-project-0924/databases"));
  ok(request("v1/projects/fireemu-oracle-query/locations/us-central1"));
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
  const nested = encodeURIComponent("test-case/all/all_namespaces/all_kinds/output-0");
  guardRestRequest(storage(`storage/v1/b/${ctx.bucket}/o/${nested}`, "DELETE"), ctx, program);
  guardRestRequest(
    storage(`storage/v1/b/${ctx.bucket}/o/${nested}`, "GET", "?alt=media"),
    ctx,
    program,
  );
  guardRestRequest(
    storage(`upload/storage/v1/b/${ctx.bucket}/o`, "POST", "?uploadType=media&name=x"),
    ctx,
    program,
  );
  for (const sneaky of [
    `storage/v1/b/${ctx.bucket}/o/..\\..\\other-bucket\\o`,
    `storage/v1/b/${ctx.bucket}/o/..\\..\\..\\projects\\fireemu-oracle-query\\databases\\(default)`,
  ])
    assert.throws(() => guardRestRequest(storage(sneaky, "DELETE"), ctx, program), /not canonical/);
  assert.throws(
    () => guardRestRequest(storage(`storage/v1/b/${ctx.bucket}%2Fother/o`), ctx, program),
    /outside the JSON API/,
  );
  assert.throws(
    () =>
      guardRestRequest(
        storage(`storage/v1/b/${ctx.bucket}/o/${encodeURIComponent("a/../b")}`, "DELETE"),
        ctx,
        program,
      ),
    /not canonical/,
  );
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
    note: "Please retry in 262 seconds. consumer projects/123456789012",
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

test("operation ids are numbered per database; a link's index id is a symbol too", () => {
  const ctx = production();
  const two = { ...program, databases: ["a", "b"] };
  const symbols = programSymbols(ctx, two);
  const [a, b] = ["a", "b"].map((letter) => databaseId(ctx, two, letter));
  const name = (db, id) => `projects/fireemu-oracle-query/databases/${db}/operations/${id}`;
  const normalized = (body) =>
    normalizeRestResponse(200, JSON.stringify(body), ctx, two, symbols).body;
  // Steps only production runs (an export in a) must not shift the numbers in b.
  assert.equal(normalized({ name: name(a, "OpA1") }).name.endsWith("<db:a>/operations/<op1>"), true);
  assert.equal(normalized({ name: name(a, "OpA2") }).name.endsWith("<db:a>/operations/<op2>"), true);
  assert.equal(normalized({ name: name(b, "OpB1") }).name.endsWith("<db:b>/operations/<op1>"), true);
  assert.equal(normalized({ name: name(a, "OpA1") }).name.endsWith("<db:a>/operations/<op1>"), true);
  // The console link to an index carries its id inside base64url protobuf.
  const index = `projects/fireemu-oracle-query/databases/${a}/collectionGroups/items/indexes/CICAgOjXh4EK`;
  const link = (id) => {
    const text = `projects/fireemu-oracle-query/databases/${a}/collectionGroups/items/indexes/${id}`;
    const bytes = Buffer.concat([Buffer.from([0x0a, text.length]), Buffer.from(text, "latin1")]);
    return `https://console.firebase.google.com/x?create_composite=${bytes.toString("base64url")}`;
  };
  const seen = normalized({ index, message: link("CICAgOjXh4EK"), never: link("_") });
  assert.equal(seen.index.endsWith("/indexes/<index1>"), true);
  const decoded = (message) =>
    Buffer.from(message.split("create_composite=")[1], "base64url").toString("latin1");
  assert.match(decoded(seen.message), /\/indexes\/<index1>$/);
  assert.match(decoded(seen.never), /\/indexes\/_$/);
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

test("rate limits, database operations and an applied exemption are recognized", async () => {
  const { isRateLimited, isDatabaseOperation, UNTIL } = await import("./harness.mjs");
  assert.ok(isRateLimited(429, { error: { details: [{ reason: "RATE_LIMIT_EXCEEDED" }] } }));
  assert.ok(!isRateLimited(429, { error: { message: "TTL" } }));
  assert.ok(!isRateLimited(400, { error: { details: [{ reason: "RATE_LIMIT_EXCEEDED" }] } }));
  const base = "https://firestore.googleapis.com/v1/projects/p/databases";
  assert.ok(isDatabaseOperation(`${base}?databaseId=x`));
  assert.ok(isDatabaseOperation(`${base}/x`));
  assert.ok(isDatabaseOperation(base));
  assert.ok(!isDatabaseOperation(`${base}/x/documents/c/d`));
  assert.ok(!isDatabaseOperation(`${base}/x:exportDocuments`));
  assert.ok(UNTIL.exempt({ indexConfig: {} }));
  assert.ok(UNTIL.exempt({ indexConfig: { indexes: [] } }));
  // What production answered for an applied exemption on 2026-09-24.
  assert.ok(UNTIL.exempt({ indexConfig: { ancestorField: "x" } }));
  assert.ok(!UNTIL.exempt({ indexConfig: { ancestorField: "x", indexes: [{ state: "READY" }] } }));
  assert.ok(!UNTIL.exempt({ indexConfig: { usesAncestorConfig: true, ancestorField: "x" } }));
  assert.ok(!UNTIL.exempt({}));
});

test("masking the export window leaves every other byte of a partition metadata file", async () => {
  const { maskExportWindow } = await import("./exports.mjs");
  // {1: {1: "all", 2: 1790224753568054, 3: 1790224800613000}, 2: {1: "__all__", 2: "output-0"}}
  const bytes = Buffer.from(
    "0a170a03616c6c10b6d284f4b2869703188885bc8ab386970312130a075f5f616c6c5f5f12086f75747075742d30",
    "hex",
  );
  const masked = maskExportWindow(bytes);
  assert.equal(
    masked.toString("hex"),
    "0a090a03616c6c1000180012130a075f5f616c6c5f5f12086f75747075742d30",
  );
  assert.deepEqual(maskExportWindow(masked), masked);
});

test("id-ordered listings are compared regardless of the order the server listed them", async () => {
  const { sortListings } = await import("./harness.mjs");
  const a = { name: "x/<index2>", state: "READY" };
  const b = { name: "x/<index1>", state: "CREATING" };
  assert.deepEqual(sortListings({ indexes: [a, b] }), sortListings({ indexes: [b, a] }));
  assert.deepEqual(sortListings({ other: [a, b] }).other, [a, b], "other arrays keep their order");
  // An index resource has `fields` too: its columns, whose order is the index definition.
  const columns = [
    { fieldPath: "a", order: "ASCENDING" },
    { fieldPath: "__name__", order: "DESCENDING" },
  ];
  assert.deepEqual(sortListings({ name: "x/<index1>", fields: columns }).fields, columns);
  const fieldA = { name: "x/fields/b", indexConfig: {} };
  const fieldB = { name: "x/fields/a", indexConfig: {} };
  assert.deepEqual(
    sortListings({ fields: [fieldA, fieldB] }),
    sortListings({ fields: [fieldB, fieldA] }),
  );
});
