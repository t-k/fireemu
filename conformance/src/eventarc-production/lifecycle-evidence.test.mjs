import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  loadNativeRequests,
  createCollector,
  collectOwnCursorWalk,
  issueOperation,
  collectOperationTerminal,
  observeUnfinishedCreate,
  collectPairedOperationTerminals,
} from "./lifecycle-evidence.mjs";
const collection = "projects/test-project/locations/us-central1/channels";
const time = "2026-10-09T00:00:00.000000000Z";
const channel = (id, n) => ({
  name: `${collection}/${id}`,
  uid: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  createTime: time,
  updateTime: time,
  pubsubTopic: `projects/test-project/topics/eventarc-${id}-123`,
  state: "ACTIVE",
});
const inventory = [channel("a", 1), channel("b", 2)];
const op = `${collection.replace(/channels$/, "operations")}/operation-1234567890123-abcdef0123456-12345678-abcdef01`;
function fixtures(t, overrides = {}, inventoryPath = `/v1/${collection}`) {
  const dir = mkdtempSync(join(tmpdir(), "eventarc-evidence-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const rows = [
    {
      n: 1,
      request: { method: "GET", path: `/v1/${collection}?pageSize=1&x=%3Ftail` },
      response: { status: 200, body: { channels: [inventory[0]], nextPageToken: "bmV4dA" } },
    },
    {
      n: 2,
      request: { method: "GET", path: inventoryPath },
      response: { status: 200, body: { channels: inventory } },
    },
    {
      n: 3,
      request: {
        method: "POST",
        path: `/v1/${collection}?channelId=a`,
        body: { name: inventory[0].name },
      },
      response: { status: 200, body: operation() },
    },
    {
      n: 4,
      request: { method: "DELETE", path: `/v1/${inventory[0].name}` },
      response: { status: 200, body: operation("delete") },
    },
  ];
  Object.assign(rows[0].request, overrides);
  const text = rows.map((x) => JSON.stringify(x)).join("\n") + "\n";
  const path = join(dir, "native.jsonl");
  writeFileSync(path, text);
  return loadNativeRequests({
    path,
    sha256: createHash("sha256").update(text).digest("hex"),
    ordinals: [1, 2, 3, 4],
  });
}
function response(body, status = 200) {
  const text = JSON.stringify(body, null, 2) + "\n";
  return new Response(text, {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "content-length": String(Buffer.byteLength(text)),
    },
  });
}
function scripted(bodies) {
  const calls = [];
  const collector = createCollector({
    base: "http://127.0.0.1:9999",
    fetchImpl: async (url, options) => {
      calls.push([url, options]);
      const x = bodies.shift();
      if (x instanceof Error) throw x;
      if (x instanceof Response) return x;
      return response(x);
    },
    maxElapsedMs: 1000,
    timeoutMs: 100,
  });
  return { collector, calls };
}
function walkBodies(
  first = { channels: [inventory[0]], nextPageToken: "bmV4dA" },
  second = { channels: [inventory[1]] },
  after = { channels: inventory },
) {
  return [{ channels: inventory }, first, second, after];
}
test("complete own-cursor walk retains exact bytes, fields, provenance and query suffix", async (t) => {
  const f = fixtures(t),
    { collector, calls } = scripted(walkBodies());
  const proof = await collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) });
  assert.equal(proof.complete, true);
  assert.equal(proof.resourceCount, 2);
  assert.ok(calls[2][0].endsWith("?pageSize=1&x=%3Ftail&pageToken=bmV4dA"));
  assert.equal(
    collector.exchanges[0].response.text,
    JSON.stringify({ channels: inventory }, null, 2) + "\n",
  );
  assert.equal(collector.exchanges[0].source.n, 2);
  assert.equal(collector.exchanges[2].derivedFrom, collector.exchanges[1].id);
  assert.equal(
    collector.exchanges[0].response.sha256,
    createHash("sha256").update(collector.exchanges[0].response.text).digest("hex"),
  );
});
for (const [name, first, second, after] of [
  ["dropped", { channels: [inventory[0]] }],
  ["duplicate", undefined, { channels: [inventory[0]] }],
  ["foreign", undefined, { channels: [channel("foreign", 3)] }],
  ["overflow", { channels: inventory }],
  ["missing tail", undefined, { channels: [inventory[1]], nextPageToken: "dGFpbA" }],
  ["invalid token", { channels: [inventory[0]], nextPageToken: "!!!" }],
  ["repeated token", undefined, { channels: [inventory[1]], nextPageToken: "bmV4dA" }],
  ["empty page", { channels: [], nextPageToken: "bmV4dA" }],
  [
    "timestamp change",
    {
      channels: [{ ...inventory[0], updateTime: "2026-10-09T00:00:01.000000000Z" }],
      nextPageToken: "bmV4dA",
    },
  ],
  [
    "extra field",
    { channels: [{ ...inventory[0], provider: "changed" }], nextPageToken: "bmV4dA" },
  ],
  ["state change", { channels: [{ ...inventory[0], state: "INACTIVE" }], nextPageToken: "bmV4dA" }],
  [
    "after change",
    undefined,
    undefined,
    { channels: [inventory[0], { ...inventory[1], updateTime: "2026-10-09T00:00:01.000000000Z" }] },
  ],
])
  test(`walk rejects ${name}`, async (t) => {
    const f = fixtures(t),
      { collector } = scripted(walkBodies(first, second, after));
    await assert.rejects(collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }));
  });
for (const path of [
  `/v1/${collection}?pageToken=foreign&pageSize=1`,
  `/v1/projects/other/locations/us-central1/channels?pageSize=1`,
  `/v1/${collection}?pageSize=1&orderBy=name`,
  `/v1/${collection}?pageSize=1&filter=state%3DACTIVE`,
])
  test("unsupported or foreign cursor scope rejected before fetch", async (t) => {
    const f = fixtures(t, { path }),
      { collector, calls } = scripted([]);
    await assert.rejects(collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }));
    assert.equal(calls.length, 0);
  });
const operation = (verb = "create", done = false) => ({
  name: op,
  metadata: {
    "@type": "type.googleapis.com/google.cloud.eventarc.v1.OperationMetadata",
    createTime: time,
    ...(done ? { endTime: time } : {}),
    target: inventory[0].name,
    verb,
    requestedCancellation: false,
    apiVersion: "v1",
  },
  done,
  ...(done
    ? {
        response:
          verb === "delete"
            ? {
                "@type": "type.googleapis.com/google.cloud.eventarc.v1.Channel",
                name: inventory[0].name,
                state: "INACTIVE",
                pubsubTopic: "",
              }
            : { "@type": "type.googleapis.com/google.cloud.eventarc.v1.Channel", ...inventory[0] },
      }
    : {}),
});
test("own delete terminal requires exact operation and subsequent404", async (t) => {
  const f = fixtures(t),
    { collector, calls } = scripted([
      operation("delete"),
      operation("delete", true),
      response({ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404),
    ]);
  const issued = await issueOperation({ collector, input: f.get(4) });
  const p = await collectOperationTerminal({
    collector,
    issued,
    pollIntervalMs: 1,
    timeoutMs: 100,
  });
  assert.equal(p.complete, true);
  assert.equal(calls[1][0], `http://127.0.0.1:9999/v1/${op}`);
});
test("create terminal snapshot can precede a later resource updateTime", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([
      operation(),
      operation("create", true),
      { ...inventory[0], updateTime: "2026-10-09T00:00:01.000000000Z" },
    ]);
  const issued = await issueOperation({ collector, input: f.get(3) });
  assert.equal(
    (await collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 100 }))
      .complete,
    true,
  );
});
for (const [name, terminal, last] of [
  ["wrong operation", { ...operation("delete", true), name: op + "x" }],
  [
    "wrong target",
    { ...operation("delete", true), metadata: { target: inventory[1].name, verb: "delete" } },
  ],
  ["wrong state", operation("create", true)],
  ["missing404", operation("delete", true), response(inventory[0])],
  [
    "wrong404",
    operation("delete", true),
    response({ error: { code: 404, status: "INVALID_ARGUMENT" } }, 404),
  ],
])
  test(`terminal rejects ${name}`, async (t) => {
    const f = fixtures(t),
      { collector } = scripted([operation("delete"), terminal, last]);
    const issued = await issueOperation({ collector, input: f.get(4) });
    await assert.rejects(
      collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 100 }),
    );
  });
test("transport failure retained without successful proof", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([new Error("transport")]);
  await assert.rejects(collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }));
  assert.equal(collector.exchanges[0].failure.message, "transport");
});
test("unresponsive fetch is bounded even when injected transport ignores abort", async (t) => {
  const f = fixtures(t),
    collector = createCollector({
      base: "http://127.0.0.1:9999",
      timeoutMs: 5,
      maxElapsedMs: 100,
      fetchImpl: () => new Promise(() => {}),
    });
  await assert.rejects(
    collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }),
    /timeout/,
  );
});
test("never-done own operation is not a terminal", async (t) => {
  const f = fixtures(t);
  const collector = createCollector({
    base: "http://127.0.0.1:9999",
    fetchImpl: async () => response(operation()),
    timeoutMs: 50,
    maxElapsedMs: 100,
  });
  const issued = await issueOperation({ collector, input: f.get(3) });
  await assert.rejects(
    collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 5 }),
    /terminal timeout/,
  );
});
test("source hash, unbound inputs and nonloopback endpoints fail closed", async (t) => {
  const f = fixtures(t);
  assert.throws(() =>
    loadNativeRequests({ path: f.get(1).source.path, sha256: "0".repeat(64), ordinals: [1] }),
  );
  assert.throws(() => createCollector({ base: "https://example.com" }));
  const { collector, calls } = scripted([]);
  await assert.rejects(issueOperation({ collector, input: { ...f.get(3) } }));
  assert.equal(calls.length, 0);
});

test("operation metadata field changes fail closed", async (t) => {
  const f = fixtures(t),
    bad = operation();
  bad.metadata.apiVersion = "v2";
  const { collector } = scripted([bad]);
  await assert.rejects(issueOperation({ collector, input: f.get(3) }));
});

test("inventory cannot introduce unrecorded resource fields", async (t) => {
  const f = fixtures(t);
  const changed = inventory.map((x) => ({ ...x, provider: "unrecorded" }));
  const { collector } = scripted([
    { channels: changed },
    { channels: [changed[0]], nextPageToken: "bmV4dA" },
    { channels: [changed[1]] },
    { channels: changed },
  ]);
  await assert.rejects(collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }));
});
test("operation metadata createTime cannot change between issuing and terminal snapshots", async (t) => {
  const f = fixtures(t),
    terminal = operation("create", true);
  terminal.metadata.createTime = "2026-10-09T00:00:01.000000000Z";
  const { collector } = scripted([operation(), terminal, inventory[0]]);
  const issued = await issueOperation({ collector, input: f.get(3) });
  await assert.rejects(
    collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 100 }),
  );
});

test("failed native issuer cannot create an own-operation proof", async (t) => {
  const f = fixtures(t);
  const p = f.get(3).source.path;
  const lines = JSON.parse(
    JSON.stringify({ n: 8, request: f.get(3).request, response: { status: 400 } }),
  );
  writeFileSync(p, JSON.stringify(lines) + "\n");
  const text = JSON.stringify(lines) + "\n";
  const input = loadNativeRequests({
    path: p,
    sha256: createHash("sha256").update(text).digest("hex"),
    ordinals: [8],
  }).get(8);
  const { collector, calls } = scripted([operation()]);
  await assert.rejects(issueOperation({ collector, input }));
  assert.equal(calls.length, 0);
});

test("missing tail is rejected even when later inventory is unchanged", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([
      { channels: inventory },
      { channels: [inventory[0]] },
      { channels: inventory },
    ]);
  await assert.rejects(
    collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }),
    /missing tail/,
  );
});
test("oversized final page is rejected independently of token checks", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([
      { channels: inventory },
      { channels: inventory },
      { channels: inventory },
    ]);
  await assert.rejects(
    collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }),
    /page size bound/,
  );
});
test("different format-valid operation identity is rejected", async (t) => {
  const f = fixtures(t),
    other = operation("create", true);
  other.name = op.replace("abcdef01", "abcdef02");
  const { collector } = scripted([operation(), other, inventory[0]]);
  const issued = await issueOperation({ collector, input: f.get(3) });
  await assert.rejects(
    collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 100 }),
  );
});
test("absence requires404 status even if a200 body looks like NOT_FOUND", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([
      operation("delete"),
      operation("delete", true),
      response({ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 200),
    ]);
  const issued = await issueOperation({ collector, input: f.get(4) });
  await assert.rejects(
    collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 100 }),
  );
});
test("native status failure cannot bind even a format-valid issuing body", async (t) => {
  const f = fixtures(t),
    path = f.get(3).source.path,
    rows = { n: 9, request: f.get(3).request, response: { status: 400, body: operation() } };
  const text = JSON.stringify(rows) + "\n";
  writeFileSync(path, text);
  const input = loadNativeRequests({
    path,
    sha256: createHash("sha256").update(text).digest("hex"),
    ordinals: [9],
  }).get(9);
  const { collector, calls } = scripted([operation()]);
  await assert.rejects(issueOperation({ collector, input }));
  assert.equal(calls.length, 0);
});

test("page order permutations preserve complete set proof without sorting", async (t) => {
  for (const [first, second] of [
    [inventory[0], inventory[1]],
    [inventory[1], inventory[0]],
  ]) {
    const f = fixtures(t),
      { collector } = scripted(
        walkBodies({ channels: [first], nextPageToken: "bmV4dA" }, { channels: [second] }),
      );
    assert.equal(
      (await collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }))
        .resourceCount,
      2,
    );
  }
});
test("response length and content type are checked against collected bytes", async (t) => {
  for (const headers of [
    { "content-type": "application/json; charset=UTF-8", "content-length": "0" },
    { "content-type": "text/plain", "content-length": "3" },
  ]) {
    const f = fixtures(t),
      { collector } = scripted([new Response("{}\n", { headers })]);
    await assert.rejects(collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }));
    assert.equal(collector.exchanges[0].response.text, "{}\n");
  }
});
test("different collector cannot consume an operation issued elsewhere", async (t) => {
  const f = fixtures(t),
    one = scripted([operation()]),
    two = scripted([]);
  const issued = await issueOperation({ collector: one.collector, input: f.get(3) });
  await assert.rejects(collectOperationTerminal({ collector: two.collector, issued }));
  assert.equal(two.calls.length, 0);
});
test("transport failure while reading body is bounded", async (t) => {
  const f = fixtures(t),
    collector = createCollector({
      base: "http://127.0.0.1:9999",
      timeoutMs: 5,
      maxElapsedMs: 100,
      fetchImpl: async () => ({
        redirected: false,
        headers: new Headers(),
        status: 200,
        arrayBuffer: () => new Promise(() => {}),
      }),
    });
  await assert.rejects(
    collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }),
    /timeout/,
  );
});

test("collected exchange provenance cannot be rewritten by a consumer", async (t) => {
  const f = fixtures(t),
    { collector } = scripted(walkBodies());
  await collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) });
  assert.throws(() => {
    collector.exchanges[0].source.n = 999;
  });
  assert.throws(() => {
    collector.exchanges.length = 0;
  });
});

test("impossible calendar timestamps in operation metadata are rejected", async (t) => {
  const f = fixtures(t),
    invalid = operation();
  invalid.metadata.createTime = "2026-02-31T00:00:00.000000000Z";
  const { collector } = scripted([invalid]);
  await assert.rejects(issueOperation({ collector, input: f.get(3) }));
});

test("paired own create-delete retains overlap, both terminals and final404", async (t) => {
  const f = fixtures(t);
  const creating = { ...inventory[0], pubsubTopic: "" };
  delete creating.state;
  const { collector, calls } = scripted([
    operation(),
    creating,
    operation(),
    { ...operation("delete"), name: op.replace("abcdef01", "abcdef02") },
    operation("create", true),
    { ...operation("delete", true), name: op.replace("abcdef01", "abcdef02") },
    response({ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404),
  ]);
  const create = await issueOperation({ collector, input: f.get(3) });
  await observeUnfinishedCreate({ collector, issued: create });
  const deleted = await issueOperation({ collector, input: f.get(4) });
  const proof = await collectPairedOperationTerminals({
    collector,
    create,
    deleted,
    pollIntervalMs: 1,
    timeoutMs: 100,
  });
  assert.equal(proof.complete, true);
  assert.equal(proof.kind, "paired-own-operation-terminals");
  assert.equal(calls.length, 7);
  assert.equal(calls[3][1].method, "DELETE");
});
test("paired operation proof rejects missing unfinished-start observation", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([operation(), operation("delete")]);
  const create = await issueOperation({ collector, input: f.get(3) }),
    deleted = await issueOperation({ collector, input: f.get(4) });
  await assert.rejects(
    collectPairedOperationTerminals({
      collector,
      create,
      deleted,
      pollIntervalMs: 1,
      timeoutMs: 100,
    }),
  );
});
test("paired start cannot use an already completed create or invented CREATING state", async (t) => {
  for (const createRead of [operation("create", true), null]) {
    const f = fixtures(t);
    const creatingChannel = { ...inventory[0], pubsubTopic: "" };
    if (createRead) delete creatingChannel.state;
    else creatingChannel.state = "CREATING";
    const { collector } = scripted([operation(), creatingChannel, createRead ?? operation()]);
    const create = await issueOperation({ collector, input: f.get(3) });
    await assert.rejects(observeUnfinishedCreate({ collector, issued: create }));
  }
});
for (const [name, change] of [
  ["uid", (r) => (r.response.uid = "00000000-0000-4000-8000-000000000009")],
  ["createTime", (r) => (r.response.createTime = "2026-10-09T00:00:01.000000000Z")],
  ["state", (r) => (r.response.state = "INACTIVE")],
  ["operation", (r) => (r.name = op.replace("abcdef01", "abcdef09"))],
])
  test(`paired terminal rejects changed ${name}`, async (t) => {
    const f = fixtures(t),
      creating = { ...inventory[0], pubsubTopic: "" };
    delete creating.state;
    const active = operation("create", true);
    change(active);
    const { collector } = scripted([
      operation(),
      creating,
      operation(),
      { ...operation("delete"), name: op.replace("abcdef01", "abcdef02") },
      active,
      { ...operation("delete", true), name: op.replace("abcdef01", "abcdef02") },
      response({ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404),
    ]);
    const create = await issueOperation({ collector, input: f.get(3) });
    await observeUnfinishedCreate({ collector, issued: create });
    const deleted = await issueOperation({ collector, input: f.get(4) });
    await assert.rejects(
      collectPairedOperationTerminals({
        collector,
        create,
        deleted,
        pollIntervalMs: 1,
        timeoutMs: 100,
      }),
    );
  });
test("paired proof rejects DELETE issued before unfinished observation", async (t) => {
  const f = fixtures(t),
    creating = { ...inventory[0], pubsubTopic: "" };
  delete creating.state;
  const { collector } = scripted([
    operation(),
    { ...operation("delete"), name: op.replace("abcdef01", "abcdef02") },
    creating,
    operation(),
    operation("create", true),
    { ...operation("delete", true), name: op.replace("abcdef01", "abcdef02") },
    response({ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404),
  ]);
  const create = await issueOperation({ collector, input: f.get(3) }),
    deleted = await issueOperation({ collector, input: f.get(4) });
  await observeUnfinishedCreate({ collector, issued: create });
  await assert.rejects(
    collectPairedOperationTerminals({
      collector,
      create,
      deleted,
      pollIntervalMs: 1,
      timeoutMs: 100,
    }),
  );
});
test("paired stage-specific updateTime may advance without changing resource identity", async (t) => {
  const f = fixtures(t),
    creating = { ...inventory[0], pubsubTopic: "" };
  delete creating.state;
  const active = operation("create", true);
  active.response.updateTime = "2026-10-09T00:00:01.000000000Z";
  const { collector } = scripted([
    operation(),
    creating,
    operation(),
    { ...operation("delete"), name: op.replace("abcdef01", "abcdef02") },
    active,
    { ...operation("delete", true), name: op.replace("abcdef01", "abcdef02") },
    response({ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404),
  ]);
  const create = await issueOperation({ collector, input: f.get(3) });
  await observeUnfinishedCreate({ collector, issued: create });
  const deleted = await issueOperation({ collector, input: f.get(4) });
  assert.equal(
    (
      await collectPairedOperationTerminals({
        collector,
        create,
        deleted,
        pollIntervalMs: 1,
        timeoutMs: 100,
      })
    ).complete,
    true,
  );
});
test("own delete absence refuses an incomplete404 error even with canonical status and message", async (t) => {
  const f = fixtures(t),
    { collector } = scripted([
      operation("delete"),
      operation("delete", true),
      response({ error: { status: "NOT_FOUND", message: "absent" } }, 404),
    ]);
  const issued = await issueOperation({ collector, input: f.get(4) });
  await assert.rejects(
    collectOperationTerminal({ collector, issued, pollIntervalMs: 1, timeoutMs: 100 }),
  );
});

// The supplemental native full inventory was recorded with exactly pageSize=10.
test("recorded pageSize10 inventory preserves the exact query and own cursor chain", async (t) => {
  const f = fixtures(t, {}, `/v1/${collection}?pageSize=10`);
  const { collector, calls } = scripted(walkBodies());
  const proof = await collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) });
  assert.equal(proof.complete, true);
  assert.ok(calls[0][0].endsWith("?pageSize=10"));
  assert.ok(calls.at(-1)[0].endsWith("?pageSize=10"));
  assert.equal(collector.exchanges[2].derivedFrom, collector.exchanges[1].id);
});
for (const suffix of [
  "?pageSize=9",
  "?pageSize=10&pageToken=foreign",
  "?pageSize=10&filter=state",
  "?pageSize=10&orderBy=name",
  "?pageSize=10&x=extra",
  "?pageSize=10&pageSize=10",
])
  test(`inventory rejects unsupported query ${suffix} before transport`, async (t) => {
    const f = fixtures(t, {}, `/v1/${collection}${suffix}`);
    const { collector, calls } = scripted([]);
    await assert.rejects(collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }));
    assert.equal(calls.length, 0);
  });

test("pageSize10 inventory retains every full-field comparison property", async (t) => {
  const changes = [
    ["name", `${collection}/other`],
    ["uid", "00000000-0000-4000-8000-000000000009"],
    ["createTime", "2026-10-09T00:00:01.000000000Z"],
    ["updateTime", "2026-10-09T00:00:01.000000000Z"],
    ["state", "INACTIVE"],
    ["pubsubTopic", "projects/test-project/topics/changed-123"],
    ["provider", "unrecorded"],
  ];
  for (const [field, value] of changes) {
    const f = fixtures(t, {}, `/v1/${collection}?pageSize=10`);
    const { collector } = scripted(
      walkBodies({ channels: [{ ...inventory[0], [field]: value }], nextPageToken: "bmV4dA" }),
    );
    await assert.rejects(
      collectOwnCursorWalk({ collector, root: f.get(1), inventory: f.get(2) }),
      undefined,
      field,
    );
  }
});
