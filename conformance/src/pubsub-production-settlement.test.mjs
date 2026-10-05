import assert from "node:assert/strict";
import test from "node:test";
import { cleanup } from "./pubsub-production/cleanup.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createLedger, kindOf } from "./pubsub-production/ledger.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { MIN_A2_WAIT_MS, summarize } from "./pubsub-production/record.mjs";

const own = () => createOwnership({ project: "demo-project", runId: "0123456789ab" });
const missing = {
  ok: false,
  code: "NOT_FOUND",
  status: 404,
  unknown: false,
  body: { error: { status: "NOT_FOUND" } },
};
const positive = (name) => ({ ok: true, code: "OK", status: 200, unknown: false, body: { name } });
const issue = (ledger, name, action, kind, extra = {}) => {
  const requestId = ledger.sent({ name, action, transport: "rest" });
  ledger.answered({ name, action, transport: "rest", requestId, kind, ...extra });
  return requestId;
};
function fixture({
  create = "unknown",
  remove,
  read = missing,
  probe = false,
  list = {},
  deleteReply = { status: 200, body: {}, unknown: false },
} = {}) {
  const ownership = own();
  const name = probe
    ? ownership.registerProbe("projects/demo-project/topics/goog-probe")
    : ownership.resource("topics", "case");
  const ledger = createLedger();
  if (create) issue(ledger, name, "create", create);
  if (remove) issue(ledger, name, "delete", remove);
  const calls = [];
  let deleted = false;
  const client = createClient({
    ownership,
    ledger,
    pushState: newPushState(),
    caseId: "cleanup",
    transport: {
      name: "rest",
      request: async (call) => {
        calls.push(call);
        if (call.path.includes("?")) return { status: 200, body: list, unknown: false };
        if (call.method === "DELETE") {
          deleted = true;
          return deleteReply;
        }
        const reply = deleted ? missing : typeof read === "function" ? read(name) : read;
        return { status: reply.status, body: reply.body, unknown: reply.unknown };
      },
    },
  });
  const run = (extra = {}) =>
    cleanup({
      client,
      ledger,
      ownership,
      project: "demo-project",
      sleep: async () => {},
      ...extra,
    });
  return { name, ledger, calls, run };
}

test("unknown CREATE stays unconfirmed after 404 in-run, cleanup-only, and aged A2", async () => {
  for (const extra of [
    {},
    { a2ElapsedMs: MIN_A2_WAIT_MS - 1 },
    { a2ElapsedMs: MIN_A2_WAIT_MS },
    { a2ElapsedMs: 86_400_000 },
  ]) {
    const f = fixture();
    const report = await f.run(extra);
    assert.deepEqual(report.unsettled, [f.name]);
    assert.deepEqual(report.unconfirmed, [f.name]);
    assert.deepEqual(report.settled, []);
    assert.equal(f.calls.filter((c) => c.method === "DELETE").length, 0);
  }
});

test("unknown CREATE followed by a later 409 and 404 remains unresolved", async () => {
  const f = fixture();
  issue(f.ledger, f.name, "create", "conflict");
  const report = await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS });
  assert.deepEqual(report.unsettled, [f.name]);
  assert.deepEqual(report.unconfirmed, [f.name]);
});

test("unknown CREATE resolves by its own complete exact-name positive read before deletion", async () => {
  const f = fixture({ read: positive });
  const report = await f.run();
  assert.deepEqual(report.unsettled, []);
  assert.deepEqual(report.unconfirmed, []);
  assert.deepEqual(report.settled, [{ name: f.name, how: "deleted" }]);
  assert.equal(f.ledger.state().get(f.name).requests[0].resolution, "gone");
  assert.equal(
    f.ledger.state().get(f.name).creates[0],
    "unknown",
    "the historical answer is preserved",
  );
});

test("positive reads fail closed for a foreign name, missing name, null, arrays, unknown answers, and operation envelopes", async () => {
  for (const body of [
    { name: "projects/demo-project/topics/other" },
    {},
    null,
    [],
    { name: "operations/foreign", done: true },
    { name: "projects/demo-project/topics/fe0123456789ab-case", done: true },
  ]) {
    const f = fixture({ read: { ...positive("unused"), body } });
    const report = await f.run();
    assert.deepEqual(report.unsettled, [f.name], JSON.stringify(body));
    assert.deepEqual(report.unconfirmed, [f.name]);
    assert.equal(
      f.calls.some((c) => c.method === "DELETE"),
      false,
    );
  }
  const f = fixture({ read: (name) => ({ ...positive(name), unknown: true }) });
  assert.deepEqual((await f.run()).unconfirmed, [f.name]);
});

test("a listing alone never confirms an unknown CREATE", async () => {
  const ownership = own();
  const name = ownership.resource("topics", "case");
  const f = fixture({ list: { topics: [{ name }] } });
  const report = await f.run();
  assert.deepEqual(report.unconfirmed, [name]);
  assert.equal(
    f.calls.some((c) => c.method === "DELETE"),
    false,
  );
  assert.ok(f.calls.some((c) => c.op === "getTopic"));
});

test("an invalid probe read never settles an unknown CREATE, including aged A2", async () => {
  const f = fixture({
    probe: true,
    read: {
      status: 400,
      ok: false,
      code: "INVALID_ARGUMENT",
      body: { error: { status: "INVALID_ARGUMENT" } },
      unknown: false,
    },
  });
  const report = await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS });
  assert.deepEqual(report.unconfirmed, [f.name]);
  assert.deepEqual(report.unsettled, [f.name]);
});

test("confirmed CREATE followed by 404 stays open until the separate ten-minute A2 boundary", async () => {
  for (const elapsed of [undefined, 0, MIN_A2_WAIT_MS - 1, MIN_A2_WAIT_MS, MIN_A2_WAIT_MS + 1]) {
    const f = fixture({ create: "ok" });
    const report = await f.run({ a2ElapsedMs: elapsed });
    assert.deepEqual(report.unsettled, elapsed >= MIN_A2_WAIT_MS ? [] : [f.name]);
    assert.deepEqual(report.unconfirmed, []);
  }
});

test("own confirmed DELETE plus complete 404 settles a confirmed CREATE in-run", async () => {
  const f = fixture({ create: "ok", remove: "ok" });
  const report = await f.run();
  assert.deepEqual(report.unsettled, []);
  assert.deepEqual(report.settled, [{ name: f.name, how: "absent" }]);
  assert.equal(
    f.calls.some((c) => c.method === "DELETE"),
    false,
  );
});

test("unknown CREATE is not erased by a later successful DELETE and 404", async () => {
  const f = fixture({ create: "unknown", remove: "ok" });
  assert.deepEqual((await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS })).unconfirmed, [f.name]);
});

test("unknown DELETE stays sticky in-run and is never resent even when present at aged A2", async () => {
  for (const [read, elapsed] of [
    [missing, undefined],
    [positive, undefined],
    [positive, MIN_A2_WAIT_MS],
    [missing, MIN_A2_WAIT_MS - 1],
  ]) {
    const f = fixture({ create: "ok", remove: "unknown", read });
    const report = await f.run({ a2ElapsedMs: elapsed });
    assert.deepEqual(report.unsettled, [f.name]);
    assert.equal(
      f.calls.some((c) => c.method === "DELETE"),
      false,
    );
  }
});

test("unknown DELETE settles only on a separate aged A2 complete 404", async () => {
  const f = fixture({ create: "ok", remove: "unknown" });
  const report = await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS });
  assert.deepEqual(report.unsettled, []);
  assert.equal(f.ledger.state().get(f.name).requests[1].resolution, "gone-a2");
});

test("unknown 404 cannot prove absence even at A2", async () => {
  const f = fixture({ create: "ok", remove: "unknown", read: { ...missing, unknown: true } });
  assert.deepEqual((await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS })).unsettled, [f.name]);
});

test("operation-pending CREATE resolves only on its own complete done read with the target name", () => {
  const ledger = createLedger();
  const name = "projects/demo-project/topics/fe0123456789ab-operation";
  const operation = "projects/demo-project/operations/own";
  issue(ledger, name, "create", "pending", { operation });
  for (const body of [
    { name: operation, done: false },
    { name: operation, done: "true", response: { name } },
    { name: "projects/demo-project/operations/other", done: true, response: { name } },
    { name: operation, done: true },
    { name: operation, done: true, response: { name: "other" } },
    { name: operation, done: true, error: { code: 5 }, response: { name } },
  ]) {
    assert.equal(ledger.observeOperation(operation, { ...positive(operation), body }), false);
    assert.equal(ledger.state().get(name).requests[0].resolution, "unresolved");
  }
  assert.equal(
    ledger.observeOperation(operation, {
      ...positive(operation),
      body: { name: operation, done: true, response: { name } },
    }),
    true,
  );
  assert.equal(ledger.state().get(name).requests[0].resolution, "confirmed");
});

test("DELETE whose operation never reads done stays sticky, and unknown operation reads cannot settle it", async () => {
  const f = fixture({ create: "ok" });
  const operation = "projects/demo-project/operations/delete";
  issue(f.ledger, f.name, "delete", "pending", { operation });
  assert.equal(
    f.ledger.observeOperation(operation, {
      ...positive(operation),
      body: { name: operation, done: false },
    }),
    false,
  );
  assert.equal(
    f.ledger.observeOperation(operation, {
      ...positive(operation),
      unknown: true,
      body: { name: operation, done: true, response: {} },
    }),
    false,
  );
  assert.deepEqual((await f.run()).unsettled, [f.name]);
  assert.equal(
    f.calls.some((c) => c.method === "DELETE"),
    false,
  );
  assert.equal(
    f.ledger.observeOperation(operation, {
      ...positive(operation),
      body: { name: operation, done: true, response: {} },
    }),
    true,
  );
  assert.deepEqual((await f.run()).unsettled, []);
});

test("pending and malformed operation bodies do not confirm creation or deletion", () => {
  assert.equal(
    kindOf({ ...positive("operations/own"), body: { name: "operations/own", done: false } }),
    "pending",
  );
  for (const body of [
    { name: "operations/own" },
    { done: false },
    { name: "operations/own", done: "true" },
    { name: "operations/own", done: true, error: { code: 5 } },
  ])
    assert.equal(kindOf({ ...positive("unused"), body }), "unknown");
});

test("request resolutions are journalled and replayed without erasing historical unknown answers", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { readLedger } = await import("./pubsub-production/ledger.mjs");
  const lines = [];
  const ledger = createLedger({ journal: { write: (line) => lines.push(line) } });
  const name = "projects/demo-project/topics/fe0123456789ab-journal";
  issue(ledger, name, "create", "unknown");
  assert.equal(ledger.observeRead(name, positive(name)), true);
  const dir = mkdtempSync(join(tmpdir(), "pubsub-settlement-"));
  try {
    const path = join(dir, "issued.jsonl");
    writeFileSync(path, lines.map((line) => JSON.stringify(line)).join("\n") + "\n");
    const replayed = readLedger(path).state().get(name);
    assert.equal(replayed.requests[0].resolution, "confirmed");
    assert.deepEqual(replayed.creates, ["unknown"]);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("closure readiness counts outstanding actions independently from historical raw unknowns", () => {
  const capture = {
    count: () => 7,
    unknownCount: () => 1,
    unknowns: () => [{ n: 1, op: "createTopic" }],
    perCase: () => ({}),
  };
  const summary = {
    stopped: null,
    limited: [],
    cleanup: { leftover: [], errors: [], unsettled: [], unconfirmed: [], outstandingActions: [] },
  };
  const result = summarize({ options: {}, capture, summary });
  assert.equal(result.unknownAnswers, 1);
  assert.equal(result.closureReady, true);
});

// This finite reference model explores answer/read orderings without a real-time clock.
test("bounded reference model agrees for unknown, conflict, exact read, wrong-name read, and absence traces", () => {
  const events = ["unknown", "conflict", "read", "wrong", "absent"];
  for (let encoded = 0; encoded < events.length ** 5; encoded += 1) {
    const ledger = createLedger();
    const name = "projects/demo-project/topics/fe0123456789ab-model";
    let unresolved = 0;
    let value = encoded;
    for (let i = 0; i < 5; i += 1) {
      const event = events[value % events.length];
      value = Math.floor(value / events.length);
      if (event === "unknown" || event === "conflict") {
        issue(ledger, name, "create", event);
        if (event === "unknown") unresolved += 1;
      } else {
        ledger.observeRead(
          name,
          event === "read" ? positive(name) : event === "wrong" ? positive("other") : missing,
        );
        if (event === "read") unresolved = 0;
      }
      const requests = ledger.state().get(name)?.requests ?? [];
      assert.equal(
        requests.filter((r) => r.action === "create" && r.resolution === "unresolved").length,
        unresolved,
        `${encoded}/${i}/${event}`,
      );
    }
  }
});

test("an earlier successful DELETE never settles a later recreated CREATE that reads absent in-run", async () => {
  const f = fixture({ create: "ok", remove: "ok" });
  issue(f.ledger, f.name, "create", "ok");
  assert.deepEqual((await f.run()).unsettled, [f.name]);
});

test("a complete 404 needs a readable NOT_FOUND body before any absence settlement", async () => {
  for (const body of [{}, null, { error: { status: "OTHER" } }]) {
    const f = fixture({ create: "ok", remove: "unknown", read: { ...missing, body } });
    assert.deepEqual((await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS })).unsettled, [f.name]);
  }
});

test("the client keeps pending and wrong-target operation creation replies unresolved", async () => {
  for (const body of [
    { name: "operations/own", done: false },
    { name: "operations/own", done: true, response: { name: "other" } },
  ]) {
    const ownership = own();
    const ledger = createLedger();
    const name = ownership.resource("topics", "op-client");
    const client = createClient({
      ownership,
      ledger,
      pushState: newPushState(),
      caseId: "case",
      transport: { name: "rest", request: async () => ({ status: 200, body, unknown: false }) },
    });
    const result = await client.createTopic(name);
    assert.equal(result.ok, false);
    assert.equal(result.unknown, true);
    assert.equal(ledger.unconfirmed(name), true);
  }
});

test("all absence proofs replay idempotently for multiple requests without relaxing unknown creation", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { readLedger } = await import("./pubsub-production/ledger.mjs");
  for (const deleting of ["ok", "unknown"]) {
    const lines = [];
    const ledger = createLedger({ journal: { write: (line) => lines.push(line) } });
    const name = "projects/demo-project/topics/fe0123456789ab-replay";
    issue(ledger, name, "create", "ok");
    issue(ledger, name, "delete", deleting);
    assert.equal(
      ledger.settleAbsent(
        name,
        missing,
        deleting === "unknown" ? { a2ElapsedMs: MIN_A2_WAIT_MS } : {},
      ),
      true,
    );
    const dir = mkdtempSync(join(tmpdir(), "pubsub-proof-replay-"));
    try {
      const path = join(dir, "issued.jsonl");
      writeFileSync(path, lines.map((line) => JSON.stringify(line)).join("\n") + "\n");
      assert.deepEqual(readLedger(path).outstanding(), []);
      assert.deepEqual(
        readLedger(path)
          .state()
          .get(name)
          .requests.map((r) => r.resolution),
        deleting === "unknown" ? ["gone-a2", "gone-a2"] : ["gone", "gone"],
      );
    } finally {
      rmSync(dir, { recursive: true });
    }
  }
});

test("a mismatched request identity or transport cannot answer another issued request", () => {
  const ledger = createLedger();
  const name = "projects/demo-project/topics/fe0123456789ab-identity";
  const requestId = ledger.sent({ name, action: "create", transport: "rest" });
  assert.throws(
    () => ledger.answered({ name, action: "delete", transport: "rest", requestId, kind: "ok" }),
    /matching issued request/,
  );
  assert.throws(
    () => ledger.answered({ name, action: "create", transport: "grpc", requestId, kind: "ok" }),
    /matching issued request/,
  );
  assert.equal(ledger.unconfirmed(name), true);
});

test("a new unknown DELETE issued inside aged A2 remains open after its immediate 404", async () => {
  const f = fixture({
    create: "ok",
    read: positive,
    deleteReply: { status: 503, body: {}, unknown: true },
  });
  const report = await f.run({ a2ElapsedMs: MIN_A2_WAIT_MS });
  assert.deepEqual(report.unsettled, [f.name]);
  assert.deepEqual(report.settled, []);
  assert.equal(f.ledger.deleting(f.name), true);
  assert.equal(f.calls.filter((c) => c.method === "DELETE").length, 1);
});
