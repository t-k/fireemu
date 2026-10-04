import assert from "node:assert/strict";
import { test } from "node:test";

import { cleanupNative, runNative, targetFor } from "./fs-listen/native-run.mjs";

const PROJECT = "p1";
const RUN = "r1";
const ROOT = `projects/${PROJECT}/databases/(default)/documents`;

/** A scripted client: a stream answers each request with the frames `script` names. */
function fakeClient(script = {}) {
  const log = [];
  const docs = new Map();
  const streams = [];
  const clock = { t: 0 };
  return {
    log,
    docs,
    streams,
    clock,
    client: {
      async commit({ writes, transaction }) {
        log.push([
          "commit",
          writes.map((w) => (w.delete ? `del ${w.delete}` : w.update.name)),
          transaction ?? null,
        ]);
        for (const w of writes) {
          if (w.delete) docs.delete(w.delete);
          else docs.set(w.update.name, w.update.fields);
        }
        return {};
      },
      async beginTransaction() {
        log.push(["begin"]);
        return Buffer.from("tx");
      },
      openStream() {
        const frames = [];
        let end;
        const stream = {
          frames,
          sent: [],
          ended: () => end,
          send(request) {
            stream.sent.push(request);
            log.push(["send", JSON.stringify(request)]);
            for (const frame of script[stream.sent.length - 1 + (stream.offset ?? 0)] ?? [])
              frames.push(frame);
            if (request.__end) end = request.__end;
          },
          async close() {
            end ??= { reason: "closed-by-harness" };
          },
        };
        streams.push(stream);
        return stream;
      },
      async missing(names) {
        return names.map((name) => ({ name, exists: docs.has(name) }));
      },
      async listIds() {
        return [...docs.keys()].filter((name) => name.includes(`${RUN}-`));
      },
    },
  };
}

const targetChange = (type, ids, extra = {}) => ({
  kind: "targetChange",
  targetChange: { targetChangeType: type, targetIds: ids, ...extra },
});

test("targetFor builds document, query and collection-group targets", () => {
  const ctx = { root: ROOT, run: RUN, tokens: new Map() };
  assert.deepEqual(targetFor({ id: 1, doc: "a" }, { ...ctx, docs: { a: "lsn/{run}-a" } }), {
    targetId: 1,
    documents: { documents: [`${ROOT}/lsn/${RUN}-a`] },
  });
  assert.deepEqual(
    targetFor(
      { id: 2, query: { collection: "lsn", where: [["g", "g1"]], orderBy: "n" }, once: true },
      ctx,
    ),
    {
      targetId: 2,
      once: true,
      query: {
        parent: ROOT,
        structuredQuery: {
          from: [{ collectionId: "lsn" }],
          where: {
            fieldFilter: { field: { fieldPath: "g" }, op: "EQUAL", value: { stringValue: "g1" } },
          },
          orderBy: [{ field: { fieldPath: "n" }, direction: "ASCENDING" }],
        },
      },
    },
  );
  assert.deepEqual(
    targetFor({ id: 3, collectionGroup: "lsn_child" }, ctx).query.structuredQuery.from,
    [{ collectionId: "lsn_child", allDescendants: true }],
  );
});

test("targetFor carries a saved token, a saved read time and an expected count", () => {
  const tokens = new Map([
    ["t1", { token: Buffer.from("abc") }],
    ["when", { readTime: { seconds: "9", nanos: 1 } }],
  ]);
  const ctx = { root: ROOT, run: RUN, tokens, docs: { a: "lsn/{run}-a" } };
  const withToken = targetFor({ id: 1, doc: "a", resume: "t1", expectedCount: 3 }, ctx);
  assert.deepEqual(withToken.resumeToken, Buffer.from("abc"));
  assert.deepEqual(withToken.expectedCount, { value: 3 });
  const withTime = targetFor({ id: 1, doc: "a", readTimeFrom: "when" }, ctx);
  assert.deepEqual(withTime.readTime, { seconds: "9", nanos: 1 });
  assert.equal(
    targetFor({ id: 1, doc: "a", rawToken: "junk" }, ctx).resumeToken.toString(),
    "junk",
  );
  assert.throws(() => targetFor({ id: 1, doc: "a", resume: "nope" }, ctx), /no saved token/);
});

test("runNative: seed, open, wait for CURRENT, record rows, remove, close", async () => {
  const { client, log } = fakeClient({
    0: [
      targetChange("ADD", [1]),
      {
        kind: "documentChange",
        documentChange: {
          document: { name: `${ROOT}/lsn/${RUN}-a`, fields: { n: { integerValue: "1" } } },
          targetIds: [1],
        },
      },
      targetChange("CURRENT", [1], { resumeToken: Buffer.from("tok") }),
      targetChange("NO_CHANGE", [], { resumeToken: Buffer.from("tok2") }),
    ],
    1: [targetChange("REMOVE", [1])],
  });
  const program = {
    id: "native/t",
    conditions: ["FS-LISTEN-SDK/native-target-protocol"],
    docs: { a: "lsn/{run}-a" },
    steps: [
      { do: "seed", doc: "a", fields: { n: 1 } },
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "wait", stream: "s", until: { current: 1 } },
      { do: "record", row: "t/open", stream: "s" },
      { do: "remove", stream: "s", id: 1 },
      { do: "wait", stream: "s", until: { type: "REMOVE", id: 1 } },
      { do: "record", row: "t/remove", stream: "s" },
      { do: "close", stream: "s" },
    ],
  };
  const out = await runNative([program], {
    client,
    project: PROJECT,
    run: RUN,
    sleep: async () => {},
    now: () => 0,
  });
  assert.deepEqual(Object.keys(out.rows), ["t/open", "t/remove"]);
  assert.deepEqual(
    out.rows["t/open"].rows.map((r) => r.kind),
    ["targetChange", "documentChange", "targetChange", "boundary"],
  );
  assert.deepEqual(out.rows["t/open"].rows[1].doc, "a");
  assert.deepEqual(out.rows["t/open"].conditions, ["FS-LISTEN-SDK/native-target-protocol"]);
  assert.equal(out.rows["t/open"].timedOut, false);
  assert.deepEqual(out.rows["t/remove"].rows, [
    { kind: "targetChange", type: "REMOVE", targetIds: [1], cause: null, resumeToken: false },
  ]);
  assert.deepEqual(log[0], ["commit", [`${ROOT}/lsn/${RUN}-a`], null]);
});

test("a wait that never completes records timedOut instead of waiting forever", async () => {
  const { client, clock } = fakeClient({ 0: [targetChange("ADD", [1])] });
  const program = {
    id: "native/t",
    conditions: [],
    docs: { a: "lsn/{run}-a" },
    steps: [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "wait", stream: "s", until: { current: 1 }, timeoutMs: 1000 },
      { do: "record", row: "t/x", stream: "s" },
    ],
  };
  const out = await runNative([program], {
    client,
    project: PROJECT,
    run: RUN,
    sleep: async (ms) => {
      clock.t += ms;
    },
    now: () => clock.t,
  });
  assert.equal(out.rows["t/x"].timedOut, true);
});

test("save keeps the latest token and read time of a target for a later open", async () => {
  const { client, streams } = fakeClient({
    0: [
      targetChange("CURRENT", [1], {
        resumeToken: Buffer.from("T1"),
        readTime: { seconds: "4", nanos: 5 },
      }),
    ],
  });
  const program = {
    id: "native/t",
    conditions: [],
    docs: { a: "lsn/{run}-a" },
    steps: [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "wait", stream: "s", until: { current: 1 } },
      { do: "save", stream: "s", id: 1, token: "t1", time: "when" },
      {
        do: "open",
        stream: "s2",
        targets: [{ id: 1, doc: "a", resume: "t1", readTimeFrom: undefined }],
      },
    ],
  };
  await runNative([program], {
    client,
    project: PROJECT,
    run: RUN,
    sleep: async () => {},
    now: () => 0,
  });
  assert.deepEqual(streams[1].sent[0].addTarget.resumeToken, Buffer.from("T1"));
});

test("a transaction step begins, then commits with the transaction id; a commit step is one Commit", async () => {
  const { client, log } = fakeClient();
  const program = {
    id: "native/t",
    conditions: [],
    docs: { a: "lsn/{run}-a", b: "lsn/{run}-b" },
    steps: [
      {
        do: "txn",
        writes: [
          { doc: "a", fields: { n: 1 } },
          { doc: "b", fields: { n: 1 } },
        ],
      },
      { do: "commit", writes: [{ doc: "a", fields: { n: 2 } }, { delete: "b" }] },
    ],
  };
  await runNative([program], {
    client,
    project: PROJECT,
    run: RUN,
    sleep: async () => {},
    now: () => 0,
  });
  assert.deepEqual(log[0], ["begin"]);
  assert.equal(log[1][0], "commit");
  assert.deepEqual(log[1][2], Buffer.from("tx"));
  assert.equal(log[2][1].length, 2);
});

test("cleanup deletes every owned document and reads each back as missing", async () => {
  const { client, docs } = fakeClient();
  docs.set(`${ROOT}/lsn/${RUN}-a`, {});
  docs.set(`${ROOT}/lsn/${RUN}-zz`, {});
  docs.set(`${ROOT}/lsn/other-1`, {});
  const report = await cleanupNative([{ docs: { a: "lsn/{run}-a" } }], {
    client,
    project: PROJECT,
    run: RUN,
    sweep: [{ parent: ROOT, collectionId: "lsn" }],
  });
  assert.equal(report.complete, true);
  assert.deepEqual([...docs.keys()], [`${ROOT}/lsn/other-1`]);
  assert.deepEqual(
    report.deleted.toSorted(),
    [`${ROOT}/lsn/${RUN}-a`, `${ROOT}/lsn/${RUN}-zz`].toSorted(),
  );
});

test("cleanup is incomplete when a document is still there after the delete", async () => {
  const { client, docs } = fakeClient();
  docs.set(`${ROOT}/lsn/${RUN}-a`, {});
  const stubborn = {
    ...client,
    async commit() {},
  };
  const report = await cleanupNative([{ docs: { a: "lsn/{run}-a" } }], {
    client: stubborn,
    project: PROJECT,
    run: RUN,
    sweep: [],
  });
  assert.equal(report.complete, false);
  assert.deepEqual(report.stillPresent, [`${ROOT}/lsn/${RUN}-a`]);
});
