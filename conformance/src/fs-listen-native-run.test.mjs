import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { runNative, targetFor, toFields, waitHolds } from "./fs-listen/native-run.mjs";

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
  const { client, log, clock } = fakeClient({
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
    sleep: async (ms) => {
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
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
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
  });
  assert.equal(out.rows["t/x"].timedOut, true);
});

test("save keeps the latest token and read time of a target for a later open", async () => {
  const { client, streams, clock } = fakeClient({
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
    sleep: async (ms) => {
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
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
    sleep: async (ms) => {
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
  });
  assert.deepEqual(log[0], ["begin"]);
  assert.equal(log[1][0], "commit");
  assert.deepEqual(log[1][2], Buffer.from("tx"));
  assert.equal(log[2][1].length, 2);
});

test("toFields writes each supported JS value as its Firestore Value and refuses the rest", () => {
  assert.deepEqual(toFields({ a: null, b: true, c: false, d: 3, e: -4, f: 1.5, g: "x", h: "" }), {
    a: { nullValue: "NULL_VALUE" },
    b: { booleanValue: true },
    c: { booleanValue: false },
    d: { integerValue: "3" },
    e: { integerValue: "-4" },
    f: { doubleValue: 1.5 },
    g: { stringValue: "x" },
    h: { stringValue: "" },
  });
  assert.deepEqual(toFields({}), {});
  assert.throws(() => toFields({ a: [1] }), /unsupported field value \[1\]/);
  assert.throws(() => toFields({ a: undefined }), /unsupported/);
});

test("targetFor: one filter is a field filter, several are AND, a number is an integer value", () => {
  const ctx = { root: ROOT, run: RUN, tokens: new Map(), docs: {} };
  const one = targetFor({ id: 1, query: { collection: "c", where: [["n", 5]] } }, ctx);
  assert.deepEqual(one.query.structuredQuery.where, {
    fieldFilter: { field: { fieldPath: "n" }, op: "EQUAL", value: { integerValue: "5" } },
  });
  assert.equal(one.query.structuredQuery.orderBy, undefined);
  const many = targetFor(
    {
      id: 1,
      query: {
        collection: "c",
        where: [
          ["n", 5],
          ["g", "x"],
        ],
      },
    },
    ctx,
  );
  assert.deepEqual(many.query.structuredQuery.where, {
    compositeFilter: {
      op: "AND",
      filters: [
        { fieldFilter: { field: { fieldPath: "n" }, op: "EQUAL", value: { integerValue: "5" } } },
        { fieldFilter: { field: { fieldPath: "g" }, op: "EQUAL", value: { stringValue: "x" } } },
      ],
    },
  });
  const none = targetFor({ id: 1, query: { collection: "c" } }, ctx);
  assert.equal(none.query.structuredQuery.where, undefined);
  // A collection-group target takes its filters from the target itself.
  const group = targetFor({ id: 2, collectionGroup: "k", where: [["g", "x"]] }, ctx);
  assert.equal(group.query.structuredQuery.where.fieldFilter.value.stringValue, "x");
  assert.equal(group.once, undefined);
  assert.equal(targetFor({ id: 2, collectionGroup: "k", once: true }, ctx).once, true);
});

test("targetFor refuses a read time that was not saved or has none", () => {
  const ctx = {
    root: ROOT,
    run: RUN,
    docs: { a: "lsn/{run}-a" },
    tokens: new Map([["t", { token: Buffer.from("x") }]]),
  };
  assert.throws(
    () => targetFor({ id: 1, doc: "a", readTimeFrom: "t" }, ctx),
    /no saved read time t/,
  );
  assert.throws(
    () => targetFor({ id: 1, doc: "a", readTimeFrom: "zz" }, ctx),
    /no saved read time zz/,
  );
  const noToken = { ...ctx, tokens: new Map([["t", { readTime: { seconds: "1" } }]]) };
  assert.throws(() => targetFor({ id: 1, doc: "a", resume: "t" }, noToken), /no saved token t/);
});

const change = (type, ids, extra = {}) => targetChange(type, ids, extra);
const docChange = { kind: "documentChange", documentChange: { document: { name: "x" } } };

test("waitHolds judges each condition on the frames it is given", () => {
  const frames = [change("ADD", [1]), docChange, change("CURRENT", [1])];
  assert.equal(waitHolds({ current: 1 }, frames, undefined), true);
  assert.equal(waitHolds({ current: 2 }, frames, undefined), false);
  assert.equal(waitHolds({ current: 1 }, [change("ADD", [1])], undefined), false);
  assert.equal(waitHolds({ current: 1 }, [change("CURRENT", [])], undefined), false);
  assert.equal(waitHolds({ type: "REMOVE", id: 1 }, [change("REMOVE", [1])], undefined), true);
  assert.equal(waitHolds({ type: "REMOVE", id: 1 }, [change("REMOVE", [2])], undefined), false);
  assert.equal(waitHolds({ type: "REMOVE", id: 1 }, [change("ADD", [1])], undefined), false);
  assert.equal(waitHolds({ type: "REMOVE", id: 1 }, [change("REMOVE", [])], undefined), false);
  assert.equal(waitHolds({ docChanges: 1 }, [docChange], undefined), true);
  assert.equal(waitHolds({ docChanges: 2 }, [docChange], undefined), false);
  assert.equal(waitHolds({ docChanges: 2 }, [docChange, docChange], undefined), true);
  assert.equal(waitHolds({ docChanges: 1 }, [change("ADD", [1])], undefined), false);
  assert.equal(waitHolds({ frames: 3 }, frames, undefined), true);
  assert.equal(waitHolds({ frames: 4 }, frames, undefined), false);
  assert.equal(waitHolds({ ended: true }, [], { reason: "ended" }), true);
  assert.equal(waitHolds({ ended: true }, frames, undefined), false);
  // A wait for a frame is not satisfied by an ended stream.
  assert.equal(waitHolds({ current: 1 }, [], { reason: "ended" }), false);
  assert.throws(() => waitHolds({ nothing: 1 }, [], undefined), /unknown wait condition/);
});

/** Runs steps against a client whose streams answer by request index; returns the run and its log. */
async function runSteps(
  steps,
  script = {},
  { docs = { a: "lsn/{run}-a", b: "lsn/{run}-b" }, ...options } = {},
) {
  const { client, log, streams, clock } = fakeClient(script);
  const out = await runNative([{ id: "native/t", conditions: ["x"], docs, steps }], {
    client,
    project: PROJECT,
    run: RUN,
    sleep: async (ms) => {
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
    ...options,
  });
  return { out, log, streams, clock };
}

test("runNative: delete, add, remove, settle and sleep do what they say", async () => {
  const { log, streams, clock } = await runSteps([
    { do: "delete", doc: "a" },
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "add", stream: "s", target: { id: 2, doc: "b" } },
    { do: "remove", stream: "s", id: 1 },
    { do: "settle", ms: 700 },
    { do: "settle" },
    { do: "sleep", ms: 300 },
    { do: "close", stream: "s" },
  ]);
  assert.deepEqual(log[0], ["commit", [`del ${ROOT}/lsn/${RUN}-a`], null]);
  const sent = streams[0].sent;
  assert.deepEqual(
    sent.map((r) => Object.keys(r).toSorted()),
    [
      ["addTarget", "database"],
      ["addTarget", "database"],
      ["database", "removeTarget"],
    ],
  );
  assert.equal(sent[1].addTarget.targetId, 2);
  assert.equal(sent[2].removeTarget, 1);
  assert.equal(sent[0].database, `projects/${PROJECT}/databases/(default)`);
  assert.equal(clock.t, 700 + 1500 + 300);
});

test("runNative: a step that does not exist is an error of its program, and the run goes on", async () => {
  const { out } = await runSteps([{ do: "teleport" }]);
  assert.match(out.errors["native/t"], /unknown step teleport/);
  assert.deepEqual(out.rows, {});
});

test("runNative stops a program at the request ceiling and says which step reached it", async () => {
  const steps = [
    { do: "write", doc: "a", fields: { n: 1 } },
    { do: "write", doc: "a", fields: { n: 2 } },
    { do: "write", doc: "a", fields: { n: 3 } },
  ];
  const { out, log } = await runSteps(steps, {}, { maxRequests: 2 });
  assert.match(out.errors["native/t"], /request ceiling 2 reached at write/);
  assert.equal(log.filter(([name]) => name === "commit").length, 2);
  assert.equal(out.requests, 3);
  const exact = await runSteps(steps, {}, { maxRequests: 3 });
  assert.deepEqual(exact.out.errors, {});
});

test("runNative: an open stream, a begin and a commit each count as a request", async () => {
  const { out } = await runSteps([
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "txn", writes: [{ doc: "a", fields: { n: 1 } }] },
    { do: "close", stream: "s" },
  ]);
  assert.equal(out.requests, 3);
});

test("runNative: record keeps the frames since the last record, the end, and resets the timeout flag", async () => {
  const { out } = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "wait", stream: "s", until: { current: 9 }, timeoutMs: 100, settleMs: 0 },
      { do: "record", row: "native/t/first", stream: "s" },
      { do: "record", row: "native/t/second", stream: "s" },
      { do: "close", stream: "s" },
    ],
    { 0: [change("ADD", [1])] },
  );
  assert.equal(out.rows["native/t/first"].timedOut, true);
  assert.equal(out.rows["native/t/first"].rows.length, 1);
  assert.equal(out.rows["native/t/second"].timedOut, false);
  assert.deepEqual(out.rows["native/t/second"].rows, []);
  assert.equal(out.rows["native/t/first"].end, null);
});

test("runNative: a stream that ended shows its reason and code in the row, and ends a wait early", async () => {
  const { client, clock } = fakeClient({});
  const open = client.openStream;
  client.openStream = () => {
    const stream = open();
    stream.ended = () => ({ reason: "error", code: 3 });
    return stream;
  };
  const out = await runNative(
    [
      {
        id: "native/t",
        conditions: ["x"],
        docs: { a: "lsn/{run}-a" },
        steps: [
          { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
          { do: "wait", stream: "s", until: { current: 1 }, timeoutMs: 100000, settleMs: 0 },
          { do: "record", row: "native/t/x", stream: "s", groups: true },
        ],
      },
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  assert.deepEqual(out.rows["native/t/x"].end, { reason: "error", code: 3 });
  assert.equal(out.rows["native/t/x"].timedOut, true);
  assert.deepEqual(out.rows["native/t/x"].groups, []);
  assert.ok(clock.t < 100000, "an ended stream does not wait out the deadline");
});

test("runNative: save keeps token and read time apart, and the same name for both when asked", async () => {
  const frames = [
    change("CURRENT", [1], {
      resumeToken: Buffer.from("T1"),
      readTime: { seconds: "4", nanos: 5 },
    }),
    change("NO_CHANGE", [], { resumeToken: Buffer.from("T2") }),
    change("CURRENT", [2], {
      resumeToken: Buffer.from("OTHER"),
      readTime: { seconds: "9", nanos: 9 },
    }),
  ];
  const { streams } = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok", time: "when" },
      {
        do: "open",
        stream: "r",
        targets: [{ id: 1, doc: "a", resume: "tok", readTimeFrom: "when" }],
      },
    ],
    { 0: frames },
  );
  const sent = streams[1].sent[0].addTarget;
  assert.deepEqual(sent.resumeToken, Buffer.from("T2"));
  assert.deepEqual(sent.readTime, { seconds: "4", nanos: 5 });
  // A token sent as the base64 text describeFrame writes is turned back into bytes.
  const text = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "tok" }] },
    ],
    { 0: [change("CURRENT", [1], { resumeToken: Buffer.from("hello").toString("base64") })] },
  );
  assert.deepEqual(text.streams[1].sent[0].addTarget.resumeToken, Buffer.from("hello"));
  const plain = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "tok" }] },
    ],
    { 0: [change("CURRENT", [1], { resumeToken: { type: "Buffer", data: [1, 2, 3] } })] },
  );
  assert.deepEqual(plain.streams[1].sent[0].addTarget.resumeToken, Buffer.from([1, 2, 3]));
});

test("runNative: a program that fails closes its streams; the next program still runs", async () => {
  const { client, streams, log } = fakeClient({});
  const programs = [
    {
      id: "native/one",
      conditions: ["x"],
      docs: { a: "lsn/{run}-a" },
      steps: [{ do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] }, { do: "teleport" }],
    },
    {
      id: "native/two",
      conditions: ["x"],
      docs: { a: "lsn/{run}-b" },
      steps: [{ do: "seed", doc: "a", fields: { n: 1 } }],
    },
  ];
  const out = await runNative(programs, {
    client,
    project: PROJECT,
    run: RUN,
    sleep: async (ms) => {
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
  });
  assert.ok(out.errors["native/one"]);
  assert.equal(out.errors["native/two"], undefined);
  assert.equal(streams[0].ended().reason, "closed-by-harness");
  assert.deepEqual(log.at(-1), ["commit", [`${ROOT}/lsn/${RUN}-b`], null]);
});

test("a wait that nothing satisfies ends exactly at its deadline, 30 s by default", async () => {
  const wait = (extra) => [
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "wait", stream: "s", until: { current: 9 }, settleMs: 0, ...extra },
  ];
  assert.equal((await runSteps(wait({}))).clock.t, 30_000);
  assert.equal((await runSteps(wait({ timeoutMs: 1000 }))).clock.t, 1000);
  assert.equal((await runSteps(wait({ timeoutMs: 1010 }))).clock.t, 1050);
});

test("a wait that is satisfied at once sleeps only its settle time: 1500 ms by default, none for 0", async () => {
  const frames = { 0: [change("CURRENT", [1])] };
  const wait = (extra) => [
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "wait", stream: "s", until: { current: 1 }, ...extra },
  ];
  assert.equal((await runSteps(wait({}), frames)).clock.t, 1500);
  assert.equal((await runSteps(wait({ settleMs: 0 }), frames)).clock.t, 0);
  assert.equal((await runSteps(wait({ settleMs: 250 }), frames)).clock.t, 250);
  const slow = await runSteps(wait({}), frames, { settleMs: 800 });
  assert.equal(slow.clock.t, 800, "the run's own settle time is the default");
});

test("a wait on a stream that is already over does not sleep past the deadline", async () => {
  const { client, clock } = fakeClient({});
  const open = client.openStream;
  client.openStream = () => Object.assign(open(), { ended: () => ({ reason: "ended" }) });
  const out = await runNative(
    [
      {
        id: "native/t",
        conditions: ["x"],
        docs: { a: "lsn/{run}-a" },
        steps: [
          { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
          { do: "wait", stream: "s", until: { ended: true }, settleMs: 0 },
          { do: "record", row: "native/t/x", stream: "s" },
        ],
      },
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  assert.equal(clock.t, 0);
  assert.equal(out.rows["native/t/x"].timedOut, false);
});

test("steps report themselves to the log as program: step", async () => {
  const lines = [];
  await runSteps(
    [
      { do: "settle", ms: 1 },
      { do: "sleep", ms: 1 },
    ],
    {},
    { log: (line) => lines.push(line) },
  );
  assert.deepEqual(lines, ["native/t: settle", "native/t: sleep"]);
});

test("the default request ceiling is 400 and the error names the step that crossed it", async () => {
  const steps = Array.from({ length: 401 }, () => ({ do: "write", doc: "a", fields: { n: 1 } }));
  const { out, log } = await runSteps(steps);
  assert.match(out.errors["native/t"], /request ceiling 400 reached at write/);
  assert.equal(log.filter(([name]) => name === "commit").length, 400);
  const begin = await runSteps(
    [{ do: "txn", writes: [{ doc: "a", fields: {} }] }],
    {},
    { maxRequests: 0 },
  );
  assert.match(begin.out.errors["native/t"], /reached at begin/);
  const open = await runSteps([{ do: "open", stream: "s", targets: [] }], {}, { maxRequests: 0 });
  assert.match(open.out.errors["native/t"], /reached at open s/);
  const txn = await runSteps(
    [{ do: "txn", writes: [{ doc: "a", fields: {} }] }],
    {},
    { maxRequests: 1 },
  );
  assert.match(txn.out.errors["native/t"], /reached at txn/);
  const commit = await runSteps(
    [{ do: "commit", writes: [{ doc: "a", fields: {} }] }],
    {},
    { maxRequests: 0 },
  );
  assert.match(commit.out.errors["native/t"], /reached at commit/);
  const del = await runSteps([{ do: "delete", doc: "a" }], {}, { maxRequests: 0 });
  assert.match(del.out.errors["native/t"], /reached at delete/);
  const seed = await runSteps([{ do: "seed", doc: "a", fields: {} }], {}, { maxRequests: 0 });
  assert.match(seed.out.errors["native/t"], /reached at seed/);
});

test("a delete step deletes and does nothing else; a failed commit, begin or delete is the program's error", async () => {
  const del = await runSteps([{ do: "delete", doc: "a" }]);
  assert.deepEqual(del.out.errors, {});
  assert.equal(del.log.length, 1);
  for (const [method, steps] of [
    ["commit", [{ do: "seed", doc: "a", fields: {} }]],
    ["commit", [{ do: "delete", doc: "a" }]],
    ["commit", [{ do: "commit", writes: [{ doc: "a", fields: {} }] }]],
    ["commit", [{ do: "txn", writes: [{ doc: "a", fields: {} }] }]],
    ["beginTransaction", [{ do: "txn", writes: [{ doc: "a", fields: {} }] }]],
  ]) {
    const { client, clock } = fakeClient({});
    client[method] = async () => {
      await Promise.resolve();
      throw new Error(`${method} failed`);
    };
    const out = await runNative(
      [{ id: "native/t", conditions: ["x"], docs: { a: "lsn/{run}-a" }, steps }],
      {
        client,
        project: PROJECT,
        run: RUN,
        sleep: async (ms) => {
          await Promise.resolve();
          clock.t += ms;
        },
        now: () => clock.t,
      },
    );
    assert.equal(out.errors["native/t"], `${method} failed`, JSON.stringify(steps));
  }
});

test("a stream name can be used again after it was closed, from its first frame", async () => {
  const { client, clock } = fakeClient({});
  const open = client.openStream;
  let n = 0;
  client.openStream = () => {
    const stream = open();
    n += 1;
    for (let i = 0; i < 4 - n; i += 1) stream.frames.push(change("ADD", [i + 1]));
    return stream;
  };
  const out = await runNative(
    [
      {
        id: "native/t",
        conditions: ["x"],
        docs: { a: "lsn/{run}-a" },
        steps: [
          { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
          { do: "record", row: "native/t/one", stream: "s" },
          { do: "close", stream: "s" },
          { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
          { do: "record", row: "native/t/two", stream: "s" },
          { do: "close", stream: "s" },
        ],
      },
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  assert.equal(out.rows["native/t/one"].rows.length, 3);
  assert.equal(out.rows["native/t/two"].rows.length, 2);
});

test("a token or read time that is a plain Buffer survives a save and an open unchanged", async () => {
  const bytes = Buffer.from([9, 8, 7]);
  const { streams } = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "t" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "t" }] },
    ],
    { 0: [change("CURRENT", [1], { resumeToken: bytes })] },
  );
  assert.deepEqual(streams[1].sent[0].addTarget.resumeToken, bytes);
  assert.ok(Buffer.isBuffer(streams[1].sent[0].addTarget.resumeToken));
});

/** A run whose sleep and close take a turn of the event loop, and which logs the order of things. */
async function ordered(steps, script = {}) {
  const events = [];
  const { client, streams, clock } = fakeClient(script);
  const commit = client.commit;
  client.commit = async (request) => {
    events.push("commit");
    return commit(request);
  };
  const open = client.openStream;
  client.openStream = () => {
    const stream = open();
    const close = stream.close;
    stream.close = async () => {
      events.push("close:start");
      await new Promise((resolve) => setTimeout(resolve, 5));
      events.push("close:end");
      return close();
    };
    return stream;
  };
  const out = await runNative(
    [{ id: "native/t", conditions: ["x"], docs: { a: "lsn/{run}-a" }, steps }],
    {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        events.push(`sleep:${ms}:start`);
        await Promise.resolve();
        clock.t += ms;
        events.push(`sleep:${ms}:end`);
      },
      now: () => clock.t,
    },
  );
  return { out, events, streams };
}

test("every wait, settle and sleep finishes before the next step starts; settle 0 never sleeps", async () => {
  const frames = { 0: [change("CURRENT", [1])] };
  const open = { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] };
  const seed = { do: "seed", doc: "a", fields: {} };
  const beforeClosing = (events) => {
    const end = events.indexOf("close:start");
    return end === -1 ? events : events.slice(0, end);
  };
  const waitThen = async (extra) =>
    (
      await ordered(
        [open, { do: "wait", stream: "s", until: { current: 1 }, ...extra }, seed],
        frames,
      )
    ).events;
  assert.deepEqual(beforeClosing(await waitThen({ settleMs: 700 })), [
    "sleep:700:start",
    "sleep:700:end",
    "commit",
  ]);
  assert.deepEqual(beforeClosing(await waitThen({ settleMs: 0 })), ["commit"]);
  assert.deepEqual((await ordered([{ do: "settle", ms: 40 }, seed])).events, [
    "sleep:40:start",
    "sleep:40:end",
    "commit",
  ]);
  assert.deepEqual((await ordered([{ do: "sleep", ms: 30 }, seed])).events, [
    "sleep:30:start",
    "sleep:30:end",
    "commit",
  ]);
});

test("a close step finishes closing before the next step, and every stream is closed when the run returns", async () => {
  const open = (name) => ({ do: "open", stream: name, targets: [{ id: 1, doc: "a" }] });
  const closing = await ordered([
    open("s"),
    { do: "close", stream: "s" },
    { do: "seed", doc: "a", fields: {} },
  ]);
  assert.deepEqual(closing.events, [
    "close:start",
    "close:end",
    "commit",
    "close:start",
    "close:end",
  ]);
  const left = await ordered([open("s"), open("t")]);
  assert.deepEqual(left.events, ["close:start", "close:end", "close:start", "close:end"]);
  assert.deepEqual(
    left.streams.map((stream) => stream.ended()?.reason),
    ["closed-by-harness", "closed-by-harness"],
  );
});

test("a save leaves its stream open, and without a token or time in the frames saves nothing to resume from", async () => {
  const { out } = await runSteps([
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "save", stream: "s", id: 1, token: "t" },
    { do: "record", row: "native/t/x", stream: "s" },
  ]);
  assert.equal(out.rows["native/t/x"].end, null);
  const empty = await runSteps([
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "save", stream: "s", id: 1, token: "t", time: "w" },
    { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "t" }] },
  ]);
  assert.equal(empty.out.errors["native/t"], "no saved token t");
  const noTime = await runSteps([
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "save", stream: "s", id: 1, token: "t", time: "w" },
    { do: "open", stream: "r", targets: [{ id: 1, doc: "a", readTimeFrom: "w" }] },
  ]);
  assert.equal(noTime.out.errors["native/t"], "no saved read time w");
});

test("each request step issues exactly its own requests and nothing else", async () => {
  const one = async (step) => {
    const { out, log } = await runSteps([step]);
    assert.deepEqual(out.errors, {});
    return { requests: out.requests, log: log.map(([name]) => name) };
  };
  assert.deepEqual(await one({ do: "seed", doc: "a", fields: {} }), {
    requests: 1,
    log: ["commit"],
  });
  assert.deepEqual(await one({ do: "write", doc: "a", fields: {} }), {
    requests: 1,
    log: ["commit"],
  });
  assert.deepEqual(await one({ do: "delete", doc: "a" }), { requests: 1, log: ["commit"] });
  assert.deepEqual(await one({ do: "commit", writes: [{ doc: "a", fields: {} }] }), {
    requests: 1,
    log: ["commit"],
  });
  assert.deepEqual(await one({ do: "txn", writes: [{ doc: "a", fields: {} }] }), {
    requests: 2,
    log: ["begin", "commit"],
  });
  const sleeps = await runSteps([
    { do: "sleep", ms: 5 },
    { do: "settle", ms: 5 },
  ]);
  assert.deepEqual(sleeps.out.errors, {});
});

test("a record with groups lists the commit groups with the program's names; without it there is no groups key", async () => {
  const stamped = (doc, seconds) => ({
    kind: "documentChange",
    documentChange: {
      document: { name: `${ROOT}/lsn/${RUN}-${doc}`, updateTime: { seconds, nanos: 1 } },
      targetIds: [1],
    },
  });
  const frames = {
    0: [
      stamped("a", "5"),
      stamped("b", "5"),
      change("NO_CHANGE", [], { resumeToken: Buffer.from("t") }),
    ],
  };
  const rec = (groups) => [
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "record", row: "native/t/x", stream: "s", ...(groups ? { groups: true } : {}) },
    { do: "close", stream: "s" },
  ];
  const withGroups = await runSteps(rec(true), frames);
  assert.deepEqual(withGroups.out.rows["native/t/x"].groups, [
    { docs: ["a", "b"], sameUpdateTime: true },
  ]);
  assert.deepEqual(
    withGroups.out.rows["native/t/x"].rows.map((r) => r.doc ?? r.kind),
    ["a", "b", "boundary"],
  );
  const without = await runSteps(rec(false), frames);
  assert.equal("groups" in without.out.rows["native/t/x"], false);
});

test("runNative reports every name it issued with what each answer said", async () => {
  const { client, clock } = fakeClient({});
  const codes = [undefined, 3, 14, undefined, 14];
  let call = 0;
  client.commit = async () => {
    const code = codes[call++];
    if (code !== undefined) throw Object.assign(new Error("x"), { code });
  };
  const one = (id, step) => ({
    id: `native/${id}`,
    conditions: ["x"],
    docs: { a: "lsn/{run}-a", b: "lsn/{run}-b", c: "lsn/{run}-c", d: "lsn/{run}-d" },
    steps: [step],
  });
  const out = await runNative(
    [
      one("1", { do: "seed", doc: "a", fields: {} }),
      one("2", { do: "seed", doc: "b", fields: {} }),
      one("3", { do: "seed", doc: "c", fields: {} }),
      one("4", { do: "delete", doc: "a" }),
      one("5", { do: "delete", doc: "d" }),
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  const issued = Object.fromEntries(
    out.issued.map(([name, state]) => [name.split("-").at(-1), state]),
  );
  // a: created (ok), then deleted (ok); b: refused (code 3), nothing issued; c: unknown (code 14);
  // d: only ever deleted, and the delete's answer was unknown.
  assert.deepEqual(issued, {
    a: { present: false, unknownDelete: false },
    c: { present: "unknown", unknownDelete: false },
    d: { present: "unknown", unknownDelete: true },
  });
  assert.deepEqual(Object.keys(out.errors), ["native/2", "native/3", "native/5"]);
});

test("a ledger supplied by the caller keeps the names even when the run is cut short", async () => {
  const { createLedger } = await import("./fs-listen/native-ledger.mjs");
  const ledger = createLedger();
  const { client, clock } = fakeClient({});
  await runNative(
    [
      {
        id: "native/t",
        conditions: ["x"],
        docs: { a: "lsn/{run}-a" },
        steps: [{ do: "seed", doc: "a", fields: {} }, { do: "teleport" }],
      },
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      ledger,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  assert.deepEqual(
    ledger.entries().map(([name]) => name),
    [`${ROOT}/lsn/${RUN}-a`],
  );
});

test("a refresh step asks the client for a new token, and a client without one is fine", async () => {
  const { client } = fakeClient({});
  let refreshed = 0;
  const steps = [{ do: "refresh" }];
  const run = (c) =>
    runNative([{ id: "native/t", conditions: ["x"], docs: {}, steps }], {
      client: c,
      project: PROJECT,
      run: RUN,
      sleep: async () => {},
      now: () => 0,
    });
  assert.deepEqual((await run(client)).errors, {});
  client.refresh = async () => {
    refreshed += 1;
  };
  assert.deepEqual((await run(client)).errors, {});
  assert.equal(refreshed, 1);
});

test("a confirmed create is present in the ledger, and a client that refuses definitively issues nothing", async () => {
  const { out } = await runSteps([{ do: "seed", doc: "a", fields: {} }]);
  assert.deepEqual(
    out.issued.map(([, state]) => state),
    [{ present: true, unknownDelete: false }],
  );
  const { client, clock } = fakeClient({});
  client.commit = async () => {
    throw Object.assign(new Error("denied"), { code: 7 });
  };
  const refused = await runNative(
    [
      {
        id: "native/t",
        conditions: ["x"],
        docs: { a: "lsn/{run}-a" },
        steps: [{ do: "seed", doc: "a", fields: {} }],
      },
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  assert.deepEqual(refused.issued, []);
});

test("a refresh step waits for the client's new token before the next step; a sleep step never refreshes", async () => {
  const events = [];
  const { client, clock } = fakeClient({});
  client.refresh = async () => {
    events.push("refresh:start");
    await new Promise((resolve) => setTimeout(resolve, 5));
    events.push("refresh:end");
  };
  const commit = client.commit;
  client.commit = async (request) => {
    events.push("commit");
    return commit(request);
  };
  const run = (steps) =>
    runNative([{ id: "native/t", conditions: ["x"], docs: { a: "lsn/{run}-a" }, steps }], {
      client,
      project: PROJECT,
      run: RUN,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    });
  await run([{ do: "refresh" }, { do: "seed", doc: "a", fields: {} }]);
  assert.deepEqual(events, ["refresh:start", "refresh:end", "commit"]);
  events.length = 0;
  await run([
    { do: "sleep", ms: 5 },
    { do: "settle", ms: 5 },
  ]);
  assert.deepEqual(events, [], "only a refresh step refreshes");
});

test("every Commit is journaled before the client sends it and again with its answer (a crash then still names the run's names)", async () => {
  const { createLedger } = await import("./fs-listen/native-ledger.mjs");
  const lines = [];
  const ledger = createLedger({ journal: { append: (r) => lines.push(r), close() {} } });
  const { client, clock } = fakeClient({});
  const commit = client.commit;
  let seenBeforeSend;
  client.commit = async (request) => {
    seenBeforeSend = lines.map((l) => l.phase);
    return commit(request);
  };
  await runNative(
    [
      {
        id: "native/t",
        conditions: ["x"],
        docs: { a: "lsn/{run}-a" },
        steps: [{ do: "seed", doc: "a", fields: {} }],
      },
    ],
    {
      client,
      project: PROJECT,
      run: RUN,
      ledger,
      sleep: async (ms) => {
        await Promise.resolve();
        clock.t += ms;
      },
      now: () => clock.t,
    },
  );
  assert.deepEqual(seenBeforeSend, ["before"]);
  assert.deepEqual(
    lines.map((l) => [l.phase, l.outcome]),
    [
      ["before", undefined],
      ["after", "ok"],
    ],
  );
  assert.deepEqual(lines[0].names, [{ name: `${ROOT}/lsn/${RUN}-a`, op: "create" }]);
});

test("a definite refusal is journaled as refused and an unknown answer as unknown", async () => {
  const { createLedger } = await import("./fs-listen/native-ledger.mjs");
  for (const [code, outcome] of [
    [7, "refused"],
    [14, "unknown"],
  ]) {
    const lines = [];
    const ledger = createLedger({ journal: { append: (r) => lines.push(r), close() {} } });
    const { client } = fakeClient({});
    client.commit = async () => {
      throw Object.assign(new Error("x"), { code });
    };
    await runNative(
      [
        {
          id: "native/t",
          conditions: ["x"],
          docs: { a: "lsn/{run}-a" },
          steps: [{ do: "seed", doc: "a", fields: {} }],
        },
      ],
      { client, project: PROJECT, run: RUN, ledger, sleep: async () => {}, now: () => 0 },
    );
    assert.equal(lines.at(-1).outcome, outcome, `${code}`);
  }
});

test("save takes the token of a kind when asked: the CURRENT frame of the target, or the last global boundary, apart from the latest of either", async () => {
  const frames = [
    change("CURRENT", [1], { resumeToken: Buffer.from("TC") }),
    change("NO_CHANGE", [], { resumeToken: Buffer.from("TG") }),
    change("NO_CHANGE", [1], { resumeToken: Buffer.from("TN") }),
    change("CURRENT", [2], { resumeToken: Buffer.from("OTHER") }),
    change("NO_CHANGE", [], {}),
  ];
  const tokenFor = async (kind) => {
    const { streams } = await runSteps(
      [
        { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
        { do: "save", stream: "s", id: 1, token: "tok", ...(kind ? { kind } : {}) },
        { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "tok" }] },
      ],
      { 0: frames },
    );
    return streams[1].sent[0].addTarget.resumeToken;
  };
  assert.deepEqual(await tokenFor(undefined), Buffer.from("TN"), "the latest covering the target");
  assert.deepEqual(await tokenFor("current"), Buffer.from("TC"));
  assert.deepEqual(await tokenFor("global"), Buffer.from("TG"));
  // A kind the frames do not hold saves nothing to resume from.
  const none = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok", kind: "current" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "tok" }] },
    ],
    { 0: [change("NO_CHANGE", [], { resumeToken: Buffer.from("TG") })] },
  );
  assert.equal(none.out.errors["native/t"], "no saved token tok");
  const noGlobal = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok", kind: "global" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "tok" }] },
    ],
    { 0: [change("CURRENT", [1], { resumeToken: Buffer.from("TC") })] },
  );
  assert.equal(noGlobal.out.errors["native/t"], "no saved token tok");
  // The CURRENT frame must be the target's own: another target's CURRENT token is not it.
  const other = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok", kind: "current" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "tok" }] },
    ],
    { 0: [change("CURRENT", [2], { resumeToken: Buffer.from("OTHER") })] },
  );
  assert.equal(other.out.errors["native/t"], "no saved token tok");
  // An unknown kind is refused, not read as the default.
  const unknown = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "tok", kind: "latest" },
    ],
    { 0: frames },
  );
  assert.match(unknown.out.errors["native/t"], /unknown save kind latest/);
});

const sha = (text) => createHash("sha256").update(Buffer.from(text)).digest("hex");

test("a save states which frame its token came from: the index, the kind, the target-change fields that identify it, and the documents delivered before it", async () => {
  const frames = [
    change("ADD", [1]),
    change("NO_CHANGE", [], { resumeToken: Buffer.from("B1") }),
    docChange,
    change("CURRENT", [1], {
      resumeToken: Buffer.from("TC"),
      readTime: { seconds: "7", nanos: 1 },
    }),
    change("NO_CHANGE", [], {
      resumeToken: Buffer.from("TG"),
      readTime: { seconds: "8", nanos: 2 },
    }),
    docChange,
    change("NO_CHANGE", [], { resumeToken: Buffer.from("G2") }),
    change("CURRENT", [2], { resumeToken: Buffer.from("OTHER") }),
  ];
  const run = async (save) => {
    const { out } = await runSteps(
      [
        { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
        { do: "save", stream: "s", id: 1, ...save },
      ],
      { 0: frames },
    );
    return out.saves;
  };
  const token = (extra) => ({ bytes: 2, ...extra });
  assert.deepEqual(await run({ token: "t", kind: "current" }), [
    {
      program: "native/t",
      stream: "s",
      id: 1,
      name: "t",
      timeName: null,
      kind: "current",
      frames: frames.length,
      token: token({ frameIndex: 3, type: "CURRENT", targetIds: [1], sha256: sha("TC") }),
      readTime: { frameIndex: 5 - 1, type: "NO_CHANGE", targetIds: [], seconds: "8", nanos: 2 },
      documentChangesBefore: 1,
      documentChangesAfterCurrent: 0,
    },
  ]);
  assert.deepEqual(await run({ token: "t", kind: "global" }), [
    {
      program: "native/t",
      stream: "s",
      id: 1,
      name: "t",
      timeName: null,
      kind: "global",
      frames: frames.length,
      token: token({ frameIndex: 6, type: "NO_CHANGE", targetIds: [], sha256: sha("G2") }),
      readTime: { frameIndex: 4, type: "NO_CHANGE", targetIds: [], seconds: "8", nanos: 2 },
      documentChangesBefore: 2,
      documentChangesAfterCurrent: 1,
    },
  ]);
  // Without a kind: the latest that covers the target (the global boundary at index 6).
  const latest = await run({ token: "t", time: "w" });
  assert.equal(latest[0].kind, "latest");
  assert.equal(latest[0].timeName, "w");
  assert.equal(latest[0].token.frameIndex, 6);
  // Nothing to resume from: the entry says so, with no token and no frame.
  const none = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "t", kind: "current" },
    ],
    { 0: [change("NO_CHANGE", [], { resumeToken: Buffer.from("TG") })] },
  );
  assert.equal(none.out.saves[0].token, null);
  assert.equal(none.out.saves[0].readTime, null);
  assert.equal(none.out.saves[0].documentChangesBefore, null);
  assert.equal(none.out.saves[0].documentChangesAfterCurrent, null);
  // A token saved before the target is CURRENT has no documents after CURRENT to count.
  const early = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "t" },
    ],
    {
      0: [
        change("ADD", [1]),
        change("NO_CHANGE", [], { resumeToken: Buffer.from("B1") }),
        docChange,
      ],
    },
  );
  assert.equal(early.out.saves[0].token.frameIndex, 1);
  assert.equal(early.out.saves[0].documentChangesAfterCurrent, null);
});

test("a row of a stream opened with a saved token says where the token came from; other rows say nothing", async () => {
  const frames = [
    change("ADD", [1]),
    change("NO_CHANGE", [], { resumeToken: Buffer.from("B1") }),
    change("CURRENT", [1], { resumeToken: Buffer.from("TC") }),
    change("NO_CHANGE", [], { resumeToken: Buffer.from("TG") }),
  ];
  const { out } = await runSteps(
    [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "t", kind: "current" },
      { do: "record", row: "native/t/first", stream: "s" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "t" }] },
      { do: "record", row: "native/t/resumed", stream: "r" },
      { do: "open", stream: "x", targets: [{ id: 1, doc: "a" }] },
      { do: "record", row: "native/t/fresh", stream: "x" },
    ],
    { 0: frames, 1: frames, 2: frames },
  );
  assert.equal(out.rows["native/t/first"].resumedFrom, undefined);
  assert.equal(out.rows["native/t/fresh"].resumedFrom, undefined);
  assert.deepEqual(out.rows["native/t/resumed"].resumedFrom, [
    {
      name: "t",
      kind: "current",
      frameIndex: 2,
      type: "CURRENT",
      targetIds: [1],
      sha256: sha("TC"),
    },
  ]);
});
