import assert from "node:assert/strict";
import { test } from "node:test";

import {
  clientRow,
  createInterpreter,
  frameRow,
  runStage2Window,
  wireCall,
} from "./auth-fs-cross/stage2-orchestrator.mjs";

const ROOT = "projects/p/databases/(default)/documents";
const ctx = { project: "p", run: "r", databases: {}, target: { kind: "local" } };
const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = (exp) => `${part({ alg: "RS256" })}.${part({ exp })}.s`;

/** A fake SDK client: commands answer at once unless `hold` names their op. */
function fakeClient({ hold = [] } = {}) {
  const events = [];
  const commands = [];
  const waiters = [];
  const deliver = (event) => {
    events.push(event);
    for (const w of waiters.slice())
      if (w.match(event)) {
        waiters.splice(waiters.indexOf(w), 1);
        w.resolve(event);
      }
  };
  return {
    events,
    commands,
    deliver,
    closed: false,
    ready: async () => ({ event: "ready" }),
    send(op, fields) {
      commands.push({ op, ...fields });
      const result = { event: "result", id: fields.id, ok: true };
      if (!hold.includes(op)) deliver(result);
      return this.waitFor((e) => e.event === "result" && e.id === fields.id);
    },
    waitFor(match) {
      const seen = events.find(match);
      if (seen) return Promise.resolve(seen);
      return new Promise((resolve) => waiters.push({ match, resolve }));
    },
    async close() {
      this.closed = true;
    },
  };
}

function fakeRecorder() {
  const frames = [];
  let end;
  return {
    frames,
    since: (n) => frames.slice(n),
    ended: () => end,
    end: (how) => {
      end = { at: 0, ...how };
    },
    close: async () => {
      end ??= { reason: "closed-by-harness" };
    },
  };
}

function fakeSession({ onSeed = () => {}, principals = {} } = {}) {
  const calls = [];
  const map = new Map(Object.entries(principals));
  const resolve = (value) =>
    JSON.parse(JSON.stringify(value).replaceAll(/UID\(([a-z0-9-]+)\)/g, (_, n) => `uid-${n}`));
  return {
    calls,
    principals: map,
    emailOf: (name) => `${name}@example.com`,
    resolve,
    mask: (value) => JSON.parse(JSON.stringify(value)),
    bearerFor: (as) => `Bearer ${as}`,
    grpcClient: {},
    protos: {},
    async seed(writes) {
      calls.push(["seed", writes.map((w) => w.doc)]);
      onSeed(writes);
    },
    async pause(ms) {
      calls.push(["pause", ms]);
    },
    async sleepUntil(target) {
      calls.push(["sleepUntil", target]);
      // One timer fires late.
      return target !== 1_035_300;
    },
    async ownerRead(doc) {
      calls.push(["read", doc]);
      return { exists: false, fields: null };
    },
    async act(step) {
      calls.push(["act", step]);
    },
    chargeHarness() {
      calls.push(["charge"]);
    },
  };
}

test("a frame row keeps what a listener saw and drops heartbeats and tokens", () => {
  assert.equal(
    frameRow(
      {
        kind: "targetChange",
        targetChange: { targetChangeType: "NO_CHANGE", targetIds: [], resumeToken: "x" },
      },
      ROOT,
    ),
    null,
  );
  assert.deepEqual(
    frameRow(
      {
        kind: "targetChange",
        targetChange: {
          targetChangeType: "REMOVE",
          targetIds: [1],
          cause: { code: 7, message: "denied" },
          readTime: {},
        },
      },
      ROOT,
    ),
    { kind: "targetChange", type: "REMOVE", targetIds: [1], cause: { code: 7, message: "denied" } },
  );
  assert.deepEqual(
    frameRow(
      { kind: "targetChange", targetChange: { targetChangeType: "CURRENT", targetIds: [2] } },
      ROOT,
    ),
    { kind: "targetChange", type: "CURRENT", targetIds: [2], cause: null },
  );
  assert.deepEqual(
    frameRow(
      {
        kind: "documentChange",
        documentChange: {
          document: {
            name: `${ROOT}/afc2-owned/a`,
            fields: { n: { integerValue: "3" } },
            updateTime: {},
          },
          targetIds: [1],
        },
      },
      ROOT,
    ),
    { kind: "documentChange", doc: "afc2-owned/a", n: "3", targetIds: [1], removedTargetIds: [] },
  );
  assert.deepEqual(
    frameRow(
      {
        kind: "documentRemove",
        documentRemove: { document: `${ROOT}/afc2-owned/a`, removedTargetIds: [2] },
      },
      ROOT,
    ),
    { kind: "documentRemove", doc: "afc2-owned/a", removedTargetIds: [2] },
  );
  assert.deepEqual(frameRow({ kind: "filter", filter: { targetId: 2, count: 1 } }, ROOT), {
    kind: "filter",
    targetId: 2,
    count: 1,
  });
});

test("a wire record names the same call on production and the local target", () => {
  const local = {
    host: "127.0.0.1",
    path: "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
  };
  const production = {
    host: "identitytoolkit.googleapis.com",
    path: "/v1/accounts:signInWithPassword",
  };
  assert.deepEqual(wireCall(local), wireCall(production));
  assert.deepEqual(wireCall({ host: "127.0.0.1", path: "/google.firestore.v1.Firestore/Commit" }), {
    service: "firestore",
    method: "/google.firestore.v1.Firestore/Commit",
  });
  assert.deepEqual(wireCall({ host: "securetoken.googleapis.com", path: "/v1/token" }), {
    service: "securetoken",
    method: "/v1/token",
  });
  assert.deepEqual(
    clientRow(
      { event: "result", id: "c", ok: false, code: "permission-denied", attempts: 1 },
      new Map([["c", "transaction"]]),
    ),
    { kind: "result", op: "transaction", ok: false, code: "permission-denied", attempts: 1 },
  );
  assert.equal(clientRow({ event: "snapshot" }, new Map()), null);
});

test("a probe records only what arrived after its commit, and a stream's end in its window", async () => {
  const recorder = fakeRecorder();
  const client = fakeClient();
  const session = fakeSession({
    principals: { a: { uid: "uid-a", idToken: token(100) } },
    onSeed: () => {
      recorder.frames.push({
        kind: "documentChange",
        documentChange: {
          document: { name: `${ROOT}/afc2-owned/a`, fields: { n: { integerValue: "1" } } },
          targetIds: [1],
        },
      });
      recorder.end({ reason: "error", code: 16 });
      client.deliver({
        event: "snapshot",
        name: "doc",
        fromCache: false,
        hasPendingWrites: false,
        docs: [{ path: "afc2-owned/a", exists: true, data: { n: 1 } }],
      });
      client.deliver({ event: "listen-error", name: "other", code: "permission-denied" });
    },
  });
  const program = {
    steps: [
      {
        do: "stream",
        name: "grpc-a",
        as: "a",
        targets: [{ targetId: 1, document: "afc2-owned/a" }],
      },
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "sdk", client: "c", op: "signIn", as: "a" },
      { do: "sdk", client: "c", op: "listen", name: "doc", path: "afc2-owned/a" },
      {
        do: "probe",
        id: "p",
        condition: "X",
        writes: [{ doc: "afc2-owned/a" }],
        observe: ["grpc-a", "c/doc"],
      },
    ],
  };
  let opened;
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: (args) => {
      opened = args;
      recorder.frames.push({
        kind: "targetChange",
        targetChange: { targetChangeType: "CURRENT", targetIds: [1] },
      });
      return recorder;
    },
    sdkConfig: {},
  });
  const rows = await interpreter.run();
  assert.equal(opened.metadata.get("authorization")[0], "Bearer a");
  // The stream is one harness request, counted before it opens.
  assert.deepEqual(session.calls[0], ["charge"]);
  assert.deepEqual(opened.targets, [
    { targetId: 1, documents: { documents: [`${ROOT}/afc2-owned/a`] } },
  ]);
  // The password goes to the client on its stdin only: never into a row or the timeline.
  assert.equal(
    JSON.stringify([rows, interpreter.timeline()]).includes(client.commands[0].password),
    false,
  );
  assert.deepEqual(client.commands[0], {
    op: "signIn",
    email: "a@example.com",
    password: client.commands[0].password,
    tenantId: null,
    id: "signIn-1",
  });
  assert.deepEqual(interpreter.wireCounts(), { c: 0 });
  client.deliver({ event: "wire", host: "127.0.0.1", path: "/x", principal: null });
  assert.deepEqual(interpreter.wireCounts(), { c: 1 });
  assert.deepEqual(rows.p, {
    id: "p",
    conditions: ["X"],
    listeners: {
      "grpc-a": {
        events: [
          {
            kind: "documentChange",
            doc: "afc2-owned/a",
            n: "1",
            targetIds: [1],
            removedTargetIds: [],
          },
        ],
        endedBefore: false,
        end: { reason: "error", code: 16 },
      },
      "c/doc": {
        events: [
          {
            kind: "snapshot",
            fromCache: false,
            pending: false,
            docs: [{ path: "afc2-owned/a", exists: true, n: 1 }],
          },
        ],
      },
    },
    clients: {},
  });
  assert.deepEqual(session.calls.slice(1, 3), [
    ["seed", ["afc2-owned/a"]],
    ["pause", 12_000],
  ]);
});

test("a listener's awaited first snapshot is in the first row that observes it, and only there", async () => {
  const client = fakeClient();
  const snapshot = (n) => ({
    event: "snapshot",
    name: "doc",
    fromCache: false,
    hasPendingWrites: false,
    docs: [{ path: "afc2-owned/a", exists: true, data: { n } }],
  });
  const send = client.send.bind(client);
  // The listen answers after its first snapshot, as the SDK operation does.
  client.send = (op, fields) => {
    if (op === "listen") client.deliver(snapshot(0));
    return send(op, fields);
  };
  let n = 0;
  const session = fakeSession({
    principals: { a: { uid: "uid-a", idToken: token(100) } },
    onSeed: () => {
      n += 1;
      client.deliver(snapshot(n));
    },
  });
  const probe = (id) => ({
    do: "probe",
    id,
    condition: "X",
    writes: [{ doc: "afc2-owned/a" }],
    observe: ["c/doc"],
  });
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "sdk", client: "c", op: "signIn", as: "a" },
      { do: "sdk", client: "c", op: "listen", name: "doc", path: "afc2-owned/a" },
      { do: "sdk", client: "c", op: "offline" },
      probe("first"),
      probe("second"),
    ],
  };
  const rows = await createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => fakeRecorder(),
    sdkConfig: {},
  }).run();
  const seen = (id) => rows[id].listeners["c/doc"].events.map((e) => e.docs[0].n);
  assert.deepEqual(seen("first"), [0, 1]);
  assert.deepEqual(seen("second"), [2]);
});

test("each native stream's end is kept with its time since opening and against its token's expiry", async () => {
  const ended = fakeRecorder();
  const open = fakeRecorder();
  const recorders = [ended, open];
  let clock = 1_000_000;
  const session = fakeSession({
    principals: {
      a: { uid: "uid-a", idToken: token(4_600) },
      b: { uid: "uid-b", idToken: token(4_700) },
    },
  });
  const program = {
    steps: [
      { do: "stream", name: "grpc-a", as: "a", targets: [{ targetId: 1, document: "afc2-owned/a" }] },
      { do: "stream", name: "grpc-b", as: "b", targets: [{ targetId: 1, document: "afc2-owned/b" }] },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => fakeClient(),
    openListen: () => {
      clock += 500;
      return recorders.shift();
    },
    now: () => clock,
    sdkConfig: {},
  });
  await interpreter.run();
  // grpc-a opened at 1,000,500 ms; it ended 3,540 s later, 40 s before its exp (4,600 s).
  ended.end({ at: 3_540_000, reason: "error", code: 13, details: "x" });
  assert.deepEqual(interpreter.streamEnds(), {
    "grpc-a": {
      reason: "error",
      code: 13,
      details: "x",
      openedAtMs: 500,
      sinceOpenedMs: 3_540_000,
      vsExpiryMs: 1_000_500 + 3_540_000 - 4_600_000,
    },
    "grpc-b": null,
  });
});

test("a resume probe reopens a listener from its resume token, as its own and as another principal", async () => {
  const change = (type, targetIds = [1], resumeToken) => ({
    kind: "targetChange",
    targetChange: { targetChangeType: type, targetIds, ...(resumeToken ? { resumeToken } : {}) },
  });
  const doc = (n) => ({
    kind: "documentChange",
    documentChange: {
      document: { name: `${ROOT}/afc2-open/resume`, fields: { n: { integerValue: String(n) } } },
      targetIds: [1],
    },
  });
  const opened = [];
  const recorders = [];
  const session = fakeSession({
    principals: {
      a: { uid: "uid-a", idToken: token(100) },
      b: { uid: "uid-b", idToken: token(100) },
    },
  });
  const interpreter = createInterpreter(
    {
      steps: [
        {
          do: "resume-probe",
          id: "resume/open",
          condition: "X",
          as: "a",
          document: "afc2-open/resume",
          write: { doc: "afc2-open/resume", fields: { n: { integerValue: "1" } } },
          resumes: [
            { name: "same", as: "a" },
            { name: "switch", as: "b" },
          ],
        },
      ],
    },
    {
      session,
      ctx,
      spawnClient: () => fakeClient(),
      openListen: (args) => {
        opened.push(args);
        const recorder = fakeRecorder();
        recorders.push(recorder);
        if (recorders.length === 1)
          recorder.frames.push(
            change("ADD"),
            doc(0),
            change("CURRENT"),
            change("NO_CHANGE", [], "dG9rZW4="),
          );
        else
          recorder.frames.push(
            change("ADD"),
            change("NO_CHANGE", []),
            change("NO_CHANGE", []),
            doc(1),
            change("CURRENT", [1], "dG9rZW4y"),
            change("NO_CHANGE", [], "dG9rZW4z"),
          );
        return recorder;
      },
      sdkConfig: {},
    },
  );
  const rows = await interpreter.run();
  // The first stream is closed before the write; each resume carries the token it gave.
  assert.equal(opened.length, 3);
  assert.equal(opened[0].metadata.get("authorization")[0], "Bearer a");
  assert.equal(opened[2].metadata.get("authorization")[0], "Bearer b");
  assert.deepEqual(opened[1].targets, [
    {
      targetId: 1,
      documents: { documents: [`${ROOT}/afc2-open/resume`] },
      resumeToken: "dG9rZW4=",
    },
  ]);
  assert.ok(recorders.every((r) => r.ended()));
  assert.deepEqual(
    session.calls.filter(([k]) => k === "seed"),
    [["seed", ["afc2-open/resume"]]],
  );
  // Boundaries are kept (collapsed when repeated), with whether a token or read time came.
  const resumed = [
    { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false },
    { kind: "boundary", resumeToken: false },
    { kind: "documentChange", doc: "afc2-open/resume", n: "1", targetIds: [1], removedTargetIds: [] },
    { kind: "targetChange", type: "CURRENT", targetIds: [1], cause: null, resumeToken: true },
    { kind: "boundary", resumeToken: true },
  ];
  assert.deepEqual(rows["resume/open"], {
    id: "resume/open",
    conditions: ["X"],
    first: [
      { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false },
      { kind: "documentChange", doc: "afc2-open/resume", n: "0", targetIds: [1], removedTargetIds: [] },
      { kind: "targetChange", type: "CURRENT", targetIds: [1], cause: null, resumeToken: false },
      { kind: "boundary", resumeToken: true },
    ],
    resumes: {
      same: { frames: resumed, end: null },
      switch: { frames: resumed, end: null },
    },
  });
});

test("a resume probe without a resume token stops the run, and a stop in its window closes its stream", async () => {
  const program = (resumes) => ({
    steps: [
      {
        do: "resume-probe",
        id: "resume/open",
        condition: "X",
        as: "a",
        document: "afc2-open/resume",
        write: { doc: "afc2-open/resume", fields: {} },
        resumes,
      },
    ],
  });
  const principals = { a: { uid: "uid-a", idToken: token(100) } };
  // The first stream ends without a token: nothing is written, the run stops.
  const tokenless = fakeSession({ principals });
  const ended = fakeRecorder();
  ended.end({ reason: "error", code: 7 });
  await assert.rejects(
    createInterpreter(program([{ name: "same", as: "a" }]), {
      session: tokenless,
      ctx,
      spawnClient: () => fakeClient(),
      openListen: () => ended,
      sdkConfig: {},
    }).run(),
    /resume\/open: no resume token/,
  );
  assert.deepEqual(
    tokenless.calls.filter(([k]) => k === "seed"),
    [],
  );
  // A stop while a resume is watched closes that stream before the run ends.
  const stopped = fakeSession({ principals });
  stopped.pause = async () => {
    throw new Error("stopped by a signal");
  };
  const recorders = [];
  await assert.rejects(
    createInterpreter(program([{ name: "same", as: "a" }]), {
      session: stopped,
      ctx,
      spawnClient: () => fakeClient(),
      openListen: () => {
        const recorder = fakeRecorder();
        if (recorders.length === 0)
          recorder.frames.push({
            kind: "targetChange",
            targetChange: { targetChangeType: "NO_CHANGE", targetIds: [], resumeToken: "dA==" },
          });
        recorders.push(recorder);
        return recorder;
      },
      sdkConfig: {},
    }).run(),
    /stopped by a signal/,
  );
  assert.equal(recorders.length, 2);
  assert.deepEqual(
    recorders.map((r) => r.ended()?.reason),
    ["closed-by-harness", "closed-by-harness"],
  );
});

test("placeholders resolve before a command leaves, and a transaction's result row names its op", async () => {
  const client = fakeClient({ hold: ["transaction"] });
  const session = fakeSession({
    principals: { alice: { uid: "uid-alice", tenantId: "tenant-1" } },
  });
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "sdk", client: "c", op: "signIn", as: "alice" },
      {
        do: "sdk",
        client: "c",
        op: "listen",
        name: "q",
        collection: "afc2-owned",
        where: [["owner", "==", "UID(alice)"]],
      },
      {
        do: "sdk",
        client: "c",
        op: "transaction",
        await: false,
        mark: "t",
        commandId: "tx-1",
        name: "t1",
        reads: ["afc2-tx/a"],
        write: { path: "afc2-tx/a", data: { by: "UID(alice)" } },
      },
      { do: "await", client: "c", event: "transaction-read", name: "t1" },
      { do: "sdk", client: "c", op: "signOut" },
      {
        do: "await",
        id: "tx/result",
        condition: "X",
        client: "c",
        event: "result",
        commandId: "tx-1",
        since: "t",
      },
      {
        do: "sdk",
        client: "c",
        op: "writeLater",
        writeId: "w",
        path: "afc2-pending/x",
        data: { owner: "UID(alice)" },
      },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => {},
    sdkConfig: {},
  });
  const running = interpreter.run();
  await new Promise((r) => setImmediate(r));
  client.deliver({ event: "transaction-read", name: "t1", attempt: 1, docs: [] });
  await new Promise((r) => setImmediate(r));
  client.deliver({
    event: "wire",
    host: "127.0.0.1",
    path: "/google.firestore.v1.Firestore/Commit",
    principal: null,
  });
  client.deliver({
    event: "result",
    id: "tx-1",
    ok: false,
    code: "permission-denied",
    attempts: 1,
  });
  const rows = await running;
  assert.equal(client.commands[0].tenantId, "tenant-1");
  assert.deepEqual(client.commands[1].where, [["owner", "==", "uid-alice"]]);
  assert.deepEqual(client.commands[2].write, { path: "afc2-tx/a", data: { by: "uid-alice" } });
  assert.equal(client.commands[2].id, "tx-1");
  assert.deepEqual(client.commands.find((c) => c.op === "writeLater").data, { owner: "uid-alice" });
  assert.equal("mark" in client.commands[2] || "await" in client.commands[2], false);
  assert.deepEqual(rows["tx/result"].result, {
    kind: "result",
    op: "transaction",
    ok: false,
    code: "permission-denied",
    attempts: 1,
  });
  assert.deepEqual(
    rows["tx/result"].clients.c.map((e) => e.kind),
    ["result", "wire", "result"],
    "the sign-out's result, the commit's wire record and the transaction's result",
  );
});

test("expiry probes wait for each token's own time and commit only that listener's document", async () => {
  const client = fakeClient();
  const session = fakeSession({ principals: { a: { uid: "uid-a", idToken: token(1_000) } } });
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      {
        do: "expiry-probes",
        id: "exp",
        plus: 35,
        conditions: ["X"],
        probes: [
          { token: { principal: "a" }, write: { doc: "afc2-owned/a-grpc" }, observe: [] },
          { token: { client: "c" }, write: { doc: "afc2-owned/a-sdk" }, observe: [] },
        ],
      },
    ],
  };
  client.deliver({ event: "auth", uid: "uid-a", exp: 2_000 });
  client.deliver({ event: "auth", uid: "uid-a", exp: 5_000 });
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => {},
    sdkConfig: {},
  });
  const rows = await interpreter.run();
  const waits = session.calls.filter(([kind]) => kind === "sleepUntil").map(([, t]) => t);
  assert.deepEqual(waits.toSorted(), [1_035_300, 2_035_300]);
  assert.deepEqual(
    session.calls
      .filter(([kind]) => kind === "seed")
      .map(([, docs]) => docs)
      .toSorted(),
    [["afc2-owned/a-grpc"], ["afc2-owned/a-sdk"]],
  );
  assert.deepEqual(
    rows.exp.probes.map((p) => [p.doc, p.onTime]),
    [
      ["afc2-owned/a-grpc", false],
      ["afc2-owned/a-sdk", true],
    ],
  );
});

test("auth steps, server reads and close-all reach the session and record every end", async () => {
  const recorder = fakeRecorder();
  const client = fakeClient();
  const session = fakeSession({ principals: { a: { uid: "uid-a" } } });
  const program = {
    steps: [
      {
        do: "stream",
        name: "grpc-a",
        as: "a",
        targets: [
          {
            targetId: 2,
            collection: "afc2-owned",
            where: [
              ["owner", "UID(a)"],
              ["via", "grpc"],
            ],
          },
        ],
      },
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "auth", action: "claims", principal: "a", claims: { c: true } },
      { do: "auth", action: "delete-tenant", tenant: "t1" },
      { do: "server", id: "s", condition: "X", docs: ["afc2-pending/x"] },
      { do: "close-all", id: "life", conditions: ["X"] },
    ],
  };
  let opened;
  client.deliver({ event: "listen-error", name: "doc", code: "unauthenticated" });
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: (args) => {
      opened = args;
      return recorder;
    },
    sdkConfig: {},
  });
  const rows = await interpreter.run();
  assert.deepEqual(
    opened.targets[0].query.structuredQuery.where.compositeFilter.filters.map(
      (f) => f.fieldFilter.value.stringValue,
    ),
    ["uid-a", "grpc"],
  );
  assert.deepEqual(
    session.calls.filter(([kind]) => kind === "act").map(([, step]) => step),
    [
      { action: "claims", principal: "a", tenant: undefined, claims: { c: true } },
      { action: "delete-tenant", principal: undefined, tenant: "t1", claims: undefined },
    ],
  );
  assert.deepEqual(rows.s.docs, { "afc2-pending/x": { exists: false, fields: null } });
  assert.deepEqual(rows.life.streams, { "grpc-a": { reason: "open" } });
  assert.deepEqual(rows.life.listeners, { "c/doc": { reason: "error", code: "unauthenticated" } });
  assert.equal(client.closed, true);
  assert.equal(recorder.ended().reason, "closed-by-harness");
});

test("a failed window still closes its clients and cleans up the sandbox, then fails", async () => {
  const client = fakeClient();
  const order = [];
  const session = {
    ...fakeSession({ principals: {} }),
    prepareSignIn: async () => order.push("prepare"),
    createTenant: async (slot) => order.push(`tenant ${slot}`),
    createPrincipal: async (name) => order.push(`principal ${name}`),
    wipe: async () => order.push("wipe"),
    publish: async (id) => order.push(`publish ${id}`),
    seed: async () => order.push("seed"),
    beginCleanup: () => order.push("begin-cleanup"),
    touchedDatabases: () => ["default"],
    deletePrincipals: async () => order.push("delete-principals"),
    deleteTenants: async () => order.push("delete-tenants"),
    deleteCreatedRulesets: async () => order.push("delete-rulesets"),
    audit: async () => [],
    close: async () => order.push("close"),
    evidence: () => ({}),
    counts: () => ({}),
  };
  const program = {
    tenants: ["t1"],
    principals: ["a"],
    ruleset: "cross2",
    seed: [],
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "sdk", client: "c", op: "signIn", as: "missing" },
    ],
  };
  await assert.rejects(
    runStage2Window(program, ctx, {
      createSession: () => session,
      spawnClient: () => client,
      principals: { a: { provider: "admin-password" } },
    }),
    (error) =>
      /no principal missing/.test(error.message) && error.partial.cleanupErrors.length === 0,
  );
  assert.equal(client.closed, true);
  assert.deepEqual(order, [
    "prepare",
    "tenant t1",
    "principal a",
    "wipe",
    "publish cross2",
    "seed",
    "begin-cleanup",
    "publish null",
    "wipe",
    "delete-principals",
    "delete-tenants",
    "delete-rulesets",
    "close",
  ]);
});

test("a stream that ended before a probe is reported as ended before, not as ending in it", async () => {
  const recorder = fakeRecorder();
  const session = fakeSession({ principals: { a: { uid: "uid-a" } } });
  const program = {
    steps: [
      {
        do: "stream",
        name: "grpc-a",
        as: "a",
        targets: [{ targetId: 1, document: "afc2-owned/a" }],
      },
      {
        do: "probe",
        id: "p",
        condition: "X",
        writes: [{ doc: "afc2-owned/a" }],
        observe: ["grpc-a"],
      },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => fakeClient(),
    openListen: () => {
      recorder.end({ reason: "error", code: 16 });
      return recorder;
    },
    sdkConfig: {},
  });
  const rows = await interpreter.run();
  assert.deepEqual(rows.p.listeners["grpc-a"], { events: [], endedBefore: true, end: null });
});

test("an aligned group waits once for its latest token, then probes one after another", async () => {
  const client = fakeClient();
  const session = fakeSession({
    principals: {
      a: { uid: "uid-a", idToken: token(1_000) },
      b: { uid: "uid-b", idToken: token(2_000) },
    },
  });
  client.deliver({ event: "auth", uid: "uid-a", exp: 3_000 });
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      {
        do: "expiry-groups",
        groups: [
          {
            id: "grpc",
            plus: 35,
            align: "latest",
            conditions: ["X"],
            probes: [
              { token: { principal: "a" }, write: { doc: "afc2-owned/a-grpc" }, observe: [] },
              { token: { principal: "b" }, write: { doc: "afc2-owned/b-grpc" }, observe: [] },
            ],
          },
          {
            id: "sdk",
            plus: 35,
            conditions: ["X"],
            probes: [{ token: { client: "c" }, write: { doc: "afc2-owned/a-sdk" }, observe: [] }],
          },
        ],
      },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => {},
    sdkConfig: {},
  });
  const rows = await interpreter.run();
  const waits = session.calls.filter(([kind]) => kind === "sleepUntil").map(([, t]) => t);
  // One wait for the aligned group (the later of a and b), one for the SDK probe.
  assert.deepEqual(waits.toSorted(), [2_035_300, 3_035_300]);
  const seeds = session.calls.filter(([kind]) => kind === "seed").map(([, docs]) => docs[0]);
  // The aligned probes go in their order, each after the previous one's window.
  assert.ok(seeds.indexOf("afc2-owned/a-grpc") < seeds.indexOf("afc2-owned/b-grpc"));
  const pauseBetween = session.calls.findIndex(
    ([kind, d]) => kind === "seed" && d[0] === "afc2-owned/b-grpc",
  );
  assert.equal(session.calls[pauseBetween - 1][0], "pause");
  assert.deepEqual(
    rows.grpc.probes.map((p) => [p.doc, p.onTime]),
    [
      ["afc2-owned/a-grpc", true],
      ["afc2-owned/b-grpc", true],
    ],
  );
  assert.deepEqual(
    rows.sdk.probes.map((p) => p.doc),
    ["afc2-owned/a-sdk"],
  );
});

test("a row names the clients whose request cap refused something, and only those", async () => {
  const capped = fakeClient();
  const fine = fakeClient();
  const spawned = [capped, fine];
  const session = fakeSession({ principals: {} });
  const program = {
    steps: [
      { do: "client", client: "a", transport: "node-sdk" },
      { do: "client", client: "b", transport: "node-sdk" },
      { do: "sdk", client: "a", op: "listen", name: "doc", path: "afc2-owned/x" },
      { do: "sdk", client: "b", op: "listen", name: "doc", path: "afc2-owned/y" },
      { do: "observe", id: "before", condition: "X", observe: ["a/doc", "b/doc"] },
      { do: "observe", id: "after", condition: "X", observe: ["a/doc", "b/doc"] },
      { do: "observe", id: "only-b", condition: "X", observe: ["b/doc"] },
      { do: "close-all", id: "life", conditions: ["X"] },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => spawned.shift(),
    openListen: () => {},
    sdkConfig: {},
  });
  const pause = session.pause;
  let pauses = 0;
  session.pause = async (ms) => {
    pauses += 1;
    // The first observation ends before the cap is hit; the second one sees it.
    if (pauses === 1)
      capped.deliver({ event: "wire-refused", host: "h", path: "/p", reason: "cap" });
    return pause(ms);
  };
  const rows = await interpreter.run();
  assert.deepEqual(rows.before.capped, ["a"]);
  assert.deepEqual(rows.after.capped, ["a"]);
  assert.equal("capped" in rows["only-b"], false);
  assert.deepEqual(rows.life.capped, ["a"]);
});

test("an owner's read of a client's writes is marked when that client was capped", async () => {
  const client = fakeClient();
  const session = fakeSession({ principals: {} });
  const program = {
    steps: [
      { do: "client", client: "p", transport: "node-sdk" },
      { do: "server", id: "before", condition: "X", client: "p", docs: ["afc2-pending/x"] },
      { do: "server", id: "after", condition: "X", client: "p", docs: ["afc2-pending/x"] },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => {},
    sdkConfig: {},
  });
  const read = session.ownerRead;
  let reads = 0;
  session.ownerRead = async (doc) => {
    reads += 1;
    if (reads === 2)
      client.deliver({ event: "wire-refused", host: "h", path: "/p", reason: "cap" });
    return read(doc);
  };
  const rows = await interpreter.run();
  assert.equal("capped" in rows.before, false);
  assert.deepEqual(rows.after.capped, ["p"]);
});

test("a failed sign-in stops the run, unless the client's cap refused something before", async () => {
  const failing = () => {
    const client = fakeClient({ hold: ["signIn"] });
    const send = client.send.bind(client);
    client.send = (op, fields) => {
      const pending = send(op, fields);
      if (op === "signIn")
        client.deliver({ event: "result", id: fields.id, ok: false, code: "wire" });
      return pending;
    };
    return client;
  };
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "sdk", client: "c", op: "signIn", as: "a" },
      { do: "server", id: "s", condition: "X", client: "c", docs: ["afc2-pending/x"] },
    ],
  };
  const run = (client) =>
    createInterpreter(program, {
      session: fakeSession({ principals: { a: { uid: "uid-a" } } }),
      ctx,
      spawnClient: () => client,
      openListen: () => {},
      sdkConfig: {},
    }).run();
  await assert.rejects(run(failing()), /c signIn failed: wire/);
  const capped = failing();
  capped.deliver({ event: "wire-refused", host: "h", path: "/p", reason: "request cap 2 reached" });
  const rows = await run(capped);
  assert.deepEqual(rows.s.capped, ["c"]);
});

test("a transaction that fails before its reads ends the wait for them, and its row records it", async () => {
  const client = fakeClient({ hold: ["transaction"] });
  const session = fakeSession({ principals: { alice: { uid: "uid-alice" } } });
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      {
        do: "sdk",
        client: "c",
        op: "transaction",
        await: false,
        mark: "t",
        commandId: "tx-1",
        name: "t1",
        reads: ["afc2-tx/a"],
        write: { path: "afc2-tx/a", data: {} },
      },
      { do: "await", client: "c", event: "transaction-read", name: "t1" },
      { do: "sdk", client: "c", op: "continueTransaction", name: "t1" },
      {
        do: "await",
        id: "tx/result",
        condition: "X",
        client: "c",
        event: "result",
        commandId: "tx-1",
        since: "t",
      },
    ],
  };
  const interpreter = createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => {},
    sdkConfig: {},
  });
  const running = interpreter.run();
  await new Promise((r) => setImmediate(r));
  client.deliver({ event: "result", id: "tx-1", ok: false, code: "unavailable", attempts: 1 });
  const rows = await running;
  assert.deepEqual(rows["tx/result"].result, {
    kind: "result",
    op: "transaction",
    ok: false,
    code: "unavailable",
    attempts: 1,
  });
});

test("a client ended by its cap answers later commands as failed, and the run goes on", async () => {
  const client = fakeClient({ hold: ["transaction"] });
  const session = fakeSession({ principals: { a: { uid: "uid-a" } } });
  const program = {
    steps: [
      { do: "client", client: "c", transport: "node-sdk" },
      { do: "sdk", client: "c", op: "signIn", as: "a" },
      {
        do: "sdk",
        client: "c",
        op: "transaction",
        await: false,
        mark: "t",
        commandId: "tx-1",
        name: "t1",
        reads: ["afc2-tx/a"],
        write: { path: "afc2-tx/a", data: {} },
      },
      { do: "await", client: "c", event: "transaction-read", name: "t1" },
      { do: "sdk", client: "c", op: "signIn", as: "a" },
      {
        do: "await",
        id: "tx/result",
        condition: "X",
        client: "c",
        event: "result",
        commandId: "tx-1",
        since: "t",
      },
      { do: "server", id: "s", condition: "X", client: "c", docs: ["afc2-tx/a"] },
    ],
  };
  // After the first sign-in, the cap refuses a request and the driver ends.
  const send = client.send.bind(client);
  let sends = 0;
  client.send = (op, fields) => {
    sends += 1;
    if (sends === 2) {
      client.deliver({
        event: "wire-refused",
        host: "h",
        path: "/p",
        reason: "request cap 3 reached",
      });
      client.exited = true;
    }
    if (client.exited) return Promise.reject(new Error("sdk driver has exited"));
    return send(op, fields);
  };
  const waitFor = client.waitFor.bind(client);
  client.waitFor = (match) =>
    client.exited ? Promise.reject(new Error("sdk driver has exited")) : waitFor(match);
  const rows = await createInterpreter(program, {
    session,
    ctx,
    spawnClient: () => client,
    openListen: () => {},
    sdkConfig: {},
  }).run();
  assert.deepEqual(rows["tx/result"].result.code, "client-ended-by-cap");
  assert.deepEqual(rows["tx/result"].capped, ["c"]);
  assert.deepEqual(rows.s.capped, ["c"]);
});

test("the runner keeps going when its console's reader is gone", async () => {
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const runner = fileURLToPath(new URL("./auth-fs-cross/stage2-run.mjs", import.meta.url));
  // A child that keeps logging after its reader went away (as a stopped `tee` leaves it), then
  // reports whether it reached the end of its work through a channel of its own (stderr).
  const script = (guarded) => `
    ${guarded ? `const { keepRunningWithoutConsole } = await import(${JSON.stringify(runner)}); keepRunningWithoutConsole([process.stdout]);` : ""}
    for (let i = 0; i < 40; i += 1) {
      console.log("step " + i);
      await new Promise((r) => setTimeout(r, 5));
    }
    process.stderr.write("finished");
  `;
  const run = (guarded) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script(guarded)], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.stdout.once("data", () => child.stdout.destroy());
      child.on("close", () => resolve(stderr));
    });
  assert.match(await run(true), /finished$/);
  assert.doesNotMatch(await run(false), /finished$/);
});
