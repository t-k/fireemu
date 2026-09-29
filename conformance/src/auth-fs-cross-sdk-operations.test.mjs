import assert from "node:assert/strict";
import { test } from "node:test";

import { allowedHosts, webChannelBearer } from "./auth-fs-cross/browser-driver.mjs";
import { createOperations } from "./auth-fs-cross/sdk-operations.mjs";
import { PRODUCTION_HOSTS } from "./auth-fs-cross/sdk-wire.mjs";

const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const TOKEN = `${part({ alg: "RS256" })}.${part({ iat: 100, exp: 3_700, sub: "u1" })}.sig`;
const tick = () => new Promise((resolve) => setImmediate(resolve));

/** A fake Web SDK: records calls; its behavior is set per test. */
function fakeSdk(overrides = {}) {
  const calls = [];
  const state = { tokenListener: null, snapshot: null, snapshotError: null };
  const fb = {
    onIdTokenChanged: (auth, listener) => {
      state.tokenListener = listener;
    },
    signInWithEmailAndPassword: async (auth, email) => {
      calls.push(["signIn", auth.tenantId, email]);
      // The Web SDK reports the new token after the call resolves (the browser's order).
      setImmediate(() => state.tokenListener?.({ uid: "u1", getIdToken: async () => TOKEN }));
      return { user: { uid: "u1" } };
    },
    signOut: async () => {
      calls.push(["signOut"]);
      setImmediate(() => state.tokenListener?.(null));
    },
    doc: (db, path) => ({ path }),
    collection: (db, path) => ({ collection: path }),
    where: (f, op, v) => ({ where: [f, op, v] }),
    query: (c, ...filters) => ({ ...c, filters }),
    onSnapshot: (target, options, next, error) => {
      calls.push(["onSnapshot", target, options]);
      state.snapshot = next;
      state.snapshotError = error;
      return () => calls.push(["unsubscribe", target]);
    },
    setDoc: async (ref, data) => calls.push(["setDoc", ref.path, data]),
    deleteDoc: async (ref) => calls.push(["deleteDoc", ref.path]),
    disableNetwork: async () => calls.push(["offline"]),
    enableNetwork: async () => calls.push(["online"]),
    runTransaction: async (db, update) => {
      const transaction = {
        get: async (ref) => ({
          ref,
          exists: () => false,
          data: () => null,
          metadata: { hasPendingWrites: false },
        }),
        set: (ref, data) => calls.push(["tx.set", ref.path, data]),
      };
      return update(transaction);
    },
    ...overrides,
  };
  const events = [];
  let exited = false;
  const auth = {
    tenantId: null,
    currentUser: {
      uid: "u1",
      getIdToken: async (force) => {
        calls.push(["getIdToken", force]);
        setImmediate(() => state.tokenListener?.({ uid: "u1", getIdToken: async () => TOKEN }));
      },
    },
  };
  const tokens = [];
  const run = createOperations({
    fb,
    auth,
    db: {},
    waitMs: overrides.waitMs ?? 1_000,
    emit: (event) => events.push(event),
    onToken: (token, uid) => tokens.push([token, uid]),
    decodeBase64Url: (text) => Buffer.from(text, "base64url").toString("utf8"),
    exit: () => {
      exited = true;
    },
  });
  return { run, calls, events, state, auth, tokens, exited: () => exited };
}

test("a token change is reported with its times and uid, never the token", async () => {
  const sdk = fakeSdk();
  await sdk.state.tokenListener({ uid: "u1", tenantId: "t-1", getIdToken: async () => TOKEN });
  await sdk.state.tokenListener(null);
  assert.deepEqual(sdk.events, [
    { event: "auth", uid: "u1", tenant: "t-1", iat: 100, exp: 3_700 },
    { event: "auth", uid: null },
  ]);
  assert.deepEqual(sdk.tokens, [[TOKEN, "u1"]]);
  assert.equal(JSON.stringify(sdk.events).includes("sig"), false);
});

test("sign-in names its tenant, and every command is answered by its own result", async () => {
  const sdk = fakeSdk();
  await sdk.run({ id: "a", op: "signIn", email: "e@example.com", password: "p", tenantId: "t-1" });
  assert.equal(sdk.auth.tenantId, "t-1");
  await sdk.run({ id: "b", op: "signIn", email: "e@example.com", password: "p" });
  assert.equal(sdk.auth.tenantId, null);
  await sdk.run({ id: "c", op: "refreshToken" });
  await sdk.run({ id: "d", op: "nope" });
  assert.deepEqual(
    sdk.calls.filter(([k]) => k !== "onSnapshot"),
    [
      ["signIn", "t-1", "e@example.com"],
      ["signIn", null, "e@example.com"],
      ["getIdToken", true],
    ],
  );
  assert.deepEqual(
    sdk.events.filter((e) => e.event === "result").map((e) => [e.id, e.ok, e.error ?? null]),
    [
      ["a", true, null],
      ["b", true, null],
      ["c", true, null],
      ["d", false, "unknown op nope"],
    ],
  );
});

test("a sign-in, sign-out or refresh answers only after its token change is reported", async () => {
  const sdk = fakeSdk();
  // A report of the same uid from before the call does not count.
  await sdk.state.tokenListener({ uid: "u1", getIdToken: async () => TOKEN });
  sdk.events.length = 0;
  await sdk.run({ id: "a", op: "signIn", email: "e@example.com", password: "p" });
  await sdk.run({ id: "b", op: "refreshToken" });
  await sdk.run({ id: "c", op: "signOut" });
  assert.deepEqual(
    sdk.events.map((e) => (e.event === "auth" ? ["auth", e.uid] : ["result", e.id])),
    [
      ["auth", "u1"],
      ["result", "a"],
      ["auth", "u1"],
      ["result", "b"],
      ["auth", null],
      ["result", "c"],
    ],
  );
  assert.deepEqual(
    sdk.events.filter((e) => e.event === "result").map((e) => e.authReported),
    [true, true, true],
  );
});

test("a sign-in waits for its own uid's report, not another's or an older one", async () => {
  // Another uid is reported during the call (the old user going away), the new one after it.
  const sdk = fakeSdk({
    signInWithEmailAndPassword: async () => {
      await sdk.state.tokenListener(null);
      setImmediate(() => sdk.state.tokenListener({ uid: "u1", getIdToken: async () => TOKEN }));
      return { user: { uid: "u1" } };
    },
  });
  await sdk.run({ id: "a", op: "signIn", email: "e@example.com", password: "p" });
  assert.deepEqual(
    sdk.events.map((e) => (e.event === "auth" ? ["auth", e.uid] : ["result", e.id])),
    [
      ["auth", null],
      ["auth", "u1"],
      ["result", "a"],
    ],
  );
  // The same uid reported before the call does not count; its report during the call does
  // (the Node order), and one after the call is waited for (the browser order).
  sdk.events.length = 0;
  const node = fakeSdk({
    signInWithEmailAndPassword: async () => {
      await node.state.tokenListener({ uid: "u1", getIdToken: async () => TOKEN });
      return { user: { uid: "u1" } };
    },
  });
  await node.state.tokenListener({ uid: "u1", getIdToken: async () => TOKEN });
  await node.run({ id: "b", op: "signIn", email: "e@example.com", password: "p" });
  assert.deepEqual(
    node.events.map((e) => (e.event === "auth" ? ["auth", e.uid] : ["result", e.id])),
    [
      ["auth", "u1"],
      ["auth", "u1"],
      ["result", "b"],
    ],
  );
  assert.equal(node.events.at(-1).authReported, true);
  // Both after the call (the browser order): the other uid's report does not end the wait.
  const browser = fakeSdk({
    signInWithEmailAndPassword: async () => {
      setImmediate(async () => {
        await browser.state.tokenListener(null);
        await browser.state.tokenListener({ uid: "u1", getIdToken: async () => TOKEN });
      });
      return { user: { uid: "u1" } };
    },
  });
  await browser.run({ id: "c", op: "signIn", email: "e@example.com", password: "p" });
  assert.deepEqual(
    browser.events.map((e) => (e.event === "auth" ? ["auth", e.uid] : ["result", e.id])),
    [
      ["auth", null],
      ["auth", "u1"],
      ["result", "c"],
    ],
  );
});

test("a sign-in whose token change never comes answers after the wait, saying so", async () => {
  const sdk = fakeSdk({
    waitMs: 20,
    signInWithEmailAndPassword: async () => ({ user: { uid: "u1" } }),
  });
  await sdk.run({ id: "a", op: "signIn", email: "e@example.com", password: "p" });
  assert.deepEqual(sdk.events, [{ event: "result", id: "a", ok: true, uid: "u1", authReported: false }]);
});

test("listeners report snapshots and errors by name, and a query carries its filters", async () => {
  const sdk = fakeSdk({ waitMs: 20 });
  await sdk.run({
    id: "a",
    op: "listen",
    name: "q",
    collection: "afc2-owned",
    where: [["owner", "==", "u1"]],
  });
  assert.deepEqual(sdk.calls[0], [
    "onSnapshot",
    { collection: "afc2-owned", filters: [{ where: ["owner", "==", "u1"] }] },
    { includeMetadataChanges: true },
  ]);
  sdk.state.snapshot({
    metadata: { fromCache: false, hasPendingWrites: true },
    docs: [
      {
        ref: { path: "afc2-owned/x" },
        exists: () => true,
        data: () => ({ n: 1 }),
        metadata: { hasPendingWrites: true },
      },
    ],
  });
  sdk.state.snapshotError({ code: "permission-denied", message: "no" });
  assert.deepEqual(sdk.events.slice(0, 1), [{ event: "result", id: "a", ok: true, first: "timeout" }]);
  assert.deepEqual(sdk.events.slice(1), [
    {
      event: "snapshot",
      name: "q",
      fromCache: false,
      hasPendingWrites: true,
      docs: [{ path: "afc2-owned/x", exists: true, data: { n: 1 }, hasPendingWrites: true }],
    },
    { event: "listen-error", name: "q", code: "permission-denied", message: "no" },
  ]);
  await sdk.run({ id: "b", op: "unlisten", name: "q" });
  assert.equal(sdk.calls.at(-1)[0], "unsubscribe");
});

const snapshotOf = (fromCache, n) => ({
  metadata: { fromCache, hasPendingWrites: false },
  ref: { path: "afc2-open/x" },
  exists: () => true,
  data: () => ({ n }),
});

test("a listen answers after its first server snapshot, which stays among the events", async () => {
  const sdk = fakeSdk();
  const answered = sdk.run({ id: "a", op: "listen", name: "d", path: "afc2-open/x" });
  await tick();
  sdk.state.snapshot(snapshotOf(true, 0));
  await tick();
  assert.equal(sdk.events.filter((e) => e.event === "result").length, 0);
  sdk.state.snapshot(snapshotOf(false, 0));
  await answered;
  sdk.state.snapshot(snapshotOf(false, 1));
  assert.deepEqual(
    sdk.events.map((e) => [e.event, e.fromCache ?? null, e.docs?.[0].data.n ?? e.first ?? null]),
    [
      ["snapshot", true, 0],
      ["snapshot", false, 0],
      ["result", null, "snapshot"],
      ["snapshot", false, 1],
    ],
  );
});

test("a refused listen answers after its error, which stays among the events", async () => {
  const sdk = fakeSdk();
  const answered = sdk.run({ id: "a", op: "listen", name: "d", path: "afc2-open/x" });
  await tick();
  sdk.state.snapshotError({ code: "permission-denied", message: "no" });
  await answered;
  assert.deepEqual(
    sdk.events.map((e) => [e.event, e.code ?? e.first]),
    [
      ["listen-error", "permission-denied"],
      ["result", "error"],
    ],
  );
  assert.equal(sdk.events.at(-1).ok, true);
});

test("a write left pending reports how it settled later", async () => {
  let fail;
  const sdk = fakeSdk({
    setDoc: () =>
      new Promise((resolve, reject) => {
        fail = reject;
      }),
  });
  await sdk.run({
    id: "a",
    op: "writeLater",
    writeId: "w",
    path: "afc2-pending/x",
    data: { n: 1 },
  });
  assert.deepEqual(sdk.events, [{ event: "result", id: "a", ok: true }]);
  fail(Object.assign(new Error("denied"), { code: "permission-denied" }));
  await tick();
  assert.deepEqual(sdk.events[1], {
    event: "write-settled",
    writeId: "w",
    ok: false,
    code: "permission-denied",
  });
});

test("a transaction pauses after its reads, goes on when told, and reports its attempts", async () => {
  let calls = 0;
  const sdk = fakeSdk({
    runTransaction: async (db, update) => {
      const transaction = {
        get: async (ref) => ({
          ref,
          exists: () => true,
          data: () => ({ n: 0 }),
          metadata: { hasPendingWrites: false },
        }),
        set: () => {},
      };
      // Two attempts, then the commit is refused.
      for (calls = 0; calls < 2; calls += 1) await update(transaction);
      throw Object.assign(new Error("denied"), { code: "permission-denied" });
    },
  });
  const done = sdk.run({
    id: "t",
    op: "transaction",
    name: "x",
    reads: ["afc2-tx/a"],
    write: { path: "afc2-tx/a", data: {} },
  });
  await tick();
  assert.deepEqual(
    sdk.events.map((e) => [e.event, e.attempt]),
    [["transaction-read", 1]],
  );
  await sdk.run({ id: "c", op: "continueTransaction", name: "x" });
  await done;
  // The second attempt ran straight through: only the first pauses.
  assert.deepEqual(
    sdk.events.map((e) => [e.event, e.id ?? e.attempt, e.ok ?? null]),
    [
      ["transaction-read", 1, null],
      ["result", "c", true],
      ["transaction-read", 2, null],
      ["result", "t", false],
    ],
  );
  assert.equal(sdk.events.at(-1).attempts, 2);
  assert.equal(sdk.events.at(-1).code, "permission-denied");
  await sdk.run({ id: "d", op: "continueTransaction", name: "x" });
  assert.deepEqual(sdk.events.at(-1), {
    event: "result",
    id: "d",
    ok: false,
    code: "harness",
    error: "transaction x is not paused",
  });
});

test("shutdown stops every listener and exits", async () => {
  const sdk = fakeSdk();
  await sdk.run({ id: "a", op: "listen", name: "d", path: "afc2-owned/x" });
  await sdk.run({ id: "b", op: "shutdown" });
  assert.equal(sdk.calls.at(-1)[0], "unsubscribe");
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(sdk.exited(), true);
});

test("the browser driver reads a WebChannel bearer and allows only its target's hosts", () => {
  const headers = encodeURIComponent(
    "X-Goog-Api-Client:gl-js/ fire/12.18.0\r\nAuthorization:Bearer abc.def.ghi\r\n",
  );
  assert.equal(
    webChannelBearer(
      `https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?VER=8&%24httpHeaders=${headers}`,
    ),
    "Bearer abc.def.ghi",
  );
  assert.equal(
    webChannelBearer(
      "https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?VER=8",
    ),
    null,
  );
  const noAuth = encodeURIComponent("X-Goog-Api-Client:gl-js/\r\n");
  assert.equal(webChannelBearer(`https://x/y?%24httpHeaders=${noAuth}`), null);
  // The SDK opens a channel with its headers encoded in the form body (encodeInitMessageHeaders).
  const body = new URLSearchParams({
    headers: "X-Goog-Api-Client:gl-js/\r\nAuthorization:Bearer jkl.mno.pqr\r\n",
    count: "1",
    req0___data__: "{}",
  }).toString();
  assert.equal(
    webChannelBearer(
      "https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8",
      body,
    ),
    "Bearer jkl.mno.pqr",
  );
  assert.equal(webChannelBearer("https://x/y?VER=8", "count=1&req0___data__=%7B%7D"), null);
  assert.deepEqual(allowedHosts({ mode: "production" }), PRODUCTION_HOSTS);
  assert.deepEqual(
    allowedHosts({
      mode: "local",
      authEmulator: "http://127.0.0.1:9099",
      firestoreEmulator: { host: "127.0.0.1", port: 8080 },
    }),
    ["127.0.0.1:9099", "127.0.0.1:8080"],
  );
});

test("no event, wire record or driver log carries a password or a bearer, only hashes", async () => {
  const { createWireLedger } = await import("./auth-fs-cross/sdk-wire.mjs");
  const secret = "SECRET-TOKEN-VALUE";
  const records = [];
  const ledger = createWireLedger({ hosts: ["h"], cap: 10, onRecord: (r) => records.push(r) });
  ledger.admit("h", "/google.firestore.v1.Firestore/Write/channel", `Bearer ${secret}`);
  const body = new URLSearchParams({ headers: `Authorization:Bearer ${secret}\r\n` }).toString();
  ledger.admit("h", "/x", webChannelBearer("https://h/x", body));
  assert.equal(JSON.stringify(records).includes(secret), false);
  assert.equal(records[0].bearer, records[1].bearer);
  assert.match(records[0].bearer, /^[0-9a-f]{64}$/);

  const sdk = fakeSdk();
  await sdk.run({ id: "a", op: "signIn", email: "e@example.com", password: "PASSWORD-VALUE" });
  await sdk.state.tokenListener({ uid: "u1", getIdToken: async () => TOKEN });
  assert.equal(JSON.stringify(sdk.events).includes("PASSWORD-VALUE"), false);
  assert.equal(JSON.stringify(sdk.events).includes(TOKEN), false);
});
