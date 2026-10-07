import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createDeps } from "../../tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs";
import { createPageDeps } from "./fs-listen/sdk-deps-browser.mjs";

/** A fake SDK that logs every call with its arguments and answers with fixed shapes. */
function fakeSdk(
  log,
  { owner = "o1", exists = true, fromCache = false, pending = false, reject = [] } = {},
) {
  const note = (name, ...args) => log.push([name, ...args.map((a) => (a?.ref ? a.ref : a))]);
  const snapshot = (path) => ({
    ref: path,
    exists: () => exists,
    data: () => ({ owner }),
    metadata: { fromCache, hasPendingWrites: pending },
  });
  // Every asynchronous call finishes a tick later and logs that it did, or rejects: a dependency
  // that does not wait for it shows in the log, or answers where the other one rejects.
  const later = async (name, ...args) => {
    note(name, ...args);
    await Promise.resolve();
    log.push([`${name}:done`]);
    if (reject.includes(name)) throw new Error(`${name} rejected`);
  };
  return {
    doc: (db, path) => ({ ref: `${db.name}:${path}` }),
    collection: (db, path) => ({ ref: `${db.name}:${path}` }),
    where: (...args) => ({ ref: `where(${args})` }),
    orderBy: (...args) => ({ ref: `orderBy(${args})` }),
    limit: (n) => ({ ref: `limit(${n})` }),
    query: (collection, ...constraints) => ({
      ref: `query(${collection.ref};${constraints.map((c) => c.ref)})`,
    }),
    async setDoc(ref, fields) {
      await later("setDoc", ref, fields);
    },
    async deleteDoc(ref) {
      await later("deleteDoc", ref);
    },
    async getDocFromServer(ref) {
      await later("getDocFromServer", ref);
      return snapshot(ref.ref);
    },
    onSnapshot(target, options, observer) {
      note("onSnapshot", target, options);
      observer.next({
        exists: () => true,
        docs: [{ ref: { path: "a/b" } }],
        docChanges: () => [
          { type: "added", doc: { ref: { path: "a/b" } }, oldIndex: -1, newIndex: 0 },
        ],
        metadata: { fromCache: true, hasPendingWrites: false },
      });
      observer.error?.(new Error("x"));
      return () => note("unsubscribe");
    },
    async runTransaction(db, fn, options) {
      await later("runTransaction", db.name, options);
      const transaction = {
        get: async (ref) => {
          note("txn.get", ref);
          return snapshot(ref.ref);
        },
        delete: (ref) => note("txn.delete", ref),
      };
      return fn(transaction);
    },
    async disableNetwork(db) {
      await later("disableNetwork", db.name);
    },
    async enableNetwork(db) {
      await later("enableNetwork", db.name);
    },
    async signInWithEmailAndPassword(auth, email, password) {
      await later("signIn", auth.name, email, password);
    },
    async signOut(auth) {
      await later("signOut", auth.name);
    },
  };
}

const clients = (currentUser = { uid: "u1" }) => ({
  primary: {
    db: { name: "db1" },
    auth: { name: "auth1", currentUser },
    account: { name: "throwaway", email: "e@example.com", password: "p" },
  },
});

/** The same sequence of calls through a deps object; returns what each call answered. */
async function drive(deps) {
  const out = [];
  const events = [];
  const keep = async (label, promise) => {
    try {
      out.push([label, await promise]);
    } catch (error) {
      out.push([label, `threw: ${error.message} ${error.code ?? ""}`.trimEnd()]);
    }
  };
  await keep("setDoc", deps.firestore.setDoc("primary", "x/1", { a: 1 }));
  await keep("deleteDoc", deps.firestore.deleteDoc("primary", "x/1"));
  await keep("deleteDoc precondition", deps.firestore.deleteDoc("primary", "x/1", { t: 1 }));
  await keep("deleteOwned ok", deps.firestore.deleteOwnedDoc("primary", "x/1", { owner: "o1" }));
  await keep("deleteOwned wrong", deps.firestore.deleteOwnedDoc("primary", "x/1", { owner: "zz" }));
  await keep("deleteOwned no marker", deps.firestore.deleteOwnedDoc("primary", "x/1", {}));
  await keep(
    "deleteOwned extra",
    deps.firestore.deleteOwnedDoc("primary", "x/1", { owner: "o", z: 1 }),
  );
  for (const [label, condition] of [
    ["null", null],
    ["number owner", { owner: 5 }],
    ["empty owner", { owner: "" }],
  ])
    await keep(`deleteOwned ${label}`, deps.firestore.deleteOwnedDoc("primary", "x/1", condition));
  await keep("getDoc", deps.firestore.getDoc("primary", "x/1"));
  const unsubscribeDoc = deps.firestore.onDocSnapshot(
    "primary",
    "x/1",
    { includeMetadataChanges: true },
    (event) => events.push(["doc", event]),
    (error) => events.push(["doc error", error.message]),
  );
  unsubscribeDoc();
  const unsubscribeQuery = deps.firestore.onQuerySnapshot(
    "primary",
    { parent: "p", target: "t", where: ["rank", "<", 10], orderBy: ["rank", "desc"], limit: 3 },
    {},
    (event) => events.push(["query", event]),
    (error) => events.push(["query error", error.message]),
  );
  unsubscribeQuery();
  deps.firestore.onQuerySnapshot(
    "primary",
    { parent: "p", target: "t", where: ["k", "==", 1] },
    {},
    () => {},
    () => {},
  );
  await keep("disable", deps.firestore.disableNetwork("primary"));
  await keep("enable", deps.firestore.enableNetwork("primary"));
  await keep("signIn", deps.auth.signIn("primary", "throwaway"));
  await keep("signIn unknown", deps.auth.signIn("primary", "stranger"));
  await keep("signOut", deps.auth.signOut("primary"));
  await keep("revoke", deps.auth.revoke("primary"));
  await keep("revoke again", deps.auth.revoke("primary"));
  out.push(["events", events]);
  out.push(["now", Number.isInteger(deps.now())]);
  await keep("sleep", deps.sleep(1));
  return out;
}

test("the page dependencies make the same SDK calls and give the same answers as the catalog adapter's", async () => {
  for (const revoke of [null, async (uid) => uid]) {
    const [nodeLog, pageLog] = [[], []];
    const nodeOut = await drive(createDeps(fakeSdk(nodeLog), clients(), { revoke }));
    const pageOut = await drive(createPageDeps(fakeSdk(pageLog), clients(), { revoke }));
    assert.deepEqual(pageLog, nodeLog);
    assert.deepEqual(pageOut, nodeOut);
    assert.ok(nodeLog.length > 10, "the sequence exercised the calls");
  }
  // A transaction that finds the owner marker changed, and a document that is not there.
  for (const options of [
    { owner: "other" },
    { exists: false },
    { exists: "yes" },
    { fromCache: true },
    { pending: true },
    { reject: ["setDoc"] },
    { reject: ["deleteDoc"] },
    { reject: ["disableNetwork"] },
    { reject: ["enableNetwork"] },
    { reject: ["signIn"] },
    { reject: ["signOut"] },
    { reject: ["getDocFromServer"] },
  ]) {
    const [nodeLog, pageLog] = [[], []];
    const nodeOut = await drive(createDeps(fakeSdk(nodeLog, options), clients()));
    const pageOut = await drive(createPageDeps(fakeSdk(pageLog, options), clients()));
    assert.deepEqual(pageLog, nodeLog, JSON.stringify(options));
    assert.deepEqual(pageOut, nodeOut, JSON.stringify(options));
  }
  // A client with nobody signed in cannot revoke.
  for (const user of [null, { uid: "" }, { uid: 7 }]) {
    const [nodeLog, pageLog] = [[], []];
    const revoke = async (uid) => uid;
    const nodeOut = await drive(createDeps(fakeSdk(nodeLog), clients(user), { revoke }));
    const pageOut = await drive(createPageDeps(fakeSdk(pageLog), clients(user), { revoke }));
    assert.deepEqual(pageOut, nodeOut);
    assert.deepEqual(
      pageOut.filter(([label]) => label.startsWith("revoke")).map(([, value]) => value),
      ["threw: revoke needs a signed-in client", "threw: revoke needs a signed-in client"],
    );
  }
  // The revoke function itself is awaited, and what it throws comes through.
  const failing = async () => {
    throw new Error("revoke failed");
  };
  const [a, b] = [[], []];
  assert.deepEqual(
    await drive(createPageDeps(fakeSdk(b), clients(), { revoke: failing })),
    await drive(createDeps(fakeSdk(a), clients(), { revoke: failing })),
  );
});

test("the page dependencies import nothing, so a page can load them", () => {
  const source = readFileSync(new URL("./fs-listen/sdk-deps-browser.mjs", import.meta.url), "utf8");
  assert.equal(/^\s*import\s/m.test(source), false);
  assert.equal(/node:|require\(|process\./.test(source), false);
});
