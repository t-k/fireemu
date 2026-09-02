// Firestore rows: value fidelity and ordering, the missing composite index decision,
// transaction read-set aborts, listener sequences with a resume, and the shapes of the
// FAILED_PRECONDITION / PERMISSION_DENIED errors each transport produces.

import { FieldValue, GeoPoint, Timestamp } from "firebase-admin/firestore";
import {
  collection,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  query,
  setDoc,
  where,
} from "firebase/firestore";
import { createUserWithEmailAndPassword, signOut } from "firebase/auth";

import { VARIANTS } from "../config.mjs";
import { sortStrings } from "../normalize.mjs";
import { emailFor } from "./context.mjs";

const valuesAndOrdering = {
  id: "firestore/values-and-ordering",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["firebase-admin"],
  title: "Every Firestore value type round-trips and the documented type ordering holds",
  async run(ctx) {
    const db = ctx.shared.adminFirestore();
    const col = db.collection("conf_values");

    await ctx.step("write-every-value-type", async () => {
      await col.doc("all-types").set({
        aNull: null,
        aFalse: false,
        aTrue: true,
        anInteger: -42,
        aDouble: 1.5,
        aNaN: Number.NaN,
        aTimestamp: Timestamp.fromDate(new Date("2020-03-04T05:06:07.008Z")),
        aString: "hello é 日本語",
        aBytes: Buffer.from([0, 1, 2, 255]),
        aReference: db.doc("conf_values/all-types"),
        aGeoPoint: new GeoPoint(35.68, 139.76),
        anArray: [1, "two", null, { three: 3 }],
        aMap: { nested: { deeper: [true] } },
      });
      return "written";
    });

    await ctx.step("read-back-every-value-type", async () => {
      const snap = await col.doc("all-types").get();
      return { exists: snap.exists, data: snap.data() };
    });

    // Firestore orders values by type first, then within the type. One document per type
    // with the same field name makes the resulting order the documented type order.
    await ctx.step("type-ordering", async () => {
      const order = db.collection("conf_values_order");
      const samples = [
        ["a-null", null],
        ["b-false", false],
        ["c-true", true],
        ["d-nan", Number.NaN],
        ["e-number", 7],
        ["f-timestamp", Timestamp.fromDate(new Date("2001-02-03T04:05:06Z"))],
        ["g-string", "s"],
        ["h-bytes", Buffer.from([1])],
        ["i-reference", db.doc("conf_values/all-types")],
        ["j-geopoint", new GeoPoint(1, 2)],
        ["k-array", [1]],
        ["l-map", { m: 1 }],
      ];
      for (const [id, v] of samples) await order.doc(id).set({ v });
      const snap = await order.orderBy("v").get();
      return snap.docs.map((d) => d.id);
    });

    await ctx.step("server-transforms", async () => {
      const ref = col.doc("transforms");
      await ref.set({ n: 1, tags: ["a"] });
      await ref.update({
        n: FieldValue.increment(4),
        tags: FieldValue.arrayUnion("b", "a"),
        at: FieldValue.serverTimestamp(),
      });
      await ref.update({ tags: FieldValue.arrayRemove("a") });
      return (await ref.get()).data();
    });

    await ctx.step("query-order-limit-and-count", async () => {
      const q = col.orderBy("__name__").limit(2);
      const snap = await q.get();
      const count = await col.count().get();
      return { ids: snap.docs.map((d) => d.id), count: count.data().count };
    });

    // `listCollections` has no documented order, so this row sorts before comparing.
    await ctx.step("list-collections-sorted", async () => {
      const cols = await db.listCollections();
      return sortStrings(cols.map((c) => c.id));
    });

    await ctx.step("auto-id-shape", async () => {
      const added = await col.add({ auto: true });
      return { length: added.id.length, id: added.id };
    });
  },
};

const missingCompositeIndex = {
  id: "firestore/missing-composite-index",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["firebase-admin", "firebase/firestore"],
  title:
    "A query needing an unconfigured composite index, with no firestore.indexes.json entry on either side",
  async run(ctx) {
    const db = ctx.shared.adminFirestore();
    const col = db.collection("conf_index");
    await ctx.step("seed", async () => {
      await col.doc("one").set({ name: "x", age: 1, city: "tokyo" });
      await col.doc("two").set({ name: "y", age: 2, city: "osaka" });
      return "seeded";
    });

    // Two equality filters on different fields need a composite index in production.
    await ctx.step("admin-two-equality-filters", async () => {
      const snap = await col.where("name", "==", "x").where("age", "==", 1).get();
      return { size: snap.size, ids: snap.docs.map((d) => d.id) };
    });

    // Equality plus an inequality on another field needs one too.
    await ctx.step("admin-equality-plus-inequality", async () => {
      const snap = await col.where("city", "==", "tokyo").where("age", ">", 0).get();
      return { size: snap.size, ids: snap.docs.map((d) => d.id) };
    });

    // The same query through the client SDK: the error has to stay usable client-side.
    await ctx.step("client-two-equality-filters", async () => {
      const web = ctx.shared.webFirestore();
      const snap = await getDocs(
        query(collection(web, "conf_index"), where("name", "==", "x"), where("age", "==", 1)),
      );
      return { size: snap.size, ids: snap.docs.map((d) => d.id) };
    });

    // A single-field query is always served by the automatic index on both sides.
    await ctx.step("admin-single-field-query-is-served", async () => {
      const snap = await col.where("age", ">", 0).orderBy("age").get();
      return { size: snap.size, ids: snap.docs.map((d) => d.id) };
    });
  },
};

const transactionReadSetAbort = {
  id: "firestore/transaction-read-set-abort",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["firebase-admin"],
  title: "A transaction whose read set is written by someone else retries and then commits",
  async run(ctx) {
    const db = ctx.shared.adminFirestore();
    const ref = db.doc("conf_txn/counter");
    await ctx.step("seed", async () => {
      await ref.set({ value: 0 });
      return "seeded";
    });

    // The first attempt reads the counter, then an out-of-band write invalidates the read
    // set exactly once. A correct implementation retries and commits on the value it read
    // the second time, so the final value proves the read set was honoured.
    await ctx.step("contended-transaction-retries-then-commits", async () => {
      let attempts = 0;
      await db.runTransaction(async (tx) => {
        attempts += 1;
        const snap = await tx.get(ref);
        if (attempts === 1) {
          await ref.set({ value: snap.data().value + 100 });
        }
        tx.update(ref, { value: snap.data().value + 1 });
      });
      return { attempts, value: (await ref.get()).data().value };
    });

    await ctx.step("concurrent-conditional-lock-retries-the-loser", async () => {
      const contextRef = db.doc("conf_txn/lock-context");
      const lockRef = db.doc("conf_txn/conditional-lock");
      await Promise.all([contextRef.set({ enabled: true }), lockRef.set({ locked: false })]);

      const attempts = [0, 0];
      const observations = [[], []];
      let firstReads = 0;
      let releaseFirstReads;
      const bothFirstReads = new Promise((resolve) => {
        releaseFirstReads = resolve;
      });

      const acquired = await Promise.all(
        [0, 1].map((participant) =>
          db.runTransaction(async (tx) => {
            attempts[participant] += 1;
            const [context, lock] = await tx.getAll(contextRef, lockRef);
            if (!context.exists || context.data().enabled !== true || !lock.exists) {
              throw new Error("conditional lock fixtures are missing");
            }
            const locked = lock.data().locked === true;
            observations[participant].push(locked);
            if (attempts[participant] === 1) {
              firstReads += 1;
              if (firstReads === 2) releaseFirstReads();
              await bothFirstReads;
            }
            if (locked) return false;
            tx.update(lockRef, { locked: true, owner: participant });
            return true;
          }),
        ),
      );

      const loser = acquired
        .map((didAcquire, participant) => ({
          acquired: didAcquire,
          attempts: attempts[participant],
          observations: observations[participant],
        }))
        .find((record) => !record.acquired);
      const finalLock = (await lockRef.get()).data();
      return {
        loser: { attempts: loser.attempts, observations: loser.observations },
        protectedActions: acquired.filter(Boolean).length,
        finalLocked: finalLock.locked,
      };
    });

    await ctx.step("transaction-write-before-read-is-refused-client-side", async () => {
      await db.runTransaction(async (tx) => {
        tx.set(db.doc("conf_txn/early"), { v: 1 });
        await tx.get(ref);
      });
      return "committed";
    });

    await ctx.step("readonly-transaction-cannot-write", async () => {
      await db.runTransaction(
        async (tx) => {
          tx.set(db.doc("conf_txn/readonly"), { v: 1 });
        },
        { readOnly: true },
      );
      return "committed";
    });
  },
};

const listenSequenceWithResume = {
  id: "firestore/listen-sequence-with-resume",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["firebase/firestore"],
  title: "A gRPC Listen stream reports the documented snapshot sequence and resumes cleanly",
  async run(ctx) {
    const web = ctx.shared.webFirestore();
    const admin = ctx.shared.adminFirestore();
    const target = doc(web, "conf_listen/tracked");

    // Snapshot sequences are compared as a sequence, so the recorder collects them in
    // arrival order and stops on a settled count rather than on a timer.
    const collectSnapshots = (ref, count) =>
      new Promise((resolvePromise, rejectPromise) => {
        const seen = [];
        const timer = setTimeout(() => {
          unsubscribe();
          rejectPromise(new Error(`only ${seen.length} of ${count} snapshots arrived`));
        }, 20_000);
        const unsubscribe = onSnapshot(
          ref,
          { includeMetadataChanges: false },
          (snap) => {
            seen.push({
              exists: snap.exists(),
              data: snap.data() ?? null,
              fromCache: snap.metadata.fromCache,
              hasPendingWrites: snap.metadata.hasPendingWrites,
            });
            if (seen.length >= count) {
              clearTimeout(timer);
              unsubscribe();
              resolvePromise(seen);
            }
          },
          (error) => {
            clearTimeout(timer);
            unsubscribe();
            rejectPromise(error);
          },
        );
      });

    await ctx.step("initial-snapshot-of-a-missing-document", async () => {
      const [first] = await collectSnapshots(target, 1);
      return first;
    });

    await ctx.step("create-update-delete-sequence", async () => {
      const pending = collectSnapshots(target, 4);
      // The listener has to be attached before the writes land, so the first snapshot of
      // this listener is the current (missing) state and the next three are the writes.
      await new Promise((r) => setTimeout(r, 250));
      await admin.doc("conf_listen/tracked").set({ v: 1 });
      await admin.doc("conf_listen/tracked").update({ v: 2 });
      await admin.doc("conf_listen/tracked").delete();
      return pending;
    });

    await ctx.step("resume-sees-current-state-not-the-history", async () => {
      await admin.doc("conf_listen/tracked").set({ v: 3 });
      const [first] = await collectSnapshots(target, 1);
      return first;
    });

    await ctx.step("query-listener-sequence", async () => {
      const q = query(collection(web, "conf_listen"), where("kind", "==", "watched"));
      const pending = new Promise((resolvePromise, rejectPromise) => {
        const seen = [];
        const timer = setTimeout(() => {
          unsubscribe();
          rejectPromise(new Error(`only ${seen.length} query snapshots arrived`));
        }, 20_000);
        const unsubscribe = onSnapshot(
          q,
          (snap) => {
            seen.push({
              size: snap.size,
              changes: snap.docChanges().map((c) => ({ type: c.type, id: c.doc.id })),
            });
            if (seen.length >= 3) {
              clearTimeout(timer);
              unsubscribe();
              resolvePromise(seen);
            }
          },
          (error) => {
            clearTimeout(timer);
            unsubscribe();
            rejectPromise(error);
          },
        );
      });
      await new Promise((r) => setTimeout(r, 250));
      await admin.doc("conf_listen/w1").set({ kind: "watched", n: 1 });
      await admin.doc("conf_listen/w1").delete();
      return pending;
    });
  },
};

const rulesDecisions = {
  id: "firestore/rules-decisions",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["firebase/firestore"],
  title: "Security Rules decisions and the PERMISSION_DENIED shape each transport reports",
  async run(ctx) {
    const web = ctx.shared.webFirestore();
    const auth = ctx.shared.webAuth();

    await ctx.step("anonymous-read-of-a-closed-document", async () => {
      const snap = await getDoc(doc(web, "conf_rules_closed/x"));
      return { exists: snap.exists() };
    });

    await ctx.step("anonymous-read-of-a-public-collection", async () => {
      const snap = await getDocs(collection(web, "conf_rules_public"));
      return { size: snap.size };
    });

    await ctx.step("anonymous-write-to-an-owner-document", async () => {
      await setDoc(doc(web, "conf_rules_owner/nobody"), { v: 1 });
      return "written";
    });

    const email = emailFor("firestore-rules", "owner");
    await ctx.step("sign-up", async () => {
      const cred = await createUserWithEmailAndPassword(auth, email, "password123");
      ctx.shared.scratch.ownerUid = cred.user.uid;
      // The uid itself is generated and neither side repeats it, so later rows -- including
      // the Rules denial message, which names the document path -- record a placeholder.
      ctx.redact(cred.user.uid, "<uid>");
      // The generated uid's shape belongs to auth/sign-up-and-sign-in-errors, not here.
      return { hasUid: typeof cred.user.uid === "string" };
    });

    await ctx.step("owner-writes-own-document", async () => {
      await setDoc(doc(web, `conf_rules_owner/${ctx.shared.scratch.ownerUid}`), { v: 1 });
      const snap = await getDoc(doc(web, `conf_rules_owner/${ctx.shared.scratch.ownerUid}`));
      return snap.data();
    });

    await ctx.step("owner-cannot-write-another-document", async () => {
      await setDoc(doc(web, "conf_rules_owner/someone-else"), { v: 1 });
      return "written";
    });

    await ctx.step("after-sign-out-the-document-is-protected-again", async () => {
      await signOut(auth);
      const snap = await getDoc(doc(web, `conf_rules_owner/${ctx.shared.scratch.ownerUid}`));
      return { exists: snap.exists() };
    });
  },
};

const restFailedPrecondition = {
  id: "firestore/rest-error-shapes",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "The Firestore REST error envelopes for a missing index, bad input and denied access",
  async run(ctx) {
    const base = `http://${ctx.hosts.firestore}/v1/projects/${ctx.project}/databases/(default)/documents`;
    const post = async (path, body) => {
      const response = await fetch(`${base}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer owner" },
        body: JSON.stringify(body),
      });
      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { nonJsonBodyLength: text.length };
      }
      return { status: response.status, body: parsed };
    };

    await ctx.step("runQuery-needing-a-composite-index", () =>
      post(":runQuery", {
        structuredQuery: {
          from: [{ collectionId: "conf_index" }],
          where: {
            compositeFilter: {
              op: "AND",
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: "name" },
                    op: "EQUAL",
                    value: { stringValue: "x" },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: "age" },
                    op: "EQUAL",
                    value: { integerValue: "1" },
                  },
                },
              ],
            },
          },
        },
      }),
    );

    await ctx.step("runQuery-with-an-unknown-operator", () =>
      post(":runQuery", {
        structuredQuery: {
          from: [{ collectionId: "conf_index" }],
          where: {
            fieldFilter: {
              field: { fieldPath: "name" },
              op: "NOT_A_REAL_OPERATOR",
              value: { stringValue: "x" },
            },
          },
        },
      }),
    );

    await ctx.step("get-a-missing-document", async () => {
      const response = await fetch(`${base}/conf_values/definitely-missing`, {
        headers: { authorization: "Bearer owner" },
      });
      const text = await response.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { nonJsonBodyLength: text.length };
      }
      return { status: response.status, body: parsed };
    });
  },
};

export const scenarios = [
  valuesAndOrdering,
  missingCompositeIndex,
  transactionReadSetAbort,
  listenSequenceWithResume,
  rulesDecisions,
  restFailedPrecondition,
];
