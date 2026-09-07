import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

assert.ok(process.env.FIRESTORE_EMULATOR_HOST, "Performance runs require a local emulator");
assert.match(process.env.FIRESTORE_EMULATOR_HOST, /^(127\.0\.0\.1|localhost|\[::1\]):\d+$/);
async function deleteFixtures(refs) {
  const errors = [];
  for (let start = 0; start < refs.length; start += 200) {
    const results = await Promise.allSettled(
      refs.slice(start, start + 200).map((ref) => ref.delete()),
    );
    for (const result of results) if (result.status === "rejected") errors.push(result.reason);
  }
  if (errors.length) throw new AggregateError(errors, "Fixture cleanup failed");
}

const app = initializeApp({ projectId: "demo-app" });
const db = getFirestore(app);
const count = Number(process.env.BENCH_ITERATIONS || 200);
const concurrency = Number(process.env.BENCH_CONCURRENCY || 1);
const duration = Number(process.env.BENCH_DURATION_MS || 0);
const querySize = Number(process.env.BENCH_QUERY_SIZE || 33);
for (const n of [count, concurrency]) assert.ok(Number.isSafeInteger(n) && n > 0);
assert.ok(Number.isSafeInteger(querySize) && querySize >= 0);
assert.ok(Number.isFinite(duration) && duration >= 0);
const prefix = `performance-${randomUUID()}`;
const fixtures = db.collection(`${prefix}-fixtures`);
const writes = db.collection(`${prefix}-writes`);
const refs = Array.from({ length: Math.max(concurrency, querySize) }, (_, i) =>
  fixtures.doc(String(i).padStart(4, "0")),
);
const written = [];
const results = [];
const operations = (process.env.BENCH_OPERATIONS || "create,get,update,query,transaction").split(
  ",",
);
assert.equal(new Set(operations).size, operations.length);
if (duration > 0)
  assert.equal(operations.length, 1, "Run duration workloads separately on fresh emulators");
try {
  const seeded = await Promise.allSettled(
    refs.map((ref, index) => ref.create({ index, value: 0, payload: "x".repeat(256) })),
  );
  for (const result of seeded) if (result.status === "rejected") throw result.reason;
  for (const operation of operations) {
    assert.ok(["create", "get", "update", "query", "transaction"].includes(operation));
    let attempts = 0;
    let issued = 0;
    const touched = Array.from({ length: concurrency }, () => 0);
    const execute = async (worker) => {
      if (operation === "create") {
        const ref = writes.doc(String(issued++).padStart(8, "0"));
        written.push(ref);
        await ref.create({ value: 1, payload: "x".repeat(256) });
      } else if (operation === "get") {
        return refs[worker].get();
      } else if (operation === "update") {
        await refs[worker].update({ value: ++touched[worker] });
      } else if (operation === "query") {
        return querySize === 0
          ? fixtures.where("index", "<", 0).get()
          : fixtures.limit(querySize).get();
      } else {
        await db.runTransaction(async (tx) => {
          attempts++;
          const snapshot = await tx.get(refs[worker]);
          tx.update(refs[worker], { value: snapshot.data().value + 1 });
        });
        touched[worker]++;
      }
    };
    const expectedDocuments = new Map(
      (await db.getAll(...refs)).map((doc) => [doc.id, doc.data()]),
    );
    const checkResult = (result, worker) => {
      if (operation === "get") {
        assert.equal(result.id, refs[worker].id);
        assert.equal(result.exists, true);
        assert.deepEqual(result.data(), expectedDocuments.get(result.id));
      }
      if (operation === "query") {
        assert.deepEqual(
          result.docs.map((doc) => doc.id),
          refs.slice(0, querySize).map((ref) => ref.id),
        );
        for (const doc of result.docs) assert.deepEqual(doc.data(), expectedDocuments.get(doc.id));
      }
    };
    for (let i = 0; i < 20; i++) checkResult(await execute(i % concurrency), i % concurrency);
    const beforeValues = await db.getAll(...refs.slice(0, concurrency));
    const beforeTouched = [...touched];
    attempts = 0;
    let next = 0;
    const samples = [];
    const errors = [];
    const responses = [];
    const started = performance.now();
    await Promise.all(
      Array.from({ length: concurrency }, async (_, worker) => {
        while (duration ? performance.now() - started < duration : next < count) {
          next++;
          const start = performance.now();
          try {
            const result = await execute(worker);
            const elapsed = performance.now() - start;
            responses.push({ result, worker });
            samples.push(elapsed);
          } catch (error) {
            errors.push({ code: error.code, message: error.message });
          }
        }
      }),
    );
    const elapsed = performance.now() - started;
    const sorted = samples.toSorted((a, b) => a - b);
    const percentile = (q) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))];
    const measurement = {
      operation,
      concurrency,
      querySize,
      successes: samples.length,
      elapsedMs: elapsed,
      opsPerSecond: (samples.length / elapsed) * 1000,
      p50: percentile(0.5),
      p95: percentile(0.95),
      p99: percentile(0.99),
      transactionAttempts: attempts,
      errors,
      samples,
      validation: "pending",
    };
    results.push(measurement);
    for (const { result, worker } of responses) checkResult(result, worker);
    const after = await db.getAll(...refs.slice(0, concurrency));
    if (operation === "transaction")
      after.forEach((doc, i) =>
        assert.equal(
          doc.data().value,
          beforeValues[i].data().value + touched[i] - beforeTouched[i],
        ),
      );
    if (operation === "update")
      after.forEach((doc, i) => assert.equal(doc.data().value, touched[i]));
    if (operation === "create") {
      const snapshot = await writes.get();
      assert.deepEqual(
        snapshot.docs.map((doc) => doc.id),
        written.map((ref) => ref.id),
      );
      assert.ok(snapshot.docs.every((doc) => doc.data().value === 1));
    }
    assert.equal(errors.length, 0, JSON.stringify(errors.slice(0, 3)));
    measurement.validation = "passed";
  }
} finally {
  console.log(
    JSON.stringify({
      node: process.version,
      platform: process.platform,
      host: process.env.FIRESTORE_EMULATOR_HOST,
      results,
    }),
  );
  try {
    await deleteFixtures([...written, ...refs]);
  } finally {
    try {
      await db.terminate();
    } finally {
      await deleteApp(app);
    }
  }
}
