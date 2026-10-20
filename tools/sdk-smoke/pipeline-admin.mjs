// Admin SDK pipeline smoke: firebase-admin executes pipelines over gRPC `ExecutePipeline`. It
// checks the document metadata of results against an Enterprise database: without a select a
// result is the source document (reference, ID, create and update times equal to a document
// read), after a select it is fields only, and every answer carries an execution time no
// earlier than the documents it read.
//
//   fireemu exec --config tools/sdk-smoke/fireemu.pipeline-strict.json --only firestore -- \
//     node tools/sdk-smoke/pipeline-admin.mjs
//
// The pipeline helpers come from `@google-cloud/firestore`, the client firebase-admin wraps.
import assert from "node:assert/strict";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { field } from "@google-cloud/firestore/pipelines";

assert.ok(process.env.FIRESTORE_EMULATOR_HOST, "this smoke runs against an emulator only");
const app = initializeApp({ projectId: process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app" });
const db = getFirestore(app);
const notBefore = (later, earlier, what) =>
  assert.ok(
    later.seconds > earlier.seconds ||
      (later.seconds === earlier.seconds && later.nanoseconds >= earlier.nanoseconds),
    `${what}: ${later.toDate().toISOString()} < ${earlier.toDate().toISOString()}`,
  );

await db.doc("pipeline-admin/a").set({ n: 1 });
await db.doc("pipeline-admin/b").set({ n: 2 });
const stored = await db.doc("pipeline-admin/a").get();
const source = () => db.pipeline().collection("pipeline-admin");

const whole = await source().where(field("n").equal(1)).execute();
assert.equal(whole.results.length, 1);
const [result] = whole.results;
assert.equal(result.ref.path, "pipeline-admin/a");
assert.equal(result.id, "a");
assert.ok(result.createTime.isEqual(stored.createTime), "createTime equals the document read");
assert.ok(result.updateTime.isEqual(stored.updateTime), "updateTime equals the document read");
assert.deepEqual(result.data(), { n: 1 });
notBefore(whole.executionTime, result.updateTime, "executionTime");

const projected = await source().select("n").execute();
assert.equal(projected.results.length, 2);
assert.equal(projected.results[0].ref, undefined);
assert.equal(projected.results[0].createTime, undefined);
notBefore(projected.executionTime, result.updateTime, "executionTime after select");

const empty = await db.pipeline().collection("pipeline-admin-empty").execute();
assert.equal(empty.results.length, 0);
notBefore(empty.executionTime, result.updateTime, "executionTime of an empty answer");

// A later snapshot answers a later execution time.
const rewritten = await db.doc("pipeline-admin/a").set({ n: 1, again: true });
const later = await source().where(field("n").equal(1)).execute();
notBefore(later.executionTime, rewritten.writeTime, "executionTime after a write");
assert.ok(!later.executionTime.isEqual(whole.executionTime), "a new snapshot is timed anew");
assert.ok(later.results[0].updateTime.isEqual(rewritten.writeTime));

console.log("pipeline-admin smoke passed");
await deleteApp(app);
