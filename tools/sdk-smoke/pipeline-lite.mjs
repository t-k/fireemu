// Web SDK pipeline smoke: `firebase/firestore/lite` executes pipelines over the REST
// `:executePipeline` route. It runs the finite local subset (nested where/select, document
// functions, offset/limit) against an Enterprise database and checks each answer.
//
//   fireemu exec --config tools/sdk-smoke/fireemu.pipeline-strict.json --only firestore -- \
//     node tools/sdk-smoke/pipeline-lite.mjs
//
// Pipelines are owner-only while Security Rules are enforced (a client pipeline is refused),
// so the SDK connects with the emulator owner token, as the Admin SDK does.
//
// PIPELINE_PROFILE (strict | emulator, default strict) names the profile the daemon runs, which
// decides the answer for the parent of a top-level document (strict refuses it as unobserved;
// the emulator profile answers the documents root, as the official emulator does).
import assert from "node:assert/strict";
import { initializeApp } from "firebase/app";
import { getFirestore, connectFirestoreEmulator, doc, setDoc } from "firebase/firestore/lite";
import {
  execute,
  field,
  documentId,
  collectionId,
  parent,
} from "firebase/firestore/lite/pipelines";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const [host, port] = (process.env.FIRESTORE_EMULATOR_HOST ?? "127.0.0.1:8080").split(":");
const profile = process.env.PIPELINE_PROFILE ?? "strict";

const app = initializeApp({ projectId: project, apiKey: "fake-api-key" });
const db = getFirestore(app);
connectFirestoreEmulator(db, host, Number(port), { mockUserToken: "owner" });
const pipeline = (database) => database.pipeline();

await setDoc(doc(db, "pipeline-lite/a"), { profile: { score: 7 }, name: "a" });
await setDoc(doc(db, "pipeline-lite/b"), { profile: { score: 8 }, name: "b" });
await setDoc(doc(db, "pipeline-lite/a/sub/s1"), { k: "x" });

const rows = async (p) => (await execute(p)).results.map((result) => result.data());
const source = () => pipeline(db).collection("pipeline-lite");

assert.deepEqual(
  await rows(source().where(field("profile.score").equal(7)).select(field("name").as("label"))),
  [{ label: "a" }],
);
assert.deepEqual(
  await rows(
    source().select(
      documentId(field("__name__")).as("id"),
      collectionId(field("__name__")).as("coll"),
      field("profile.score").as("score"),
    ),
  ),
  [
    { id: "a", coll: "pipeline-lite", score: 7 },
    { id: "b", coll: "pipeline-lite", score: 8 },
  ],
);
const up = await rows(
  pipeline(db).collection("pipeline-lite/a/sub").select(parent(field("__name__")).as("up")),
);
assert.equal(up.length, 1);
assert.equal(up[0].up.path, "pipeline-lite/a");
assert.deepEqual(
  await rows(source().where(documentId(field("__name__")).equal("b")).select("name").limit(5)),
  [{ name: "b" }],
);
assert.deepEqual(await rows(source().select("name").offset(1).limit(1)), [{ name: "b" }]);
assert.deepEqual(await rows(pipeline(db).collection("pipeline-lite-empty")), []);
// Without a select a result is the source document: reference, ID and times, and the
// snapshot carries the execution time.
const whole = await execute(source().where(field("name").equal("a")));
assert.equal(whole.results.length, 1);
assert.equal(whole.results[0].ref.path, "pipeline-lite/a");
assert.equal(whole.results[0].id, "a");
assert.ok(whole.results[0].createTime, "createTime");
assert.ok(whole.results[0].updateTime, "updateTime");
assert.ok(whole.executionTime, "executionTime");
const projected = await execute(source().select("name").limit(1));
assert.equal(projected.results[0].ref, undefined);
assert.ok(projected.executionTime, "executionTime after select");
await assert.rejects(rows(source().where(field("profile.score").greaterThan(1))), (error) => {
  assert.equal(error.code, "unimplemented");
  return true;
});
const topParent = rows(source().select(parent(field("__name__")).as("up")));
if (profile === "strict") {
  await assert.rejects(topParent, (error) => error.code === "unimplemented");
} else {
  // The documents root, which the Lite SDK decodes into a reference with an empty path.
  const [{ up: root }] = await topParent;
  assert.equal(root.path, "");
}
console.log(`pipeline-lite smoke passed (${profile})`);
process.exit(0);
