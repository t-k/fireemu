// Web SDK pipeline smoke: `firebase/firestore/lite` executes pipelines over the REST
// `:executePipeline` route. It runs the finite local subset (nested where/select, document
// functions, offset/limit) against an Enterprise database and checks each answer. Under the strict
// profile the offset step expects the unobserved refusal, and every check after it still runs.
//
//   fireemu exec --config tools/sdk-smoke/fireemu.pipeline-strict.json --only firestore -- \
//     node tools/sdk-smoke/pipeline-lite.mjs
//
// Pipelines are owner-only while Security Rules are enforced (a client pipeline is refused),
// so the SDK connects with the emulator owner token, as the Admin SDK does.
//
// PIPELINE_PROFILE (strict | emulator, default strict) names the profile the daemon runs, which
// decides the answer for inputs production has not answered (strict refuses them as
// unobserved; the emulator profile answers as the official emulator does).
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
// An offset: production has no recorded answer for any offset argument yet (FS-PIPELINE), so the strict
// profile refuses it as unobserved and the emulator profile answers as the official emulator does. The
// checks after this step run under both profiles; once production records offset forms, strict follows.
const offsetPipeline = () => rows(source().select("name").offset(1).limit(1));
if (profile === "strict") {
  await assert.rejects(offsetPipeline(), (error) => {
    assert.equal(error.code, "unimplemented");
    assert.match(error.message, /this offset argument is not observed locally/);
    return true;
  });
} else {
  assert.deepEqual(await offsetPipeline(), [{ name: "b" }]);
}
assert.deepEqual(await rows(pipeline(db).collection("pipeline-lite-empty")), []);
// The Lite SDK's executionTime getter throws when the answer lacks it, empty answers included.
assert.ok((await execute(pipeline(db).collection("pipeline-lite-empty"))).executionTime);
// Without a select a result is the source document: reference, ID and times, and the
// snapshot carries the execution time.
const whole = await execute(source().where(field("name").equal("a")));
assert.equal(whole.results.length, 1);
assert.equal(whole.results[0].ref.path, "pipeline-lite/a");
assert.equal(whole.results[0].id, "a");
// The Lite SDK's document snapshots do not expose the times, so compare with a REST read.
const read = await fetch(
  `http://${host}:${port}/v1/projects/${project}/databases/(default)/documents/pipeline-lite/a`,
  { headers: { authorization: "Bearer owner" } },
);
assert.equal(read.status, 200);
const stored = await read.json();
const timestamp = (text) => {
  const [, seconds, fraction = ""] = /^(.*?)(?:\.(\d+))?Z$/.exec(text);
  return [Date.parse(`${seconds}Z`) / 1000, Number(fraction.padEnd(9, "0"))];
};
const parts = (time) => [time.seconds, time.nanoseconds];
assert.deepEqual(parts(whole.results[0].createTime), timestamp(stored.createTime), "createTime");
assert.deepEqual(parts(whole.results[0].updateTime), timestamp(stored.updateTime), "updateTime");
const [executed, updated] = [parts(whole.executionTime), parts(whole.results[0].updateTime)];
assert.ok(
  executed[0] > updated[0] || (executed[0] === updated[0] && executed[1] >= updated[1]),
  "executionTime is no earlier than the update time",
);
const projected = await execute(source().select("name").limit(1));
assert.equal(projected.results[0].ref, undefined);
assert.ok(projected.executionTime, "executionTime after select");
// A field compared with a literal, as a where condition and as a select value.
assert.deepEqual(
  await rows(
    source()
      .where(field("profile.score").greaterThan(7))
      .select(field("profile.score").lessThanOrEqual(8).as("le")),
  ),
  [{ le: true }],
);
// Comparisons across kinds and of two fields answer as production does (FS-ENT-ORACLE O-1).
assert.deepEqual(await rows(source().where(field("name").lessThan(1)).select("name")), []);
assert.deepEqual(
  await rows(source().where(field("profile.score").equal(field("profile.score"))).select("name")),
  [{ name: "a" }, { name: "b" }],
);
await assert.rejects(rows(source().where(field("name").regexMatch("a"))), (error) => {
  assert.equal(error.code, "unimplemented");
  return true;
});
// The parent of a top-level document is the documents root, which the Lite SDK decodes into
// a reference with an empty path.
const [{ up: root }] = await rows(source().select(parent(field("__name__")).as("up")).limit(1));
assert.equal(root.path, "");
// The collection ID of the documents root: production and the official emulator refuse it as
// INVALID_ARGUMENT (400, FS-ENT-ORACLE O-3), which the Lite SDK reports as failed-precondition,
// as it maps every HTTP 400.
await assert.rejects(
  rows(source().select(collectionId(parent(field("__name__"))).as("c"))),
  (error) => error.code === "failed-precondition",
);
console.log(`pipeline-lite smoke passed (${profile})`);
process.exit(0);
