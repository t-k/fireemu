import assert from "node:assert/strict";
import {
  initializeApp as initializeAdminApp,
  deleteApp as deleteAdminApp,
} from "firebase-admin/app";
import { getFirestore as getAdminFirestore } from "firebase-admin/firestore";
import { initializeApp as initializeLiteApp, deleteApp as deleteLiteApp } from "firebase/app";
import {
  connectFirestoreEmulator,
  getFirestore as getLiteFirestore,
} from "firebase/firestore/lite";
import { documentMatches, execute, score } from "firebase/firestore/lite/pipelines";
import {
  documentMatches as adminDocumentMatches,
  score as adminScore,
} from "@google-cloud/firestore/pipelines";

import { createControlClient } from "../../npm/fireemu/control.mjs";
const control = createControlClient();
const indexPath = "sessions/default/firestore/text-indexes/file-text-0";
const project = process.env.GOOGLE_CLOUD_PROJECT;
const endpoint = process.env.FIRESTORE_EMULATOR_HOST;
assert.equal(project, "demo-text-search", "set GOOGLE_CLOUD_PROJECT to the smoke-only project");
assert.ok(endpoint, "FIRESTORE_EMULATOR_HOST is required; this script never selects production");
const match = /^(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$/.exec(endpoint);
assert.ok(match, `refusing non-loopback emulator endpoint: ${endpoint}`);
const host = match[1] === "[::1]" ? "::1" : match[1];
const port = Number(match[2]);
assert.ok(port > 0 && port <= 65535, "emulator port is out of range");
assert.ok(process.env.FIRESTORE_EMULATOR_HOST, "emulator-only guard");

const adminApp = initializeAdminApp({ projectId: project }, `text-search-smoke-${process.pid}`);
const admin = getAdminFirestore(adminApp);
const liteApp = initializeLiteApp(
  { projectId: project, apiKey: "fake-api-key" },
  `text-search-lite-${process.pid}`,
);
const lite = getLiteFirestore(liteApp);
connectFirestoreEmulator(lite, host, port, { mockUserToken: "owner" });
const ids = ["waffle-plain", "waffle-berry", "coffee-only", "waffle-coffee"];
const refs = ids.map((id) => admin.doc(`products/${id}`));

const rows = async (db, predicate, scoreExpression, includeScore = false) => {
  const options = includeScore
    ? {
        query: predicate,
        addFields: [scoreExpression().as("searchScore")],
        sort: scoreExpression().descending(),
      }
    : { query: predicate };
  const query = db.pipeline().collection("products").search(options);
  const result = await query.execute();
  return result.results.map((row) => Object.assign({ id: row.id }, row.data()));
};
const liteRows = async (predicate, includeScore = false) => {
  const options = includeScore
    ? { query: predicate, addFields: [score().as("searchScore")], sort: score().descending() }
    : { query: predicate };
  const query = lite.pipeline().collection("products").search(options);
  const result = await execute(query);
  return result.results.map((row) => Object.assign({ id: row.id }, row.data()));
};

const assertUnavailable = async () => {
  await assert.rejects(rows(admin, adminDocumentMatches("waffles"), adminScore), /FS_TEXT_INDEX/);
  await assert.rejects(liteRows(documentMatches("waffles")), /FS_TEXT_INDEX/);
};

try {
  await Promise.all([
    refs[0].set({ title: "waffles", description: "warm breakfast" }),
    refs[1].set({ title: "berry waffles", description: "fresh fruit" }),
    refs[2].set({ title: "coffee", description: "dark roast" }),
    refs[3].set({ title: "waffles and coffee", description: "breakfast pair" }),
  ]);

  const failed = await control.request("POST", `${indexPath}:failBuild`, {
    reason: "smoke failure",
  });
  assert.equal(failed.state, "NEEDS_REPAIR");
  await assertUnavailable();
  const repaired = await control.request("POST", `${indexPath}:repair`, {
    generation: failed.build.generation,
  });
  assert.equal(repaired.state, "CREATING");
  const advanced = await control.request("POST", `${indexPath}:advanceBackfill`, {
    generation: repaired.build.generation,
    batchSize: 1,
  });
  assert.equal(advanced.build.indexedDocuments, 1);
  assert.equal(advanced.build.processedDocuments, 1);
  assert.equal(advanced.build.totalDocuments, 4);
  assert.equal(advanced.state, "CREATING");
  await assertUnavailable();
  const completed = await control.request("POST", `${indexPath}:completeBackfill`, {
    generation: repaired.build.generation,
  });
  assert.equal(completed.state, "READY");
  assert.equal(completed.build.indexedDocuments, 4);

  const positive = adminDocumentMatches("waffles -coffee");
  const adminInitial = await rows(admin, positive, adminScore);
  const liteInitial = await liteRows(documentMatches("waffles -coffee"));
  assert.deepEqual(adminInitial.map(({ id }) => id).toSorted(), ["waffle-berry", "waffle-plain"]);
  assert.deepEqual(
    liteInitial.map(({ id }) => id).toSorted(),
    adminInitial.map(({ id }) => id).toSorted(),
  );

  const phrase = await rows(admin, adminDocumentMatches('"berry waffles"'), adminScore);
  const litePhrase = await liteRows(documentMatches('"berry waffles"'));
  assert.deepEqual(
    phrase.map(({ id }) => id),
    ["waffle-berry"],
  );
  assert.deepEqual(
    litePhrase.map(({ id }) => id).toSorted(),
    phrase.map(({ id }) => id).toSorted(),
  );

  const negativeOnly = await rows(admin, adminDocumentMatches("-coffee"), adminScore);
  const liteNegativeOnly = await liteRows(documentMatches("-coffee"));
  assert.deepEqual(negativeOnly.map(({ id }) => id).toSorted(), ["waffle-berry", "waffle-plain"]);
  assert.deepEqual(
    liteNegativeOnly.map(({ id }) => id).toSorted(),
    negativeOnly.map(({ id }) => id).toSorted(),
  );

  const adminScored = await rows(admin, adminDocumentMatches("waffles"), adminScore, true);
  const liteScored = await liteRows(documentMatches("waffles"), true);
  assert.deepEqual(
    liteScored.map(({ id, searchScore }) => ({ id, searchScore })),
    adminScored.map(({ id, searchScore }) => ({ id, searchScore })),
  );

  await refs[0].update({ title: "pancakes", description: "pancakes now" });
  const afterUpdate = await rows(admin, adminDocumentMatches("waffles -coffee"), adminScore);
  const liteAfterUpdate = await liteRows(documentMatches("waffles -coffee"));
  assert.deepEqual(afterUpdate.map(({ id }) => id).toSorted(), ["waffle-berry"]);
  assert.deepEqual(
    liteAfterUpdate.map(({ id }) => id).toSorted(),
    afterUpdate.map(({ id }) => id).toSorted(),
  );

  await refs[1].delete();
  const afterDelete = await rows(admin, adminDocumentMatches("waffles -coffee"), adminScore);
  const liteAfterDelete = await liteRows(documentMatches("waffles -coffee"));
  assert.deepEqual(afterDelete, []);
  assert.deepEqual(
    liteAfterDelete.map(({ id }) => id).toSorted(),
    afterDelete.map(({ id }) => id).toSorted(),
  );
  console.log("Admin gRPC and Web Lite text-search smoke passed");
} finally {
  await Promise.all(refs.map((ref) => ref.delete().catch(() => undefined)));
  await Promise.all([deleteLiteApp(liteApp), deleteAdminApp(adminApp)]);
}
