// The checks that read a production answer, replayed on recorded production bodies: the FE v4 function
// lists (masked) with only the names changed to ours. The shapes, the labels, the Eventarc trigger and
// topic names and the Cloud Run URL are the recorded ones; nothing here is made up from the code.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PROJECT, resolveTarget, validateFunctionRecord } from "../../functions-http/harness.mjs";
import { CODEBASE, TARGETS } from "./targets.mjs";
import { resolveGen1Target, validateGen1Record } from "./gen1.mjs";
import { ownedEventarcNames } from "./inventory.mjs";

const recorded = (file) => {
  const doc = JSON.parse(
    readFileSync(
      new URL(`../functions-events/record/recorded/v4-run/${file}`, import.meta.url),
      "utf8",
    ),
  );
  return typeof doc.body === "string" ? JSON.parse(doc.body) : doc.body;
};
const gen2 = recorded("0140-lists.functions-v2.json").functions.find(
  (f) => f.environment === "GEN_2",
);
const gen1 = recorded("0028-lists.functions-v1.json").functions[0];
const spec2 = TARGETS.find((t) => t.functionName === "rtdbWrittenV2");
const spec1 = TARGETS.find((t) => t.functionName === "rtdbWrittenV1");
const from = (record, oldName, newName) =>
  JSON.parse(
    JSON.stringify(record)
      .replaceAll("fireemu-oracle-events", PROJECT)
      .replaceAll(oldName.toLowerCase(), newName.toLowerCase())
      .replaceAll(oldName, newName)
      .replaceAll('"events"', `"${CODEBASE}"`),
  );

test("a recorded 2nd gen function record passes the reviewed checks once it carries our names", () => {
  const record = from(gen2, "storageArchivedV2", "rtdbWrittenV2");
  assert.equal(record.name.split("/").at(-1), "rtdbWrittenV2");
  assert.doesNotThrow(() => validateFunctionRecord(record, spec2));
  const owned = ownedEventarcNames(record, spec2);
  assert.match(owned.trigger, /\/triggers\/rtdbwrittenv2-\d+$/u);
  assert.match(owned.topic, /\/topics\/eventarc-us-central1-rtdbwrittenv2-\d+-\d+$/u);
  // the record of another function is refused
  assert.throws(() => validateFunctionRecord(from(gen2, "storageArchivedV2", "other"), spec2));
});

test("a recorded 1st gen function record passes the 1st gen check once it carries our names", () => {
  const record = from(gen1, "storageArchivedV1", "rtdbWrittenV1");
  assert.equal(record.labels["firebase-functions-codebase"], CODEBASE);
  assert.doesNotThrow(() => validateGen1Record(record, spec1));
  assert.equal(typeof record.eventTrigger.eventType, "string");
  // the 1st gen source is uploaded outside the project (the recorded sourceUploadUrl)
  assert.match(
    record.sourceUploadUrl,
    /^https:\/\/storage\.googleapis\.com\/uploads-\d+\.us-central1\.cloudfunctions\.appspot\.com\/[0-9a-f-]+\.zip$/u,
  );
  assert.throws(() => validateGen1Record(from(gen1, "storageArchivedV1", "other"), spec1));
});

test("the recorded labels name the codebase the way the checks read it", () => {
  assert.ok("firebase-functions-codebase" in gen2.labels);
  assert.ok("firebase-functions-codebase" in gen1.labels);
  assert.equal(gen1.labels["deployment-tool"], "cli-firebase");
  assert.equal(
    resolveGen1Target({
      functionName: "rtdbWrittenV1",
      region: "us-central1",
      codebase: CODEBASE,
      generation: "gcfv1",
    }).codebase,
    CODEBASE,
  );
  assert.equal(
    resolveTarget({
      functionName: "rtdbWrittenV2",
      region: "us-central1",
      codebase: CODEBASE,
      generation: "gcfv2",
    }).key,
    "rtdbWrittenV2",
  );
});
