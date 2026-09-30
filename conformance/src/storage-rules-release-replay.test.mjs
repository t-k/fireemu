import assert from "node:assert/strict";
import test from "node:test";
import { bucketReleaseName, BUCKETLESS_RELEASE_NAME, classifyRelease, classifyRuleset, isEmptyOk } from "./storage-rules-release/release.mjs";
import { PRODUCTION, rawOf } from "./storage-rules-production-fixtures.mjs";

// The stage 2c judges against the bodies production actually answered: the release and ruleset reads of stage 2c-pre (2026-09-29), the release publication of stage 3 v9 (2026-09-30), the
// ruleset reads and deletions of stages 2e and 2f. Each test names the fixture it fits.
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const RELEASE = bucketReleaseName(BUCKET);
const SAVED_RULESET = "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8";

// The Google 404 `NOT_FOUND` body of a missing release and of a missing ruleset is the same 114 bytes (blob 10e8e245), so a 404 says "absent" for whichever resource the request named; which resource that was is
// decided by the exact URL, which the stage 2c transport allows route by route. A Firestore document's NOT_FOUND has the same `error.status`, and reads as absent for the same reason.
test("a release is present with its ruleset on the bodies production gave for a read (2c-pre) and for a publication (stage 3 v9), and absent on its 404", () => {
  const read = classifyRelease(rawOf(PRODUCTION.releasePresent), RELEASE);
  assert.deepEqual([read.state, read.release.name, read.release.rulesetName], ["present", RELEASE, SAVED_RULESET]);
  const created = classifyRelease(rawOf(PRODUCTION.releaseCreated), RELEASE);
  const body = JSON.parse(PRODUCTION.releaseCreated.body);
  assert.deepEqual([created.state, created.release.rulesetName, created.release.createTime, created.release.updateTime], ["present", body.rulesetName, body.createTime, body.updateTime]);
  assert.equal(classifyRelease(rawOf(PRODUCTION.releaseAbsent), RELEASE).state, "absent");
  assert.equal(classifyRelease(rawOf(PRODUCTION.releaseBucketlessAbsent), BUCKETLESS_RELEASE_NAME).state, "absent");
  assert.equal(PRODUCTION.releaseAbsent.body, PRODUCTION.rulesetNeverExisted.body);
  // What is not exactly a release of this name, or not exactly the Google 404, is unexpected.
  for (const [fixture, name] of [[PRODUCTION.releasePresent, BUCKETLESS_RELEASE_NAME], [PRODUCTION.releaseCreated, bucketReleaseName("other-bucket.appspot.com")], [PRODUCTION.rulesetSaved, RELEASE], [PRODUCTION.rulesetDeleted, RELEASE], [PRODUCTION.noRelease, RELEASE], [PRODUCTION.objectMetadataAbsent, RELEASE]]) assert.equal(classifyRelease(rawOf(fixture), name).state, "unexpected");
  const extra = JSON.stringify({ ...JSON.parse(PRODUCTION.releasePresent.body), extra: 1 });
  assert.equal(classifyRelease({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(extra) }, RELEASE).state, "unexpected");
});

test("a ruleset is present on the read production gave for the saved ruleset (2c-pre) and for a created one (2f), and absent on the 404 of a name that never existed or was deleted (2f)", () => {
  const saved = classifyRuleset(rawOf(PRODUCTION.rulesetSaved), SAVED_RULESET);
  assert.deepEqual([saved.state, saved.ruleset.name, saved.ruleset.createTime], ["present", SAVED_RULESET, JSON.parse(PRODUCTION.rulesetSaved.body).createTime]);
  assert.match(saved.ruleset.sourceSha256, /^[0-9a-f]{64}$/);
  const createdName = JSON.parse(PRODUCTION.rulesetCreated.body).name;
  assert.equal(classifyRuleset(rawOf(PRODUCTION.rulesetCreated), createdName).state, "present");
  assert.equal(classifyRuleset(rawOf(PRODUCTION.rulesetNeverExisted), SAVED_RULESET).state, "absent");
  for (const [fixture, name] of [[PRODUCTION.rulesetSaved, createdName], [PRODUCTION.releasePresent, SAVED_RULESET], [PRODUCTION.rulesetDeleted, SAVED_RULESET], [PRODUCTION.noRelease, SAVED_RULESET]]) assert.equal(classifyRuleset(rawOf(fixture), name).state, "unexpected");
});

test("a release deletion is accepted only as the empty object production answered (2c-pre, 2e, 2f)", () => {
  for (const fixture of [PRODUCTION.releaseDeleted, PRODUCTION.rulesetDeleted]) assert.equal(isEmptyOk(rawOf(fixture)), true);
  for (const fixture of [PRODUCTION.releaseCreated, PRODUCTION.releaseAbsent, PRODUCTION.objectDeleted, PRODUCTION.accountDeleted, PRODUCTION.prefixEmpty]) assert.equal(isEmptyOk(rawOf(fixture)), false);
});
