import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createResourceLedger } from "./storage-rules/resource-ledger.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const load = async () => {
  const module = await import("./storage-rules/run-ledger.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createRunLedger, "function");
  return module;
};
async function fresh() {
  const { createRunLedger } = await load();
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  return { objects, run };
}
const out = (kind, verdict, facts = {}) => ({ kind, verdict, facts: { status: 200, ...facts } });
const RS = (id) => `projects/fireemu-oracle-query/rulesets/${id}`;
const decide = (run, id, tokens) => run.evaluate(row(id), tokens);

// Seed and read back the witness controls (and the other two) the way the schedule does.
function seedControls(objects, indexes = [0, 1, 2, 3, 4, 5]) {
  for (const index of indexes) {
    const id = (stage) => row(`management/control-${index}/${stage}`);
    objects.recordOutcome(id("baseline-metadata"), out("gcs-metadata-read", "absent"));
    objects.recordIntent(id("seed"));
    objects.recordOutcome(id("seed"), out("gcs-seed-upload", "accepted", { generation: `17000000000000${index}1`, metageneration: "1", size: "4" }));
    objects.recordOutcome(id("seed-metadata"), out("gcs-metadata-read", "present", { generation: `17000000000000${index}1`, metageneration: "1" }));
  }
}

test("the run ledger owns exactly the tokens it handles and its checks are listed", async () => {
  const { run } = await fresh();
  assert.ok(run.ownedTokens().includes("all-four-controls-confirmed-and-retained"));
  assert.ok(run.checkTokens().includes("release-name-and-created-ruleset-match"));
  const registry = new Set(manifest.rows.flatMap((r) => r.requires));
  for (const token of [...run.ownedTokens(), ...run.checkTokens()]) assert.ok(registry.has(token), token);
});

test("the four witnesses count as confirmed only after every one is seeded, read back and still there", async () => {
  const { objects, run } = await fresh();
  const publish = row("release/v1/publish");
  assert.equal(run.evaluate(publish, ["all-four-controls-confirmed-and-retained"]).decision, "stop");
  seedControls(objects, [0, 1, 3]);
  assert.equal(run.evaluate(publish, ["all-four-controls-confirmed-and-retained"]).decision, "stop");
  seedControls(objects, [4]);
  assert.equal(run.evaluate(publish, ["all-four-controls-confirmed-and-retained"]).decision, "go");
  objects.recordIntent(row("management/control-1/delete"));
  assert.equal(run.evaluate(publish, ["all-four-controls-confirmed-and-retained"]).decision, "stop");
});

test("control rows follow their own control's state", async () => {
  const { objects, run } = await fresh();
  seedControls(objects, [5]);
  const subject = row("management/no-release/entry/subject");
  assert.equal(subject.request.objectName, manifest.resources.controls[5]);
  assert.equal(run.evaluate(subject, ["owned-control-confirmed-present", "owned-control-retained-through-final-readback"]).decision, "go");
  objects.recordIntent(row("management/control-5/delete"));
  const decision = run.evaluate(subject, ["owned-control-confirmed-present", "owned-control-retained-through-final-readback"]);
  assert.equal(decision.decision, "stop");
  assert.deepEqual(decision.failed.map((f) => f.token).sort(), ["owned-control-confirmed-present", "owned-control-retained-through-final-readback"]);
});

test("the control cleanup deletes only after every control was read back", async () => {
  const { objects, run } = await fresh();
  const del = row("management/control-0/delete");
  assert.equal(run.evaluate(del, ["all-final-control-readbacks-complete"]).decision, "stop");
  for (let index = 0; index < 6; index++) {
    run.recordOutcome(row(`management/control-${index}/cleanup-metadata`), out("gcs-metadata-read", index % 2 ? "present" : "absent"));
    assert.equal(run.evaluate(del, ["all-final-control-readbacks-complete"]).decision, index === 5 ? "go" : "stop", `after ${index}`);
  }
  void objects;
});

test("credentials must be marked fresh before a row may go", async () => {
  const { run } = await fresh();
  const anyRow = row("management/control-0/baseline-metadata");
  assert.equal(run.evaluate(anyRow, ["canonical-program-state-and-fresh-credential"]).decision, "stop");
  run.setFlag("credentialFresh", true);
  assert.equal(run.evaluate(anyRow, ["canonical-program-state-and-fresh-credential"]).decision, "go");
  run.setFlag("credentialFresh", false);
  assert.equal(run.evaluate(anyRow, ["canonical-program-state-and-fresh-credential"]).decision, "stop");
  for (const bad of [["credentialFresh", 1], ["other", true], [7, true]]) assert.throws(() => run.setFlag(...bad), /invalid run ledger flag/);
});

test("the entry baseline needs both releases read as absent before compile and creation", async () => {
  const { run } = await fresh();
  const create = row("ruleset/v1/create");
  const compileBefore = row("compile/release/before");
  assert.equal(run.evaluate(compileBefore, ["entry-baseline-unchanged"]).decision, "stop");
  run.recordOutcome(row("preflight/release/entry/bucket"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(compileBefore, ["entry-baseline-unchanged"]).decision, "stop");
  run.recordOutcome(row("preflight/release/entry/bucketless"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(compileBefore, ["entry-baseline-unchanged"]).decision, "go");
  assert.equal(run.evaluate(create, ["compiled-source-and-entry-baseline"]).decision, "stop");
  const tests = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test");
  for (const [index, test] of tests.entries()) {
    run.recordOutcome(test, out("rules-test", index === tests.length - 1 ? "rejected" : "accepted", { issues: 0, errors: 0 }));
    assert.equal(run.evaluate(create, ["compiled-source-and-entry-baseline"]).decision, index === tests.length - 1 ? "go" : "stop", `after ${index}`);
  }
  run.recordOutcome(row("release/no-release-entry-after/bucket"), out("rules-release-read", "present", { rulesetName: RS("foreign") }));
  assert.equal(run.evaluate(create, ["compiled-source-and-entry-baseline"]).decision, "stop");
});

test("a release is publishable only for a created and read-back Ruleset, and its change must be ours", async () => {
  const { objects, run } = await fresh();
  const publish = row("release/v1/publish");
  const create = row("ruleset/v1/create");
  const read = row("ruleset/v1/read-source");
  assert.equal(run.evaluate(publish, ["owned-ruleset-and-source-readback"]).decision, "stop");
  run.recordIntent(create);
  run.recordOutcome(create, out("rules-ruleset-create", "accepted", { rulesetName: RS("aaa"), createTime: "t", sourceSha256: "1".repeat(64) }));
  assert.equal(run.evaluate(publish, ["owned-ruleset-and-source-readback"]).decision, "stop");
  run.recordOutcome(read, out("rules-ruleset-read", "present", { rulesetName: RS("aaa"), sourceSha256: "2".repeat(64) }));
  assert.equal(run.evaluate(publish, ["owned-ruleset-and-source-readback"]).decision, "stop");
  run.recordOutcome(read, out("rules-ruleset-read", "present", { rulesetName: RS("aaa"), sourceSha256: "1".repeat(64) }));
  assert.equal(run.evaluate(publish, ["owned-ruleset-and-source-readback"]).decision, "go");
  assert.throws(() => run.recordIntent(create), /mutation already attempted/);
  assert.equal(run.evaluate(read, ["acknowledged-ruleset-create"]).decision, "go");
  assert.equal(run.evaluate(row("ruleset/v2/read-source"), ["acknowledged-ruleset-create"]).decision, "stop");
  void objects;
});

test("a Ruleset the run creates must be a new one: an acknowledged create that names a Ruleset listed at entry makes it unowned, and nothing of it can be read, published or deleted", async () => {
  const listEntry = (name, services) => ({ name, services });
  const entryList = out("rules-list-page", "accepted", { count: 2, hasNextPage: false, rulesets: [listEntry(RS("kept-storage"), ["firebase.storage"]), listEntry(RS("firestore"), ["cloud.firestore"])] });
  for (const listed of ["kept-storage", "firestore"]) {
    const { run } = await fresh();
    run.recordOutcome(row("preflight/rulesets-list/entry/1"), entryList);
    const create = row("ruleset/v1/create");
    run.recordIntent(create);
    run.recordOutcome(create, out("rules-ruleset-create", "accepted", { rulesetName: RS(listed), createTime: "t", sourceSha256: "1".repeat(64) }));
    assert.equal(run.evaluate(row("ruleset/v1/read-source"), ["acknowledged-ruleset-create"]).decision, "stop", listed);
    assert.equal(run.evaluate(row("ruleset/v1/delete"), ["owned-ruleset-and-unreferenced-after-restore"]).decision, "stop", listed);
    assert.equal(run.evaluate(row("release/v1/publish"), ["owned-ruleset-and-source-readback"]).decision, "stop", listed);
  }
  // A new name is acknowledged as before, and a later page of the final list never widens or replaces the entry list.
  const { run } = await fresh();
  run.recordOutcome(row("preflight/rulesets-list/entry/1"), entryList);
  run.recordOutcome(row("rulesets-list/final/1"), out("rules-list-page", "accepted", { count: 1, hasNextPage: false, rulesets: [listEntry(RS("later"), [])] }));
  const create = row("ruleset/v1/create");
  run.recordIntent(create);
  run.recordOutcome(create, out("rules-ruleset-create", "accepted", { rulesetName: RS("kept-storage"), createTime: "t", sourceSha256: "1".repeat(64) }));
  assert.equal(run.evaluate(row("ruleset/v1/read-source"), ["acknowledged-ruleset-create"]).decision, "stop");
  const other = await fresh();
  other.run.recordOutcome(row("preflight/rulesets-list/entry/1"), entryList);
  other.run.recordOutcome(row("rulesets-list/final/1"), out("rules-list-page", "accepted", { count: 1, hasNextPage: false, rulesets: [listEntry(RS("later"), [])] }));
  other.run.recordIntent(create);
  other.run.recordOutcome(create, out("rules-ruleset-create", "accepted", { rulesetName: RS("later"), createTime: "t", sourceSha256: "1".repeat(64) }));
  assert.equal(other.run.evaluate(row("ruleset/v1/read-source"), ["acknowledged-ruleset-create"]).decision, "go");
  const fresh2 = await fresh();
  fresh2.run.recordOutcome(row("preflight/rulesets-list/entry/1"), out("rules-list-page", "unexpected", { status: 200 }));
  fresh2.run.recordIntent(create);
  fresh2.run.recordOutcome(create, out("rules-ruleset-create", "accepted", { rulesetName: RS("kept-storage"), createTime: "t", sourceSha256: "1".repeat(64) }));
  assert.equal(fresh2.run.evaluate(row("ruleset/v1/read-source"), ["acknowledged-ruleset-create"]).decision, "go");
});

test("the previous-release check follows the publication chain", async () => {
  const { run } = await fresh();
  const before = (name) => row(`release/${name}/before`);
  assert.equal(run.check(before("v1"), out("rules-release-read", "absent")).ok, true);
  assert.equal(run.check(before("v1"), out("rules-release-read", "present", { rulesetName: RS("x") })).ok, false);
  assert.equal(run.check(before("v2"), out("rules-release-read", "present", { rulesetName: RS("aaa") })).ok, false);
  run.recordOutcome(row("ruleset/v1/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("aaa"), createTime: "t", sourceSha256: "1".repeat(64) }));
  assert.equal(run.check(before("v2"), out("rules-release-read", "present", { rulesetName: RS("aaa") })).ok, true);
  assert.equal(run.check(before("v2"), out("rules-release-read", "present", { rulesetName: RS("bbb") })).ok, false);
  assert.equal(run.check(before("v2"), out("rules-release-read", "absent")).ok, false);
  assert.equal(run.check(before("v2"), out("gcs-metadata-read", "present")).ok, true);
  const after = row("release/v1/after");
  assert.equal(run.check(after, out("rules-release-read", "present", { rulesetName: RS("aaa") })).ok, true);
  assert.equal(run.check(after, out("rules-release-read", "present", { rulesetName: RS("zzz") })).ok, false);
  assert.equal(run.check(after, out("rules-release-read", "absent")).ok, false);
});

test("management rows of a published source need the release to name that Ruleset and its settle to have finished", async () => {
  const { run } = await fresh();
  const rowA = row("management/A/control-3/subject");
  const token = ["exact-release-source-and-effective-settle"];
  assert.equal(run.evaluate(rowA, token).decision, "stop");
  run.recordOutcome(row("ruleset/A/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("aa"), createTime: "t", sourceSha256: "1".repeat(64) }));
  run.recordOutcome(row("release/A/publish"), out("rules-release-patch", "accepted", { rulesetName: RS("aa"), releaseName: "n", updateTime: "t" }));
  assert.equal(run.evaluate(rowA, token).decision, "stop");
  run.recordSettle("A", "exhausted");
  assert.equal(run.evaluate(rowA, token).decision, "stop");
  run.recordSettle("A", "settled");
  assert.equal(run.evaluate(rowA, token).decision, "go");
  run.recordOutcome(row("release/A/publish"), out("rules-release-patch", "accepted", { rulesetName: RS("other"), releaseName: "n", updateTime: "t" }));
  assert.equal(run.evaluate(rowA, token).decision, "stop");
  assert.equal(run.evaluate(row("management/B/control-3/subject"), token).decision, "stop");
  assert.throws(() => run.recordSettle("v9", "settled"), /invalid run ledger settle/);
  assert.throws(() => run.recordSettle("A", "waiting"), /invalid run ledger settle/);
});

test("the release removal needs our current release and an untouched entry baseline", async () => {
  const { run } = await fresh();
  const del = row("release/restore/delete");
  const token = ["exact-owned-current-release-and-absent-entry-baseline"];
  run.recordOutcome(row("preflight/release/entry/bucket"), out("rules-release-read", "absent"));
  run.recordOutcome(row("preflight/release/entry/bucketless"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(del, token).decision, "stop");
  run.recordOutcome(row("ruleset/B/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("bb"), createTime: "t", sourceSha256: "1".repeat(64) }));
  run.recordOutcome(row("release/B/publish"), out("rules-release-patch", "accepted", { rulesetName: RS("bb"), releaseName: "n", updateTime: "t" }));
  assert.equal(run.evaluate(del, token).decision, "go");
  run.recordOutcome(row("release/restore/owner-before-delete"), out("rules-release-read", "present", { rulesetName: RS("foreign"), releaseName: "n", updateTime: "t" }));
  assert.equal(run.evaluate(del, token).decision, "stop");
  assert.equal(run.evaluate(row("release/restore/bucket-absence"), ["restore-without-unowned-release-change"]).decision, "stop");
});

test("Ruleset deletion waits for the release to be gone, and a recovery read needs a started Ruleset", async () => {
  const { run } = await fresh();
  const del = row("ruleset/v1/delete");
  const token = ["owned-ruleset-and-unreferenced-after-restore"];
  run.recordOutcome(row("ruleset/v1/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("aaa"), createTime: "t", sourceSha256: "1".repeat(64) }));
  assert.equal(run.evaluate(del, token).decision, "stop");
  run.recordOutcome(row("release/restore/bucket-absence"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(del, token).decision, "go");
  const current = row("recovery/ruleset/v2/current");
  assert.equal(run.evaluate(current, ["acknowledged-ruleset-create"]).decision, "stop");
  assert.equal(run.evaluate(row("recovery/ruleset/v2/delete"), ["delete-not-attempted"]).decision, "go");
  run.recordIntent(row("recovery/ruleset/v1/delete"));
  assert.equal(run.evaluate(row("recovery/ruleset/v1/delete"), ["delete-not-attempted"]).decision, "stop");
  assert.throws(() => run.recordIntent(row("ruleset/v1/delete")), /mutation already attempted/);
});

test("document deletes follow the document's own readbacks like object deletes do", async () => {
  const { run } = await fresh();
  const del = row("recovery/document-0/delete");
  const tokens = ["confirmed-document-write-history-and-current-version", "delete-not-attempted", "document-not-absent-per-latest-readback"];
  assert.equal(run.evaluate(del, tokens).decision, "skip");
  const create = manifest.rows.find((r) => r.service === "firestore" && r.request.method === "POST" && r.request.documentName === del.request.documentName);
  assert.ok(create);
  run.recordIntent(create);
  assert.equal(run.evaluate(del, tokens).decision, "stop");
  run.recordOutcome(create, out("firestore-write", "accepted", { documentName: create.request.documentName, updateTime: "2026-09-29T10:00:00Z" }));
  assert.equal(run.evaluate(del, tokens).decision, "go");
  run.recordOutcome(row("recovery/document-0/current"), out("firestore-read", "absent"));
  assert.equal(run.evaluate(del, tokens).decision, "skip");
  run.recordOutcome(row("recovery/document-0/current"), out("firestore-read", "present", { documentName: del.request.documentName, updateTime: "2026-09-29T10:01:00Z" }));
  run.recordIntent(del);
  assert.equal(run.evaluate(del, tokens).decision, "stop");
  assert.throws(() => run.recordIntent(del), /mutation already attempted/);
  run.recordOutcome(del, { uncertain: true });
  assert.equal(run.evaluate(row("recovery/document-1/delete"), tokens).decision, "skip");
});

test("a session cancel goes only for a known-active session and only once, and skips a finished one", async () => {
  const { run } = await fresh();
  const session = manifest.resources.sessions[0];
  const cancel = manifest.rows.find((r) => r.family === "declared" && r.stage === "cleanup" && r.programId === session.caseId && r.request.headers["x-goog-upload-command"] === "cancel");
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId === session.caseId);
  const finalize = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "upload, finalize" && r.programId === session.caseId);
  const tokens = ["confirmed-active-session", "cancel-not-attempted", "session-active-per-latest-query", "durable-verified-start-url-and-target"];
  assert.equal(run.evaluate(cancel, tokens).decision, "skip");
  run.recordIntent(start);
  run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
  assert.equal(run.evaluate(cancel, tokens).decision, "go");
  run.recordIntent(finalize);
  assert.equal(run.evaluate(cancel, tokens).decision, "stop");
  run.recordOutcome(row(`recovery/session/${session.caseId}/current`), out("session-command", "final", { uploadStatus: "final", sizeReceived: 4 }));
  assert.equal(run.evaluate(cancel, tokens).decision, "skip");
  run.recordOutcome(row(`recovery/session/${session.caseId}/current`), out("session-command", "active", { uploadStatus: "active", sizeReceived: 0 }));
  assert.equal(run.evaluate(cancel, tokens).decision, "go");
  run.recordIntent(cancel);
  assert.equal(run.evaluate(cancel, tokens).decision, "stop");
  assert.throws(() => run.recordIntent(row(`recovery/session/${session.caseId}/cancel`)), /mutation already attempted/);
});

test("witnesses may be deleted in recovery only after the owner readbacks, other objects any time", async () => {
  const { objects, run } = await fresh();
  const witness = manifest.resources.controls[0];
  const indexOf = manifest.resources.objects.indexOf(witness);
  const other = manifest.resources.objects.findIndex((name) => !manifest.resources.controls.includes(name));
  const token = ["restore-controls-retained-until-owner-readbacks"];
  assert.equal(run.evaluate(row(`recovery/object-${indexOf}/delete`), token).decision, "stop");
  assert.equal(run.evaluate(row(`recovery/object-${other}/delete`), token).decision, "go");
  for (let index = 0; index < 4; index++) {
    run.recordOutcome(row(`management/restore-owner-media/${index}`), out("gcs-media-read", "present", { bodyBytes: 4, bodySha256: "0".repeat(64) }));
    assert.equal(run.evaluate(row(`recovery/object-${indexOf}/delete`), token).decision, index === 3 ? "go" : "stop");
  }
  void objects;
});

test("the owner readbacks need present witnesses at the seeded version and a settled restoration", async () => {
  const { objects, run } = await fresh();
  const readback = row("management/restore-owner-media/0");
  const tokens = ["owned-control-still-present-and-version-matches", "two-complete-all-denied-restore-cycles"];
  assert.deepEqual(run.evaluate(readback, tokens).failed.map((f) => f.token).sort(), [...tokens].sort());
  seedControls(objects, [0]);
  assert.deepEqual(run.evaluate(readback, tokens).failed.map((f) => f.token), ["two-complete-all-denied-restore-cycles"]);
  run.recordSettle("restore", "settled");
  assert.equal(run.evaluate(readback, tokens).decision, "go");
  objects.recordOutcome(row("management/control-0/seed-metadata"), out("gcs-metadata-read", "present", { generation: "1700000000009999", metageneration: "1" }));
  assert.equal(run.evaluate(readback, tokens).decision, "stop");
  run.recordSettle("restore", "exhausted");
  assert.equal(run.evaluate(readback, ["two-complete-all-denied-restore-cycles"]).decision, "stop");
});

test("the final prefix check needs every owned resource proven gone, releases absent and sessions finished", async () => {
  const { objects, run } = await fresh();
  const prefix = row("management/prefix-empty");
  const token = ["all-owned-resources-and-sessions-cleaned"];
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(row("release/restore/bucket-absence"), out("rules-release-read", "absent"));
  run.recordOutcome(row("release/restore/bucketless-absence"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(prefix, token).decision, "go");
  objects.recordOutcome(row("management/control-0/baseline-metadata"), out("gcs-metadata-read", "absent"));
  objects.recordIntent(row("management/control-0/seed"));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  objects.recordOutcome(row("management/control-0/absence-metadata"), out("gcs-metadata-read", "absent"));
  assert.equal(run.evaluate(prefix, token).decision, "go");
  const session = manifest.resources.sessions[0];
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId === session.caseId);
  run.recordIntent(start);
  run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(row(`recovery/session/${session.caseId}/current`), out("session-command", "final", { uploadStatus: "final", sizeReceived: 4 }));
  assert.equal(run.evaluate(prefix, token).decision, "go");
  const ruleset = row("ruleset/v1/create");
  run.recordIntent(ruleset);
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(ruleset, out("rules-ruleset-create", "accepted", { rulesetName: RS("a"), createTime: "t", sourceSha256: "1".repeat(64) }));
  run.recordIntent(row("ruleset/v1/delete"));
  run.recordOutcome(row("ruleset/v1/delete"), out("rules-ruleset-delete", "accepted"));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(row("ruleset/v1/absence"), out("rules-ruleset-read", "absent"));
  assert.equal(run.evaluate(prefix, token).decision, "go");
});

const KNOWN = [
  { name: "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8", services: ["firebase.storage"] },
  { name: "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1", services: ["cloud.firestore"] },
];
test("the Rulesets baseline is a check of the list page itself, at entry and at the end: exactly the two known rulesets, by name and service, on a single page", async () => {
  const { run } = await fresh();
  const list = (rulesets, extra = {}) => out("rules-list-page", "accepted", { count: rulesets.length, hasNextPage: false, rulesets, ...extra });
  const stranger = { name: RS("aaaaaaaa-0000-4000-8000-000000000000"), services: ["firebase.storage"] };
  for (const id of ["preflight/rulesets-list/entry/1", "rulesets-list/final/1"]) {
    assert.equal(run.check(row(id), list(KNOWN)).ok, true, id);
    assert.deepEqual([...run.check(row(id), list([...KNOWN].reverse())).failed], ["approved-ruleset-count-and-cleanup-baseline"], "unsorted");
    for (const [name, bad] of Object.entries({
      "empty": list([]), "only storage": list([KNOWN[0]]), "only firestore": list([KNOWN[1]]), "a stranger": list([...KNOWN, stranger]), "a leftover of the run": list([...KNOWN, { name: RS("11111111-0000-4000-8000-000000000000"), services: ["firebase.storage"] }]),
      "storage replaced": list([stranger, KNOWN[1]]), "services swapped": list([{ ...KNOWN[0], services: ["cloud.firestore"] }, { ...KNOWN[1], services: ["firebase.storage"] }]), "an extra service": list([{ ...KNOWN[0], services: ["cloud.firestore", "firebase.storage"] }, KNOWN[1]]),
      "no services": list([{ name: KNOWN[0].name, services: [] }, KNOWN[1]]), "a next page": list(KNOWN, { hasNextPage: true, nextPageToken: "t" }), "no rulesets fact": out("rules-list-page", "accepted", { count: 2, hasNextPage: false }),
      "not accepted": out("rules-list-page", "unexpected", { status: 200 }), "another kind": out("rules-release-read", "absent", { rulesets: KNOWN, hasNextPage: false }), "not an array": out("rules-list-page", "accepted", { count: 2, hasNextPage: false, rulesets: "x" }),
    })) assert.equal(run.check(row(id), bad).ok, false, `${id} ${name}`);
  }
});

test("post-response checks read the classification of their own row", async () => {
  const { run } = await fresh();
  const cases = [
    ["preflight/query/permissions", out("preflight-permissions", "accepted", { missing: [] }), out("preflight-permissions", "accepted", { missing: ["a.b"] })],
    ["preflight/bucket/permissions", out("preflight-bucket-permissions", "accepted", { missing: [] }), out("preflight-bucket-permissions", "accepted", { missing: ["x"] })],
    ["preflight/release/entry/bucket", out("rules-release-read", "absent"), out("rules-release-read", "present", { rulesetName: RS("a") })],
    ["preflight/release/entry/bucketless", out("rules-release-read", "absent"), out("rules-release-read", "present", { rulesetName: RS("a") })],
    ["management/prefix-empty", out("gcs-prefix-list", "accepted", { itemCount: 0, hasNextPage: false }), out("gcs-prefix-list", "accepted", { itemCount: 1, hasNextPage: false })],
    ["preflight/rulesets-list/entry/1", out("rules-list-page", "accepted", { count: 2, hasNextPage: false, rulesets: KNOWN }), out("rules-list-page", "accepted", { count: 2, hasNextPage: true, nextPageToken: "t", rulesets: KNOWN })],
  ];
  for (const [id, good, bad] of cases) {
    assert.equal(run.check(row(id), good).ok, true, id);
    assert.equal(run.check(row(id), bad).ok, false, id);
  }
  const compile = manifest.rows.find((r) => r.family === "compile" && r.stage === "test");
  assert.equal(run.check(compile, out("rules-test", "accepted", { issues: 0, errors: 0 })).ok, true);
  assert.deepEqual([...run.check(row("preflight/query/permissions"), out("gcs-metadata-read", "present")).failed], ["all-explicit-permissions-present-does-not-authorize-send"]);
});

test("uncertain outcomes are remembered and inputs are closed", async () => {
  const { run } = await fresh();
  const create = row("ruleset/v1/create");
  run.recordIntent(create);
  run.recordOutcome(create, { uncertain: true });
  assert.equal(run.evaluate(row("ruleset/v1/read-source"), ["acknowledged-ruleset-create"]).decision, "stop");
  run.recordIntent(row("release/v1/publish"));
  run.recordOutcome(row("release/v1/publish"), { uncertain: true });
  assert.equal(run.evaluate(row("release/restore/bucket-absence"), ["restore-without-unowned-release-change"]).decision, "stop");
  const { createRunLedger } = await load();
  const objects = createResourceLedger({ manifest });
  for (const bad of [null, {}, { manifest }, { manifest, objects: {} }, { manifest: { ...manifest, sendAuthorized: true }, objects }, { manifest, objects, extra: 1 }]) assert.throws(() => createRunLedger(bad), /invalid run ledger options/);
  for (const bad of [null, {}, { id: "x" }]) assert.throws(() => run.evaluate(bad), /invalid run ledger row/);
  assert.throws(() => run.recordOutcome(create, { kind: "x", verdict: "accepted" }), /invalid run ledger outcome/);
  assert.throws(() => run.check(create, null), /invalid run ledger outcome/);
});

test("a cancelled session that is not proven final, or one in an unknown state, keeps the cleanup guard false until it is verified final", async () => {
  const { run } = await fresh();
  const prefix = row("management/prefix-empty");
  const token = ["all-owned-resources-and-sessions-cleaned"];
  run.recordOutcome(row("release/restore/bucket-absence"), out("rules-release-read", "absent"));
  run.recordOutcome(row("release/restore/bucketless-absence"), out("rules-release-read", "absent"));
  const session = manifest.resources.sessions[0];
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId === session.caseId);
  const cancel = manifest.rows.find((r) => r.family === "declared" && r.stage === "cleanup" && r.programId === session.caseId && r.request.headers["x-goog-upload-command"] === "cancel");
  const verify = row(`session-verify/${session.caseId}`);
  run.recordIntent(start);
  run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordIntent(cancel);
  run.recordOutcome(cancel, out("session-command", "acknowledged"));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordIntent(verify);
  run.recordOutcome(verify, out("session-command", "active", { uploadStatus: "active", sizeReceived: 0 }));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(verify, { uncertain: true });
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(verify, out("session-command", "final", { uploadStatus: "final", sizeReceived: 0 }));
  assert.equal(run.evaluate(prefix, token).decision, "go");
  assert.equal(run.snapshot().sessions, 1);
});

test("a finalize decides the session: accepted means final, a denial leaves it active, anything else is unknown", async () => {
  const session = manifest.resources.sessions[0];
  const finalize = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "upload, finalize" && r.programId === session.caseId);
  const cancel = manifest.rows.find((r) => r.family === "declared" && r.stage === "cleanup" && r.programId === session.caseId && r.request.headers["x-goog-upload-command"] === "cancel");
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId === session.caseId);
  const tokens = ["session-active-per-latest-query"];
  for (const [status, expected] of [[200, "skip"], [403, "go"], [500, "stop"], [412, "stop"]]) {
    const { run } = await fresh();
    run.recordIntent(start);
    run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
    run.recordIntent(finalize);
    assert.equal(run.evaluate(cancel, tokens).decision, "stop", `before the answer ${status}`);
    run.recordOutcome(finalize, { kind: "subject-observed", verdict: "observed", facts: { status, bodyBytes: 0, bodySha256: "0".repeat(64) } });
    assert.equal(run.evaluate(cancel, tokens).decision, expected, String(status));
  }
  const { run } = await fresh();
  run.recordIntent(start);
  run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
  run.recordIntent(finalize);
  run.recordOutcome(finalize, { uncertain: true });
  assert.equal(run.evaluate(cancel, tokens).decision, "stop");
});

test("the absence reads of a control follow its final readback and its deletion, and every other control row precedes the deletion", async () => {
  const { objects, run } = await fresh();
  seedControls(objects, [2]);
  const token = ["owned-control-retained-through-final-readback"];
  const absence = row("management/control-2/absence-metadata");
  const media = row("management/control-2/absence-media");
  const readback = row("management/control-2/cleanup-metadata");
  const del = row("management/control-2/delete");
  assert.equal(run.evaluate(readback, token).decision, "go");
  assert.equal(run.evaluate(absence, token).decision, "stop");
  run.recordOutcome(readback, out("gcs-metadata-read", "present", { generation: "1700000000000021", metageneration: "1" }));
  assert.equal(run.evaluate(absence, token).decision, "stop");
  objects.recordIntent(del);
  assert.equal(run.evaluate(absence, token).decision, "go");
  assert.equal(run.evaluate(media, token).decision, "go");
  assert.equal(run.evaluate(readback, token).decision, "stop");
  const noReadback = await fresh();
  seedControls(noReadback.objects, [2]);
  noReadback.objects.recordIntent(del);
  assert.equal(noReadback.run.evaluate(absence, token).decision, "stop");
});

// Recovery groups are enabled only by ledger facts; nothing else decides whether a group of recovery rows is sent.
test("the recovery groups are closed and nothing is enabled on a fresh ledger", async () => {
  const { run } = await fresh();
  assert.equal(typeof run.recoveryEnabled, "function");
  for (const name of ["release-written", "release-written-not-deleted", "restore-needed", "ruleset-attempted:v1", "ruleset-created-not-deleted:v1"]) {
    assert.equal(run.recoveryEnabled(name), false, name);
  }
  assert.equal(run.recoveryEnabled(`session-started:${manifest.resources.sessions[0].caseId}`), false);
  for (const bad of ["", "release", "release-written:1", "ruleset-attempted:C", "ruleset-attempted", "session-started:unknown", "session-started:", "restore-needed:x", null, undefined, 1, {}]) {
    assert.throws(() => run.recoveryEnabled(bad), /invalid recovery group/, String(bad));
  }
});

test("the release groups follow the release writes: written and not yet deleted, or written at all", async () => {
  const { run } = await fresh();
  const publish = row("release/v1/publish");
  run.recordIntent(publish);
  assert.deepEqual(["release-written", "release-written-not-deleted"].map((name) => run.recoveryEnabled(name)), [true, true]);
  run.recordIntent(row("release/restore/delete"));
  assert.deepEqual(["release-written", "release-written-not-deleted"].map((name) => run.recoveryEnabled(name)), [true, false]);
});

test("the restore group is needed once a witness exists and until the four owner readbacks are done", async () => {
  const { objects, run } = await fresh();
  assert.equal(run.recoveryEnabled("restore-needed"), false);
  seedControls(objects, [2]);
  assert.equal(run.recoveryEnabled("restore-needed"), false, "a non-witness control does not need the restore");
  seedControls(objects, [0]);
  assert.equal(run.recoveryEnabled("restore-needed"), true);
  const media = (index, prefix = "") => row(`${prefix}management/restore-owner-media/${index}`);
  for (const index of [0, 1, 2]) run.recordOutcome(media(index), out("gcs-media-read", "present"));
  assert.equal(run.recoveryEnabled("restore-needed"), true);
  run.recordOutcome(media(3), out("gcs-media-read", "present"));
  assert.equal(run.recoveryEnabled("restore-needed"), false);
});

test("the recovery owner media reads count toward the restore the same as the normal ones", async () => {
  const { objects, run } = await fresh();
  seedControls(objects, [0, 1, 3, 4]);
  for (const index of [0, 1, 2, 3]) run.recordOutcome(row(`recovery/management/restore-owner-media/${index}`), out("gcs-media-read", "present"));
  assert.equal(run.recoveryEnabled("restore-needed"), false);
});

test("a session group is enabled once its start is confirmed or it has any state", async () => {
  const { run } = await fresh();
  const session = manifest.resources.sessions[0];
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId === session.caseId);
  const name = `session-started:${session.caseId}`;
  assert.equal(run.recoveryEnabled(name), false);
  run.recordIntent(start);
  assert.equal(run.recoveryEnabled(name), false, "an intent alone is not a confirmed session");
  run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
  assert.equal(run.recoveryEnabled(name), true);
  const other = manifest.resources.sessions[1].caseId;
  assert.equal(run.recoveryEnabled(`session-started:${other}`), false);
});

test("a Ruleset group is enabled by its create attempt, and the delete group only until its delete", async () => {
  const { run } = await fresh();
  assert.deepEqual([run.recoveryEnabled("ruleset-attempted:v1"), run.recoveryEnabled("ruleset-created-not-deleted:v1")], [false, false]);
  run.recordIntent(row("ruleset/v1/create"));
  assert.deepEqual([run.recoveryEnabled("ruleset-attempted:v1"), run.recoveryEnabled("ruleset-created-not-deleted:v1")], [true, true]);
  assert.deepEqual([run.recoveryEnabled("ruleset-attempted:v2"), run.recoveryEnabled("ruleset-created-not-deleted:v2")], [false, false]);
  run.recordIntent(row("ruleset/v1/delete"));
  assert.deepEqual([run.recoveryEnabled("ruleset-attempted:v1"), run.recoveryEnabled("ruleset-created-not-deleted:v1")], [true, false]);
});

// Mutation-driven tests: each one pins a conjunct or a state transition that the tests above left open.

test("a delete of a document or of the release is never attempted twice, whatever row carries it", async () => {
  const { run } = await fresh();
  const step = row("firestore-program/firestore-get-transition/step/doc-delete");
  const cleanup = row("firestore-program/firestore-get-transition/cleanup/doc-cleanup-delete");
  const recovery = row("recovery/document-0/delete");
  assert.equal(step.request.documentName, recovery.request.documentName);
  run.recordIntent(step);
  assert.throws(() => run.recordIntent(cleanup), /mutation already attempted/);
  assert.throws(() => run.recordIntent(recovery), /mutation already attempted/);
  run.recordIntent(row("release/restore/delete"));
  assert.throws(() => run.recordIntent(row("recovery/release/restore/delete")), /mutation already attempted/);
  const other = await fresh();
  other.run.recordIntent(row("recovery/release/restore/delete"));
  assert.throws(() => other.run.recordIntent(row("release/restore/delete")), /mutation already attempted/);
});

test("a Ruleset readback counts only when both the created name and the source digest match", async () => {
  const { run } = await fresh();
  const publish = row("release/v1/publish");
  const token = ["owned-ruleset-and-source-readback"];
  run.recordOutcome(row("ruleset/v1/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("aaa"), createTime: "t", sourceSha256: "1".repeat(64) }));
  run.recordOutcome(row("ruleset/v1/read-source"), out("rules-ruleset-read", "present", { rulesetName: RS("other"), sourceSha256: "1".repeat(64) }));
  assert.equal(run.evaluate(publish, token).decision, "stop");
  run.recordOutcome(row("ruleset/v1/read-source"), out("rules-ruleset-read", "present", { rulesetName: RS("aaa"), sourceSha256: "1".repeat(64) }));
  assert.equal(run.evaluate(publish, token).decision, "go");
});

test("a bucketless release that is present is an unowned change", async () => {
  const { run } = await fresh();
  const read = row("release/restore/bucket-absence");
  const token = ["restore-without-unowned-release-change"];
  assert.equal(run.evaluate(read, token).decision, "go");
  run.recordOutcome(row("preflight/release/entry/bucketless"), out("rules-release-read", "present", { rulesetName: RS("foreign") }));
  assert.equal(run.evaluate(read, token).decision, "stop");
});

test("an accepted release write naming a Ruleset that is not ours does not make the release ours", async () => {
  const { run } = await fresh();
  const del = row("release/restore/delete");
  const token = ["exact-owned-current-release-and-absent-entry-baseline"];
  run.recordOutcome(row("preflight/release/entry/bucket"), out("rules-release-read", "absent"));
  run.recordOutcome(row("preflight/release/entry/bucketless"), out("rules-release-read", "absent"));
  run.recordOutcome(row("ruleset/B/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("bb"), createTime: "t", sourceSha256: "1".repeat(64) }));
  run.recordOutcome(row("release/B/publish"), out("rules-release-patch", "accepted", { rulesetName: RS("foreign"), releaseName: "n", updateTime: "t" }));
  assert.equal(run.evaluate(del, token).decision, "stop");
  run.recordOutcome(row("release/B/publish"), out("rules-release-patch", "accepted", { rulesetName: RS("bb"), releaseName: "n", updateTime: "t" }));
  assert.equal(run.evaluate(del, token).decision, "go");
});

test("the release removal needs each part of the entry baseline and no unowned change", async () => {
  const token = ["exact-owned-current-release-and-absent-entry-baseline"];
  const publishB = (run) => {
    run.recordOutcome(row("ruleset/B/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("bb"), createTime: "t", sourceSha256: "1".repeat(64) }));
    run.recordOutcome(row("release/B/publish"), out("rules-release-patch", "accepted", { rulesetName: RS("bb"), releaseName: "n", updateTime: "t" }));
  };
  for (const entries of [[], ["bucket"], ["bucketless"]]) {
    const { run } = await fresh();
    for (const slot of entries) run.recordOutcome(row(`preflight/release/entry/${slot}`), out("rules-release-read", "absent"));
    publishB(run);
    assert.equal(run.evaluate(row("release/restore/delete"), token).decision, "stop", entries.join(",") || "no entry reads");
  }
  const { run } = await fresh();
  run.recordOutcome(row("preflight/release/entry/bucket"), out("rules-release-read", "absent"));
  run.recordOutcome(row("preflight/release/entry/bucketless"), out("rules-release-read", "absent"));
  publishB(run);
  assert.equal(run.evaluate(row("release/restore/delete"), token).decision, "go");
  run.recordOutcome(row("release/restore/bucketless-absence"), out("rules-release-read", "present", { rulesetName: RS("foreign") }));
  assert.equal(run.evaluate(row("release/restore/delete"), token).decision, "stop");
});

test("after an accepted release delete the release is unknown until it is read back", async () => {
  const { run } = await fresh();
  const delRuleset = row("ruleset/v1/delete");
  const token = ["owned-ruleset-and-unreferenced-after-restore"];
  run.recordOutcome(row("ruleset/v1/create"), out("rules-ruleset-create", "accepted", { rulesetName: RS("aaa"), createTime: "t", sourceSha256: "1".repeat(64) }));
  const del = row("release/restore/delete");
  run.recordIntent(del);
  run.recordOutcome(del, out("rules-release-delete", "accepted"));
  assert.equal(run.snapshot().release, "unknown");
  assert.equal(run.evaluate(delRuleset, token).decision, "stop");
  run.recordOutcome(row("release/restore/bucket-absence"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(delRuleset, token).decision, "go");
});

test("a control's final readback counts only when it read the control as present or absent", async () => {
  const { run } = await fresh();
  const del = row("management/control-0/delete");
  const token = ["all-final-control-readbacks-complete"];
  for (let index = 0; index < 5; index++) run.recordOutcome(row(`management/control-${index}/cleanup-metadata`), out("gcs-metadata-read", "present"));
  for (const verdict of ["unexpected", "denied", "unknown"]) {
    run.recordOutcome(row("management/control-5/cleanup-metadata"), out("gcs-metadata-read", verdict));
    assert.equal(run.evaluate(del, token).decision, "stop", verdict);
  }
  run.recordOutcome(row("management/control-5/cleanup-metadata"), out("gcs-metadata-read", "absent"));
  assert.equal(run.evaluate(del, token).decision, "go");
});

test("an owner media read counts toward the restore only when it found the witness", async () => {
  const { objects, run } = await fresh();
  seedControls(objects, [0, 1, 3, 4]);
  const witnessDelete = row(`recovery/object-${manifest.resources.objects.indexOf(manifest.resources.controls[0])}/delete`);
  const token = ["restore-controls-retained-until-owner-readbacks"];
  for (const index of [0, 1, 2]) run.recordOutcome(row(`management/restore-owner-media/${index}`), out("gcs-media-read", "present"));
  for (const verdict of ["absent", "unexpected"]) {
    run.recordOutcome(row("management/restore-owner-media/3"), out("gcs-media-read", verdict));
    run.recordOutcome(row("recovery/management/restore-owner-media/3"), out("gcs-media-read", verdict));
    assert.equal(run.recoveryEnabled("restore-needed"), true, verdict);
    assert.equal(run.evaluate(witnessDelete, token).decision, "stop", verdict);
  }
  run.recordOutcome(row("management/restore-owner-media/3"), out("gcs-media-read", "present"));
  assert.equal(run.recoveryEnabled("restore-needed"), false);
  assert.equal(run.evaluate(witnessDelete, token).decision, "go");
});

test("a witness whose delete was attempted is not retained even when a later read shows it present", async () => {
  const { objects, run } = await fresh();
  const publish = row("release/v1/publish");
  const token = ["all-four-controls-confirmed-and-retained"];
  seedControls(objects, [0, 1, 3, 4]);
  assert.equal(run.evaluate(publish, token).decision, "go");
  const del = row("management/control-1/delete");
  objects.recordIntent(del);
  objects.recordOutcome(del, out("gcs-delete", "unexpected"));
  objects.recordOutcome(row("management/control-1/cleanup-metadata"), out("gcs-metadata-read", "present", { generation: "1700000000000011", metageneration: "1" }));
  const witness = objects.object(manifest.resources.controls[1]);
  assert.deepEqual([witness.owned, witness.latest, witness.deleteAttempted], [true, "present", true]);
  assert.equal(run.evaluate(publish, token).decision, "stop");
});

test("a witness seeded without a proven-absent baseline is not owned and does not count", async () => {
  const { objects, run } = await fresh();
  const publish = row("release/v1/publish");
  const token = ["all-four-controls-confirmed-and-retained"];
  seedControls(objects, [0, 1, 3]);
  const id = (stage) => row(`management/control-4/${stage}`);
  objects.recordIntent(id("seed"));
  objects.recordOutcome(id("seed"), out("gcs-seed-upload", "accepted", { generation: "1700000000000041", metageneration: "1", size: "4" }));
  objects.recordOutcome(id("seed-metadata"), out("gcs-metadata-read", "present", { generation: "1700000000000041", metageneration: "1" }));
  const witness = objects.object(manifest.resources.controls[4]);
  assert.deepEqual([witness.owned, witness.latest, witness.deleteAttempted, witness.generation], [false, "present", false, "1700000000000041"]);
  assert.equal(run.evaluate(publish, token).decision, "stop");
});

test("the compile is done only when every test answered and the invalid source was rejected", async () => {
  const create = row("ruleset/v1/create");
  const token = ["compiled-source-and-entry-baseline"];
  const tests = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test");
  const invalid = row("compile/invalid/storage-expression");
  const baseline = (run) => {
    run.recordOutcome(row("preflight/release/entry/bucket"), out("rules-release-read", "absent"));
    run.recordOutcome(row("preflight/release/entry/bucketless"), out("rules-release-read", "absent"));
  };
  const allAccepted = await fresh();
  baseline(allAccepted.run);
  for (const test of tests) allAccepted.run.recordOutcome(test, out("rules-test", "accepted", { issues: 0, errors: 0 }));
  assert.equal(allAccepted.run.evaluate(create, token).decision, "stop", "no test was rejected");
  const invalidFirst = await fresh();
  baseline(invalidFirst.run);
  invalidFirst.run.recordOutcome(invalid, out("rules-test", "rejected", { issues: 1, errors: 1 }));
  assert.equal(invalidFirst.run.evaluate(create, token).decision, "stop", "only the invalid test answered");
  const rest = tests.filter((t) => t.id !== invalid.id);
  for (const [index, test] of rest.entries()) {
    invalidFirst.run.recordOutcome(test, out("rules-test", "accepted", { issues: 0, errors: 0 }));
    assert.equal(invalidFirst.run.evaluate(create, token).decision, index === rest.length - 1 ? "go" : "stop", `after ${index}`);
  }
});

test("a confirmed session is active only while its latest state is active", async () => {
  const { run } = await fresh();
  const session = manifest.resources.sessions[0];
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId === session.caseId);
  const cancel = manifest.rows.find((r) => r.family === "declared" && r.stage === "cleanup" && r.programId === session.caseId && r.request.headers["x-goog-upload-command"] === "cancel");
  const token = ["confirmed-active-session"];
  run.recordIntent(start);
  run.recordOutcome(start, out("session-start", "accepted", { uploadStatus: "active" }));
  assert.equal(run.evaluate(cancel, token).decision, "go");
  run.recordOutcome(row(`recovery/session/${session.caseId}/current`), out("session-command", "final", { uploadStatus: "final", sizeReceived: 4 }));
  assert.equal(run.evaluate(cancel, token).decision, "stop");
  run.recordOutcome(row(`recovery/session/${session.caseId}/current`), { uncertain: true });
  assert.equal(run.evaluate(cancel, token).decision, "stop");
});

test("the final prefix check needs every written document proven absent", async () => {
  const { run } = await fresh();
  const prefix = row("management/prefix-empty");
  const token = ["all-owned-resources-and-sessions-cleaned"];
  run.recordOutcome(row("release/restore/bucket-absence"), out("rules-release-read", "absent"));
  run.recordOutcome(row("release/restore/bucketless-absence"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(prefix, token).decision, "go");
  const create = row("firestore-program/firestore-get-transition/step/doc-create-true");
  run.recordIntent(create);
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(create, out("firestore-write", "accepted", { documentName: create.request.documentName, updateTime: "2026-09-29T10:00:00Z" }));
  assert.equal(run.evaluate(prefix, token).decision, "stop");
  run.recordOutcome(row("recovery/document-0/absence"), out("firestore-read", "absent"));
  assert.equal(run.evaluate(prefix, token).decision, "go");
});

test("a publication needs exactly the previous release: absence before v1, and the previous created Ruleset after it", async () => {
  const token = ["exact-previous-release-or-entry-absence"];
  const create = (run, name, id) => run.recordOutcome(row(`ruleset/${name}/create`), out("rules-ruleset-create", "accepted", { rulesetName: RS(id), createTime: "t", sourceSha256: "1".repeat(64) }));
  const publishOutcome = (rulesetName) => out("rules-release-patch", "accepted", { rulesetName, releaseName: "n", updateTime: "t" });
  const { run } = await fresh();
  assert.equal(run.evaluate(row("release/v1/publish"), token).decision, "stop", "the release was never read");
  run.recordOutcome(row("release/v1/before"), out("rules-release-read", "absent"));
  assert.equal(run.evaluate(row("release/v1/publish"), token).decision, "go");
  assert.equal(run.evaluate(row("release/v2/publish"), token).decision, "stop", "an absent release is not v1's");
  create(run, "v1", "aaa");
  run.recordOutcome(row("release/v1/publish"), publishOutcome(RS("aaa")));
  assert.equal(run.evaluate(row("release/v1/publish"), token).decision, "stop", "v1 needs an absent release");
  assert.equal(run.evaluate(row("release/v2/publish"), token).decision, "go");
  assert.equal(run.evaluate(row("release/A/publish"), token).decision, "stop", "v2 was never created");
  create(run, "v2", "bbb");
  assert.equal(run.evaluate(row("release/A/publish"), token).decision, "stop", "the release still names v1");
  run.recordOutcome(row("release/v2/publish"), publishOutcome(RS("bbb")));
  assert.equal(run.evaluate(row("release/A/publish"), token).decision, "go");
  assert.equal(run.evaluate(row("release/v2/publish"), token).decision, "stop");
  const unnamed = await fresh();
  unnamed.run.recordOutcome(row("release/v1/publish"), publishOutcome(null));
  assert.equal(unnamed.run.evaluate(row("release/v2/publish"), token).decision, "stop", "an unnamed release never matches an uncreated Ruleset");
});

test("a document is deletable and has a confirmed history only when present with an update time and no doubt", async () => {
  const { run } = await fresh();
  const name = row("recovery/document-0/delete").request.documentName;
  const token = ["confirmed-document-write-history-and-current-version"];
  const del = row("recovery/document-0/delete");
  const state = () => [run.document(name).deletable, run.evaluate(del, token).decision];
  assert.deepEqual(state(), [false, "stop"]);
  const create = row("firestore-program/firestore-get-transition/step/doc-create-true");
  run.recordIntent(create);
  assert.deepEqual(state(), [false, "stop"], "started only");
  run.recordOutcome(create, out("firestore-write", "accepted", { documentName: name }));
  assert.equal(run.document(name).latest, "present");
  assert.deepEqual(state(), [false, "stop"], "present without an update time");
  run.recordOutcome(row("recovery/document-0/current"), out("firestore-read", "present", { documentName: name, updateTime: "2026-09-29T10:00:00Z" }));
  assert.deepEqual(state(), [true, "go"]);
  const update = row("firestore-program/firestore-get-transition/step/doc-update-false");
  run.recordIntent(update);
  run.recordOutcome(update, { uncertain: true });
  run.recordOutcome(row("recovery/document-0/current"), out("firestore-read", "present", { documentName: name, updateTime: "2026-09-29T10:01:00Z" }));
  assert.equal(run.document(name).latest, "present");
  assert.deepEqual(state(), [false, "stop"], "present after an unanswered write");
});

test("the prefix is empty only with no items and no next page", async () => {
  const { run } = await fresh();
  const prefix = row("management/prefix-empty");
  assert.equal(run.check(prefix, out("gcs-prefix-list", "accepted", { itemCount: 0, hasNextPage: false })).ok, true);
  for (const facts of [{ itemCount: 0, hasNextPage: true, nextPageToken: "t" }, { itemCount: 0 }, { itemCount: 1, hasNextPage: false }]) {
    assert.equal(run.check(prefix, out("gcs-prefix-list", "accepted", facts)).ok, false, JSON.stringify(facts));
  }
});
