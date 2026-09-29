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
  assert.equal(run.check(before("v2"), out("gcs-metadata-read", "present")).ok, false);
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

test("post-response checks read the classification of their own row", async () => {
  const { run } = await fresh();
  const cases = [
    ["preflight/query/permissions", out("preflight-permissions", "accepted", { missing: [] }), out("preflight-permissions", "accepted", { missing: ["a.b"] })],
    ["preflight/bucket/permissions", out("preflight-bucket-permissions", "accepted", { missing: [] }), out("preflight-bucket-permissions", "accepted", { missing: ["x"] })],
    ["preflight/release/entry/bucket", out("rules-release-read", "absent"), out("rules-release-read", "present", { rulesetName: RS("a") })],
    ["preflight/release/entry/bucketless", out("rules-release-read", "absent"), out("rules-release-read", "present", { rulesetName: RS("a") })],
    ["management/prefix-empty", out("gcs-prefix-list", "accepted", { itemCount: 0, hasNextPage: false }), out("gcs-prefix-list", "accepted", { itemCount: 1, hasNextPage: false })],
    ["preflight/rulesets-list/entry/1", out("rules-list-page", "accepted", { count: 3, hasNextPage: false }), out("rules-list-page", "accepted", { count: 3, hasNextPage: true, nextPageToken: "t" })],
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
