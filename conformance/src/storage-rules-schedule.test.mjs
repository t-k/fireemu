import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const load = async () => {
  const module = await import("./storage-rules/schedule.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.buildSchedule, "function");
  return module;
};
const schedule = async () => (await load()).buildSchedule(manifest);
const position = (steps, predicate) => steps.findIndex(predicate);
const rowStep = (id) => (step) => step.type === "row" && step.id === id;

test("every preflight ID runs once in the reviewed order, the two credential IDs first", async () => {
  const s = await schedule();
  assert.equal(Object.isFrozen(s), true);
  assert.deepEqual([...s.preflight].sort(), [...manifest.preflightIds].sort());
  assert.deepEqual(s.preflight.slice(0, 3), ["preflight/auth/owner-token", "preflight/auth/signing-keys", "preflight/owner/identity"]);
  assert.equal(new Set(s.preflight).size, 19);
});

test("each normal row is scheduled exactly once, explicitly, in a settle block or in a delegated group", async () => {
  const s = await schedule();
  const covered = new Map();
  const cover = (id, how) => { assert.equal(covered.has(id), false, `${id} twice (${covered.get(id)} and ${how})`); covered.set(id, how); };
  for (const id of s.preflight) cover(id, "preflight");
  for (const step of s.steps) {
    if (step.type === "row") cover(step.id, "row");
    else if (step.type === "settle") for (const id of step.rowIds) cover(id, `settle ${step.name}`);
    else if (step.type === "pages") for (const id of step.rowIds) cover(id, "pages");
    else if (step.type === "delegate") for (const id of step.rowIds) cover(id, `delegate ${step.op}`);
    else assert.fail(`unknown step ${step.type}`);
  }
  const normal = manifest.rows.filter((r) => r.phase !== "recovery").map((r) => r.id);
  assert.deepEqual([...covered.keys()].sort(), normal.sort());
  assert.equal(covered.size, 4638);
  assert.ok(![...covered.keys()].some((id) => id.startsWith("recovery/")));
});

test("the four witnesses are seeded and read back before any release is written", async () => {
  const s = await schedule();
  const firstPublish = position(s.steps, rowStep("release/v1/publish"));
  assert.ok(firstPublish > 0);
  for (const index of [0, 1, 3, 4]) {
    for (const stage of ["baseline-metadata", "baseline-media", "seed", "seed-metadata", "seed-media"]) assert.ok(position(s.steps, rowStep(`management/control-${index}/${stage}`)) < firstPublish, `control-${index}/${stage}`);
    const order = ["baseline-metadata", "baseline-media", "seed", "seed-metadata", "seed-media"].map((stage) => position(s.steps, rowStep(`management/control-${index}/${stage}`)));
    assert.deepEqual([...order].sort((a, b) => a - b), order);
  }
});

test("compile checks and Ruleset creation precede publication, and the invalid source comes last", async () => {
  const s = await schedule();
  const firstPublish = position(s.steps, rowStep("release/v1/publish"));
  const before = position(s.steps, rowStep("compile/release/before"));
  const after = position(s.steps, rowStep("compile/release/after-invalid"));
  const tests = s.steps.map((step, index) => [step, index]).filter(([step]) => step.type === "row" && step.id.startsWith("compile/") && !step.id.startsWith("compile/release/"));
  assert.equal(tests.length, 339);
  assert.ok(tests.every(([, index]) => index > before && index < after));
  assert.ok(after < firstPublish);
  for (const name of ["v1", "v2", "A", "B"]) {
    const create = position(s.steps, rowStep(`ruleset/${name}/create`));
    const read = position(s.steps, rowStep(`ruleset/${name}/read-source`));
    assert.ok(create > after && read > create && read < firstPublish, name);
  }
  const invalid = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").at(-1).id;
  assert.equal(tests.at(-1)[0].id, invalid);
});

test("credentials are prepared before the first subject that needs a user token and cleaned last", async () => {
  const s = await schedule();
  const prepare = position(s.steps, (step) => step.type === "delegate" && step.op === "prepare-query");
  const cleanup = position(s.steps, (step) => step.type === "delegate" && step.op === "cleanup-query");
  assert.ok(prepare >= 0 && cleanup === s.steps.length - 1);
  assert.ok(prepare < position(s.steps, rowStep("management/no-release/entry/subject")));
  const firstUserRow = position(s.steps, (step) => step.type === "row" && manifest.rows.find((r) => r.id === step.id).request.credential === "user-a");
  assert.ok(prepare < firstUserRow);
  const cache = s.steps.filter((step) => step.type === "delegate" && step.op === "credential-cache");
  assert.equal(cache.length, 1);
  assert.equal(cache[0].rowIds.length, 9);
});

test("each publication is preceded by its before-read and followed by its after-read, a settle and only then its cases", async () => {
  const s = await schedule();
  for (const name of ["v1", "v2", "A", "B"]) {
    const before = position(s.steps, rowStep(`release/${name}/before`));
    const publish = position(s.steps, rowStep(`release/${name}/publish`));
    const after = position(s.steps, rowStep(`release/${name}/after`));
    const settle = position(s.steps, (step) => step.type === "settle" && step.name === name);
    assert.ok(before >= 0 && before < publish && publish < after && after < settle, name);
    assert.equal(s.steps[before + 1].id, `release/${name}/publish`);
    assert.equal(s.steps[before + 2].id, `release/${name}/after`);
    assert.equal(s.steps[before + 3].type, "settle");
  }
  const casesOf = (ids) => s.steps.map((step, index) => [step, index]).filter(([step]) => step.type === "row" && ids.some((id) => manifest.rows.find((r) => r.id === step.id).programId === id)).map(([, index]) => index);
  const v1 = casesOf(manifest.publication.v1);
  const v2 = casesOf(manifest.publication.v2);
  const settleIndex = (name) => position(s.steps, (step) => step.type === "settle" && step.name === name);
  assert.ok(v1.every((i) => i > settleIndex("v1") && i < position(s.steps, rowStep("release/v2/before"))));
  assert.ok(v2.every((i) => i > settleIndex("v2") && i < position(s.steps, rowStep("release/A/before"))));
  assert.ok(position(s.steps, rowStep("release/A/publish")) > Math.max(...v2));
});

test("a case runs its rows in the corpus's order without interleaving with another case", async () => {
  const s = await schedule();
  const rows = s.steps.filter((step) => step.type === "row").map((step) => manifest.rows.find((r) => r.id === step.id));
  for (const id of [...manifest.publication.v1, ...manifest.publication.v2]) {
    const belongs = (r) => r.programId === id && (r.family === "declared" || r.family === "session-verify");
    const indices = rows.map((r, index) => [r, index]).filter(([r]) => belongs(r)).map(([, index]) => index);
    assert.ok(indices.length > 0, id);
    assert.equal(indices.at(-1) - indices[0] + 1, indices.length, `${id} is interleaved`);
    // The corpus's order, with each session's verify row directly after its cancel.
    const inventory = manifest.rows.filter((r) => r.programId === id && r.family === "declared").flatMap((r) => (r.request.headers?.["x-goog-upload-command"] === "cancel" ? [r.id, `session-verify/${id}`] : [r.id]));
    assert.deepEqual(indices.map((i) => rows[i].id), inventory, id);
  }
});

test("the restoration follows the release removal and precedes any witness deletion", async () => {
  const s = await schedule();
  const del = position(s.steps, rowStep("release/restore/delete"));
  assert.ok(position(s.steps, rowStep("release/restore/owner-before-delete")) === del - 1);
  assert.ok(position(s.steps, rowStep("release/restore/bucket-absence")) === del + 1 && position(s.steps, rowStep("release/restore/bucketless-absence")) === del + 2);
  const settle = position(s.steps, (step) => step.type === "settle" && step.name === "restore");
  assert.ok(settle === del + 3);
  for (let index = 0; index < 4; index++) assert.ok(position(s.steps, rowStep(`management/restore-owner-media/${index}`)) > settle);
  const lastOwnerMedia = position(s.steps, rowStep("management/restore-owner-media/3"));
  const firstControlDelete = Math.min(...[0, 1, 2, 3, 4, 5].map((index) => position(s.steps, rowStep(`management/control-${index}/delete`))));
  assert.ok(firstControlDelete > lastOwnerMedia);
  const firstA = position(s.steps, rowStep("release/A/before"));
  assert.ok(del > position(s.steps, rowStep("management/B/control-4/after-media")) && firstA < del);
});

test("control cleanup reads every control before deleting any and proves absence after", async () => {
  const s = await schedule();
  const at = (index, stage) => position(s.steps, rowStep(`management/control-${index}/${stage}`));
  const reads = [0, 1, 2, 3, 4, 5].map((index) => at(index, "cleanup-metadata"));
  const deletes = [0, 1, 2, 3, 4, 5].map((index) => at(index, "delete"));
  assert.ok(Math.max(...reads) < Math.min(...deletes));
  for (let index = 0; index < 6; index++) assert.ok(at(index, "delete") < at(index, "absence-metadata") && at(index, "absence-metadata") < at(index, "absence-media"));
});

test("Rulesets are deleted after the release is gone, the list pages come after, and the owned prefix is checked last before credentials", async () => {
  const s = await schedule();
  const del = position(s.steps, rowStep("release/restore/delete"));
  for (const name of ["v1", "v2", "A", "B"]) {
    assert.ok(position(s.steps, rowStep(`ruleset/${name}/delete`)) > del);
    assert.equal(position(s.steps, rowStep(`ruleset/${name}/absence`)), position(s.steps, rowStep(`ruleset/${name}/delete`)) + 1);
  }
  const pages = s.steps.find((step) => step.type === "pages");
  assert.deepEqual(pages.rowIds, Array.from({ length: 10 }, (_, index) => `rulesets-list/final/${index + 1}`));
  assert.equal(pages.stopWhen, "no-next-page-token");
  const lastDelete = Math.max(...["v1", "v2", "A", "B"].map((name) => position(s.steps, rowStep(`ruleset/${name}/absence`))));
  assert.ok(s.steps.indexOf(pages) > lastDelete);
  const prefix = position(s.steps, rowStep("management/prefix-empty"));
  assert.ok(prefix > s.steps.indexOf(pages) && prefix === s.steps.length - 2);
});

test("the settle blocks carry the manifest's witnesses and limits", async () => {
  const s = await schedule();
  const blocks = s.steps.filter((step) => step.type === "settle");
  assert.deepEqual(blocks.map((b) => b.name), ["v1", "v2", "A", "B", "restore"]);
  for (const block of blocks.slice(0, 4)) {
    assert.equal(block.config.kind, "publication");
    assert.equal(block.config.maxCycles, 30);
    assert.equal(block.rowIds.length, 60);
    assert.equal(block.config.witnesses.length, 2);
  }
  const restore = blocks[4];
  assert.equal(restore.config.kind, "restoration");
  assert.equal(restore.config.maxCycles, manifest.restoration.maxCycles);
  assert.equal(restore.config.requiredConsecutive, manifest.restoration.consecutiveCompleteCycles);
  assert.equal(restore.rowIds.length, 60);
  assert.equal(new Set(restore.config.witnesses.map((w) => w.objectName)).size, 4);
  assert.equal(restore.intervalMs, manifest.restoration.intervalMs);
});

test("the schedule is deterministic and refuses a manifest it does not recognize", async () => {
  const { buildSchedule } = await load();
  assert.equal(JSON.stringify(buildSchedule(manifest)), JSON.stringify(buildSchedule(manifest)));
  for (const bad of [null, {}, { ...manifest, rows: manifest.rows.slice(1) }, { ...manifest, publication: undefined }, { ...manifest, sendAuthorized: true }, { ...manifest, preflightIds: manifest.preflightIds.slice(1) }]) {
    assert.throws(() => buildSchedule(bad), /invalid schedule manifest/);
  }
});

test("every session is asked again right after its cancel and before the case ends", async () => {
  const s = await schedule();
  for (const session of manifest.resources.sessions) {
    const cancel = s.steps.findIndex((step) => step.type === "row" && manifest.rows.find((r) => r.id === step.id).request.headers?.["x-goog-upload-command"] === "cancel" && manifest.rows.find((r) => r.id === step.id).programId === session.caseId);
    const verify = position(s.steps, rowStep(`session-verify/${session.caseId}`));
    assert.ok(cancel >= 0 && verify === cancel + 1, session.caseId);
  }
});
