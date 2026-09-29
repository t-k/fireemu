import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "5".repeat(64);
const KINDS = ["generation", "metageneration", "update-time", "ruleset-name", "ruleset-path", "page-token"];

async function load() {
  const module = await import("./storage-rules/runtime-refs.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.buildRefTables, "function");
  assert.equal(typeof module.createRuntimeRefStore, "function");
  return module;
}
const ref = (type, key) => ({ kind: "runtime-reference", type, key, resolveOnlyAfterDurableProof: true });
const walk = (value, visit) => {
  if (value && typeof value === "object") { visit(value); for (const inner of Object.values(value)) walk(inner, visit); }
};
const occurrences = () => manifest.rows.flatMap((row) => { const found = []; walk(row.request, (v) => { if (v.kind === "runtime-reference" && KINDS.includes(v.type)) found.push({ row, ref: v }); }); return found; });
async function fresh(overrides = {}) {
  const { buildRefTables, createRuntimeRefStore } = await load();
  const proofs = [];
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async (proof) => { proofs.push(proof); }, ...overrides });
  return { store, proofs };
}
const seedRow = manifest.rows.find((r) => r.id === "management/control-0/seed");
const objectName = seedRow.request.objectName;
const deleteRow = manifest.rows.find((r) => r.id === "management/control-0/delete");
const patchRow = manifest.rows.find((r) => r.family === "declared" && r.request.operation === "patch" && r.stage === "setup");
const metadataRow = manifest.rows.find((r) => r.id === "management/control-0/seed-metadata");
const producer = (row, verdict = "accepted", attempt = 1, deletable = true) => ({ operationId: row.id, attempt, verdict, deletable });

test("the tables cover every declared reference of the six kinds and give each a producer", async () => {
  const { buildRefTables } = await load();
  const tables = buildRefTables(manifest);
  assert.equal(Object.isFrozen(tables), true);
  const found = occurrences();
  assert.ok(found.length > 1000);
  for (const { row, ref: r } of found) {
    assert.ok(tables.consumers[r.type]?.[r.key]?.includes(row.id), `${row.id} ${r.type}`);
    if (r.type !== "ruleset-path") assert.ok(tables.producers[r.type]?.[r.key]?.length > 0, `${r.type} ${r.key}`);
  }
  const keys = new Set(found.map(({ ref: r }) => `${r.type}|${r.key}`));
  let tableKeys = 0;
  for (const type of KINDS) tableKeys += Object.keys(tables.consumers[type] ?? {}).length;
  assert.equal(tableKeys, keys.size);
  assert.deepEqual(tables.producers["ruleset-name"].v1, [{ operationId: "ruleset/v1/create", verdict: "accepted" }]);
  assert.deepEqual(tables.producers["page-token"]["normal/final/1"], [{ operationId: "rulesets-list/final/1", verdict: "accepted" }]);
  assert.deepEqual(tables.producers["page-token"]["recovery/final/3"], [{ operationId: "recovery/rulesets-list/final/3", verdict: "accepted" }]);
  const generation = tables.producers.generation[objectName].map((p) => p.operationId);
  assert.ok(generation.includes(seedRow.id) && generation.includes(metadataRow.id));
  assert.ok(!generation.some((id) => manifest.rows.find((r) => r.id === id).stage === "subject"));
});

test("a bound value becomes resolvable only after its proof is durable, and the proof carries a salted digest, never the value", async () => {
  const { store, proofs } = await fresh();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const { buildRefTables, createRuntimeRefStore } = await load();
  const slow = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => { await gate; } });
  const pending = slow.bind({ ref: ref("generation", objectName), value: "1700000000000001", provenance: producer(seedRow) });
  assert.throws(() => slow.resolve(ref("generation", objectName), deleteRow.id), /reference is not bound/);
  release();
  await pending;
  assert.equal(slow.resolve(ref("generation", objectName), deleteRow.id), "1700000000000001");
  await store.bind({ ref: ref("generation", objectName), value: "1700000000000002", provenance: producer(seedRow) });
  assert.equal(proofs.length, 1);
  const digest = createHash("sha256").update([salt, "generation", objectName, "1700000000000002"].join("\0")).digest("hex");
  assert.deepEqual(Object.keys(proofs[0]).sort(), ["attempt", "key", "operationId", "runId", "type", "valueSha256"]);
  assert.equal(proofs[0].valueSha256, digest);
  assert.equal(JSON.stringify(proofs).includes("1700000000000002"), false);
});

test("a proof writer that rejects leaves the store uncertain for every later call", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  let fail = true;
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => { if (fail) throw new Error("disk full"); } });
  await assert.rejects(store.bind({ ref: ref("generation", objectName), value: "1700000000000001", provenance: producer(seedRow) }), /disk full/);
  fail = false;
  await assert.rejects(store.bind({ ref: ref("generation", objectName), value: "1700000000000003", provenance: producer(seedRow, "accepted", 2) }), /runtime reference store is uncertain/);
  assert.throws(() => store.resolve(ref("generation", objectName), deleteRow.id), /runtime reference store is uncertain/);
  assert.equal(store.state().uncertain, true);
});

test("a bind is refused for an undeclared reference, a foreign producer or a wrong verdict", async () => {
  const { store } = await fresh();
  const good = { ref: ref("generation", objectName), value: "1700000000000001", provenance: producer(seedRow) };
  for (const bad of [
    { ...good, ref: ref("generation", `${objectName}x`) }, { ...good, ref: ref("update-time", objectName) }, { ...good, ref: ref("password", "user-a") },
    { ...good, provenance: producer(manifest.rows.find((r) => r.id === "management/control-1/seed")) },
    { ...good, provenance: producer(manifest.rows.find((r) => r.stage === "subject")) },
    { ...good, provenance: producer(seedRow, "observed") }, { ...good, provenance: producer(seedRow, "unexpected") }, { ...good, provenance: producer(metadataRow, "accepted") },
    { ...good, provenance: { ...producer(seedRow), attempt: 0 } }, { ...good, provenance: { ...producer(seedRow), attempt: 1.5 } }, { ...good, provenance: { ...producer(seedRow), extra: 1 } },
    { ...good, ref: ref("ruleset-path", "v1") },
  ]) await assert.rejects(store.bind(bad), /invalid runtime reference bind/);
  assert.equal(store.state().bound.length, 0);
  await store.bind({ ref: ref("generation", objectName), value: "1700000000000001", provenance: producer(metadataRow, "present") });
});

test("values outside each kind's grammar are refused", async () => {
  const { store } = await fresh();
  const cases = [
    ["generation", objectName, seedRow, ["0", "01", "1e3", "-1", "1\r\n", " 1", "1 ", "", "9".repeat(20), 7, null, undefined]],
    ["metageneration", patchRow.request.objectName, manifest.rows.find((r) => r.request.objectName === patchRow.request.objectName && r.request.operation === "upload" && r.request.credential === "admin"), ["0", "01", "1x", "1e3", "-1", "", "1\n"]],
    ["ruleset-name", "v1", manifest.rows.find((r) => r.id === "ruleset/v1/create"), ["projects/other/rulesets/abc", "projects/fireemu-oracle-query/rulesets/", "projects/fireemu-oracle-query/rulesets/a/b", "projects/fireemu-oracle-query/rulesets/a b", "/v1/projects/fireemu-oracle-query/rulesets/abc", "projects/fireemu-oracle-query/rulesets/abc?x=1", `projects/fireemu-oracle-query/rulesets/${"a".repeat(129)}`]],
    ["page-token", "normal/final/1", manifest.rows.find((r) => r.id === "rulesets-list/final/1"), ["", "a b", "a\r\nb", "x".repeat(2049), "tok%2Fen", "tok&x=1"]],
  ];
  for (const [type, key, row, values] of cases) {
    for (const value of values) await assert.rejects(store.bind({ ref: ref(type, key), value, provenance: producer(row) }), /invalid runtime reference bind/, `${type} ${String(value).slice(0, 20)}`);
  }
  const update = manifest.rows.find((r) => r.id === "recovery/document-0/current");
  const key = manifest.rows.find((r) => r.id === "recovery/document-0/delete").request.query["currentDocument.updateTime"].key;
  for (const value of ["2026-09-29", "2026-09-29T10:00:00", "2026-09-29T10:00:00+09:00", "2026-13-29T10:00:00Z", "2026-09-29T10:00:00.1234567890Z", "x", "2026-02-30T10:00:00Z", "2026-04-31T10:00:00Z", "2026-02-29T10:00:00Z", "2026-00-10T10:00:00Z", "2026-09-29T24:00:00Z", "2026-09-29T10:00:60Z", "2026-09-29T10:60:00Z", "2026-09-29t10:00:00z", " 2026-09-29T10:00:00Z", "2026-09-29T10:00:00Z\n"]) {
    await assert.rejects(store.bind({ ref: ref("update-time", key), value, provenance: producer(update) }), /invalid runtime reference bind/, value);
  }
  await store.bind({ ref: ref("update-time", key), value: "2028-02-29T23:59:59.123456789Z", provenance: producer(update) });
  await store.bind({ ref: ref("update-time", key), value: "2026-09-29T10:00:00Z", provenance: producer(update, "accepted", 2) });
});

test("a reference is resolved only by a declared consumer, and a page token only once", async () => {
  const { store } = await fresh();
  const first = manifest.rows.find((r) => r.id === "rulesets-list/final/1");
  await assert.rejects(store.bind({ ref: ref("page-token", "normal/final/1"), value: "next-page-1", provenance: producer(seedRow) }), /invalid runtime reference bind/);
  await store.bind({ ref: ref("page-token", "normal/final/1"), value: "next-page-1", provenance: producer(first) });
  assert.throws(() => store.resolve(ref("page-token", "normal/final/1"), "rulesets-list/final/3"), /invalid runtime reference resolve/);
  assert.throws(() => store.resolve(ref("page-token", "normal/final/1"), "rulesets-list/final/1"), /invalid runtime reference resolve/);
  assert.equal(store.resolve(ref("page-token", "normal/final/1"), "rulesets-list/final/2"), "next-page-1");
  assert.throws(() => store.resolve(ref("page-token", "normal/final/1"), "rulesets-list/final/2"), /reference already used/);
});

test("a ruleset name binds once and derives its path", async () => {
  const { store } = await fresh();
  const create = manifest.rows.find((r) => r.id === "ruleset/v1/create");
  const path = manifest.rows.find((r) => r.id === "ruleset/v1/read-source").request.pathReference;
  assert.throws(() => store.resolve(path, "ruleset/v1/read-source"), /reference is not bound/);
  await store.bind({ ref: ref("ruleset-name", "v1"), value: "projects/fireemu-oracle-query/rulesets/0000-abc", provenance: producer(create) });
  assert.equal(store.resolve(path, "ruleset/v1/read-source"), "/v1/projects/fireemu-oracle-query/rulesets/0000-abc");
  assert.equal(store.resolve(ref("ruleset-name", "v1"), "release/v1/publish"), "projects/fireemu-oracle-query/rulesets/0000-abc");
  assert.throws(() => store.resolve(path, "ruleset/v2/read-source"), /invalid runtime reference resolve/);
  await assert.rejects(store.bind({ ref: ref("ruleset-name", "v1"), value: "projects/fireemu-oracle-query/rulesets/0000-def", provenance: producer(create, "accepted", 2) }), /invalid runtime reference bind/);
});

test("a later accepted readback supersedes a generation, an earlier attempt cannot, and a non-deletable one cannot feed a delete", async () => {
  const { store } = await fresh();
  const r = ref("generation", objectName);
  await store.bind({ ref: r, value: "1700000000000001", provenance: producer(seedRow, "accepted", 1, true) });
  await store.bind({ ref: r, value: "1700000000000005", provenance: producer(metadataRow, "present", 3, true) });
  assert.equal(store.resolve(r, deleteRow.id), "1700000000000005");
  for (const attempt of [3, 2]) await assert.rejects(store.bind({ ref: r, value: "1700000000000009", provenance: producer(metadataRow, "present", attempt, true) }), /invalid runtime reference bind/);
  assert.equal(store.resolve(r, deleteRow.id), "1700000000000005");
  await store.bind({ ref: r, value: "1700000000000006", provenance: producer(metadataRow, "present", 4, false) });
  assert.throws(() => store.resolve(r, deleteRow.id), /reference is not deletable/);
  const meta = patchRow.request.query.ifMetagenerationMatch;
  const patchSeed = manifest.rows.find((row) => row.request.objectName === patchRow.request.objectName && row.request.operation === "upload" && row.request.credential === "admin");
  await store.bind({ ref: meta, value: "1", provenance: producer(patchSeed, "accepted", 1, false) });
  assert.equal(store.resolve(meta, patchRow.id), "1");
});

test("bind and resolve refuse malformed references, and the store options are a closed record", async () => {
  const { store } = await fresh();
  const value = "1700000000000001";
  for (const badRef of [null, {}, { ...ref("generation", objectName), extra: 1 }, { ...ref("generation", objectName), kind: "other" }, { ...ref("generation", objectName), resolveOnlyAfterDurableProof: false }, { ...ref("generation", objectName), key: "" }, { ...ref("generation", objectName), key: 7 }, { ...ref("generation", objectName), key: "x".repeat(1025) }]) {
    await assert.rejects(store.bind({ ref: badRef, value, provenance: producer(seedRow) }), /invalid runtime reference bind/);
    assert.throws(() => store.resolve(badRef, deleteRow.id), /invalid runtime reference resolve/);
  }
  const accessor = Object.defineProperty({ ...ref("generation", objectName) }, "type", { enumerable: true, get() { return "generation"; } });
  await assert.rejects(store.bind({ ref: accessor, value, provenance: producer(seedRow) }), /invalid runtime reference bind/);
  const { buildRefTables, createRuntimeRefStore } = await load();
  const base = { tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => {} };
  for (const bad of [{ ...base, extra: 1 }, { ...base, digestSalt: "short" }, { ...base, digestSalt: "Z".repeat(64) }, { ...base, runId: "" }, { ...base, writeProof: 7 }, { ...base, tables: {} }, null]) {
    assert.throws(() => createRuntimeRefStore(bad), /invalid runtime reference store options/);
  }
});

test("a bind is refused while another proof write is in flight", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => { await gate; } });
  const first = store.bind({ ref: ref("generation", objectName), value: "1700000000000001", provenance: producer(seedRow) });
  const meta = patchRow.request.query.ifMetagenerationMatch;
  const patchSeed = manifest.rows.find((row) => row.request.objectName === patchRow.request.objectName && row.request.operation === "upload" && row.request.credential === "admin");
  await assert.rejects(store.bind({ ref: meta, value: "1", provenance: producer(patchSeed) }), /runtime reference store is busy/);
  release();
  await first;
  await store.bind({ ref: meta, value: "1", provenance: producer(patchSeed) });
});

const nativeConsumers = () => manifest.rows.flatMap((row) => {
  const found = [];
  walk(row.request, (v) => { if (["firestore-update-time", "gcs-object-generation"].includes(v.kind)) found.push({ row, ref: v }); });
  return found;
});
const producerOf = (row, step) => manifest.rows.find((r) => r.programId === row.programId && r.request.id === step) ?? assert.fail(`no producer ${step}`);

test("the corpus's own Firestore-program references are declared, each pinned to the step that must produce it", async () => {
  const { buildRefTables } = await load();
  const tables = buildRefTables(manifest);
  const native = nativeConsumers();
  assert.ok(native.length >= 19);
  for (const { row, ref: r } of native) {
    const type = r.kind === "firestore-update-time" ? "update-time" : "generation";
    const key = r.kind === "firestore-update-time" ? r.documentName : r.objectName;
    assert.ok(tables.consumers[type][key].includes(row.id), row.id);
    const producer = producerOf(row, r.fromStep);
    assert.equal(tables.pinned[`${type}|${key}|${row.id}`], producer.id, row.id);
    assert.ok(tables.producers[type][key].some((p) => p.operationId === producer.id), row.id);
  }
});

test("a pinned consumer sees the value its step produced, even after a later readback", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => {} });
  const { row, ref: r } = nativeConsumers().find(({ ref }) => ref.kind === "firestore-update-time" && ref.fromStep === "doc-read-false");
  const key = r.documentName;
  const pinned = producerOf(row, "doc-read-false");
  const other = nativeConsumers().map((c) => producerOf(c.row, c.ref.fromStep)).find((p) => p.id !== pinned.id && p.request.documentName === key);
  assert.ok(other, "another readback of the same document exists");
  const recoveryDelete = manifest.rows.find((x) => x.family === "recovery-document" && x.stage === "delete" && x.request.query["currentDocument.updateTime"].key === key);
  assert.throws(() => store.resolve(r, row.id), /reference is not bound/);
  await store.bind({ ref: ref("update-time", key), value: "2026-09-29T10:00:00Z", provenance: producer(pinned, "accepted", 1) });
  assert.equal(store.resolve(r, row.id), "2026-09-29T10:00:00Z");
  await store.bind({ ref: ref("update-time", key), value: "2026-09-29T10:05:00Z", provenance: producer(other, "accepted", 2) });
  assert.equal(store.resolve(r, row.id), "2026-09-29T10:00:00Z");
  assert.equal(store.resolve(recoveryDelete.request.query["currentDocument.updateTime"], recoveryDelete.id), "2026-09-29T10:05:00Z");
});

test("a pinned generation resolves for its own cleanup delete only from its own metadata readback", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  const tables = buildRefTables(manifest);
  const store = createRuntimeRefStore({ tables, runId: options.runId, digestSalt: salt, writeProof: async () => {} });
  const { row, ref: r } = nativeConsumers().find(({ ref }) => ref.kind === "gcs-object-generation");
  const pinned = producerOf(row, r.fromStep);
  assert.throws(() => store.resolve(r, row.id), /reference is not bound/);
  const others = tables.producers.generation[r.objectName].filter((p) => p.operationId !== pinned.id);
  if (others.length) {
    const otherRow = manifest.rows.find((x) => x.id === others[0].operationId);
    await store.bind({ ref: ref("generation", r.objectName), value: "1700000000000009", provenance: producer(otherRow, others[0].verdict, 1, true) });
    assert.throws(() => store.resolve(r, row.id), /reference is not bound/);
  }
  await store.bind({ ref: ref("generation", r.objectName), value: "1700000000000010", provenance: producer(pinned, "present", 2, true) });
  assert.equal(store.resolve(r, row.id), "1700000000000010");
});

test("a native reference with an unknown shape is refused on resolve", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => {} });
  const { row, ref: r } = nativeConsumers().find(({ ref }) => ref.kind === "firestore-update-time");
  for (const bad of [{ ...r, field: "generation" }, { ...r, documentName: `${r.documentName}x` }, { ...r, kind: "other" }, { ...r, fromStep: "doc-somewhere-else" }, { ...r, fromStep: 7 }]) {
    assert.throws(() => store.resolve(bad, row.id), /invalid runtime reference resolve/);
  }
});

const SESSION_URL = (objectName, id = "CANARYUPLOADID0123456789") => `https://firebasestorage.googleapis.com/v0/b/${binding.bucket}/o?name=${encodeURIComponent(objectName)}&upload_id=${id}&upload_protocol=resumable`;
const sessionConsumers = () => manifest.rows.filter((r) => r.request.sessionUrlReference);
const tokenConsumer = () => manifest.rows.find((r) => r.request.query?.token?.kind === "firebase-download-token");

test("session URLs and download tokens are declared, pinned to the step that produces them, and used by many rows", async () => {
  const { buildRefTables } = await load();
  const tables = buildRefTables(manifest);
  const consumers = sessionConsumers();
  assert.equal(consumers.length, 8 + 8 + 8 + 8 + 8 + 8);
  for (const row of consumers) {
    const key = row.request.sessionUrlReference.expectedObjectName;
    assert.ok(tables.consumers["session-url"][key].includes(row.id), row.id);
    const start = manifest.rows.find((r) => r.programId === row.programId && r.request.id === "start");
    assert.equal(tables.pinned[`session-url|${key}|${row.id}`], start.id);
    assert.deepEqual(tables.producers["session-url"][key], [{ operationId: start.id, verdict: "accepted" }]);
  }
  const token = tokenConsumer();
  const create = manifest.rows.find((r) => r.programId === token.programId && r.request.id === "create-token");
  assert.equal(tables.pinned[`download-token|${token.request.query.token.objectName}|${token.id}`], create.id);
  assert.deepEqual(tables.producers["download-token"][token.request.query.token.objectName], [{ operationId: create.id, verdict: "accepted" }]);
});

test("a session URL binds once per session, resolves for every consumer and never appears in a proof", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  const proofs = [];
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async (proof) => { proofs.push(proof); } });
  const cleanup = manifest.rows.find((r) => r.family === "declared" && r.stage === "cleanup" && r.request.sessionUrlReference);
  const key = cleanup.request.sessionUrlReference.expectedObjectName;
  const start = manifest.rows.find((r) => r.programId === cleanup.programId && r.request.id === "start");
  const url = SESSION_URL(key);
  assert.throws(() => store.resolve(cleanup.request.sessionUrlReference, cleanup.id), /reference is not bound/);
  await store.bind({ ref: ref("session-url", key), value: url, provenance: producer(start, "accepted", 1, false) });
  const consumers = sessionConsumers().filter((r) => r.request.sessionUrlReference.expectedObjectName === key);
  assert.ok(consumers.length >= 3);
  for (const consumer of consumers) assert.equal(store.resolve(consumer.request.sessionUrlReference, consumer.id), url);
  assert.equal(JSON.stringify(proofs).includes("CANARYUPLOADID"), false);
  assert.equal(JSON.stringify(store.state()).includes("CANARYUPLOADID"), false);
  assert.equal(proofs.length, 1);
  await assert.rejects(store.bind({ ref: ref("session-url", key), value: SESSION_URL(key, "OTHERUPLOADID987654321"), provenance: producer(start, "accepted", 2, false) }), /invalid runtime reference bind/);
  const other = sessionConsumers().find((r) => r.request.sessionUrlReference.expectedObjectName !== key);
  assert.throws(() => store.resolve(cleanup.request.sessionUrlReference, other.id), /invalid runtime reference resolve/);
});

test("session URL and token values outside their grammar or from another producer are refused", async () => {
  const { buildRefTables, createRuntimeRefStore } = await load();
  const store = createRuntimeRefStore({ tables: buildRefTables(manifest), runId: options.runId, digestSalt: salt, writeProof: async () => {} });
  const cleanup = manifest.rows.find((r) => r.family === "declared" && r.stage === "cleanup" && r.request.sessionUrlReference);
  const key = cleanup.request.sessionUrlReference.expectedObjectName;
  const start = manifest.rows.find((r) => r.programId === cleanup.programId && r.request.id === "start");
  for (const value of ["", "not a url", "http://firebasestorage.googleapis.com/v0/b/b/o?upload_id=x", `${SESSION_URL(key)}#f`, `${SESSION_URL(key)}\r\nX: y`, `${SESSION_URL(key)} `, "https://evil.example/v0/b/b/o?upload_id=abcdefgh", "x".repeat(4100), 7]) {
    await assert.rejects(store.bind({ ref: ref("session-url", key), value, provenance: producer(start, "accepted", 1, false) }), /invalid runtime reference bind/);
  }
  await assert.rejects(store.bind({ ref: ref("session-url", key), value: SESSION_URL(key), provenance: producer(manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.programId !== cleanup.programId), "accepted", 1, false) }), /invalid runtime reference bind/);
  const token = tokenConsumer();
  const tokenKey = token.request.query.token.objectName;
  const create = manifest.rows.find((r) => r.programId === token.programId && r.request.id === "create-token");
  for (const value of ["", "short", "has space 123456", "a".repeat(129), "tok\r\nen1234", "token,second-token", 7]) {
    await assert.rejects(store.bind({ ref: ref("download-token", tokenKey), value, provenance: producer(create, "accepted", 1, false) }), /invalid runtime reference bind/);
  }
  await store.bind({ ref: ref("download-token", tokenKey), value: "0a1b2c3d-1111-2222-3333-444455556666", provenance: producer(create, "accepted", 1, false) });
  assert.equal(store.resolve(token.request.query.token, token.id), "0a1b2c3d-1111-2222-3333-444455556666");
});
