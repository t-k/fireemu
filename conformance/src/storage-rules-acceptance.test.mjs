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
const load = async () => {
  const module = await import("./storage-rules/acceptance.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.acceptanceKindOf, "function");
  assert.equal(typeof module.classifyResponse, "function");
  return module;
};
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const response = (status, body = "", headers = {}) => {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  const raw = Object.entries(headers).flatMap(([name, value]) => (Array.isArray(value) ? value : [value]).flatMap((one) => [name, one]));
  return { status, rawHeaders: raw, bytes };
};
const json = (status, body, extra = {}) => response(status, body, { "Content-Type": "application/json; charset=UTF-8", ...extra });
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(`missing row ${id}`);
const object = (name, extra = {}) => ({ kind: "storage#object", bucket: binding.bucket, name, size: "4", generation: "1700000000000001", metageneration: "1", ...extra });
const gcsNotFound = (name) => json(404, { error: { code: 404, message: `No such object: ${binding.bucket}/${name}`, errors: [{ message: `No such object: ${binding.bucket}/${name}`, domain: "global", reason: "notFound" }] } });
const denial = json(403, { error: { code: 403, message: "Permission denied. Could not perform this operation" } });

const seedRow = row("management/control-0/seed");
const seedName = seedRow.request.objectName;
const seedBytes = Buffer.from(seedRow.request.body.base64, "base64");

test("every one of the 6,172 rows maps to exactly one closed acceptance kind", async () => {
  const { acceptanceKindOf, ACCEPTANCE_KINDS } = await load();
  assert.equal(Object.isFrozen(ACCEPTANCE_KINDS), true);
  const used = new Map();
  for (const r of manifest.rows) {
    const kind = acceptanceKindOf(r);
    assert.ok(Object.hasOwn(ACCEPTANCE_KINDS, kind), `${r.id}: ${kind}`);
    used.set(kind, (used.get(kind) ?? 0) + 1);
  }
  assert.deepEqual([...used.keys()].sort(), Object.keys(ACCEPTANCE_KINDS).sort());
  assert.equal([...used.values()].reduce((a, b) => a + b, 0), 6172);
});

test("a row of an unknown family, stage, method or service has no kind", async () => {
  const { acceptanceKindOf } = await load();
  const base = row("management/control-0/seed");
  for (const delta of [{ family: "unknown" }, { service: "unknown" }, { stage: "unknown", family: "management" }, { request: { ...base.request, method: "PUT" } }, { request: { ...base.request, operation: "unknown" } }]) {
    assert.throws(() => acceptanceKindOf({ ...base, ...delta }), /invalid acceptance kind/);
  }
  assert.throws(() => acceptanceKindOf(null), /invalid acceptance kind/);
});

const settleRow = row("settle/v1/1/0");
const allowedBytes = Buffer.from("allow");
test("a settle read is allowed only for the exact witness bytes and denied only for the closed Firebase 403", async () => {
  const { classifyResponse } = await load();
  const ctx = { expectedSha256: sha(allowedBytes) };
  const verdict = (r) => classifyResponse(settleRow, r, ctx).verdict;
  assert.equal(verdict(response(200, allowedBytes)), "allowed");
  assert.equal(verdict(denial), "denied");
  for (const other of [
    response(200, Buffer.from("other")), response(200, ""), response(401, "{}"), response(404, "{}"), response(302, ""), response(500, ""),
    json(403, { error: { code: 403, message: "Billing account for project is disabled" } }), json(403, { error: { code: 401, message: "Permission denied." } }),
    response(403, JSON.stringify({ error: { code: 403, message: "Permission denied. x" } }), { "Content-Type": "text/html" }),
    response(403, Buffer.from([0xff, 0xfe, 0xfd]), { "Content-Type": "application/json" }),
    response(403, `${JSON.stringify({ error: { code: 403, message: "Permission denied. x" } })} trailing`, { "Content-Type": "application/json" }),
    { ...denial, rawHeaders: [...denial.rawHeaders, "content-type", "text/plain"] },
    response(206, allowedBytes), response(404, allowedBytes), response(401, allowedBytes),
    json(200, { error: { code: 403, message: "Permission denied. Could not perform this operation" } }), json(500, { error: { code: 403, message: "Permission denied. Could not perform this operation" } }),
    response(403, Buffer.concat([Buffer.from('{"error":{"code":403,"message":"Permission denied. '), Buffer.from([0xff]), Buffer.from('"}}')]), { "Content-Type": "application/json" }),
    response(403, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify({ error: { code: 403, message: "Permission denied. x" } }))]), { "Content-Type": "application/json" }),
  ]) assert.equal(verdict(other), "other");
  assert.equal(classifyResponse(settleRow, denial, ctx).facts.status, 403);
});

test("a settle read needs an expected digest in a closed context", async () => {
  const { classifyResponse } = await load();
  for (const ctx of [undefined, {}, { expectedSha256: "x" }, { expectedSha256: sha(allowedBytes), extra: 1 }]) {
    assert.throws(() => classifyResponse(settleRow, response(200, allowedBytes), ctx), /invalid acceptance context/);
  }
});

test("a GCS seed is accepted only for the exact object with the declared size and metageneration 1", async () => {
  const { classifyResponse } = await load();
  const good = json(200, object(seedName, { size: String(seedBytes.length) }));
  const result = classifyResponse(seedRow, good);
  assert.equal(result.verdict, "accepted");
  assert.deepEqual({ ...result.facts }, { status: 200, generation: "1700000000000001", metageneration: "1", size: String(seedBytes.length) });
  for (const bad of [
    json(412, { error: { code: 412, message: "Precondition Failed" } }), json(201, object(seedName, { size: "4" })), json(206, object(seedName, { size: "4" })),
    json(200, object(seedName, { size: "5" })), json(200, object(`${seedName}x`, { size: "4" })), json(200, object(seedName, { bucket: "other", size: "4" })),
    json(200, object(seedName, { size: "4", metageneration: "2" })), json(200, object(seedName, { size: "4", generation: "01" })), json(200, object(seedName, { size: "4", generation: "0" })),
    json(200, object(seedName, { size: "4", generation: "1e3" })), json(200, object(seedName, { size: "4", kind: "storage#objects" })),
    response(200, `${JSON.stringify(object(seedName, { size: "4" }))}x`, { "Content-Type": "application/json" }), response(200, "", {}), response(500, ""),
  ]) assert.equal(classifyResponse(seedRow, bad).verdict, "unexpected");
});

test("subject and comparison rows are observed whatever the complete response is, and never carry state facts", async () => {
  const { classifyResponse } = await load();
  const subjects = manifest.rows.filter((r) => ["subject", "comparison"].includes(r.stage));
  assert.ok(subjects.length > 100);
  for (const r of [subjects[0], subjects.at(-1), row("management/A/control-3/subject")]) {
    for (const res of [response(200, "x"), response(403, "{}"), response(500, ""), json(200, object(seedName))]) {
      const result = classifyResponse(r, res);
      assert.equal(result.verdict, "observed");
      assert.deepEqual(Object.keys(result.facts).sort(), ["bodyBytes", "bodySha256", "status"]);
    }
  }
});

test("a conditional GCS delete is accepted only as an empty 204 and claims no absence", async () => {
  const { classifyResponse } = await load();
  const del = row("management/control-0/delete");
  const ok = classifyResponse(del, response(204, ""));
  assert.equal(ok.verdict, "accepted");
  assert.deepEqual({ ...ok.facts }, { status: 204, deleteAcknowledged: true });
  for (const bad of [response(204, "x"), response(200, ""), gcsNotFound("x"), json(412, {}), response(500, "")]) assert.equal(classifyResponse(del, bad).verdict, "unexpected");
});

test("GCS metadata reads are present with canonical facts, absent only for the closed 404, and unexpected otherwise", async () => {
  const { classifyResponse } = await load();
  const meta = row("management/control-0/baseline-metadata");
  const name = meta.request.objectName;
  const present = classifyResponse(meta, json(200, object(name)));
  assert.equal(present.verdict, "present");
  assert.deepEqual({ ...present.facts }, { status: 200, generation: "1700000000000001", metageneration: "1", size: "4", hasDownloadToken: false });
  assert.equal(classifyResponse(meta, gcsNotFound(name)).verdict, "absent");
  for (const bad of [
    json(404, { error: { code: 404, message: "Not Found" } }), json(404, { error: { code: 404, errors: [{ reason: "other" }] } }), response(404, "<html/>", { "Content-Type": "text/html" }),
    json(200, object("other/name")), json(200, object(name, { generation: "007" })), response(401, ""), response(403, "{}"), response(500, ""),
    json(200, (({ size, ...rest }) => rest)(object(name))), json(200, object(name, { size: "-1" })), json(201, object(name)),
    json(400, { error: { code: 404, message: "x", errors: [{ reason: "notFound" }] } }), json(404, { error: { code: 400, message: "x", errors: [{ reason: "notFound" }] } }),
  ]) assert.equal(classifyResponse(meta, bad).verdict, "unexpected");
});

test("GCS media reads carry a digest, the 404 absence and nothing else", async () => {
  const { classifyResponse } = await load();
  const media = row("management/control-0/baseline-media");
  const present = classifyResponse(media, response(200, seedBytes, { "Content-Type": "text/plain", "x-goog-generation": "1700000000000001" }));
  assert.equal(present.verdict, "present");
  assert.deepEqual({ ...present.facts }, { status: 200, bodyBytes: seedBytes.length, bodySha256: sha(seedBytes), generation: "1700000000000001" });
  assert.equal(classifyResponse(media, response(200, seedBytes)).facts.generation, undefined);
  assert.equal(classifyResponse(media, gcsNotFound(media.request.objectName)).verdict, "absent");
  for (const bad of [response(200, seedBytes, { "x-goog-generation": "0" }), response(200, seedBytes, { "x-goog-generation": ["1", "2"] }), response(404, ""), response(403, "{}"), response(500, "")]) {
    assert.equal(classifyResponse(media, bad).verdict, "unexpected");
  }
});

test("a canary in a download token never reaches a fact", async () => {
  const { classifyResponse } = await load();
  const meta = row("management/control-0/baseline-metadata");
  const canary = "CANARY-DOWNLOAD-TOKEN-0123456789";
  const result = classifyResponse(meta, json(200, object(meta.request.objectName, { metadata: { firebaseStorageDownloadTokens: canary }, mediaLink: `https://x/?token=${canary}` })));
  assert.equal(result.verdict, "present");
  assert.equal(result.facts.hasDownloadToken, true);
  assert.equal(JSON.stringify(result).includes(canary), false);
  assert.equal(JSON.stringify(Object.getOwnPropertyNames(result)).includes(canary), false);
  const observed = classifyResponse(row("management/A/control-3/subject"), json(200, { downloadTokens: canary }));
  assert.equal(JSON.stringify(observed).includes(canary), false);
});

test("a malformed response object is refused with a fixed message", async () => {
  const { classifyResponse } = await load();
  const r = row("management/control-0/delete");
  const good = response(204, "");
  const accessor = Object.defineProperty({ ...good }, "status", { enumerable: true, get() { return 204; } });
  for (const bad of [null, {}, { ...good, status: "204" }, { ...good, status: 99 }, { ...good, status: 600 }, { ...good, rawHeaders: ["a"] }, { ...good, rawHeaders: [1, 2] }, { ...good, bytes: "x" }, { ...good, bytes: null }, { ...good, bytes: undefined }, { ...good, bytes: new Uint8Array(0) }, { ...good, extra: 1 }, accessor]) {
    assert.throws(() => classifyResponse(r, bad), /invalid acceptance response/);
  }
});

test("a duplicated content-type or a foreign charset is not silently accepted", async () => {
  const { classifyResponse } = await load();
  const meta = row("management/control-0/baseline-metadata");
  const name = meta.request.objectName;
  const twice = { ...json(200, object(name)), rawHeaders: ["Content-Type", "application/json", "content-type", "application/json"] };
  assert.equal(classifyResponse(meta, twice).verdict, "unexpected");
  assert.equal(classifyResponse(meta, response(200, object(name), { "Content-Type": "application/json; charset=ISO-8859-1" })).verdict, "unexpected");
  assert.equal(classifyResponse(meta, response(200, object(name), { "Content-Type": "application/json" })).verdict, "present");
});

test("kinds without a reviewed response schema fail closed and are listed", async () => {
  const module = await load();
  const listed = module.unimplementedKinds();
  assert.ok(Array.isArray(listed) && Object.isFrozen(listed));
  for (const kind of listed) assert.equal(module.ACCEPTANCE_KINDS[kind].implemented, false);
  for (const kind of Object.keys(module.ACCEPTANCE_KINDS)) assert.equal(listed.includes(kind), !module.ACCEPTANCE_KINDS[kind].implemented);
  for (const kind of listed) {
    const pending = manifest.rows.find((r) => module.acceptanceKindOf(r) === kind);
    assert.throws(() => module.classifyResponse(pending, json(200, {})), /acceptance kind not implemented/, kind);
  }
  for (const kind of ["subject-observed", "settle-read", "gcs-seed-upload", "gcs-delete", "gcs-metadata-read", "gcs-media-read"]) assert.equal(module.ACCEPTANCE_KINDS[kind].implemented, true);
});

test("kinds other than the settle read take no context", async () => {
  const { classifyResponse } = await load();
  const del = row("management/control-0/delete");
  for (const ctx of [{}, { expectedSha256: "a".repeat(64) }, null, 0]) assert.throws(() => classifyResponse(del, response(204, ""), ctx), /invalid acceptance context/);
  assert.equal(classifyResponse(del, response(204, "")).verdict, "accepted");
});
