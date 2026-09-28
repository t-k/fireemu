import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { CREDENTIAL_CACHE_REQUEST_IDS } from "./storage-rules/credential-cache.mjs";
import { buildDeclaredRequestManifest } from "./storage-rules/manifest.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const build = (changedOptions = options, corpus = buildCorpus(binding)) => buildFullRequestManifest(corpus, closure, changedOptions);

test("full draft has one finite ID per attempt and stays inside both fixed caps", () => {
  const m = build();
  assert.equal(m.status, "LOCAL_FULL_DRAFT_NO_SEND");
  assert.equal(m.sendAuthorized, false);
  assert.equal(m.controllerReady, false);
  assert.deepEqual(m.counts, { normal: 4630, recovery: 1534, preflight: 19, total: 6164 });
  assert.deepEqual(m.limits, { normal: 4648, recovery: 2000, total: 6648 });
  assert.equal(m.rows.length, 6164);
  assert.equal(new Set(m.rows.map((r) => r.id)).size, 6164);
  assert.ok(m.rows.every((r) => /^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/.test(r.id) && r.request.capture.body === "raw-bytes"));
  assert.equal(m.preflightIds.length, 19);
  assert.match(m.corpusSha256, /^[a-f0-9]{64}$/);
  assert.match(m.closureSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(m.preflightIds, m.rows.filter((r) => r.phase === "preflight").map((r) => r.id));
  assert.equal(build().sha256, m.sha256);
  const { sha256, ...body } = m;
  assert.equal(createHash("sha256").update(JSON.stringify(body)).digest("hex"), sha256);
});
test("all declared preflight IDs can complete the existing counted admission seam", async () => {
  const m = build(); const reservations = [];
  const counter = createStage3RequestCounter({ preflightIds: m.preflightIds, onStarted: async () => {}, onReserve: async (r) => reservations.push(r), onTerminal: async () => {} });
  await counter.start({ runId: options.runId });
  for (const id of m.preflightIds) await counter.sendPreflight(id, async () => ({ verified: true }), (r) => r.verified === true);
  counter.admit();
  assert.equal(counter.snapshot().mode, "normal");
  assert.equal(reservations.length, 19);
  assert.ok(reservations.every((r) => r.phase === "preflight"));
});

test("source inventory bounds every owned object, document and session", () => {
  const m = build();
  assert.equal(m.resources.objects.length, 344);
  assert.equal(new Set(m.resources.objects).size, 344);
  assert.equal(m.resources.documents.length, 9);
  assert.equal(m.resources.sessions.length, 8);
  assert.equal(m.resources.controls.length, 6);
  assert.ok(m.resources.objects.every((name) => name.startsWith(binding.prefix)));
  assert.equal(m.rows.filter((r) => r.family === "compile").length, 341);
  assert.equal(m.rows.filter((r) => r.family === "declared").length, 3799);
  assert.equal(m.rows.filter((r) => r.family === "management").length, 87);
  assert.equal(m.rows.filter((r) => r.family === "release" && r.phase !== "recovery").length, 22);
});

test("declared subjects keep their canonical HTTP inputs and finite IDs", () => {
  const corpus = buildCorpus(binding);
  const old = buildDeclaredRequestManifest(corpus, closure);
  const m = build(options, corpus);
  for (const row of old.rows.filter((r) => ["subject", "comparison"].includes(r.stage))) {
    const full = m.rows.find((r) => r.id === row.id);
    assert.deepEqual(full.request, row.request);
    assert.equal(full.service, row.service);
  }
  assert.equal(m.rows.filter((r) => r.family === "declared" && r.stage === "subject").length, 331);
  for (const row of old.rows.filter((r) => r.family === "firestore-program")) {
    const full = m.rows.find((r) => r.id === row.id);
    assert.equal(full.when, row.when);
    assert.equal(full.requiredState, row.requiredState);
  }
});

test("owned setup and cleanup use generation and metadata version references", () => {
  const m = build();
  const owner = m.rows.filter((r) => r.family === "declared" && !["subject", "comparison"].includes(r.stage) && r.request.service !== "firestore" && r.request.credential === "admin");
  const seeds = owner.filter((r) => r.request.operation === "upload");
  assert.ok(seeds.length > 0);
  assert.ok(seeds.every((r) => r.request.query.ifGenerationMatch === "0" && r.requires.includes("owned-namespace-and-absence")));
  for (const r of owner.filter((r) => ["delete", "patch"].includes(r.request.operation))) {
    assert.ok(r.request.query.ifGenerationMatch);
    if (r.request.query.ifGenerationMatch.kind === "runtime-reference") assert.equal(r.request.query.ifGenerationMatch.type, "generation");
    assert.ok(r.requires.includes("confirmed-write-history-and-current-version"));
    if (r.request.operation === "patch") assert.ok(r.request.query.ifMetagenerationMatch);
    if (r.request.operation === "delete") assert.ok(r.requires.includes("delete-not-attempted"));
  }
  const recovery = m.rows.filter((r) => r.family === "recovery-object" && r.stage === "delete");
  assert.equal(recovery.length, 344);
  assert.ok(recovery.every((r) => r.request.query.ifGenerationMatch.kind === "runtime-reference" && r.requires.includes("delete-not-attempted")));
  assert.equal(m.rows.filter((r) => r.family === "recovery-document" && r.stage === "delete").length, 9);
});

test("every publication and restoration uses finite cycle IDs and four retained witnesses", () => {
  const m = build();
  const settle = m.rows.filter((r) => r.family === "settle");
  assert.equal(settle.length, 360);
  assert.equal(settle.filter((r) => r.phase === "normal" && r.programId !== "restore").length, 240);
  for (const phase of ["normal", "recovery"]) {
    const restore = settle.filter((r) => r.phase === phase && r.programId === "restore");
    assert.equal(restore.length, 60);
    assert.equal(new Set(restore.map((r) => r.request.objectName)).size, 4);
    assert.deepEqual(new Set(restore.map((r) => r.request.objectName)), new Set(m.resources.controls.filter((_, index) => [0, 1, 3, 4].includes(index))));
    assert.ok(restore.every((r) => r.requires.includes("all-four-controls-confirmed-and-retained")));
    assert.equal(m.rows.filter((r) => r.phase === phase && r.stage === "restore-owner-media").length, 4);
  }
  assert.deepEqual(m.restoration, { intervalMs: 20000, maxCycles: 15, consecutiveCompleteCycles: 2, witnessCount: 4, retainUntil: "restore-owner-readbacks-complete", missingProof: "needs-recovery" });
});

test("support rows use concrete fixed preflight routes without listing or key creation", () => {
  const m = build();
  const rows = m.rows.filter((r) => r.family === "preflight");
  assert.equal(rows.length, 14);
  assert.ok(rows.every((r) => r.phase === "preflight" && ["GET", "POST"].includes(r.request.method)));
  const identity = rows.find((r) => r.id === "preflight/owner/identity");
  assert.equal(identity.request.origin, "https://www.googleapis.com");
  assert.equal(identity.request.path, "/oauth2/v2/userinfo");
  assert.equal(identity.request.body, null);
  assert.equal(rows.filter((r) => r.request.origin === "https://apikeys.googleapis.com").length, 4);
  assert.ok(rows.filter((r) => r.request.origin === "https://apikeys.googleapis.com").every((r) => r.request.method === "GET" && r.request.path.includes("/locations/global/keys/")));
  assert.equal(rows.find((r) => r.id === "preflight/bucket/permissions").request.path, `/storage/v1/b/${binding.bucket}/iam/testPermissions`);
  assert.ok(m.pending.includes("offline-adc-quota-billing-and-approved-input-provenance"));
  assert.ok(m.rows.find((r) => r.phase === "preflight" && r.family === "rulesets-list").requires.includes("entry-page-has-no-next-token"));
  assert.ok(m.rows.filter((r) => r.family === "rulesets-list").every((r) => r.request.query.pageSize === "100"));
});

test("session recovery declares only proven start URL references and three finite commands", () => {
  const m = build();
  const rows = m.rows.filter((r) => r.family === "recovery-session");
  assert.equal(rows.length, 24);
  for (const session of m.resources.sessions) {
    const steps = rows.filter((r) => r.programId === session.caseId);
    assert.deepEqual(steps.map((r) => r.request.headers["x-goog-upload-command"]), ["query", "cancel", "query"]);
    assert.ok(steps.every((r) => r.request.method === "POST" && r.request.origin === "https://firebasestorage.googleapis.com" && r.request.path === null && r.request.body === null && r.request.sessionUrlReference.resolveOnlyAfterVerifiedStart));
    assert.equal(steps[0].request.sessionUrlReference.startRequestId, `case/${session.caseId}/setup/start`);
    assert.ok(steps[1].requires.includes("confirmed-active-session") && steps[1].requires.includes("cancel-not-attempted"));
  }
  assert.deepEqual(m.sessionPolicy.queryStatus, ["active", "final"]);
  assert.equal(m.sessionPolicy.unknownTerminalShape, "needs-recovery");
  assert.equal(m.sessionPolicy.maxReceivedBytes, 4);
  assert.deepEqual(m.sessionPolicy.requiredQueryKeys, ["name", "upload_id", "upload_protocol"]);
  assert.equal(m.sessionPolicy.cancelResponseAloneProvesTerminal, false);
  const normal = m.rows.filter((r) => r.family === "declared" && r.request.sessionUrlReference);
  assert.equal(normal.length, 16);
  assert.ok(normal.every((r) => r.requires.includes("durable-verified-start-url-and-target") && r.sessionStartRequestId === `case/${r.programId}/setup/start`));
  assert.ok(normal.filter((r) => r.stage === "cleanup").every((r) => r.requires.includes("confirmed-active-session") && r.requires.includes("cancel-not-attempted")));
});
test("every additional preflight is pinned to the expected project, route and HTTP method", () => {
  const m = build();
  const rows = m.rows.filter((r) => r.family === "preflight");
  const expected = {
    "owner/identity": ["https://www.googleapis.com", "/oauth2/v2/userinfo", "GET"],
    "bucket/metadata": ["https://storage.googleapis.com", `/storage/v1/b/${binding.bucket}`, "GET"],
    "bucket/iam": ["https://storage.googleapis.com", `/storage/v1/b/${binding.bucket}/iam`, "GET"],
    "bucket/permissions": ["https://storage.googleapis.com", `/storage/v1/b/${binding.bucket}/iam/testPermissions`, "GET"],
    "query/database": ["https://firestore.googleapis.com", "/v1/projects/fireemu-oracle-query/databases/(default)", "GET"],
    "query/iam": ["https://cloudresourcemanager.googleapis.com", `/v3/projects/${options.queryProjectNumber}:getIamPolicy`, "POST"],
  };
  for (const [key, number, keyId] of [["query", options.queryProjectNumber, options.queryApiKeyId], ["idp", options.idpProjectNumber, options.idpApiKeyId]]) {
    expected[`${key}/project`] = ["https://cloudresourcemanager.googleapis.com", `/v3/projects/${number}`, "GET"];
    expected[`${key}/permissions`] = ["https://cloudresourcemanager.googleapis.com", `/v3/projects/${number}:testIamPermissions`, "POST"];
    expected[`${key}/key-metadata`] = ["https://apikeys.googleapis.com", `/v2/projects/${number}/locations/global/keys/${keyId}`, "GET"];
    expected[`${key}/key-string`] = ["https://apikeys.googleapis.com", `/v2/projects/${number}/locations/global/keys/${keyId}/keyString`, "GET"];
  }
  assert.equal(Object.keys(expected).length, rows.length);
  for (const row of rows) assert.deepEqual([row.request.origin, row.request.path, row.request.method], expected[row.programId]);
  assert.equal(rows.find((r) => r.programId === "bucket/iam").request.query.optionsRequestedPolicyVersion, "3");
  assert.equal(rows.find((r) => r.programId === "query/iam").request.body.json.options.requestedPolicyVersion, 3);
  assert.ok(rows.filter((r) => r.programId.endsWith("/permissions")).every((r) => (r.request.body?.json.permissions ?? r.request.query.permissions).length > 0));
});
test("Ruleset sources and release PATCH schemas remain exact and typed", () => {
  const m = build();
  for (const source of m.sources) {
    const create = m.rows.find((r) => r.id === `ruleset/${source.id}/create`);
    assert.equal(create.request.method, "POST");
    assert.equal(createHash("sha256").update(create.request.body.json.source.files[0].content).digest("hex"), source.sha256);
    const publish = m.rows.find((r) => r.id === `release/${source.id}/publish`);
    if (source.id === "v1") assert.equal(publish.request.method, "POST");
    else {
      assert.equal(publish.request.method, "PATCH");
      assert.equal(publish.request.body.json.updateMask, "rulesetName");
      assert.equal(publish.request.body.json.release.rulesetName.type, "ruleset-name");
      assert.equal(publish.request.body.json.release.rulesetName.key, source.id);
    }
    assert.ok(publish.requires.includes("all-four-controls-confirmed-and-retained"));
  }
  assert.ok(m.rows.filter((r) => r.family === "recovery-document" && r.stage === "delete").every((r) => r.request.query["currentDocument.updateTime"].type === "update-time" && r.requires.includes("delete-not-attempted")));
});

test("Auth and credential cache IDs agree with the existing finite send seams", () => {
  const m = build();
  for (const id of CREDENTIAL_CACHE_REQUEST_IDS) assert.equal(m.rows.filter((r) => r.id === id).length, 1);
  const auth = m.rows.filter((r) => r.family === "auth");
  assert.equal(auth.filter((r) => r.phase === "normal").length, 29);
  assert.equal(auth.filter((r) => r.phase === "recovery").length, 8);
  assert.equal(auth.filter((r) => r.phase === "normal" && r.request.project === "fireemu-oracle-idp").length, 5);
  assert.equal(m.rows.find((r) => r.id === "auth/user-a/create").request.body.json.password.kind, "runtime-reference");
  assert.equal(m.rows.find((r) => r.id === "auth/foreign-project-token/delete").request.body.json.localId.kind, "runtime-reference");
});

test("input snapshots and output hashes do not alias caller-owned data", () => {
  const c = buildCorpus(binding); const o = { ...options }; const m = build(o, c);
  const original = JSON.stringify(m);
  c.cases[0].subject.path = "/changed"; o.queryApiKeyId = "changed";
  assert.equal(JSON.stringify(m), original);
});
test("every newly declared runtime reference requires durable proof and a finite type", () => {
  const m = build(); const refs = [];
  const visit = (value) => {
    if (value === null || typeof value !== "object") return;
    if (value.kind === "runtime-reference") refs.push(value);
    for (const child of Object.values(value)) visit(child);
  };
  visit(m);
  assert.ok(refs.length > 400);
  const types = new Set(["generation", "metageneration", "update-time", "ruleset-name", "ruleset-path", "page-token", "password", "foreign-uid", "id-token", "valid-since", "oauth-refresh-body"]);
  assert.ok(refs.every((r) => types.has(r.type) && r.resolveOnlyAfterDurableProof === true && typeof r.key === "string"));
});
test("corpus principals must match the same run's credential-session UIDs", () => {
  for (const field of ["uidA", "uidB"]) assert.throws(() => build(options, buildCorpus({ ...binding, [field]: "different-local-user" })), /invalid full manifest input/);
});

for (const [field, value] of Object.entries({ runId: "other-run", sourceCommit: "bad", queryProjectNumber: "../other", idpProjectNumber: options.queryProjectNumber, queryApiKeyId: "key/escape", idpApiKeyId: "key?secret=value" })) {
  test(`rejects an invalid or mismatched private binding: ${field}`, () => assert.throws(() => build({ ...options, [field]: value }), /invalid full manifest input/));
}
test("rejects extra configuration, arbitrary endpoint injection and changed corpus", () => {
  assert.throws(() => build({ ...options, endpoint: "https://attacker.invalid" }), /invalid full manifest input/);
  const c = buildCorpus(binding); c.cases[0].subject.path = "/storage/v1/b/foreign/o";
  assert.throws(() => build(options, c), /invalid full manifest input/);
});
for (const field of Object.keys(options)) {
  test(`rejects line breaks in the exact binding: ${field}`, () => {
    assert.throws(() => build({ ...options, [field]: options[field] + "\n" }), /invalid full manifest input/);
    assert.throws(() => build({ ...options, [field]: options[field] + "\r" }), /invalid full manifest input/);
  });
}
test("rejects accessors, symbols, sparse arrays and cyclic data without calling a getter", () => {
  let calls = 0;
  const o = { ...options }; Object.defineProperty(o, "queryApiKeyId", { enumerable: true, get() { calls++; throw new Error("secret"); } });
  assert.throws(() => build(o), /invalid full manifest input/); assert.equal(calls, 0);
  const c = buildCorpus(binding); Object.defineProperty(c.cases[0].subject, "path", { enumerable: true, get() { calls++; return "/secret"; } });
  assert.throws(() => build(options, c), /invalid full manifest input/); assert.equal(calls, 0);
  const symbolic = { ...options, [Symbol("secret")]: "hidden" }; assert.throws(() => build(symbolic), /invalid full manifest input/);
  const sparse = buildCorpus(binding); delete sparse.cases[0]; assert.throws(() => build(options, sparse), /invalid full manifest input/);
  const cyclic = buildCorpus(binding); cyclic.extra = cyclic; assert.throws(() => build(options, cyclic), /invalid full manifest input/);
});
