import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { classifyResponse } from "./storage-rules/acceptance.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { parsePrivateInputs } from "./storage-rules/private-inputs.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "111111111111", idpProjectNumber: "222222222222", queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const bucketBindings = [{ role: "roles/storage.admin", members: ["user:owner@example.test"] }];
const projectBindings = [{ role: "roles/owner", members: ["user:owner@example.test"] }];
const canonicalSha = (bindings) => sha(JSON.stringify(bindings.map((entry) => ({ role: entry.role, members: [...entry.members].sort() })).sort((a, b) => (a.role < b.role ? -1 : a.role > b.role ? 1 : 0))));

const packet = () => ({
  schemaVersion: 1, adcPath: "/private/adc.json", owner: { emailSha256: sha("owner@example.test"), subjectSha256: sha("owner-subject") },
  projects: {
    query: { projectId: "fireemu-oracle-query", projectNumber: "111111111111", apiKeyId: options.queryApiKeyId, apiKey: "Q".repeat(39), keyUid: "query-key-uid", apiTargets: ["identitytoolkit.googleapis.com"] },
    idp: { projectId: "fireemu-oracle-idp", projectNumber: "222222222222", apiKeyId: options.idpApiKeyId, apiKey: "I".repeat(39), keyUid: "idp-key-uid", apiTargets: ["identitytoolkit.googleapis.com"] },
  },
  bucket: { name: "synthetic-rules-bucket", location: "US-CENTRAL1", uniformBucketLevelAccess: true, iamPolicySha256: canonicalSha(bucketBindings) },
  database: { locationId: "us-central1", type: "FIRESTORE_NATIVE" }, queryProjectIamPolicySha256: canonicalSha(projectBindings),
});
const raw = (body, status = 200) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify(body)) });

// The answer production gives when every fact matches the packet, per preflight row that carries an expectation.
const good = {
  "preflight/owner/identity": () => ({ id: "owner-subject", email: "owner@example.test", verified_email: true }),
  "preflight/query/project": () => ({ name: "projects/111111111111", projectId: "fireemu-oracle-query", state: "ACTIVE" }),
  "preflight/idp/project": () => ({ name: "projects/222222222222", projectId: "fireemu-oracle-idp", state: "ACTIVE" }),
  "preflight/query/key-metadata": () => ({ name: `projects/111111111111/locations/global/keys/${options.queryApiKeyId}`, uid: "query-key-uid", restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }] } }),
  "preflight/idp/key-metadata": () => ({ name: `projects/222222222222/locations/global/keys/${options.idpApiKeyId}`, uid: "idp-key-uid", restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }] } }),
  "preflight/query/key-string": () => ({ keyString: "Q".repeat(39) }),
  "preflight/idp/key-string": () => ({ keyString: "I".repeat(39) }),
  "preflight/query/permissions": (r) => ({ permissions: r.request.body.json.permissions }),
  "preflight/idp/permissions": (r) => ({ permissions: r.request.body.json.permissions }),
  "preflight/bucket/permissions": (r) => ({ kind: "storage#testIamPermissionsResponse", permissions: r.request.query.permissions }),
  "preflight/bucket/metadata": () => ({ kind: "storage#bucket", name: "synthetic-rules-bucket", projectNumber: "111111111111", location: "US-CENTRAL1", iamConfiguration: { uniformBucketLevelAccess: { enabled: true } } }),
  "preflight/bucket/iam": () => ({ kind: "storage#policy", bindings: bucketBindings, version: 1 }),
  "preflight/query/database": () => ({ name: "projects/fireemu-oracle-query/databases/(default)", locationId: "us-central1", type: "FIRESTORE_NATIVE" }),
  "preflight/query/iam": () => ({ bindings: projectBindings, version: 3 }),
};
const ids = Object.keys(good);
const load = async () => {
  const module = await import("./storage-rules/preflight-judge.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createPreflightJudge, "function");
  return module;
};
const judgeWith = async (edit = () => {}) => { const value = packet(); edit(value); return (await load()).createPreflightJudge({ inputs: parsePrivateInputs(value) }); };
const seen = (id, bodyEdit = (body) => body) => classifyResponse(row(id), raw(bodyEdit(good[id](row(id)))));

test("every fact matching the private packet is accepted, for each of the fourteen probes", async () => {
  const judge = await judgeWith();
  for (const id of ids) assert.equal(judge(row(id), seen(id)), true, id);
});

test("the two entry reads and the Rulesets list entry are judged by their own verdicts, not by the packet", async () => {
  const judge = await judgeWith();
  const list = classifyResponse(row("preflight/rulesets-list/entry/1"), raw({}));
  assert.equal(judge(row("preflight/rulesets-list/entry/1"), list), true);
  const absent = classifyResponse(row("preflight/release/entry/bucket"), raw({ error: { code: 404, message: "not found", status: "NOT_FOUND" } }, 404));
  assert.equal(judge(row("preflight/release/entry/bucket"), absent), true);
  assert.equal(judge(row("preflight/release/entry/bucketless"), classifyResponse(row("preflight/release/entry/bucketless"), raw({ error: { code: 404, message: "not found", status: "NOT_FOUND" } }, 404))), true);
  const broken = classifyResponse(row("preflight/rulesets-list/entry/1"), raw("nope"));
  assert.equal(judge(row("preflight/rulesets-list/entry/1"), broken), false);
});

const perturb = {
  "preflight/owner/identity": [(b) => ({ ...b, email: "someone@example.test" }), (b) => ({ ...b, id: "other-subject" }), (b) => ({ ...b, verified_email: false })],
  "preflight/query/project": [(b) => ({ ...b, projectId: "fireemu-oracle-idp" }), (b) => ({ ...b, state: "DELETE_REQUESTED" }), (b) => ({ ...b, deleteTime: "2026-01-01T00:00:00Z" })],
  "preflight/idp/project": [(b) => ({ ...b, projectId: "fireemu-oracle-query" }), (b) => ({ ...b, state: "ACTIVE_WITH_ISSUES" }), (b) => ({ ...b, deleteTime: "x" })],
  "preflight/query/key-metadata": [(b) => ({ ...b, uid: "another-uid" }), (b) => ({ ...b, deleteTime: "x" }), (b) => ({ ...b, restrictions: { apiTargets: [{ service: "storage.googleapis.com" }] } }), (b) => ({ ...b, restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }, { service: "storage.googleapis.com" }] } }), (b) => ({ ...b, restrictions: {} }), (b) => ({ ...b, restrictions: { apiTargets: b.restrictions.apiTargets, browserKeyRestrictions: { allowedReferrers: ["*"] } } }), (b) => ({ ...b, restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com", methods: ["x"] }] } })],
  "preflight/idp/key-metadata": [(b) => ({ ...b, uid: "query-key-uid" }), (b) => ({ ...b, deleteTime: "x" }), (b) => ({ ...b, restrictions: { apiTargets: [] } })],
  "preflight/query/key-string": [(b) => ({ keyString: "Q".repeat(38) }), (b) => ({ keyString: "I".repeat(39) }), (b) => ({ keyString: `${"Q".repeat(39)}x` })],
  "preflight/idp/key-string": [(b) => ({ keyString: "Q".repeat(39) }), (b) => ({ keyString: "I".repeat(38) })],
  "preflight/query/permissions": [(b) => ({ permissions: b.permissions.slice(1) }), () => ({})],
  "preflight/idp/permissions": [(b) => ({ permissions: b.permissions.slice(1) }), () => ({})],
  "preflight/bucket/permissions": [(b) => ({ ...b, permissions: b.permissions.slice(1) }), (b) => ({ kind: b.kind })],
  "preflight/bucket/metadata": [(b) => ({ ...b, projectNumber: "222222222222" }), (b) => ({ ...b, location: "EU" }), (b) => ({ ...b, iamConfiguration: { uniformBucketLevelAccess: { enabled: false } } }), (b) => ({ ...b, iamConfiguration: {} })],
  "preflight/bucket/iam": [(b) => ({ ...b, bindings: [...b.bindings, { role: "roles/storage.objectViewer", members: ["allUsers"] }] }), (b) => ({ ...b, bindings: [{ role: "roles/storage.admin", members: ["user:other@example.test"] }] }), (b) => ({ ...b, bindings: [] })],
  "preflight/query/database": [(b) => ({ ...b, locationId: "europe-west1" }), (b) => ({ ...b, type: "DATASTORE_MODE" })],
  "preflight/query/iam": [(b) => ({ ...b, bindings: [...b.bindings, { role: "roles/editor", members: ["user:x@example.test"] }] }), (b) => ({ ...b, bindings: [] })],
};

test("a single fact that differs from the private packet refuses the probe", async () => {
  const judge = await judgeWith();
  for (const [id, edits] of Object.entries(perturb)) {
    edits.forEach((edit, index) => {
      const outcome = classifyResponse(row(id), raw(edit(good[id](row(id)))));
      assert.equal(judge(row(id), outcome), false, `${id} #${index}`);
    });
  }
  assert.deepEqual(Object.keys(perturb).sort(), [...ids].sort());
});

test("the packet's facts, not the manifest's, decide: a packet with other expectations refuses the same answers", async () => {
  const edits = {
    "preflight/owner/identity": (v) => { v.owner.emailSha256 = sha("x"); },
    "preflight/query/project": (v) => { v.projects.query.projectNumber = "333333333333"; },
    "preflight/idp/project": (v) => { v.projects.idp.projectNumber = "333333333333"; },
    "preflight/query/key-metadata": (v) => { v.projects.query.keyUid = "other"; },
    "preflight/idp/key-metadata": (v) => { v.projects.idp.apiTargets = ["a.googleapis.com"]; },
    "preflight/query/key-string": (v) => { v.projects.query.apiKey = "Z".repeat(39); },
    "preflight/idp/key-string": (v) => { v.projects.idp.apiKey = "Z".repeat(39); },
    "preflight/bucket/metadata": (v) => { v.bucket.location = "ASIA"; },
    "preflight/bucket/iam": (v) => { v.bucket.iamPolicySha256 = sha("x"); },
    "preflight/query/database": (v) => { v.database.type = "OTHER"; },
    "preflight/query/iam": (v) => { v.queryProjectIamPolicySha256 = sha("x"); },
  };
  for (const [id, edit] of Object.entries(edits)) assert.equal((await judgeWith(edit))(row(id), seen(id)), false, id);
  // An unknown uniform-access expectation accepts either state; a known one requires it.
  const unknown = await judgeWith((v) => { v.bucket.uniformBucketLevelAccess = null; });
  assert.equal(unknown(row("preflight/bucket/metadata"), seen("preflight/bucket/metadata", (b) => ({ ...b, iamConfiguration: {} }))), true);
  assert.equal(unknown(row("preflight/bucket/metadata"), seen("preflight/bucket/metadata", (b) => ({ ...b, iamConfiguration: { uniformBucketLevelAccess: { enabled: false } } }))), true);
});

test("the judge refuses rows it does not know, malformed answers and outcomes that carry no secret facts where it needs them", async () => {
  const judge = await judgeWith();
  const identity = seen("preflight/owner/identity");
  assert.equal(judge(row("preflight/auth/owner-token"), identity), false);
  assert.equal(judge(row("management/control-0/seed"), identity), false);
  assert.equal(judge(row("preflight/owner/identity"), null), false);
  assert.equal(judge(row("preflight/owner/identity"), undefined), false);
  assert.equal(judge(row("preflight/owner/identity"), { kind: "preflight-identity", verdict: "accepted", facts: { status: 200, verifiedEmail: true } }), false);
  assert.equal(judge(row("preflight/owner/identity"), { ...identity, kind: "preflight-project" }), false);
  assert.equal(judge(row("preflight/query/project"), identity), false);
  const unexpected = classifyResponse(row("preflight/query/project"), raw({ error: "x" }, 500));
  assert.equal(judge(row("preflight/query/project"), unexpected), false);
});

test("the judge's options are a closed record around parsed inputs", async () => {
  const { createPreflightJudge } = await load();
  for (const bad of [undefined, null, {}, { inputs: null }, { inputs: {} }, { inputs: packet() }, { inputs: parsePrivateInputs(packet()), extra: 1 }]) assert.throws(() => createPreflightJudge(bad), /invalid preflight judge options/);
  assert.equal(typeof createPreflightJudge({ inputs: parsePrivateInputs(packet()) }), "function");
});
