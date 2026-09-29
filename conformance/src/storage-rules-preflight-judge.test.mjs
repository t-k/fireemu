import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { classifyResponse } from "./storage-rules/acceptance.mjs";
import { restrictionsSha256 } from "./storage-rules/acceptance-preflight.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { parsePrivateInputs } from "./storage-rules/private-inputs.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "111111111111", idpProjectNumber: "222222222222", queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
// The two shapes production has: a dedicated key with two services, and a Browser key with empty browser restrictions and many services.
const QUERY_SERVICES = ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"];
const IDP_SERVICES = ["identitytoolkit.googleapis.com", "securetoken.googleapis.com", ...Array.from({ length: 25 }, (_, index) => `service${String(index).padStart(2, "0")}.googleapis.com`)];
const queryRestrictions = () => ({ apiTargets: QUERY_SERVICES.map((service) => ({ service })) });
const idpRestrictions = () => ({ browserKeyRestrictions: { allowedReferrers: [] }, apiTargets: IDP_SERVICES.map((service) => ({ service })) });
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const bucketBindings = [{ role: "roles/storage.admin", members: ["user:owner@example.test"] }];
const projectBindings = [{ role: "roles/owner", members: ["user:owner@example.test"] }];
const canonicalSha = (bindings) => sha(JSON.stringify(bindings.map((entry) => ({ role: entry.role, members: [...entry.members].sort() })).sort((a, b) => (a.role < b.role ? -1 : a.role > b.role ? 1 : 0))));

const packet = () => ({
  schemaVersion: 1, adcPath: "/private/adc.json", owner: { emailSha256: sha("owner@example.test"), subjectSha256: sha("owner-subject") },
  projects: {
    query: { projectId: "fireemu-oracle-query", projectNumber: "111111111111", apiKeyId: options.queryApiKeyId, apiKey: "Q".repeat(39), keyUid: "query-key-uid", apiTargets: [...QUERY_SERVICES].sort(), restrictionsSha256: restrictionsSha256(queryRestrictions()) },
    idp: { projectId: "fireemu-oracle-idp", projectNumber: "222222222222", apiKeyId: options.idpApiKeyId, apiKey: "I".repeat(39), keyUid: "idp-key-uid", apiTargets: [...IDP_SERVICES].sort(), restrictionsSha256: restrictionsSha256(idpRestrictions()) },
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
  "preflight/query/key-metadata": () => ({ name: `projects/111111111111/locations/global/keys/${options.queryApiKeyId}`, uid: "query-key-uid", restrictions: queryRestrictions() }),
  "preflight/idp/key-metadata": () => ({ name: `projects/222222222222/locations/global/keys/${options.idpApiKeyId}`, uid: "idp-key-uid", restrictions: idpRestrictions() }),
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
  "preflight/query/key-metadata": [(b) => ({ ...b, uid: "another-uid" }), (b) => ({ ...b, deleteTime: "x" }), (b) => ({ ...b, restrictions: { apiTargets: [{ service: "storage.googleapis.com" }] } }), (b) => ({ ...b, restrictions: { apiTargets: [...b.restrictions.apiTargets, { service: "storage.googleapis.com" }] } }), (b) => ({ ...b, restrictions: {} }), (b) => ({ ...b, restrictions: { apiTargets: b.restrictions.apiTargets, browserKeyRestrictions: { allowedReferrers: ["*"] } } }), (b) => ({ ...b, restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com", methods: ["x"] }, { service: "securetoken.googleapis.com" }] } }), (b) => ({ ...b, restrictions: { apiTargets: b.restrictions.apiTargets, androidKeyRestrictions: { allowedApplications: [] } } })],
  "preflight/idp/key-metadata": [(b) => ({ ...b, uid: "query-key-uid" }), (b) => ({ ...b, deleteTime: "x" }), (b) => ({ ...b, restrictions: { apiTargets: [] } }), (b) => ({ ...b, restrictions: { ...b.restrictions, browserKeyRestrictions: { allowedReferrers: ["*"] } } }), (b) => ({ ...b, restrictions: { apiTargets: b.restrictions.apiTargets } }), (b) => ({ ...b, restrictions: { ...b.restrictions, apiTargets: b.restrictions.apiTargets.slice(1) } }), (b) => ({ ...b, restrictions: { ...b.restrictions, apiTargets: [...b.restrictions.apiTargets, { service: "zz.googleapis.com" }] } }), (b) => ({ ...b, restrictions: { ...b.restrictions, iosKeyRestrictions: { allowedBundleIds: [] } } })],
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
    "preflight/idp/key-metadata": (v) => { v.projects.idp.apiTargets = [...v.projects.idp.apiTargets, "zz.googleapis.com"]; },
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

// The genuine outcome of every probe the judge knows, including the three entry reads judged by their verdicts.
const absentRelease = (id) => classifyResponse(row(id), raw({ error: { code: 404, message: "not found", status: "NOT_FOUND" } }, 404));
const genuine = () => ({
  ...Object.fromEntries(ids.map((id) => [id, seen(id)])),
  "preflight/rulesets-list/entry/1": classifyResponse(row("preflight/rulesets-list/entry/1"), raw({})),
  "preflight/release/entry/bucket": absentRelease("preflight/release/entry/bucket"),
  "preflight/release/entry/bucketless": absentRelease("preflight/release/entry/bucketless"),
});
// A copy of an outcome with some fields replaced that keeps the non-enumerable secret facts a plain spread would drop.
const reshape = (outcome, changes) => Object.defineProperty({ ...outcome, ...changes }, "secretFacts", { value: Object.hasOwn(changes, "secretFacts") ? changes.secretFacts : outcome.secretFacts, enumerable: false });

test("an outcome of another kind carrying the very same facts and secrets is refused, for every probe", async () => {
  const judge = await judgeWith();
  const outcomes = genuine();
  const kinds = [...new Set([...Object.values(outcomes).map((outcome) => outcome.kind), "rules-release-create", "rules-test"])];
  for (const [id, outcome] of Object.entries(outcomes)) {
    assert.equal(judge(row(id), reshape(outcome, {})), true, `${id} as read`);
    for (const kind of kinds.filter((kind) => kind !== outcome.kind)) assert.equal(judge(row(id), reshape(outcome, { kind })), false, `${id} as ${kind}`);
  }
});

test("an outcome read for one probe is refused when handed to another probe whose expected facts happen to match", async () => {
  // The project and bucket policies canonicalise to the same digest here, so only the kind tells the two reads apart.
  const judge = await judgeWith((v) => { v.bucket.iamPolicySha256 = v.queryProjectIamPolicySha256; });
  assert.equal(judge(row("preflight/query/iam"), seen("preflight/query/iam")), true);
  assert.equal(judge(row("preflight/bucket/iam"), seen("preflight/query/iam")), false);
  assert.equal(judge(row("preflight/query/iam"), seen("preflight/bucket/iam", (b) => ({ ...b, bindings: projectBindings }))), false);
  // Every permission granted on the bucket says nothing about the projects, and the reverse.
  const bucketGrants = seen("preflight/bucket/permissions");
  const queryGrants = seen("preflight/query/permissions");
  assert.deepEqual([bucketGrants.facts.missing, queryGrants.facts.missing], [[], []]);
  assert.equal(judge(row("preflight/query/permissions"), bucketGrants), false);
  assert.equal(judge(row("preflight/idp/permissions"), bucketGrants), false);
  assert.equal(judge(row("preflight/bucket/permissions"), queryGrants), false);
  // The Rulesets list and the release reads are well formed only as themselves.
  const outcomes = genuine();
  assert.equal(judge(row("preflight/rulesets-list/entry/1"), outcomes["preflight/release/entry/bucket"]), false);
  assert.equal(judge(row("preflight/release/entry/bucket"), outcomes["preflight/rulesets-list/entry/1"]), false);
  assert.equal(judge(row("preflight/release/entry/bucketless"), outcomes["preflight/rulesets-list/entry/1"]), false);
});

test("a row that carries a known id but asks another target is refused even with the genuine outcome", async () => {
  const judge = await judgeWith();
  const moved = (id, path) => ({ ...row(id), request: { ...row(id).request, path } });
  const swaps = [["preflight/query/project", "preflight/idp/project"], ["preflight/query/key-metadata", "preflight/idp/key-metadata"], ["preflight/query/key-string", "preflight/idp/key-string"]];
  for (const [left, right] of swaps) {
    assert.equal(judge(moved(left, row(right).request.path), seen(left)), false, left);
    assert.equal(judge(moved(right, row(left).request.path), seen(right)), false, right);
  }
  assert.equal(judge(moved("preflight/bucket/metadata", "/storage/v1/b/another-rules-bucket"), seen("preflight/bucket/metadata")), false);
  for (const id of ["preflight/query/project", "preflight/query/key-metadata", "preflight/query/key-string", "preflight/bucket/metadata"]) assert.equal(judge(moved(id, row(id).request.path), seen(id)), true, id);
});

test("a release read that production answered unexpectedly is not a well-formed entry", async () => {
  const judge = await judgeWith();
  for (const id of ["preflight/release/entry/bucket", "preflight/release/entry/bucketless"]) {
    const failed = classifyResponse(row(id), raw({ error: "x" }, 500));
    assert.equal(failed.verdict, "unexpected");
    assert.equal(judge(row(id), failed), false, id);
  }
});

test("facts the classifier never produces are still refused: inconsistent permission counts and bytes where strings belong", async () => {
  const value = packet();
  const judge = await judgeWith();
  const accepted = (id, facts) => ({ kind: seen(id).kind, verdict: "accepted", facts: { ...seen(id).facts, ...facts } });
  for (const id of ["preflight/query/permissions", "preflight/idp/permissions", "preflight/bucket/permissions"]) {
    assert.equal(judge(row(id), accepted(id, { requested: 2, granted: 2, missing: [] })), true, id);
    assert.equal(judge(row(id), accepted(id, { requested: 2, granted: 2, missing: ["storage.buckets.get"] })), false, `${id} missing`);
    assert.equal(judge(row(id), accepted(id, { requested: 2, granted: 1, missing: [] })), false, `${id} counts`);
  }
  // A buffer or byte array spelling the expected digest is not the digest.
  const policy = parsePrivateInputs(value).bucket.iamPolicySha256;
  for (const policySha256 of [Buffer.from(policy), [...Buffer.from(policy)]]) assert.equal(judge(row("preflight/bucket/iam"), accepted("preflight/bucket/iam", { policySha256 })), false);
  const keyString = seen("preflight/query/key-string");
  assert.equal(judge(row("preflight/query/key-string"), reshape(keyString, { secretFacts: { keyString: Buffer.from(value.projects.query.apiKey) } })), false);
  const identity = seen("preflight/owner/identity");
  assert.equal(judge(row("preflight/owner/identity"), reshape(identity, { secretFacts: { email: Buffer.from("owner@example.test"), subject: Buffer.from("owner-subject") } })), false);
  assert.equal(judge(row("preflight/owner/identity"), reshape(identity, { secretFacts: { email: "owner@example.test", subject: Buffer.from("owner-subject") } })), false);
  // An array-like list that reads like the expected targets is not a list.
  const arrayLike = { length: 1, 0: "identitytoolkit.googleapis.com", every: Array.prototype.every };
  assert.equal(judge(row("preflight/query/key-metadata"), accepted("preflight/query/key-metadata", { apiTargets: arrayLike })), false);
  assert.equal(judge(row("preflight/query/key-metadata"), accepted("preflight/query/key-metadata", { apiTargets: [...QUERY_SERVICES].sort() })), true);
  assert.equal(judge(row("preflight/query/key-metadata"), accepted("preflight/query/key-metadata", { apiTargets: ["identitytoolkit.googleapis.com"] })), false);
  for (const value of [undefined, "", "0".repeat(64), 5, Buffer.from(restrictionsSha256(queryRestrictions()))]) assert.equal(judge(row("preflight/query/key-metadata"), accepted("preflight/query/key-metadata", { restrictionsSha256: value })), false, String(value));
  assert.equal(judge(row("preflight/query/key-metadata"), accepted("preflight/query/key-metadata", { otherRestrictions: ["anything"], restrictionsSha256: restrictionsSha256(queryRestrictions()) })), true);
});

test("the judge answers false, never another value, for inherited ids, callable outcomes and outcomes that throw", async () => {
  const judge = await judgeWith();
  const project = seen("preflight/query/project");
  // The judge table is an ordinary object: ids that name Object.prototype members must not reach them.
  for (const id of ["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"]) assert.equal(judge({ id, request: row("preflight/query/project").request }, project), false, id);
  assert.equal(judge(row("preflight/query/project"), Object.assign(() => {}, project)), false);
  assert.equal(judge(row("preflight/query/project"), { kind: project.kind, verdict: "accepted" }), false);
  assert.equal(judge(row("preflight/query/project"), { get kind() { throw new Error("boom"); } }), false);
  assert.equal(judge(null, project), false);
  assert.equal(judge(row("preflight/query/project"), project), true);
});

test("the judge's options must be a plain record around frozen inputs with string keys behind them", async () => {
  const { createPreflightJudge } = await load();
  const inputs = parsePrivateInputs(packet());
  const withSecrets = (target, secrets) => Object.defineProperty(target, "secrets", { value: secrets, enumerable: false });
  const bad = [
    new Proxy({ inputs }, {}),
    { inputs: withSecrets({ ...inputs }, inputs.secrets) },
    { inputs: Object.freeze({ ...inputs }) },
    { inputs: Object.freeze(withSecrets({ ...inputs }, { apiKeys: { query: 1, idp: inputs.secrets.apiKeys.idp } })) },
    { inputs: Object.freeze(withSecrets({ ...inputs }, { apiKeys: { query: inputs.secrets.apiKeys.query } })) },
  ];
  bad.forEach((options, index) => assert.throws(() => createPreflightJudge(options), /invalid preflight judge options/, `#${index}`));
  assert.equal(typeof createPreflightJudge({ inputs: Object.freeze(withSecrets({ ...inputs }, inputs.secrets)) }), "function");
});

test("the key facts are order independent, and a key's whole restriction shape is compared, not only its targets", async () => {
  const judge = (await load()).createPreflightJudge({ inputs: parsePrivateInputs(packet()) });
  const reordered = (id, restrictions) => classifyResponse(row(id), raw({ ...good[id](), restrictions }));
  // The same targets in another order, and the same object with its keys in another order, are the same key.
  const idp = idpRestrictions();
  assert.equal(judge(row("preflight/idp/key-metadata"), reordered("preflight/idp/key-metadata", { apiTargets: [...idp.apiTargets].reverse(), browserKeyRestrictions: { allowedReferrers: [] } })), true);
  assert.equal(judge(row("preflight/query/key-metadata"), reordered("preflight/query/key-metadata", { apiTargets: [...queryRestrictions().apiTargets].reverse() })), true);
  // A key that allows the same services but has any other restriction (or none) is another key.
  assert.equal(judge(row("preflight/idp/key-metadata"), reordered("preflight/idp/key-metadata", { apiTargets: idp.apiTargets })), false);
  assert.equal(judge(row("preflight/idp/key-metadata"), reordered("preflight/idp/key-metadata", { ...idp, browserKeyRestrictions: { allowedReferrers: ["https://example.test/"] } })), false);
  // A packet that records another restriction digest for the same targets refuses the very key it describes.
  const other = await judgeWith((v) => { v.projects.idp.restrictionsSha256 = "0".repeat(64); v.projects.query.restrictionsSha256 = "1".repeat(64); });
  assert.equal(other(row("preflight/idp/key-metadata"), classifyResponse(row("preflight/idp/key-metadata"), raw(good["preflight/idp/key-metadata"]()))), false);
  assert.equal(other(row("preflight/query/key-metadata"), classifyResponse(row("preflight/query/key-metadata"), raw(good["preflight/query/key-metadata"]()))), false);
});

test("a key with a method restriction is refused even when the packet recorded exactly that restriction", async () => {
  const methodsRestrictions = () => ({ apiTargets: QUERY_SERVICES.map((service) => ({ service, methods: ["*.Get"] })) });
  const judge = await judgeWith((v) => { v.projects.query.restrictionsSha256 = restrictionsSha256(methodsRestrictions()); });
  const outcome = classifyResponse(row("preflight/query/key-metadata"), raw({ ...good["preflight/query/key-metadata"](), restrictions: methodsRestrictions() }));
  assert.equal(outcome.facts.restrictionsSha256, restrictionsSha256(methodsRestrictions()));
  assert.equal(outcome.facts.methodRestricted, true);
  assert.equal(judge(row("preflight/query/key-metadata"), outcome), false);
});
