// Compare isolated and bundled Storage Rules decisions in a disposable local fireemu session.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { buildCorpus, validateCorpus } from "./corpus.mjs";
import { buildPublicationSources } from "./publication.mjs";

const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
const firestoreHost = process.env.FIRESTORE_EMULATOR_HOST;
const controlBase = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;
for (const host of [storageHost, firestoreHost]) {
  assert.match(host ?? "", /^(?:127\.0\.0\.1:\d+|\[::1\]:\d+)$/, "local emulator host required");
}
assert.ok(controlBase && controlToken, "local fireemu control required");
assert.ok(["127.0.0.1", "[::1]"].includes(new URL(controlBase).hostname), "local control required");

const binding = {
  bucket: "fireemu-oracle-query.firebasestorage.app",
  prefix: "STORAGE-RULES/local-equiv/",
  uidA: "local-user-a",
  uidB: "local-user-b",
};
const storageBase = `http://${storageHost}`;
const firestoreBase = `http://${firestoreHost}`;
const corpus = buildCorpus(binding);
const closure = JSON.parse(readFileSync(new URL("../../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
validateCorpus(corpus, closure);
const bundles = new Map(buildPublicationSources(corpus, binding).map((bundle) => [bundle.version, bundle]));
const only = process.env.STORAGE_RULES_LOCAL_ONLY ?? "";

function mockToken(uid, claims = {}, project = "fireemu-oracle-query") {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode({
    iss: `https://securetoken.google.com/${project}`,
    aud: project,
    iat: 0,
    exp: 3600,
    auth_time: 0,
    sub: uid,
    user_id: uid,
    firebase: { identities: {}, sign_in_provider: "custom" },
    ...claims,
  })}.`;
}
const credentials = {
  admin: "Bearer owner",
  "user-a": `Firebase ${mockToken(binding.uidA, { email_verified: true, role: "reader", level: 7 })}`,
  "user-b": `Firebase ${mockToken(binding.uidB, { email_verified: false, role: "writer", level: "7" })}`,
  "user-plain": `Firebase ${mockToken(binding.uidA, { email_verified: true })}`,
  "foreign-project-token": `Firebase ${mockToken("foreign-user", {}, "different-local-project")}`,
  "revoked-token": `Firebase ${mockToken("local-revoked-user")}`,
  "malformed-token": "Firebase invalid-local-token",
  "malformed-oauth": "Bearer invalid-local-oauth",
  anonymous: null,
};
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const localCaseControls = new Map([
  ["list-v1-read-get-media-present", { subject: 200 }],
  ["method-read-get-media-present", { subject: 200 }],
  ["denial-get-media-present", { subject: 403 }],
  ["method-read-list-present", { subject: 200 }],
  ["method-get-list-present", { subject: 403 }],
  ["method-create-upload-absent", { subject: 200 }],
  ["method-get-upload-absent", { subject: 403 }],
  ["method-write-patch-present", { subject: 200 }],
  ["method-read-patch-present", { subject: 403 }],
  ["method-write-delete-present", { subject: 204 }],
  ["method-read-delete-present", { subject: 403 }],
  ["principal-user-b-owner-b-get-media", { subject: 200 }],
  ["principal-user-b-owner-a-get-media", { subject: 403 }],
  ["claims-verified-user-plain-get-media", { subject: 200 }],
  ["token-valid", { subject: 200 }],
  ["token-missing", { subject: 403 }],
  ["boundary-gcs-admin-get-media-present", { subject: 200 }],
  ["incoming-upload-multipart-size-true", { subject: 200 }],
  ["incoming-upload-resumable-size-true", { subject: 200 }],
  ["download-token-deny", { subject: 403, comparison: 200 }],
]);
const localProgramControls = new Map([
  ["firestore-get-transition/subject-true", 200],
  ["firestore-get-transition/subject-false", 403],
  ["firestore-get-transition/subject-missing", 403],
  ["firestore-exists-transition/subject-present", 200],
  ["firestore-exists-transition/subject-missing", 403],
  ["firestore-budget-two/subject", 200],
  ["firestore-budget-three/subject", 403],
  ["firestore-budget-repeat/subject", 200],
]);
let activeSource = null;

async function fetchBounded(url, init) {
  const response = await fetch(url, { ...init, redirect: "manual" });
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.ok(bytes.length <= 128 * 1024, "local response exceeds bound");
  return { status: response.status, headers: Object.fromEntries(response.headers), bytes };
}
function json(response) {
  return JSON.parse(response.bytes.toString("utf8"));
}
function captured(captures, step) {
  const response = captures.get(step);
  assert.ok(response, `missing local capture: ${step}`);
  return response;
}
function resolveValue(value, captures) {
  if (typeof value === "string") return value;
  assert.ok(value && typeof value === "object", "invalid local query reference");
  if (value.kind === "firestore-update-time") {
    const body = json(captured(captures, value.fromStep));
    assert.equal(body.name, value.documentName);
    assert.match(body.updateTime, /^\d{4}-\d\d-\d\dT/);
    if (value.ownerWriteSteps) {
      const ownedTimes = value.ownerWriteSteps.map((step) => {
        const receipt = captured(captures, step);
        assert.ok(receipt.status >= 200 && receipt.status < 300, "owned document write did not succeed");
        const owned = json(receipt);
        assert.equal(owned.name, value.documentName);
        return owned.updateTime;
      });
      assert.ok(ownedTimes.includes(body.updateTime), "current document is not an owned write generation");
    }
    return body.updateTime;
  }
  if (value.kind === "gcs-object-generation") {
    const body = json(captured(captures, value.fromStep));
    assert.equal(body.name, value.objectName);
    assert.match(String(body.generation), /^\d+$/);
    const receipt = captured(captures, value.ownerReceiptStep);
    assert.ok(receipt.status >= 200 && receipt.status < 300, "owned object write did not succeed");
    const owned = json(receipt);
    assert.equal(owned.name, value.objectName);
    assert.equal(String(body.generation), String(owned.generation), "current object is not the owned generation");
    return String(body.generation);
  }
  if (value.kind === "firebase-download-token") {
    const before = json(captured(captures, value.priorStep));
    const created = json(captured(captures, value.fromStep));
    assert.equal(created.name, value.objectName);
    const oldTokens = new Set(String(before.metadata?.firebaseStorageDownloadTokens ?? "").split(",").filter(Boolean));
    const newTokens = String(created.downloadTokens ?? "").split(",").filter(Boolean).filter((token) => !oldTokens.has(token));
    assert.equal(newTokens.length, 1, "exactly one local download token must be new");
    return newTokens[0];
  }
  throw new Error(`unsupported local reference: ${value.kind}`);
}
function requestUrl(request, captures) {
  const base = request.service === "firestore" ? firestoreBase : storageBase;
  let url;
  if (request.sessionUrlReference) {
    const ref = request.sessionUrlReference;
    const start = captured(captures, ref.fromStep);
    assert.ok(start.status >= 200 && start.status < 300, "resumable start was refused");
    url = new URL(start.headers[ref.fromHeader]);
    assert.equal(url.origin, storageBase);
    assert.ok(url.pathname.startsWith(`/v0/b/${ref.expectedBucket}/o`));
    assert.equal(url.searchParams.get("name"), ref.expectedObjectName);
  } else {
    assert.ok(typeof request.path === "string" && request.path.startsWith("/"));
    url = new URL(request.path, base);
    assert.equal(url.origin, base);
  }
  for (const [key, value] of Object.entries(request.query)) url.searchParams.set(key, resolveValue(value, captures));
  return url;
}
async function sendRequest(request, captures) {
  assert.ok(Object.hasOwn(credentials, request.credential));
  if (request.id.startsWith("subject") || request.id === "comparison") await assertActiveSource();
  const headers = { ...request.headers };
  if (credentials[request.credential]) headers.authorization = credentials[request.credential];
  let body;
  if (request.body?.base64 !== undefined) body = Buffer.from(request.body.base64, "base64");
  if (request.body?.json !== undefined) {
    body = JSON.stringify(request.body.json);
    headers["content-type"] ??= "application/json";
  }
  const response = await fetchBounded(requestUrl(request, captures), { method: request.method, headers, body });
  captures.set(request.id, response);
  return response;
}
async function activate(source) {
  const response = await fetchBounded(new URL("/internal/setRules", storageBase), {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rules: { files: [{ name: "storage.rules", content: source }] } }),
  });
  assert.equal(response.status, 200, "local rules activation");
  const snapshot = await fetchBounded(new URL("storage/rules", controlBase), {
    headers: { authorization: `Bearer ${controlToken}` },
  });
  assert.equal(snapshot.status, 200);
  assert.equal(json(snapshot).source, source, "local rules readback");
  activeSource = source;
}
async function assertActiveSource() {
  assert.ok(activeSource, "no local rules source active");
  const snapshot = await fetchBounded(new URL("storage/rules", controlBase), {
    headers: { authorization: `Bearer ${controlToken}` },
  });
  assert.equal(snapshot.status, 200);
  assert.equal(json(snapshot).source, activeSource, "local source changed before subject");
}
function objectState(metadata, media) {
  if (metadata.status === 404) {
    assert.equal(media.status, 404);
    return { status: 404 };
  }
  assert.equal(metadata.status, 200);
  assert.equal(media.status, 200);
  const value = json(metadata);
  const custom = { ...value.metadata };
  if (custom.firebaseStorageDownloadTokens) custom.firebaseStorageDownloadTokens = "<present>";
  return {
    status: 200,
    name: value.name,
    size: String(value.size),
    contentType: value.contentType,
    metadata: custom,
    mediaSha256: digest(media.bytes),
  };
}
async function runCase(entry) {
  const captures = new Map();
  const baseline = await Promise.all(entry.baseline.map((request) => sendRequest(request, captures)));
  assert.deepEqual(baseline.map((response) => response.status), [404, 404], `local baseline ${entry.id}`);
  for (const request of entry.setup) {
    const response = await sendRequest(request, captures);
    assert.ok(response.status >= 200 && response.status < 300, `local setup ${entry.id}/${request.id}: ${response.status}`);
  }
  const before = [];
  for (const request of entry.before) before.push(await sendRequest(request, captures));
  const subject = await sendRequest(entry.subject, captures);
  const comparison = entry.comparison ? await sendRequest(entry.comparison, captures) : null;
  const after = [];
  for (const request of entry.after) after.push(await sendRequest(request, captures));
  const result = {
    before: objectState(...before),
    subject: subject.status,
    comparison: comparison?.status ?? null,
    after: objectState(...after),
  };
  const control = localCaseControls.get(entry.id);
  if (control) {
    assert.equal(result.subject, control.subject, `local positive/negative control ${entry.id}`);
    if (control.comparison !== undefined) assert.equal(result.comparison, control.comparison, `local comparison control ${entry.id}`);
  }
  for (const request of entry.cleanup) {
    if (request.when === "session-active-or-outcome-unknown" && subject.status >= 200 && subject.status < 300) continue;
    const response = await sendRequest(request, captures);
    if (request.id.startsWith("cleanup-absence")) assert.equal(response.status, 404, `local cleanup ${entry.id}`);
  }
  return result;
}
async function runProgram(program) {
  const captures = new Map();
  const observed = [];
  for (const step of [...program.steps, ...program.cleanup]) {
    if (step.when) {
      const current = captured(captures, step.request.query?.ifGenerationMatch?.fromStep ?? step.request.query?.["currentDocument.updateTime"]?.fromStep);
      if (current.status === 404) continue;
    }
    const response = await sendRequest(step.request, captures);
    const control = localProgramControls.get(`${program.id}/${step.id}`);
    if (control !== undefined) assert.equal(response.status, control, `local Firestore control ${program.id}/${step.id}`);
    if (step.id.startsWith("subject") || step.id.startsWith("after")) {
      const body = step.id.endsWith("metadata") && response.status === 200 ? json(response) : null;
      observed.push({
        id: step.id,
        status: response.status,
        name: body?.name ?? null,
        size: body?.size ?? null,
        contentType: body?.contentType ?? null,
        mediaSha256: step.id.endsWith("media") && response.status === 200 ? digest(response.bytes) : null,
      });
    }
    if (step.requiredState === "absent") assert.equal(response.status, 404, `local document/object absence ${program.id}/${step.id}`);
    if (step.requiredState === "present") assert.equal(response.status, 200, `local object presence ${program.id}/${step.id}`);
    if (step.requiredState?.startsWith("present-allowed-")) {
      assert.equal(response.status, 200, `local document presence ${program.id}/${step.id}`);
      assert.equal(json(response).fields.allowed.booleanValue, step.requiredState.endsWith("true"));
    }
    if (step.id.includes("cleanup-absence")) assert.equal(response.status, 404, `local cleanup absence ${program.id}/${step.id}`);
  }
  return observed;
}

let comparedCases = 0;
let comparedPrograms = 0;
try {
  const selectedCases = corpus.cases.filter((entry) => !only || entry.id.includes(only));
  const selectedPrograms = corpus.firestorePrograms.filter((program) => !only || program.id.includes(only));
  const isolatedCases = new Map();
  const isolatedPrograms = new Map();
  for (const entry of selectedCases) {
    await activate(entry.rulesSource);
    isolatedCases.set(entry.id, await runCase(entry));
  }
  for (const program of selectedPrograms) {
    await activate(program.rulesSource);
    isolatedPrograms.set(program.id, await runProgram(program));
  }
  for (const version of [1, 2]) {
    const cases = selectedCases.filter((entry) => entry.rule.version === version);
    const programs = version === 2 ? selectedPrograms : [];
    if (cases.length + programs.length === 0) continue;
    await activate(bundles.get(version).content);
    for (const entry of cases) {
      assert.deepEqual(await runCase(entry), isolatedCases.get(entry.id), `local bundled decision changed: ${entry.id}`);
      comparedCases++;
    }
    for (const program of programs) {
      assert.deepEqual(await runProgram(program), isolatedPrograms.get(program.id), `local bundled cross-service decision changed: ${program.id}`);
      comparedPrograms++;
    }
  }
  if (!only) {
    assert.equal(comparedCases, 331);
    assert.equal(comparedPrograms, 5);
  }
  console.log(`storage-rules local equivalence passed: ${comparedCases} cases, ${comparedPrograms} Firestore programs`);
} finally {
  await fetchBounded(new URL("storage/rules", controlBase), {
    method: "DELETE",
    headers: { authorization: `Bearer ${controlToken}` },
  });
}
