import { createHash } from "node:crypto";
import { CREDENTIAL_CACHE_REQUEST_IDS } from "./credential-cache.mjs";
import { buildDeclaredRequestManifest } from "./manifest.mjs";
import { assertManifestPredicates } from "./predicates.mjs";
import { buildPublicationSources } from "./publication.mjs";
import { DRAFT_REQUEST_LIMITS } from "./request-counter.mjs";

const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const RULES = "https://firebaserules.googleapis.com";
const GCS = "https://storage.googleapis.com";
const FIREBASE = "https://firebasestorage.googleapis.com";
const AUTH = "https://identitytoolkit.googleapis.com";
const PROJECTS = "https://cloudresourcemanager.googleapis.com";
const ROOT = `/v1/projects/${QUERY}`;
/** The origin of every declared object and Firestore request, fixed by service and dialect. */
export const REQUEST_ORIGINS = Object.freeze({ "storage/gcs": GCS, "storage/firebase": FIREBASE, firestore: "https://firestore.googleapis.com" });
const AUTH_STEPS = {
  "user-a": ["create", "lookup-created", "set-claims", "lookup-claims", "sign-in", "clear-claims", "lookup-plain", "sign-in-plain", "delete", "absence"],
  "user-b": ["create", "lookup-created", "set-claims", "lookup-claims", "sign-in", "delete", "absence"],
  "revoked-token": ["create", "lookup-created", "sign-in", "revoke", "lookup-revoked", "delete", "absence"],
  "foreign-project-token": ["baseline", "sign-up", "lookup-token", "delete", "absence"],
};
const REF_TYPES = new Set(["generation", "metageneration", "update-time", "ruleset-name", "ruleset-path", "page-token", "password", "foreign-uid", "id-token", "valid-since", "oauth-refresh-body"]);
const reference = (type, key) => {
  if (!REF_TYPES.has(type) || typeof key !== "string" || !key || key.length > 1024) throw new Error();
  return { kind: "runtime-reference", type, key, resolveOnlyAfterDurableProof: true };
};
const hash = (value) => createHash("sha256").update(value).digest("hex");
const matches = (value, pattern) => typeof value === "string" && !/[\r\n]/.test(value) && pattern.test(value);

function snapshot(value, budget = { nodes: 250000, bytes: 16000000 }, depth = 0, active = new Set()) {
  if (--budget.nodes < 0 || depth > 32) throw new Error();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { budget.bytes -= value.length; if (budget.bytes < 0 || value.length > 100000) throw new Error(); return value; }
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error(); return value; }
  if (!value || typeof value !== "object" || active.has(value)) throw new Error();
  const array = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) throw new Error();
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string" || key.length > 1024) || keys.length > 10000) throw new Error();
  budget.bytes -= keys.reduce((sum, key) => sum + key.length, 0);
  if (budget.bytes < 0) throw new Error();
  active.add(value);
  const out = array ? [] : {};
  if (array && (value.length > 10000 || keys.length !== value.length + 1)) throw new Error();
  for (const key of keys) {
    if (array && key === "length") continue;
    if (array && !/^(0|[1-9]\d*)$/.test(key)) throw new Error();
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error();
    Object.defineProperty(out, key, { value: snapshot(field.value, budget, depth + 1, active), enumerable: true, writable: true, configurable: true });
  }
  active.delete(value);
  return out;
}

function build(corpusInput, closureInput, optionsInput) {
  const corpus = snapshot(corpusInput);
  const closure = snapshot(closureInput);
  const options = snapshot(optionsInput);
  const keys = ["runId", "sourceCommit", "queryProjectNumber", "idpProjectNumber", "queryApiKeyId", "idpApiKeyId"];
  if (Object.keys(options).length !== keys.length || keys.some((key) => !Object.hasOwn(options, key))) throw new Error();
  const { runId, sourceCommit } = options;
  if (!matches(runId, /^[a-z0-9][a-z0-9-]{0,47}$/) || !matches(sourceCommit, /^[a-f0-9]{40}$/)) throw new Error();
  for (const key of ["queryProjectNumber", "idpProjectNumber"]) if (!matches(options[key], /^[1-9]\d{0,19}$/)) throw new Error();
  for (const key of ["queryApiKeyId", "idpApiKeyId"]) if (!matches(options[key], /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/)) throw new Error();
  if (options.queryProjectNumber === options.idpProjectNumber) throw new Error();
  const binding = corpus.binding;
  if (binding.prefix !== `STORAGE-RULES/${runId}/` || binding.uidA !== `storage-rules-${runId}-user-a` || binding.uidB !== `storage-rules-${runId}-user-b`) throw new Error();
  const declared = buildDeclaredRequestManifest(corpus, closure);
  const bundles = buildPublicationSources(corpus, binding);
  const compile = corpus.managementPrograms.find((p) => p.id === "storage-service-compile");
  const switched = corpus.managementPrograms.find((p) => p.id === "release-switch");
  const controls = ["list-v1-read-get-media-present/settle-allow.bin", "method-get-get-media-present/settle-allow.bin", "settle-control/deny.bin", "release-switch/old.bin", "release-switch/new.bin", "no-release/object.bin"].map((p) => `${binding.prefix}${p}`);
  const witnesses = [controls[0], controls[1], controls[3], controls[4]];
  const fsRequests = corpus.firestorePrograms.flatMap((p) => [...p.steps, ...p.cleanup].map((s) => s.request));
  const objects = [...corpus.cases.map((c) => c.objectName), ...new Set(fsRequests.map((r) => r.objectName).filter(Boolean)), ...controls];
  const documents = [...new Set(fsRequests.map((r) => r.documentName).filter(Boolean))];
  const sessions = corpus.cases.filter((c) => c.setup.some((r) => r.headers["x-goog-upload-command"] === "start")).map((c) => ({ caseId: c.id, objectName: c.objectName, startRequestId: `case/${c.id}/setup/start`, reference: { ...c.subject.sessionUrlReference, startRequestId: `case/${c.id}/setup/start` } }));
  if (objects.length !== 344 || new Set(objects).size !== 344 || documents.length !== 9 || sessions.length !== 8 || !objects.every((name) => name.startsWith(binding.prefix))) throw new Error();
  const rows = []; const ids = new Set();
  const counts = { normal: 0, recovery: 0, preflight: 0, total: 0 };
  const add = (id, phase, family, programId, stage, service, request, requires = []) => {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9/_-]{0,159}$/.test(id) || (phase === "preflight" && !/^preflight\/[A-Za-z0-9/_-]{1,150}$/.test(id)) || ids.has(id) || !["preflight", "normal", "recovery"].includes(phase)) throw new Error();
    ids.add(id);
    rows.push({ id, phase, family, programId, stage, service, request, requires });
    counts[phase === "recovery" ? "recovery" : "normal"]++;
    if (phase === "preflight") counts.preflight++;
    counts.total++;
  };
  const req = (origin, path, method = "GET", extra = {}) => ({ origin, path, method, query: {}, headers: {}, body: null, credential: "admin", project: QUERY, capture: { status: true, headers: "all", body: "raw-bytes" }, ...extra });
  const storage = (name, media = false, dialect = "gcs") => req(dialect === "gcs" ? GCS : FIREBASE, dialect === "gcs" ? `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(name)}` : `/v0/b/${binding.bucket}/o/${encodeURIComponent(name)}`, "GET", { objectName: name, dialect, operation: media ? "get-media" : "get-metadata", ...(media ? { query: { alt: "media" } } : {}), ...(dialect === "firebase" ? { credential: "user-a" } : {}) });
  const sourceBody = (content) => ({ json: { source: { files: [{ name: "storage.rules", content }] } } });
  const releaseName = `projects/${QUERY}/releases/firebase.storage/${binding.bucket}`;
  const releasePath = `/v1/${releaseName}`;
  const bucketless = `/v1/projects/${QUERY}/releases/firebase.storage`;

  for (const r of declared.rows) {
    const request = r.request; const requires = ["canonical-program-state-and-fresh-credential"];
    const originKey = r.service === "firestore" ? "firestore" : `storage/${request.dialect}`;
    if (!Object.hasOwn(REQUEST_ORIGINS, originKey)) throw new Error();
    request.origin = REQUEST_ORIGINS[originKey];
    if (request.sessionUrlReference) {
      if (r.stage !== "subject") request.credential = "anonymous";
      requires.push("durable-verified-start-url-and-target");
      if (request.headers["x-goog-upload-command"] === "cancel") requires.push("confirmed-active-session", "cancel-not-attempted", "session-active-per-latest-query");
    }
    if (request.credential === "admin" && r.stage !== "subject" && r.stage !== "comparison") {
      if (request.operation === "upload") { request.query.ifGenerationMatch = "0"; requires.push("owned-namespace-and-absence"); }
      if (["delete", "patch"].includes(request.operation)) {
        request.query.ifGenerationMatch ??= reference("generation", request.objectName);
        if (request.operation === "patch") request.query.ifMetagenerationMatch ??= reference("metageneration", request.objectName);
        requires.push("confirmed-write-history-and-current-version");
        if (request.operation === "delete") requires.push("delete-not-attempted", "object-not-absent-per-latest-readback");
      }
    }
    if (r.service === "firestore" && request.method === "DELETE" && r.stage === "cleanup") requires.push("document-not-absent-per-latest-readback");
    add(r.id, "normal", "declared", r.programId, r.stage, r.service, request, requires);
    if (Object.hasOwn(r, "requiredState")) rows.at(-1).requiredState = r.requiredState;
    if (Object.hasOwn(r, "when")) rows.at(-1).when = r.when;
    if (request.sessionUrlReference) rows.at(-1).sessionStartRequestId = `case/${r.programId}/setup/start`;
  }

  const pre = (id, request, proof) => add(`preflight/${id}`, "preflight", "preflight", id, "readback", "preflight", request, [proof, "approved-private-input-provenance"]);
  pre("owner/identity", req("https://www.googleapis.com", "/oauth2/v2/userinfo"), "verified-email-and-subject-match-packet-owner");
  for (const [key, project, number, keyId] of [["query", QUERY, options.queryProjectNumber, options.queryApiKeyId], ["idp", IDP, options.idpProjectNumber, options.idpApiKeyId]]) {
    pre(`${key}/project`, req(PROJECTS, `/v3/projects/${number}`, "GET", { project }), "project-id-number-active-match");
    const keyPath = `/v2/projects/${number}/locations/global/keys/${keyId}`;
    pre(`${key}/key-metadata`, req("https://apikeys.googleapis.com", keyPath, "GET", { project }), "key-name-uid-not-deleted-and-approved-restrictions-match");
    pre(`${key}/key-string`, req("https://apikeys.googleapis.com", `${keyPath}/keyString`, "GET", { project }), "private-key-string-matches-key-metadata-and-cached-secret");
    const permissions = key === "query" ? ["firebaserules.rulesets.create", "firebaserules.rulesets.delete", "firebaserules.rulesets.get", "firebaserules.rulesets.list", "firebaserules.rulesets.test", "firebaserules.releases.create", "firebaserules.releases.delete", "firebaserules.releases.get", "firebaserules.releases.update", "firebaseauth.users.create", "firebaseauth.users.delete", "firebaseauth.users.get", "firebaseauth.users.update", "datastore.entities.create", "datastore.entities.delete", "datastore.entities.get", "datastore.entities.update"] : ["firebaseauth.users.delete", "firebaseauth.users.get"];
    pre(`${key}/permissions`, req(PROJECTS, `/v3/projects/${number}:testIamPermissions`, "POST", { project, body: { json: { permissions } } }), "all-explicit-permissions-present-does-not-authorize-send");
  }
  pre("bucket/metadata", req(GCS, `/storage/v1/b/${binding.bucket}`), "bucket-name-project-number-and-baseline-match");
  pre("bucket/iam", req(GCS, `/storage/v1/b/${binding.bucket}/iam`, "GET", { query: { optionsRequestedPolicyVersion: "3" } }), "approved-bucket-policy-baseline-match");
  // Only the bucket-level permissions IAM can report here. The bucket uses fine-grained access, so the project's owners hold object read and
  // update through object ACLs (storage.legacyObjectOwner), which a bucket-level test never lists; asking for them stopped stage 2a in production.
  pre("bucket/permissions", req(GCS, `/storage/v1/b/${binding.bucket}/iam/testPermissions`, "GET", { query: { permissions: ["storage.buckets.get", "storage.buckets.getIamPolicy", "storage.objects.create", "storage.objects.delete", "storage.objects.list"] } }), "all-explicit-bucket-permissions-present");
  pre("query/database", req("https://firestore.googleapis.com", `/v1/projects/${QUERY}/databases/(default)`), "default-database-project-and-baseline-match");
  pre("query/iam", req(PROJECTS, `/v3/projects/${options.queryProjectNumber}:getIamPolicy`, "POST", { body: { json: { options: { requestedPolicyVersion: 3 } } } }), "approved-cross-service-grant-and-policy-baseline-match");

  for (const [stage, path] of [["before", releasePath], ["after-invalid", releasePath]]) add(`compile/release/${stage}`, "normal", "compile", "source-validation", stage, "firebase-rules", req(RULES, path), ["entry-baseline-unchanged"]);
  for (const source of [...compile.validSources, compile.invalidSource]) add(`compile/${source.ref}`, "normal", "compile", source.ref, "test", "firebase-rules", req(RULES, `${ROOT}:test`, "POST", { body: sourceBody(source.content) }), ["literal-source-digest-match"]);

  const sources = [
    { id: "v1", content: bundles[0].content }, { id: "v2", content: bundles[1].content },
    { id: "A", content: switched.sourceA }, { id: "B", content: switched.sourceB },
  ];
  for (const source of sources) {
    add(`ruleset/${source.id}/create`, "normal", "ruleset", source.id, "create", "firebase-rules", req(RULES, `${ROOT}/rulesets`, "POST", { body: sourceBody(source.content) }), ["compiled-source-and-entry-baseline"]);
    for (const stage of ["read-source", "delete", "absence"]) add(`ruleset/${source.id}/${stage}`, "normal", "ruleset", source.id, stage, "firebase-rules", req(RULES, null, stage === "delete" ? "DELETE" : "GET", { pathReference: reference("ruleset-path", source.id) }), stage === "delete" ? ["owned-ruleset-and-unreferenced-after-restore", "delete-not-attempted"] : ["acknowledged-ruleset-create"]);
  }
  const list = (phase, position, page) => add(`${position === "entry" ? "preflight/" : phase === "recovery" ? "recovery/" : ""}rulesets-list/${position}/${page}`, position === "entry" ? "preflight" : phase, "rulesets-list", position, `page-${page}`, "firebase-rules", req(RULES, `${ROOT}/rulesets`, "GET", { query: { pageSize: "100", ...(page > 1 ? { pageToken: reference("page-token", `${phase}/${position}/${page - 1}`) } : {}) } }), position === "entry" ? ["approved-ruleset-count-and-cleanup-baseline", "entry-page-has-no-next-token"] : page > 1 ? ["previous-page-token-verified", "at-most-ten-pages-or-stop"] : ["approved-ruleset-count-and-cleanup-baseline"]);
  list("normal", "entry", 1);
  for (let page = 1; page <= 10; page++) list("normal", "final", page);
  const release = (id, stage, path, phase = "normal", method = "GET", extra = {}, requires = []) => add(id, phase, "release", "publication", stage, "firebase-rules", req(RULES, path, method, extra), requires);
  for (const [position, phase] of [["entry", "preflight"], ["no-release-entry-after", "normal"], ["final", "normal"]]) {
    release(`${phase === "preflight" ? "preflight/" : ""}release/${position}/bucket`, position, releasePath, phase, "GET", {}, ["bucket-release-absent"]);
    release(`${phase === "preflight" ? "preflight/" : ""}release/${position}/bucketless`, position, bucketless, phase, "GET", {}, ["bucketless-release-absent"]);
  }
  for (const source of sources) {
    release(`release/${source.id}/before`, "before-switch", releasePath, "normal", "GET", {}, ["exact-previous-release-or-entry-absence"]);
    const value = { name: releaseName, rulesetName: reference("ruleset-name", source.id) };
    release(`release/${source.id}/publish`, "publish", source.id === "v1" ? `${ROOT}/releases` : releasePath, "normal", source.id === "v1" ? "POST" : "PATCH", { body: { json: source.id === "v1" ? value : { release: value, updateMask: "rulesetName" } } }, ["all-four-controls-confirmed-and-retained", "owned-ruleset-and-source-readback", "exact-previous-release-or-entry-absence"]);
    release(`release/${source.id}/after`, "after-switch", releasePath, "normal", "GET", {}, ["release-name-and-created-ruleset-match"]);
  }
  for (const phase of ["normal", "recovery"]) {
    const prefix = phase === "recovery" ? "recovery/" : "";
    for (const [stage, path, method] of [["owner-before-delete", releasePath, "GET"], ["delete", releasePath, "DELETE"], ["bucket-absence", releasePath, "GET"], ["bucketless-absence", bucketless, "GET"]]) release(`${prefix}release/restore/${stage}`, stage, path, phase, method, {}, method === "DELETE" ? ["exact-owned-current-release-and-absent-entry-baseline", "delete-not-attempted"] : ["restore-without-unowned-release-change"]);
  }

  const settle = (phase, name, objectsToRead, cycles) => {
    for (let cycle = 1; cycle <= cycles; cycle++) for (let index = 0; index < objectsToRead.length; index++) add(`${phase === "recovery" ? "recovery/" : ""}settle/${name}/${cycle}/${index}`, phase, "settle", name, `cycle-${cycle}`, "storage", { ...storage(objectsToRead[index], true, "firebase"), credential: "anonymous" }, ["all-four-controls-confirmed-and-retained", "finite-distinct-cycle-and-fresh-user-token"]);
  };
  for (const [name, allowed, denied] of [["v1", controls[0], controls[2]], ["v2", controls[1], controls[0]], ["A", controls[3], controls[1]], ["B", controls[4], controls[3]]]) settle("normal", name, [allowed, denied], 30);
  settle("normal", "restore", witnesses, 15); settle("recovery", "restore", witnesses, 15);

  for (let index = 0; index < controls.length; index++) {
    const name = controls[index];
    for (const [stage, media] of [["baseline-metadata", false], ["baseline-media", true], ["seed-metadata", false], ["seed-media", true], ["cleanup-metadata", false], ["absence-metadata", false], ["absence-media", true]]) add(`management/control-${index}/${stage}`, "normal", "management", `control-${index}`, stage, "storage", storage(name, media), [stage.startsWith("baseline") ? "owned-namespace-and-absence" : "owned-control-retained-through-final-readback"]);
    add(`management/control-${index}/seed`, "normal", "management", `control-${index}`, "seed", "storage", req(GCS, `/upload/storage/v1/b/${binding.bucket}/o`, "POST", { dialect: "gcs", operation: "upload", objectName: name, query: { uploadType: "media", name, ifGenerationMatch: "0" }, headers: { "content-type": "text/plain" }, body: { base64: Buffer.from("next").toString("base64") } }), ["owned-namespace-and-absence"]);
    add(`management/control-${index}/delete`, "normal", "management", `control-${index}`, "delete", "storage", { ...storage(name), method: "DELETE", operation: "delete", query: { ifGenerationMatch: reference("generation", name) } }, ["confirmed-write-history-and-current-version", "all-final-control-readbacks-complete", "delete-not-attempted", "object-not-absent-per-latest-readback"]);
  }
  for (const [source, index] of [["A", 3], ["A", 4], ["B", 3], ["B", 4]]) {
    const name = controls[index];
    for (const [stage, media, dialect] of [["before-metadata", false, "gcs"], ["before-media", true, "gcs"], ["subject", true, "firebase"], ["after-metadata", false, "gcs"], ["after-media", true, "gcs"]]) add(`management/${source}/control-${index}/${stage}`, "normal", "management", source, stage, "storage", storage(name, media, dialect), ["exact-release-source-and-effective-settle", "owned-control-retained-through-final-readback"]);
  }
  for (const position of ["entry", "final"]) for (const [stage, media, dialect] of [["subject", true, "firebase"], ["after-metadata", false, "gcs"], ["after-media", true, "gcs"], ...(position === "final" ? [["before-metadata", false, "gcs"], ["before-media", true, "gcs"]] : [])]) add(`management/no-release/${position}/${stage}`, "normal", "management", "no-release", stage, "storage", storage(controls[5], media, dialect), ["both-releases-absent", "owned-control-confirmed-present"]);
  const prefixEmpty = (phase) => add(`${phase === "recovery" ? "recovery/" : ""}management/prefix-empty`, phase, phase === "recovery" ? "recovery-prefix" : "management", "cleanup", "prefix-empty", "storage", req(GCS, `/storage/v1/b/${binding.bucket}/o`, "GET", { dialect: "gcs", operation: "list", query: { prefix: binding.prefix, maxResults: "1" } }), ["all-owned-resources-and-sessions-cleaned", "empty-items-and-no-next-page-token"]);
  for (const phase of ["normal", "recovery"]) for (let i = 0; i < witnesses.length; i++) add(`${phase === "recovery" ? "recovery/" : ""}management/restore-owner-media/${i}`, phase, phase === "recovery" ? "recovery-control" : "management", "restore", "restore-owner-media", "storage", storage(witnesses[i], true), ["two-complete-no-release-restore-cycles", "owned-control-still-present-and-version-matches"]);
  prefixEmpty("normal");

  for (const [account, steps] of Object.entries(AUTH_STEPS)) for (const phase of ["normal", "recovery"]) for (const step of phase === "normal" ? steps : ["delete", "absence"]) {
    const project = account === "foreign-project-token" ? IDP : QUERY;
    const client = ["sign-in", "sign-in-plain", "sign-up", "lookup-token"].includes(step);
    const action = step === "create" ? "" : ["sign-in", "sign-in-plain"].includes(step) ? "signInWithPassword" : step === "sign-up" ? "signUp" : ["set-claims", "clear-claims", "revoke"].includes(step) ? "update" : step === "delete" ? "delete" : "lookup";
    const uid = account === "foreign-project-token" ? reference("foreign-uid", account) : `storage-rules-${runId}-${account}`;
    const email = `storage-rules-${runId}-${account}@example.com`;
    let body;
    if (step === "create") body = { localId: uid, email, password: reference("password", account), emailVerified: account === "user-a" };
    else if (["sign-in", "sign-in-plain", "sign-up"].includes(step)) body = { email, password: reference("password", account), returnSecureToken: true };
    else if (step === "lookup-token") body = { idToken: reference("id-token", account) };
    else if (step === "baseline") body = { email: [email] };
    else if (["set-claims", "clear-claims"].includes(step)) body = { localId: uid, customAttributes: step === "clear-claims" ? "{}" : JSON.stringify({ role: account === "user-a" ? "reader" : "writer", level: account === "user-a" ? 7 : "7" }) };
    else if (step === "revoke") body = { localId: uid, validSince: reference("valid-since", account) };
    else body = { localId: step === "delete" ? uid : [uid] };
    add(`${phase === "recovery" ? "recovery/" : ""}auth/${account}/${step}`, phase, "auth", account, step, "auth", req(AUTH, client ? `/v1/accounts:${action}` : `/v1/projects/${project}/accounts${action ? `:${action}` : ""}`, "POST", { project, credential: client ? "api-key-only" : "owner-oauth", apiKeyReference: project === QUERY ? "query-api-key" : "idp-api-key", body: { json: body } }), step === "delete" ? ["confirmed-owned-account", "delete-not-attempted"] : ["credential-session-exact-state-and-project"]);
  }
  for (const id of CREDENTIAL_CACHE_REQUEST_IDS) {
    const phase = id.startsWith("recovery/") ? "recovery" : id.startsWith("preflight/") ? "preflight" : "normal";
    const keys = id.includes("signing-keys");
    add(id, phase, "credential-cache", keys ? "keys" : "owner", "acquire", "auth", keys ? req("https://www.googleapis.com", "/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", "GET", { credential: "anonymous" }) : req("https://oauth2.googleapis.com", "/token", "POST", { credential: "adc-refresh", headers: { "content-type": "application/x-www-form-urlencoded" }, body: { reference: reference("oauth-refresh-body", "approved-authorized-user-adc") } }), ["explicit-counted-refresh-and-durable-cache-proof"]);
  }

  for (let index = 0; index < objects.length; index++) {
    const name = objects[index];
    for (const [stage, media, method] of [["metadata", false, "GET"], ["delete", false, "DELETE"], ["absence-metadata", false, "GET"], ["absence-media", true, "GET"]]) add(`recovery/object-${index}/${stage}`, "recovery", "recovery-object", `object-${index}`, stage, "storage", { ...storage(name, media), method, ...(method === "DELETE" ? { operation: "delete", query: { ifGenerationMatch: reference("generation", name) } } : {}) }, method === "DELETE" ? ["confirmed-write-history-and-current-version", "delete-not-attempted", "object-not-absent-per-latest-readback", "restore-controls-retained-until-owner-readbacks"] : ["resource-started-and-provenance-matches"]);
  }
  for (let index = 0; index < documents.length; index++) {
    const name = documents[index];
    for (const stage of ["current", "delete", "absence"]) add(`recovery/document-${index}/${stage}`, "recovery", "recovery-document", `document-${index}`, stage, "firestore", req("https://firestore.googleapis.com", `/v1/${name}`, stage === "delete" ? "DELETE" : "GET", { documentName: name, ...(stage === "delete" ? { query: { "currentDocument.updateTime": reference("update-time", name) } } : {}) }), stage === "delete" ? ["confirmed-document-write-history-and-current-version", "delete-not-attempted", "document-not-absent-per-latest-readback"] : ["resource-started-and-provenance-matches"]);
  }
  // A cancel's answer alone does not prove a session finished, so the normal path asks once more.
  for (const session of sessions) add(`session-verify/${session.caseId}`, "normal", "session-verify", session.caseId, "verify", "storage", req(FIREBASE, null, "POST", { objectName: session.objectName, credential: "anonymous", dialect: "firebase", operation: "upload", sessionUrlReference: { ...session.reference }, headers: { "x-goog-upload-protocol": "resumable", "x-goog-upload-command": "query" } }), ["durable-verified-start-url-and-target", "unknown-terminal-shape-remains-needs-recovery"]);
  for (const session of sessions) for (const [stage, command] of [["current", "query"], ["cancel", "cancel"], ["terminal", "query"]]) add(`recovery/session/${session.caseId}/${stage}`, "recovery", "recovery-session", session.caseId, stage, "storage", req(FIREBASE, null, "POST", { objectName: session.objectName, credential: "anonymous", dialect: "firebase", operation: "upload", sessionUrlReference: { ...session.reference }, headers: { "x-goog-upload-protocol": "resumable", "x-goog-upload-command": command } }), command === "cancel" ? ["durable-verified-start-url-and-target", "confirmed-active-session", "cancel-not-attempted", "session-active-per-latest-query"] : ["durable-verified-start-url-and-target", "unknown-terminal-shape-remains-needs-recovery"]);
  for (const source of sources) for (const stage of ["current", "delete", "absence"]) add(`recovery/ruleset/${source.id}/${stage}`, "recovery", "recovery-ruleset", source.id, stage, "firebase-rules", req(RULES, null, stage === "delete" ? "DELETE" : "GET", { pathReference: reference("ruleset-path", source.id) }), stage === "delete" ? ["owned-ruleset-and-unreferenced-after-restore", "delete-not-attempted"] : ["acknowledged-ruleset-create"]);
  for (let page = 1; page <= 10; page++) list("recovery", "final", page);
  prefixEmpty("recovery");
  const limits = { normal: DRAFT_REQUEST_LIMITS.maxRequests - DRAFT_REQUEST_LIMITS.recoveryReserve, recovery: DRAFT_REQUEST_LIMITS.recoveryReserve, total: DRAFT_REQUEST_LIMITS.maxRequests };
  if (counts.normal !== 4638 || counts.recovery !== 1534 || counts.preflight !== 19 || counts.total !== 6172 || counts.normal > limits.normal || counts.recovery > limits.recovery || counts.total > limits.total) throw new Error();
  const manifest = {
    status: "LOCAL_FULL_DRAFT_NO_SEND", sendAuthorized: false, controllerReady: false,
    binding: { ...binding, ...options }, corpusSha256: hash(JSON.stringify(corpus)), closureSha256: hash(JSON.stringify(closure)), counts, limits, preflightIds: rows.filter((r) => r.phase === "preflight").map((r) => r.id),
    publication: { v1: [...bundles[0].caseIds], v2: [...bundles[1].caseIds] },
    resources: { objects, documents, sessions, controls }, sources: sources.map((s) => ({ id: s.id, sha256: hash(s.content) })),
    restoration: { intervalMs: 20000, maxCycles: 15, consecutiveCompleteCycles: 2, witnessCount: 4, retainUntil: "restore-owner-readbacks-complete", missingProof: "needs-recovery" },
    sessionPolicy: { queryStatus: ["active", "final"], maxReceivedBytes: 4, unknownTerminalShape: "needs-recovery", startStatus: 200, startHeaderStatus: "active", origin: FIREBASE, duplicateHeaders: "reject", literalUrls: "private-only", cancelResponseAloneProvesTerminal: false, paths: ["exact-bucket-collection", "exact-encoded-owned-object"], queryKeys: ["name", "upload_id", "upload_protocol", "uploadType"], requiredQueryKeys: ["name", "upload_id", "upload_protocol"], queryValues: { name: "exact-owned-object", upload_id: "bounded-private-opaque-id", upload_protocol: "resumable", uploadType: "resumable-if-present" }, duplicateQueryKeys: "reject", querySuccessStatus: 200, missingDurableStart: "needs-recovery" },
    pending: ["offline-adc-quota-billing-and-approved-input-provenance", "closed-runtime-reference-resolution-and-response-validation", "controller-ordering-and-state-proofs", "durable-target-response-and-resource-proofs", "live-admission-final-pins-and-presend-review"], rows,
  };
  assertManifestPredicates(manifest);
  return { ...manifest, sha256: hash(JSON.stringify(manifest)) };
}

/** Pure finite declarations. Row order is not an execution plan or permission to send. */
export function buildFullRequestManifest(corpus, closure, options) {
  try { return build(corpus, closure, options); } catch { throw new Error("invalid full manifest input"); }
}
