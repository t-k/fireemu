import { renderRules } from "./rulesets.mjs";
import { buildFirestorePrograms, countFirestoreProgramRequests } from "./cross_service.mjs";
import { buildManagementPrograms } from "./management_programs.mjs";

const RECIPES = [
  "method-grants",
  "list-v2",
  "principals",
  "token-claims",
  "token-refusal",
  "request-resource-upload",
  "request-resource-metadata",
  "stored-resource",
  "state-transitions",
  "request-time",
  "path-variables",
  "recursive-wildcard",
  "storage-service-compile",
  "firestore-get",
  "firestore-exists",
  "firestore-access-budget",
  "errors/firebase-denial",
  "errors/precedence",
  "gcs-admin-boundary",
  "download-token-boundary",
  "release-switch",
  "no-release",
].map((id) => `storage-rules/${id}`);
const OPERATIONS = ["get-metadata", "get-media", "list", "upload", "patch", "delete"];
const INITIAL = ["absent", "present"];
const CAPTURE = { status: true, headers: "all", body: "raw-bytes" };
const REQUIREMENTS = [
  "exclusive-storage-window-after-storage-object",
  "baseline-release-and-source-saved",
  "fresh-owned-objects-proven-absent",
  "principal-fixtures-verified",
  "rule-compile-and-settle-observed",
  "admin-state-readback-verified",
  "restore-baseline-release-and-effective-decision",
];
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function requireValue(ok, message) {
  if (!ok) throw new Error(message);
}
function requireExactData(actual, expected, path) {
  if (expected === null || typeof expected !== "object") {
    requireValue(Object.is(actual, expected), `changed ${path}`);
    return;
  }
  requireValue(
    actual !== null &&
      typeof actual === "object" &&
      Object.getPrototypeOf(actual) === Object.getPrototypeOf(expected),
    `invalid ${path} object`,
  );
  const actualKeys = Reflect.ownKeys(actual);
  const expectedKeys = Reflect.ownKeys(expected);
  requireValue(
    actualKeys.length === expectedKeys.length &&
      actualKeys.every((key) => typeof key === "string" && expectedKeys.includes(key)),
    `unexpected ${path} field`,
  );
  for (const key of expectedKeys) {
    const value = Object.getOwnPropertyDescriptor(actual, key);
    const required = Object.getOwnPropertyDescriptor(expected, key);
    requireValue(
      value &&
        Object.hasOwn(value, "value") &&
        value.enumerable === required.enumerable &&
        value.configurable === required.configurable &&
        value.writable === required.writable,
      `invalid ${path}.${key} property`,
    );
    requireExactData(value.value, required.value, `${path}.${key}`);
  }
}
function validateBinding(binding) {
  requireValue(
    binding && equal(Object.keys(binding).toSorted(), ["bucket", "prefix", "uidA", "uidB"]),
    "invalid binding shape",
  );
  requireValue(
    typeof binding.bucket === "string" &&
      binding.bucket.length >= 3 &&
      binding.bucket.length <= 222 &&
      binding.bucket.split(".").every((p) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(p)),
    "invalid bucket",
  );
  requireValue(
    typeof binding.prefix === "string" &&
      /^STORAGE-RULES\/[a-z0-9][a-z0-9-]{0,47}\/$/.test(binding.prefix),
    "invalid owned prefix",
  );
  requireValue(
    [binding.uidA, binding.uidB].every(
      (uid) => typeof uid === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(uid),
    ) && binding.uidA !== binding.uidB,
    "invalid principal uid binding",
  );
}
function specifications() {
  const specs = [];
  const add = (recipe, id, operation, initialState, rule, extra = {}) =>
    specs.push({
      id,
      recipeId: `storage-rules/${recipe}`,
      operation,
      initialState,
      principal: "user-a",
      dialect: "firebase",
      rule: { version: 2, ...rule },
      ...extra,
    });
  for (const grant of ["read", "write", "get", "list", "create", "update", "delete"])
    for (const operation of OPERATIONS)
      for (const initial of INITIAL)
        add("method-grants", `method-${grant}-${operation}-${initial}`, operation, initial, {
          kind: "grant",
          grant,
        });
  for (const [version, grant] of [
    [1, "read"],
    [2, "read"],
    [2, "get"],
    [2, "list"],
  ])
    for (const operation of ["get-media", "list"])
      for (const initial of INITIAL)
        add("list-v2", `list-v${version}-${grant}-${operation}-${initial}`, operation, initial, {
          kind: "grant",
          grant,
          version,
        });
  for (const principal of ["anonymous", "user-a", "user-b"]) {
    add(
      "principals",
      `principal-null-${principal}`,
      "get-media",
      "present",
      { kind: "anonymous" },
      { principal },
    );
    for (const owner of ["a", "b"])
      for (const operation of ["get-media", "upload"])
        add(
          "principals",
          `principal-${principal}-owner-${owner}-${operation}`,
          operation,
          operation === "upload" ? "absent" : "present",
          { kind: "uid" },
          { principal, owner },
        );
  }
  for (const field of ["verified", "role", "number"])
    for (const principal of ["user-a", "user-b", "user-plain"])
      for (const operation of ["get-media", "upload"])
        add(
          "token-claims",
          `claims-${field}-${principal}-${operation}`,
          operation,
          operation === "upload" ? "absent" : "present",
          { kind: "claim", field },
          { principal },
        );
  for (const [kind, principal] of [
    ["missing", "anonymous"],
    ["malformed", "malformed-token"],
    ["foreign-project", "foreign-project-token"],
    ["revoked", "revoked-token"],
    ["valid", "user-a"],
  ])
    add(
      "token-refusal",
      `token-${kind}`,
      "get-media",
      "present",
      { kind: "auth-required" },
      { principal },
    );
  for (const uploadProtocol of ["simple", "multipart", "resumable"])
    for (const field of ["size", "contentType", "name", "metadata"])
      for (const matches of [true, false])
        add(
          "request-resource-upload",
          `incoming-upload-${uploadProtocol}-${field}-${matches}`,
          "upload",
          "absent",
          { kind: "upload-incoming", field, matches },
          { uploadProtocol },
        );
  for (const initial of INITIAL)
    for (const dialect of ["firebase", "gcs"])
      for (const credentialState of ["valid", "malformed"])
        for (const inputState of ["valid", "malformed"])
          add(
            "errors/precedence",
            `precedence-${initial}-${dialect}-${credentialState}-${inputState}`,
            "patch",
            initial,
            { kind: "deny" },
            {
              dialect,
              credentialState,
              inputState,
              principal:
                dialect === "firebase"
                  ? credentialState === "valid"
                    ? "user-a"
                    : "malformed-token"
                  : credentialState === "valid"
                    ? "admin"
                    : "malformed-oauth",
            },
          );
  for (const initial of INITIAL)
    for (const dialect of ["firebase", "gcs"])
      for (const inputState of ["valid", "malformed"])
        add(
          "errors/precedence",
          `precedence-control-${initial}-${dialect}-${inputState}`,
          "patch",
          initial,
          { kind: "grant", grant: "write" },
          {
            dialect,
            credentialState: "valid",
            inputState,
            principal: dialect === "firebase" ? "user-a" : "admin",
          },
        );
  add(
    "download-token-boundary",
    "download-token-deny",
    "get-media",
    "present",
    { kind: "deny" },
    { principal: "anonymous", sendAuthorized: false, tokenResolutionImplemented: false },
  );
  for (const field of ["size", "contentType", "name", "metadata"])
    for (const matches of [true, false]) {
      add("request-resource-metadata", `incoming-${field}-${matches}`, "patch", "present", {
        kind: "incoming",
        field,
        matches,
      });
      for (const operation of ["get-media", "patch", "delete"])
        for (const initial of INITIAL)
          add(
            "stored-resource",
            `stored-${field}-${matches}-${operation}-${initial}`,
            operation,
            initial,
            { kind: "stored", field, matches },
          );
    }
  for (const permit of ["create", "update"])
    for (const initial of INITIAL)
      add("state-transitions", `state-upload-${permit}-${initial}`, "upload", initial, {
        kind: "state-dispatch",
        permit,
      });
  for (const matchesNull of [true, false])
    for (const initial of INITIAL)
      add(
        "state-transitions",
        `state-delete-${matchesNull ? "null" : "nonnull"}-${initial}`,
        "delete",
        initial,
        { kind: "delete-request-resource", matchesNull },
      );
  for (const inside of [true, false])
    for (const operation of ["get-media", "upload"])
      add(
        "request-time",
        `time-${inside ? "inside" : "outside"}-${operation}`,
        operation,
        operation === "upload" ? "absent" : "present",
        { kind: "time-window", inside },
        {
          timeEvidence: {
            lowerUtc: "2000-01-01T00:00:00Z",
            upperUtc: "2100-01-01T00:00:00Z",
            serverClockIntervalRequired: true,
            uncertainDecision: "INDETERMINATE",
          },
        },
      );
  for (const matches of [true, false])
    for (const operation of ["get-media", "upload", "patch", "delete"])
      for (const initial of INITIAL)
        add(
          "stored-resource",
          `stored-null-${matches}-${operation}-${initial}`,
          operation,
          initial,
          { kind: "stored-null", matches },
        );
  for (const matches of [true, false])
    for (const operation of ["get-media", "upload"])
      add(
        "path-variables",
        `path-bucket-${matches}-${operation}`,
        operation,
        operation === "upload" ? "absent" : "present",
        { kind: "bucket", matches },
      );
  for (const leaf of ["allowed.bin", "sibling.bin"])
    add(
      "path-variables",
      `path-leaf-${leaf.replace(".", "-")}`,
      "get-media",
      "present",
      { kind: "leaf" },
      { leaf },
    );
  for (const version of [1, 2])
    for (const depth of [0, 1, 2])
      add(
        "recursive-wildcard",
        `recursive-v${version}-depth-${depth}`,
        "get-media",
        "present",
        { kind: "recursive", version },
        { depth },
      );
  for (const operation of OPERATIONS)
    for (const initial of INITIAL) {
      add("errors/firebase-denial", `denial-${operation}-${initial}`, operation, initial, {
        kind: "deny",
      });
      for (const [dialect, principal] of [
        ["firebase", "user-a"],
        ["firebase", "admin"],
        ["gcs", "admin"],
      ])
        add(
          "gcs-admin-boundary",
          `boundary-${dialect}-${principal}-${operation}-${initial}`,
          operation,
          initial,
          { kind: "deny" },
          { dialect, principal },
        );
    }
  return specs;
}
function principalFixtures(binding) {
  return {
    anonymous: { kind: "no-authorization-header" },
    admin: {
      kind: "owner-oauth-reference",
      requirement: "actual IAM permissions observed; no literal owner token",
    },
    "user-a": {
      kind: "firebase-id-token-reference",
      uid: binding.uidA,
      requiredClaims: { email_verified: true, role: "reader", level: 7 },
    },
    "user-b": {
      kind: "firebase-id-token-reference",
      uid: binding.uidB,
      requiredClaims: { email_verified: false, role: "writer", level: "7" },
    },
    "user-plain": {
      kind: "firebase-id-token-reference",
      uid: binding.uidA,
      requiredClaims: { email_verified: true },
      absentClaims: ["role", "level"],
      requirement:
        "separate immutable token snapshot after clearing custom claims; verify claims before use",
    },
    "malformed-token": {
      kind: "invalid-authorization-reference",
      requirement:
        "prepare one deliberately malformed bearer value outside this corpus; record only a digest and keep the actual header private",
    },
    "malformed-oauth": {
      kind: "invalid-oauth-token-reference",
      requirement:
        "prepare one deliberately malformed OAuth bearer value outside this corpus; record only a digest and keep OAuth header bytes private",
    },
    "foreign-project-token": {
      kind: "firebase-id-token-reference",
      requirement:
        "externally minted and verified Firebase ID token from a different project; record project and token digest privately, never token bytes here",
    },
    "revoked-token": {
      kind: "firebase-id-token-reference",
      requirement:
        "same-project signed token issued before a verified account token revocation; retain issuance and revocation readback privately",
    },
  };
}
function request(binding, row, operation, dialect, credential, id) {
  const root = `${dialect === "firebase" ? "/v0" : "/storage/v1"}/b/${binding.bucket}/o`;
  const value = {
    id,
    operation,
    dialect,
    credential,
    objectName: row.objectName,
    method: "GET",
    path: `${root}/${encodeURIComponent(row.objectName)}`,
    query: {},
    headers: {},
    body: null,
    capture: { ...CAPTURE },
  };
  if (operation === "get-media") value.query = { alt: "media" };
  else if (operation === "list") {
    value.path = root;
    value.query = { prefix: row.casePrefix, maxResults: "3" };
  } else if (operation === "upload") {
    value.method = "POST";
    value.path = dialect === "gcs" ? `/upload${root}` : root;
    value.query = { ...(dialect === "gcs" ? { uploadType: "media" } : {}), name: row.objectName };
    value.headers = { "content-type": "text/plain" };
    value.body = { base64: Buffer.from(id === "seed" ? "base" : "next").toString("base64") };
  } else if (operation === "patch") {
    value.method = "PATCH";
    value.headers = { "content-type": "application/json" };
    value.body =
      row.recipeId === "storage-rules/errors/precedence" && id === "subject"
        ? row.inputState === "malformed"
          ? { base64: Buffer.from("{").toString("base64") }
          : { json: {} }
        : {
            json: {
              contentType: id === "seed-metadata" ? "text/plain" : "text/markdown",
              metadata: { owner: id === "seed-metadata" ? "old" : "new" },
            },
          };
  } else if (operation === "create-token") {
    value.method = "POST";
    value.query = { create_token: "true" };
  } else if (operation === "delete") value.method = "DELETE";
  else if (operation !== "get-metadata") throw new Error("unknown request operation");
  return value;
}
const uploadBytes = Buffer.from("next");
function uploadMetadata(row) {
  return { name: row.objectName, contentType: "text/plain", metadata: { owner: "probe" } };
}
function uploadSessionReference(binding, row) {
  return {
    kind: "firebase-resumable-session-url",
    fromStep: "start",
    fromHeader: "x-goog-upload-url",
    expectedBucket: binding.bucket,
    expectedObjectName: row.objectName,
    secretHandling: "private-only",
    resolveOnlyAfterVerifiedStart: true,
  };
}
function multipartUploadBody(row) {
  const boundary = "rules-boundary";
  return Buffer.concat([
    Buffer.from(
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(uploadMetadata(row))}\r\n--${boundary}\r\nContent-Type: text/plain\r\n\r\n`,
    ),
    uploadBytes,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
}
function uploadCase(binding, row, admin, readback) {
  const subject = request(binding, row, "upload", "firebase", "user-a", "subject");
  subject.body = { base64: uploadBytes.toString("base64") };
  const setup = [];
  const cleanup = [];
  if (row.uploadProtocol === "multipart") {
    subject.query.uploadType = "multipart";
    subject.headers = {
      "content-type": "multipart/related; boundary=rules-boundary",
      "x-goog-upload-protocol": "multipart",
    };
    subject.body = { base64: multipartUploadBody(row).toString("base64") };
  } else if (row.uploadProtocol === "resumable") {
    const start = request(binding, row, "upload", "firebase", "user-a", "start");
    start.query.uploadType = "resumable";
    start.headers = {
      "content-type": "application/json; charset=utf-8",
      "x-goog-upload-protocol": "resumable",
      "x-goog-upload-command": "start",
    };
    start.body = { json: uploadMetadata(row) };
    setup.push(start);
    const sessionUrlReference = uploadSessionReference(binding, row);
    subject.path = null;
    subject.query = {};
    subject.headers = {
      "content-type": "application/octet-stream",
      "x-goog-upload-protocol": "resumable",
      "x-goog-upload-command": "upload, finalize",
      "x-goog-upload-offset": "0",
    };
    subject.sessionUrlReference = { ...sessionUrlReference };
    const cancel = request(binding, row, "upload", "firebase", "user-a", "cancel");
    cancel.path = null;
    cancel.query = {};
    cancel.headers = {
      "x-goog-upload-protocol": "resumable",
      "x-goog-upload-command": "cancel",
    };
    cancel.body = null;
    cancel.sessionUrlReference = { ...sessionUrlReference };
    cancel.when = "session-active-or-outcome-unknown";
    cleanup.push(cancel);
  }
  return {
    ...row,
    rulesSource: renderRules(row, binding),
    observationStatus: "PENDING_PRODUCTION",
    baseline: readback("baseline-absence"),
    setup,
    before: readback("before"),
    subject,
    after: readback("after"),
    cleanup: [...cleanup, admin("delete", "cleanup-delete"), ...readback("cleanup-absence")],
  };
}
function materialize(binding, spec) {
  const casePrefix = `${binding.prefix}${spec.id}/`;
  let suffix = "object.bin";
  if (spec.owner) suffix = `${spec.owner === "a" ? binding.uidA : binding.uidB}/object.bin`;
  if (spec.leaf) suffix = spec.leaf;
  if (spec.depth !== undefined)
    suffix = ["anchor", "one", "two"].slice(0, spec.depth + 1).join("/");
  const row = { ...structuredClone(spec), casePrefix, objectName: `${casePrefix}${suffix}` };
  const admin = (operation, id) => request(binding, row, operation, "gcs", "admin", id);
  const readback = (tag) => [
    admin("get-metadata", `${tag}-metadata`),
    admin("get-media", `${tag}-media`),
  ];
  if (row.recipeId === "storage-rules/request-resource-upload")
    return uploadCase(binding, row, admin, readback);
  if (row.recipeId === "storage-rules/download-token-boundary") {
    const subject = request(binding, row, "get-media", "firebase", "anonymous", "subject");
    const comparison = request(binding, row, "get-media", "firebase", "anonymous", "comparison");
    comparison.query.token = {
      kind: "firebase-download-token",
      fromStep: "create-token",
      priorStep: "pre-token-metadata",
      fromField: "downloadTokens",
      priorField: "metadata.firebaseStorageDownloadTokens",
      selection: "exactly-one-new",
      objectName: row.objectName,
      secretHandling: "private-only",
    };
    return {
      ...row,
      rulesSource: renderRules(row, binding),
      observationStatus: "PENDING_PRODUCTION",
      baseline: readback("baseline-absence"),
      setup: [
        admin("upload", "seed"),
        admin("patch", "seed-metadata"),
        admin("get-metadata", "pre-token-metadata"),
        request(binding, row, "create-token", "firebase", "admin", "create-token"),
      ],
      before: readback("before"),
      subject,
      comparison,
      after: readback("after"),
      cleanup: [admin("delete", "cleanup-delete"), ...readback("cleanup-absence")],
    };
  }
  return {
    ...row,
    rulesSource: renderRules(row, binding),
    observationStatus: "PENDING_PRODUCTION",
    baseline: readback("baseline-absence"),
    setup:
      row.initialState === "present"
        ? [admin("upload", "seed"), admin("patch", "seed-metadata")]
        : [],
    before: readback("before"),
    subject: request(binding, row, row.operation, row.dialect, row.principal, "subject"),
    after: readback("after"),
    cleanup: [admin("delete", "cleanup-delete"), ...readback("cleanup-absence")],
  };
}

/** A finite partial declaration; no network, credentials, rule publishing, or runner entry point. */
export function buildCorpus(binding) {
  validateBinding(binding);
  const cases = specifications().map((spec) => materialize(binding, spec));
  const firestorePrograms = buildFirestorePrograms(binding);
  const managementPrograms = buildManagementPrograms(binding, cases, firestorePrograms);
  const declaredRecipes = [...new Set([...cases, ...firestorePrograms, ...managementPrograms].map((c) => c.recipeId))];
  return {
    schemaVersion: 1,
    parent: "STORAGE-RULES",
    declarationStatus: "LOCAL_PARTIAL",
    binding: structuredClone(binding),
    productionRecordingsRequired: 2,
    sendAuthorized: false,
    compatibilityEstablished: false,
    requirements: [...REQUIREMENTS],
    principals: principalFixtures(binding),
    declaredRecipes,
    pendingRecipes: RECIPES.filter((id) => !declaredRecipes.includes(id)),
    cases,
    firestorePrograms,
    managementPrograms,
  };
}

export function validateCorpus(corpus, closure) {
  validateBinding(corpus.binding);
  requireValue(
    corpus.schemaVersion === 1 &&
      corpus.parent === "STORAGE-RULES" &&
      corpus.declarationStatus === "LOCAL_PARTIAL" &&
      corpus.productionRecordingsRequired === 2 &&
      corpus.sendAuthorized === false &&
      corpus.compatibilityEstablished === false,
    "invalid declaration state",
  );
  requireValue(
    equal(corpus.requirements, REQUIREMENTS) &&
      equal(corpus.principals, principalFixtures(corpus.binding)),
    "missing prerequisites or changed principal fixtures",
  );
  const frozen = closure.conditions
    .flatMap((c) => c.recipeIds)
    .filter((id) => !["storage-rules/final-artifact", "storage-rules/closure-review"].includes(id));
  requireValue(
    closure.parent === "STORAGE-RULES" &&
      closure.inventoryState === "FROZEN" &&
      equal([...frozen].toSorted(), [...RECIPES].toSorted()),
    "frozen recipe mismatch",
  );
  const specs = specifications();
  const byId = new Map(specs.map((s) => [s.id, s]));
  const expectedCases = specs.map((spec) => materialize(corpus.binding, spec));
  requireValue(
    Array.isArray(corpus.cases) &&
      corpus.cases.length === specs.length &&
      new Set(corpus.cases.map((c) => c.id)).size === specs.length,
    "missing or duplicate cases",
  );
  const expectedFirestorePrograms = buildFirestorePrograms(corpus.binding);
  const expectedManagementPrograms = buildManagementPrograms(corpus.binding, expectedCases, expectedFirestorePrograms);
  const declared = [...new Set([...specs, ...expectedFirestorePrograms, ...expectedManagementPrograms].map((s) => s.recipeId))];
  requireValue(
    equal(corpus.declaredRecipes, declared) &&
      equal(
        corpus.pendingRecipes,
        RECIPES.filter((id) => !declared.includes(id)),
      ),
    "recipe partition mismatch",
  );
  let requests = 0;
  for (const row of corpus.cases) {
    const spec = byId.get(row.id);
    requireValue(spec, "unknown case");
    const expected = materialize(corpus.binding, spec);
    for (const field of [
      "recipeId",
      "operation",
      "initialState",
      "principal",
      "dialect",
      "rule",
      "casePrefix",
      "objectName",
      "rulesSource",
      "observationStatus",
      "owner",
      "leaf",
      "depth",
      "timeEvidence",
      "credentialState",
      "inputState",
      "sendAuthorized",
      "tokenResolutionImplemented",
      "uploadProtocol",
    ])
      requireValue(equal(row[field], expected[field]), `changed case field ${field}`);
    requireValue(!Object.hasOwn(row, "expectedStatus"), "production status must remain unobserved");
    for (const section of ["baseline", "setup", "before", "after", "cleanup"]) {
      requireValue(
        Array.isArray(row[section]) && row[section].length === expected[section].length,
        `missing ${section}`,
      );
      row[section].forEach((r, n) => validateRequest(r, expected[section][n], corpus.binding, row));
      requests += row[section].length;
    }
    validateRequest(row.subject, expected.subject, corpus.binding, row);
    requests++;
    if (expected.comparison) {
      validateRequest(row.comparison, expected.comparison, corpus.binding, row);
      requests++;
    }
  }
  requireValue(
    Array.isArray(corpus.firestorePrograms) && corpus.firestorePrograms.length === 5,
    "missing Firestore programs",
  );
  requireExactData(corpus.firestorePrograms, expectedFirestorePrograms, "firestorePrograms");
  requireExactData(corpus.managementPrograms, expectedManagementPrograms, "managementPrograms");
  const crossServiceRequests = countFirestoreProgramRequests(expectedFirestorePrograms);
  requests += crossServiceRequests.storage;
  requireExactData(corpus, buildCorpus(corpus.binding), "corpus");
  return {
    cases: specs.length,
    declaredRecipes: declared.length,
    pendingRecipes: RECIPES.length - declared.length,
    firestorePrograms: expectedFirestorePrograms.length,
    managementPrograms: expectedManagementPrograms.length,
    declaredObjectRequestsPerRecording: requests,
    declaredFirestoreRequestsPerRecording: crossServiceRequests.firestore,
    includesReleaseAuthOrRecoveryBudget: false,
    sendAuthorized: false,
  };
}
function validateRequest(value, expected, binding, row) {
  requireValue(
    value &&
      (expected.sessionUrlReference
        ? value.path === null && equal(value.sessionUrlReference, expected.sessionUrlReference)
        : typeof value.path === "string" &&
          value.path.startsWith("/") &&
          !value.path.startsWith("//") &&
          !value.path.includes("://")),
    "request must use a relative path",
  );
  requireValue(
    value.objectName === row.objectName && value.objectName.startsWith(binding.prefix),
    "request must address owned object",
  );
  requireValue(
    Object.hasOwn(principalFixtures(binding), value.credential),
    "unknown credential reference",
  );
  requireValue(
    !Object.keys(value.headers).some((key) => /authorization|cookie|token|key/i.test(key)),
    "credential bytes forbidden",
  );
  if (value.body?.base64 !== undefined) {
    const bytes = Buffer.from(value.body.base64, "base64");
    requireValue(
      bytes.length <= 2048 && bytes.toString("base64") === value.body.base64,
      "invalid or oversized body",
    );
  }
  requireValue(equal(value.capture, CAPTURE), "raw response capture required");
  requireValue(equal(value, expected), "request differs from finite declaration");
}
