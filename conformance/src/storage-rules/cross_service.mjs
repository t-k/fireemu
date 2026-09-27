const PROJECT = "fireemu-oracle-query";
const DATABASE = "(default)";
const COLLECTION = "STORAGE-RULES";
const CAPTURE = { status: true, headers: "all", body: "raw-bytes" };
const docRoot = `projects/${PROJECT}/databases/${DATABASE}/documents/${COLLECTION}`;
const docUrl = `/v1/${docRoot}`;

const step = (id, request, requiredState = null, when = null) => ({
  id,
  request,
  requiredState,
  when,
});
const documentName = (id) => `${docRoot}/${id}`;
const updateTimeRef = (fromStep, name, ownerWriteSteps = null) => ({
  kind: "firestore-update-time",
  fromStep,
  documentName: name,
  field: "updateTime",
  ownerWriteSteps,
});
const generationRef = (fromStep, name, ownerReceiptStep) => ({
  kind: "gcs-object-generation",
  fromStep,
  objectName: name,
  field: "generation",
  ownerReceiptStep,
});

function firestoreRequest(id, name, method, options = {}) {
  const documentId = name.slice(`${docRoot}/`.length);
  const path = method === "POST" ? docUrl : `/v1/${name}`;
  const query =
    method === "POST"
      ? { documentId }
      : method === "PATCH"
        ? {
            "updateMask.fieldPaths": "allowed",
            "currentDocument.updateTime": options.updateTime,
          }
        : method === "DELETE"
          ? { "currentDocument.updateTime": options.updateTime }
          : {};
  return {
    service: "firestore",
    id,
    method,
    path,
    query,
    headers: {},
    body:
      method === "POST" || method === "PATCH"
        ? { json: { fields: { allowed: { booleanValue: options.allowed } } } }
        : null,
    credential: "admin",
    documentName: name,
    capture: { ...CAPTURE },
  };
}

function storageRequest(binding, id, name, operation, credential = "admin", options = {}) {
  const firebase = credential === "user-a";
  const root = `${firebase ? "/v0" : "/storage/v1"}/b/${binding.bucket}/o`;
  const upload = operation === "upload";
  const result = {
    service: "storage",
    id,
    operation,
    dialect: firebase ? "firebase" : "gcs",
    credential,
    objectName: name,
    method: upload ? "POST" : operation === "delete" ? "DELETE" : "GET",
    path: upload ? (firebase ? root : `/upload${root}`) : `${root}/${encodeURIComponent(name)}`,
    query: upload
      ? firebase
        ? { name }
        : { name, uploadType: "media", ifGenerationMatch: "0" }
      : operation === "get-media"
        ? { alt: "media" }
        : operation === "delete"
          ? { ifGenerationMatch: options.generation }
          : {},
    headers: upload ? { "content-type": "text/plain" } : {},
    body: upload
      ? { base64: Buffer.from(credential === "user-a" ? "next" : "base").toString("base64") }
      : null,
    capture: { ...CAPTURE },
  };
  return result;
}

function objectReads(binding, name, tag, requiredState = null) {
  return [
    step(
      `${tag}-metadata`,
      storageRequest(binding, `${tag}-metadata`, name, "get-metadata"),
      requiredState ?? "object-state-readback",
    ),
    step(
      `${tag}-media`,
      storageRequest(binding, `${tag}-media`, name, "get-media"),
      requiredState ?? "object-byte-readback",
    ),
  ];
}

function objectCleanup(binding, name, tag, ownerReceiptStep) {
  const read = `${tag}-cleanup-metadata`;
  return [
    step(read, storageRequest(binding, read, name, "get-metadata"), "owned-or-absent"),
    step(
      `${tag}-cleanup-delete`,
      storageRequest(binding, `${tag}-cleanup-delete`, name, "delete", "admin", {
        generation: generationRef(read, name, ownerReceiptStep),
      }),
      null,
      "owned-generation-matches-receipt",
    ),
    ...objectReads(binding, name, `${tag}-cleanup-absence`),
  ];
}

function documentCleanup(name, tag, ownerWriteSteps) {
  const read = `${tag}-cleanup-read`;
  return [
    step(read, firestoreRequest(read, name, "GET"), "owned-or-absent"),
    step(
      `${tag}-cleanup-delete`,
      firestoreRequest(`${tag}-cleanup-delete`, name, "DELETE", {
        updateTime: updateTimeRef(read, name, ownerWriteSteps),
      }),
      null,
      "owned-update-time-matches-run-write",
    ),
    step(
      `${tag}-cleanup-absence`,
      firestoreRequest(`${tag}-cleanup-absence`, name, "GET"),
      "absent",
    ),
  ];
}

function rulesSource(prefix, pathPattern, expression, grant) {
  return `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /${prefix}${pathPattern} {\n      allow ${grant}: if ${expression};\n    }\n  }\n}\n`;
}

function programBase(id, recipe, binding, docs, objects, source, accessOrder = null) {
  return {
    id,
    recipeId: `storage-rules/${recipe}`,
    projectId: PROJECT,
    databaseId: DATABASE,
    collectionId: COLLECTION,
    requiredBucketProjectAttestation: PROJECT,
    firestoreDocumentNames: docs,
    storageObjectNames: objects,
    accessOrder,
    rulesSource: source,
    observationStatus: "PENDING_PRODUCTION",
    sendAuthorized: false,
    steps: [],
    cleanup: [],
  };
}

function getProgram(binding, run) {
  const id = "firestore-get-transition";
  const prefix = `${binding.prefix}${id}/`;
  const document = documentName(`${run}-get-a`);
  const docId = document.slice(`${docRoot}/`.length);
  const objects = ["true", "false", "missing"].map((tag) => `${prefix}${docId}/${tag}.bin`);
  const expression =
    "firestore.get(/databases/(default)/documents/STORAGE-RULES/$(doc)).data.allowed == true";
  const program = programBase(
    id,
    "firestore-get",
    binding,
    [document],
    objects,
    rulesSource(prefix, "{doc}/{file=**}", expression, "create"),
  );
  program.steps.push(
    ...objects.flatMap((name, index) => objectReads(binding, name, `baseline-${index}`, "absent")),
  );
  program.steps.push(
    step("doc-absence", firestoreRequest("doc-absence", document, "GET"), "absent"),
  );
  program.steps.push(
    step(
      "doc-create-true",
      firestoreRequest("doc-create-true", document, "POST", { allowed: true }),
    ),
  );
  program.steps.push(
    step(
      "doc-read-true",
      firestoreRequest("doc-read-true", document, "GET"),
      "present-allowed-true",
    ),
  );
  program.steps.push(
    step("subject-true", storageRequest(binding, "subject-true", objects[0], "upload", "user-a")),
  );
  program.steps.push(...objectReads(binding, objects[0], "after-true"));
  program.steps.push(
    step(
      "doc-update-false",
      firestoreRequest("doc-update-false", document, "PATCH", {
        allowed: false,
        updateTime: updateTimeRef("doc-read-true", document),
      }),
    ),
  );
  program.steps.push(
    step(
      "doc-read-false",
      firestoreRequest("doc-read-false", document, "GET"),
      "present-allowed-false",
    ),
  );
  program.steps.push(
    step("subject-false", storageRequest(binding, "subject-false", objects[1], "upload", "user-a")),
  );
  program.steps.push(...objectReads(binding, objects[1], "after-false"));
  program.steps.push(
    step(
      "doc-delete",
      firestoreRequest("doc-delete", document, "DELETE", {
        updateTime: updateTimeRef("doc-read-false", document),
      }),
    ),
  );
  program.steps.push(
    step("doc-read-missing", firestoreRequest("doc-read-missing", document, "GET"), "absent"),
  );
  program.steps.push(
    step(
      "subject-missing",
      storageRequest(binding, "subject-missing", objects[2], "upload", "user-a"),
    ),
  );
  program.steps.push(...objectReads(binding, objects[2], "after-missing"));
  program.cleanup.push(
    ...objects.flatMap((name, index) =>
      objectCleanup(
        binding,
        name,
        `object-${index}`,
        `subject-${["true", "false", "missing"][index]}`,
      ),
    ),
    ...documentCleanup(document, "doc", ["doc-create-true", "doc-update-false"]),
  );
  return program;
}

function existsProgram(binding, run) {
  const id = "firestore-exists-transition";
  const prefix = `${binding.prefix}${id}/`;
  const document = documentName(`${run}-exists-a`);
  const docId = document.slice(`${docRoot}/`.length);
  const object = `${prefix}${docId}/object.bin`;
  const expression = "firestore.exists(/databases/(default)/documents/STORAGE-RULES/$(doc))";
  const program = programBase(
    id,
    "firestore-exists",
    binding,
    [document],
    [object],
    rulesSource(prefix, "{doc}/{file=**}", expression, "get"),
  );
  program.steps.push(...objectReads(binding, object, "baseline", "absent"));
  program.steps.push(step("seed-object", storageRequest(binding, "seed-object", object, "upload")));
  program.steps.push(...objectReads(binding, object, "before", "present"));
  program.steps.push(
    step("doc-absence", firestoreRequest("doc-absence", document, "GET"), "absent"),
  );
  program.steps.push(
    step("doc-create", firestoreRequest("doc-create", document, "POST", { allowed: true })),
  );
  program.steps.push(
    step(
      "doc-read-present",
      firestoreRequest("doc-read-present", document, "GET"),
      "present-allowed-true",
    ),
  );
  program.steps.push(
    step(
      "subject-present",
      storageRequest(binding, "subject-present", object, "get-media", "user-a"),
    ),
  );
  program.steps.push(...objectReads(binding, object, "after-present"));
  program.steps.push(
    step(
      "doc-delete",
      firestoreRequest("doc-delete", document, "DELETE", {
        updateTime: updateTimeRef("doc-read-present", document),
      }),
    ),
  );
  program.steps.push(
    step("doc-read-missing", firestoreRequest("doc-read-missing", document, "GET"), "absent"),
  );
  program.steps.push(
    step(
      "subject-missing",
      storageRequest(binding, "subject-missing", object, "get-media", "user-a"),
    ),
  );
  program.steps.push(...objectReads(binding, object, "after-missing"));
  program.cleanup.push(
    ...objectCleanup(binding, object, "object", "seed-object"),
    ...documentCleanup(document, "doc", ["doc-create"]),
  );
  return program;
}

function budgetProgram(binding, run, kind, order) {
  const id = `firestore-budget-${kind}`;
  const prefix = `${binding.prefix}${id}/`;
  const letters = [...new Set(order)];
  const names = Object.fromEntries(
    ["a", "b", "c"].map((letter) => [letter, documentName(`${run}-budget-${kind}-${letter}`)]),
  );
  const object = `${prefix}${["a", "b", "c"].map((letter) => names[letter].slice(`${docRoot}/`.length)).join("/")}/object.bin`;
  const terms = order.map(
    (letter) => `firestore.exists(/databases/(default)/documents/STORAGE-RULES/$(${letter}))`,
  );
  const source = rulesSource(prefix, "{a}/{b}/{c}/{file=**}", terms.join(" && "), "get");
  const program = programBase(
    id,
    "firestore-access-budget",
    binding,
    letters.map((letter) => names[letter]),
    [object],
    source,
    order,
  );
  program.steps.push(...objectReads(binding, object, "baseline", "absent"));
  program.steps.push(step("seed-object", storageRequest(binding, "seed-object", object, "upload")));
  program.steps.push(...objectReads(binding, object, "before", "present"));
  for (const letter of letters) {
    const name = names[letter];
    program.steps.push(
      step(
        `doc-absence-${letter}`,
        firestoreRequest(`doc-absence-${letter}`, name, "GET"),
        "absent",
      ),
    );
    program.steps.push(
      step(
        `doc-create-${letter}`,
        firestoreRequest(`doc-create-${letter}`, name, "POST", { allowed: true }),
      ),
    );
    program.steps.push(
      step(
        `doc-read-${letter}`,
        firestoreRequest(`doc-read-${letter}`, name, "GET"),
        "present-allowed-true",
      ),
    );
  }
  program.steps.push(
    step("subject", storageRequest(binding, "subject", object, "get-media", "user-a")),
  );
  program.steps.push(...objectReads(binding, object, "after"));
  program.cleanup.push(
    ...objectCleanup(binding, object, "object", "seed-object"),
    ...letters.flatMap((letter) =>
      documentCleanup(names[letter], `doc-${letter}`, [`doc-create-${letter}`]),
    ),
  );
  return program;
}

/** Static cross-service inputs only; no credential loader, sender, publisher, or result comparator. */
export function buildFirestorePrograms(binding) {
  const run = binding.prefix.split("/")[1];
  return [
    getProgram(binding, run),
    existsProgram(binding, run),
    budgetProgram(binding, run, "two", ["a", "b"]),
    budgetProgram(binding, run, "three", ["a", "b", "c"]),
    budgetProgram(binding, run, "repeat", ["a", "b", "a"]),
  ];
}

export function countFirestoreProgramRequests(programs) {
  const counts = { storage: 0, firestore: 0 };
  for (const program of programs)
    for (const entry of [...program.steps, ...program.cleanup]) counts[entry.request.service]++;
  return counts;
}
