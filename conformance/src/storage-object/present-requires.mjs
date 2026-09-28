const MAX_BODY_BYTES = 1024 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });
const MATCHED = Object.freeze({
  status: "MATCHED_SUPPLIED_RECORDS",
  sendAuthorized: false,
  cleanupAuthorized: false,
});

function reject(code) {
  const error = new Error(`Storage object present-state check rejected: ${code}`);
  error.code = code;
  throw error;
}

function plainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function rawBytes(response) {
  if (
    !plainObject(response) ||
    response.status !== 200 ||
    typeof response.bodyBase64 !== "string" ||
    response.bodyBase64.length > Math.ceil(MAX_BODY_BYTES / 3) * 4
  ) {
    reject("INVALID_EVIDENCE");
  }
  const bytes = Buffer.from(response.bodyBase64, "base64");
  if (bytes.length > MAX_BODY_BYTES || bytes.toString("base64") !== response.bodyBase64) {
    reject("INVALID_EVIDENCE");
  }
  return bytes;
}

function metadataBody(response, name, bucket, dialect = "gcs") {
  let body;
  try {
    body = JSON.parse(decoder.decode(rawBytes(response)));
  } catch {
    reject("INVALID_EVIDENCE");
  }
  if (
    !plainObject(body) ||
    ((dialect === "gcs" || Object.hasOwn(body, "kind")) && typeof body.kind !== "string") ||
    typeof body.name !== "string" ||
    typeof body.bucket !== "string"
  ) {
    reject("INVALID_EVIDENCE");
  }
  if (
    (body.kind !== undefined && body.kind !== "storage#object") ||
    body.name !== name ||
    body.bucket !== bucket
  ) {
    reject("EVIDENCE_IDENTITY_MISMATCH");
  }
  return body;
}

function decimalField(body, field) {
  const value = body[field];
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) reject("INVALID_EVIDENCE");
  return value;
}

function subsetMatches(actual, expected) {
  if (plainObject(expected)) {
    return (
      plainObject(actual) &&
      Object.entries(expected).every(([key, value]) => subsetMatches(actual[key], value))
    );
  }
  return Object.is(actual, expected);
}

// The returned record only describes supplied bytes. It is never a request or cleanup admission.
export function evaluatePresentRequires({ recipe, stepIndex, responses, bucket }) {
  if (
    !plainObject(recipe) ||
    !Array.isArray(recipe.preflight) ||
    !Array.isArray(recipe.steps) ||
    !Array.isArray(recipe.objects) ||
    !Number.isInteger(stepIndex) ||
    stepIndex < 0 ||
    stepIndex >= recipe.steps.length ||
    !(responses instanceof Map) ||
    typeof bucket !== "string" ||
    !bucket
  ) {
    reject("INVALID_DECLARATION");
  }
  const step = recipe.steps[stepIndex];
  const required = step?.requires;
  if (!plainObject(step) || !plainObject(required) || !recipe.objects.includes(step.objectName))
    reject("INVALID_DECLARATION");
  if (required.state === "absent") reject("ABSENCE_UNPROVEN");
  if (
    required.state !== "present" ||
    !Array.isArray(required.metadata) ||
    !Array.isArray(required.media) ||
    !Array.isArray(required.relations) ||
    required.metadata.length < 1 ||
    required.metadata.length > 2 ||
    required.media.length < 1 ||
    required.media.length > 2 ||
    typeof required.bodyBase64 !== "string" ||
    (required.metadataSubset !== undefined && !plainObject(required.metadataSubset))
  ) {
    reject("INVALID_DECLARATION");
  }
  const root = `/storage/v1/b/${bucket}/o`;
  const targetPath =
    step.method === "POST" ? `/upload${root}` : `${root}/${encodeURIComponent(step.objectName)}`;
  if (
    step.dialect !== "gcs" ||
    !["GET", "POST", "PATCH", "PUT", "DELETE"].includes(step.method) ||
    step.path !== targetPath ||
    (step.method === "POST" && step.query?.name !== step.objectName)
  ) {
    reject("INVALID_DECLARATION");
  }
  const prior = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)];
  function source(id, kind, dialect) {
    if (typeof id !== "string") reject("INVALID_DECLARATION");
    const matches = prior.filter((row) => row.id === id);
    if (matches.length !== 1) reject("INVALID_DECLARATION");
    const row = matches[0];
    if (
      !["firebase", "gcs"].includes(row.dialect) ||
      (dialect && row.dialect !== dialect) ||
      row.objectName !== step.objectName ||
      row.credential !== "admin" ||
      row.method !== "GET" ||
      !plainObject(row.query) ||
      !plainObject(row.headers) ||
      Object.keys(row.query).length !== (kind === "media" ? 1 : 0) ||
      (kind === "media" && row.query.alt !== "media") ||
      Object.keys(row.headers).length !== 0 ||
      row.path !==
        `${row.dialect === "gcs" ? root : `/v0/b/${bucket}/o`}/${encodeURIComponent(step.objectName)}`
    ) {
      reject("INVALID_DECLARATION");
    }
    if (!responses.has(id)) reject("MISSING_EVIDENCE");
    return row;
  }
  const metadataDialects = new Set();
  for (const id of required.metadata) {
    const row = source(id, "metadata");
    if (metadataDialects.has(row.dialect)) reject("INVALID_DECLARATION");
    metadataDialects.add(row.dialect);
    const body = metadataBody(responses.get(id), step.objectName, bucket, row.dialect);
    if (required.metadataSubset && !subsetMatches(body, required.metadataSubset))
      reject("STATE_MISMATCH");
  }
  if (required.bodyBase64.length > Math.ceil(MAX_BODY_BYTES / 3) * 4) reject("INVALID_DECLARATION");
  const expectedBytes = Buffer.from(required.bodyBase64, "base64");
  if (
    expectedBytes.length > MAX_BODY_BYTES ||
    expectedBytes.toString("base64") !== required.bodyBase64
  )
    reject("INVALID_DECLARATION");
  const mediaDialects = new Set();
  for (const id of required.media) {
    const row = source(id, "media");
    if (mediaDialects.has(row.dialect)) reject("INVALID_DECLARATION");
    mediaDialects.add(row.dialect);
    if (!rawBytes(responses.get(id)).equals(expectedBytes)) reject("STATE_MISMATCH");
  }
  if (
    metadataDialects.size !== mediaDialects.size ||
    [...metadataDialects].some((dialect) => !mediaDialects.has(dialect))
  )
    reject("INVALID_DECLARATION");
  for (const relation of required.relations) {
    if (
      !plainObject(relation) ||
      !["generation", "metageneration"].includes(relation.field) ||
      !["equal", "different"].includes(relation.relation)
    )
      reject("INVALID_DECLARATION");
    source(relation.leftStep, "metadata", "gcs");
    source(relation.rightStep, "metadata", "gcs");
    const left = decimalField(
      metadataBody(responses.get(relation.leftStep), step.objectName, bucket),
      relation.field,
    );
    const right = decimalField(
      metadataBody(responses.get(relation.rightStep), step.objectName, bucket),
      relation.field,
    );
    if ((left === right) !== (relation.relation === "equal")) reject("RELATION_MISMATCH");
  }
  return MATCHED;
}
