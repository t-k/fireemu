const MAX_BODY_BYTES = 1024 * 1024;
const MATCHED = Object.freeze({
  status: "MATCHED_SUPPLIED_404_READS",
  sendAuthorized: false,
  cleanupAuthorized: false,
});

function reject(code) {
  const error = new Error(`Storage object supplied-404 check rejected: ${code}`);
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

function checkRaw404(response) {
  if (!plainObject(response) || response.status !== 404) reject("NOT_SUPPLIED_404");
  if (
    typeof response.bodyBase64 !== "string" ||
    response.bodyBase64.length > Math.ceil(MAX_BODY_BYTES / 3) * 4
  )
    reject("INVALID_EVIDENCE");
  const body = Buffer.from(response.bodyBase64, "base64");
  if (body.length > MAX_BODY_BYTES || body.toString("base64") !== response.bodyBase64)
    reject("INVALID_EVIDENCE");
}

// This classifies only supplied raw 404 reads. It does not prove absence or admit a send.
export function evaluateSupplied404Reads({ recipe, stepIndex, responses, bucket }) {
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
  )
    reject("INVALID_DECLARATION");
  const step = recipe.steps[stepIndex];
  const required = step?.requires;
  if (
    !plainObject(step) ||
    !plainObject(required) ||
    recipe.id !== "storage-object/gcs/generation-preconditions" ||
    required.state !== "absent" ||
    !recipe.objects.includes(step.objectName) ||
    !plainObject(step.preconditionCase) ||
    step.preconditionCase.sample !== "zero-absent" ||
    step.dialect !== "gcs" ||
    step.credential !== "admin" ||
    !["GET", "POST", "DELETE"].includes(step.method) ||
    !plainObject(step.query) ||
    !plainObject(step.headers) ||
    required.bodyBase64 !== null ||
    !Array.isArray(required.relations) ||
    required.relations.length !== 0 ||
    required.metadataSubset !== undefined ||
    !Array.isArray(required.metadata) ||
    required.metadata.length !== 2 ||
    !Array.isArray(required.media) ||
    required.media.length !== 2
  )
    reject("INVALID_DECLARATION");
  const root = `/storage/v1/b/${bucket}/o`;
  const expectedPath =
    step.method === "POST" ? `/upload${root}` : `${root}/${encodeURIComponent(step.objectName)}`;
  const guard = ["ifGenerationMatch", "ifGenerationNotMatch"].filter((key) =>
    Object.hasOwn(step.query, key),
  );
  const expectedQueryKeys =
    step.method === "POST"
      ? ["uploadType", "name", guard[0]]
      : step.query.alt === "media"
        ? ["alt", guard[0]]
        : [guard[0]];
  const expectedOperation =
    step.method === "POST"
      ? "upload"
      : step.method === "DELETE"
        ? "delete"
        : step.query.alt === "media"
          ? "media-read"
          : "metadata-read";
  if (
    step.id !== `${expectedOperation}-${guard[0]}-zero-absent` ||
    [...recipe.preflight, ...recipe.steps].filter((row) => row.id === step.id).length !== 1 ||
    step.path !== expectedPath ||
    guard.length !== 1 ||
    step.preconditionCase.guard !== guard[0] ||
    step.preconditionCase.operation !== expectedOperation ||
    step.query[guard[0]] !== "0" ||
    Object.keys(step.query).length !== expectedQueryKeys.length ||
    expectedQueryKeys.some((key) => !Object.hasOwn(step.query, key)) ||
    (step.method === "POST" &&
      (step.query.uploadType !== "media" || step.query.name !== step.objectName)) ||
    (step.method === "DELETE" && step.query.alt !== undefined) ||
    (step.method === "GET" && step.query.alt !== undefined && step.query.alt !== "media") ||
    Object.keys(step.headers).some((key) => key.toLowerCase() === "range")
  )
    reject("INVALID_DECLARATION");
  const prior = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)];
  function source(id, kind) {
    if (typeof id !== "string") reject("INVALID_DECLARATION");
    const matches = prior.filter((row) => row.id === id);
    if (matches.length !== 1) reject("INVALID_DECLARATION");
    const row = matches[0];
    if (
      !["firebase", "gcs"].includes(row.dialect) ||
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
    )
      reject("INVALID_DECLARATION");
    if (!responses.has(id)) reject("MISSING_EVIDENCE");
    checkRaw404(responses.get(id));
    return row.dialect;
  }
  const metadataDialects = new Set(required.metadata.map((id) => source(id, "metadata")));
  const mediaDialects = new Set(required.media.map((id) => source(id, "media")));
  if (
    metadataDialects.size !== 2 ||
    mediaDialects.size !== 2 ||
    [...metadataDialects].some((dialect) => !mediaDialects.has(dialect))
  )
    reject("INVALID_DECLARATION");
  return MATCHED;
}
