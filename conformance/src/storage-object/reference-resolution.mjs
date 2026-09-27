const FIELD_BY_QUERY = Object.freeze({
  generation: "generation",
  ifGenerationMatch: "generation",
  ifGenerationNotMatch: "generation",
  ifMetagenerationMatch: "metageneration",
  ifMetagenerationNotMatch: "metageneration",
  ifSourceGenerationMatch: "generation",
  ifSourceMetagenerationMatch: "metageneration",
});
const MAX_METADATA_BYTES = 1024 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });

function reject(code) {
  const error = new Error(`Storage object reference resolution rejected: ${code}`);
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

function readMetadata(response, objectName, bucket) {
  if (
    !plainObject(response) ||
    response.status !== 200 ||
    typeof response.bodyBase64 !== "string" ||
    response.bodyBase64.length > Math.ceil(MAX_METADATA_BYTES / 3) * 4
  ) {
    reject("INVALID_EVIDENCE");
  }
  const bytes = Buffer.from(response.bodyBase64, "base64");
  if (bytes.length > MAX_METADATA_BYTES || bytes.toString("base64") !== response.bodyBase64) {
    reject("INVALID_EVIDENCE");
  }
  let body;
  try {
    body = JSON.parse(decoder.decode(bytes));
  } catch {
    reject("INVALID_EVIDENCE");
  }
  if (!plainObject(body)) reject("INVALID_EVIDENCE");
  if (body.kind !== "storage#object" || body.bucket !== bucket || body.name !== objectName) {
    reject("EVIDENCE_IDENTITY_MISMATCH");
  }
  return body;
}

function resolveReference({ key, reference, recipe, stepIndex, step, responses, bucket }) {
  if (
    !plainObject(reference) ||
    Object.keys(reference).sort().join(",") !== "field,format,kind,step" ||
    reference.kind !== "metadata-field" ||
    reference.format !== "positive-decimal-string" ||
    reference.field !== FIELD_BY_QUERY[key] ||
    typeof reference.step !== "string"
  ) {
    reject("INVALID_REFERENCE");
  }
  const sources = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)].filter(
    (candidate) => candidate.id === reference.step,
  );
  if (sources.length !== 1) reject("INVALID_REFERENCE");
  const source = sources[0];
  const objectName = key.startsWith("ifSource") ? step.transfer.sourceName : step.objectName;
  if (
    source.objectName !== objectName ||
    source.dialect !== "gcs" ||
    source.method !== "GET" ||
    !plainObject(source.query) ||
    Object.keys(source.query).length !== 0 ||
    source.path !== `/storage/v1/b/${bucket}/o/${encodeURIComponent(objectName)}`
  ) {
    reject("INVALID_REFERENCE");
  }
  if (!responses.has(reference.step)) reject("MISSING_EVIDENCE");
  const value = readMetadata(responses.get(reference.step), objectName, bucket)[reference.field];
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) reject("INVALID_FIELD");
  return value;
}

// This only resolves declared query data. It does not evaluate state prerequisites or authorize a send.
export function resolveDeclaredQuery({ recipe, stepIndex, responses, bucket }) {
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
    reject("INVALID_REFERENCE");
  }
  const step = recipe.steps[stepIndex];
  if (!plainObject(step) || !recipe.objects.includes(step.objectName) || !plainObject(step.query))
    reject("INVALID_REFERENCE");
  if (Object.values(step.query).some((value) => typeof value !== "string")) {
    const root = `/storage/v1/b/${bucket}/o`;
    let expectedPath =
      step.method === "POST" ? `/upload${root}` : `${root}/${encodeURIComponent(step.objectName)}`;
    if (step.transfer !== undefined) {
      if (
        !plainObject(step.transfer) ||
        !["copyTo", "rewriteTo"].includes(step.transfer.operation) ||
        !recipe.objects.includes(step.transfer.sourceName) ||
        step.transfer.destinationName !== step.objectName ||
        step.method !== "POST"
      )
        reject("INVALID_REFERENCE");
      expectedPath = `${root}/${encodeURIComponent(step.transfer.sourceName)}/${step.transfer.operation}/b/${bucket}/o/${encodeURIComponent(step.objectName)}`;
    } else if (Object.keys(step.query).some((key) => key.startsWith("ifSource"))) {
      reject("INVALID_REFERENCE");
    }
    if (
      step.dialect !== "gcs" ||
      !["GET", "POST", "PATCH", "PUT", "DELETE"].includes(step.method) ||
      step.path !== expectedPath ||
      (step.method === "POST" && step.transfer === undefined && step.query.name !== step.objectName)
    )
      reject("INVALID_REFERENCE");
  }
  return Object.fromEntries(
    Object.entries(step.query).map(([key, value]) => {
      if (typeof value === "string") return [key, value];
      return [
        key,
        resolveReference({ key, reference: value, recipe, stepIndex, step, responses, bucket }),
      ];
    }),
  );
}
