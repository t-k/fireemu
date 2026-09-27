import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { buildCorpus } from "./corpus.mjs";

const MAX_URI_BYTES = 8192;
const RESUMABLE_OBJECT_SUFFIX = "gcs/resumable.bin";

function reject(code) {
  const error = new Error(`Storage object session location rejected: ${code}`);
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

// The digest classifies supplied private bytes; it is never a session capability or send admission.
export function evaluateSuppliedSessionLocation({ recipe, response, bucket }) {
  if (
    !plainObject(recipe) ||
    recipe.id !== "storage-object/gcs/resumable-upload" ||
    !Array.isArray(recipe.objects) ||
    recipe.objects.length !== 1 ||
    !Array.isArray(recipe.steps) ||
    recipe.steps.length !== 8 ||
    !recipe.steps.every(plainObject) ||
    recipe.sessionUriHandling !== "private-only" ||
    recipe.sendAuthorized !== false ||
    recipe.cleanupAuthorized !== false ||
    typeof bucket !== "string" ||
    !bucket
  )
    reject("INVALID_DECLARATION");
  const initiate = recipe.steps[0];
  const name = recipe.objects[0];
  if (typeof name !== "string" || !name.endsWith(RESUMABLE_OBJECT_SUFFIX))
    reject("INVALID_DECLARATION");
  const expectedPath = `/upload/storage/v1/b/${bucket}/o`;
  if (
    !plainObject(initiate) ||
    initiate.id !== "initiate" ||
    recipe.steps.filter((step) => step?.id === "initiate").length !== 1 ||
    initiate.objectName !== name ||
    initiate.method !== "POST" ||
    initiate.dialect !== "gcs" ||
    initiate.credential !== "admin" ||
    initiate.path !== expectedPath ||
    !plainObject(initiate.query) ||
    Object.keys(initiate.query).length !== 3 ||
    initiate.query.uploadType !== "resumable" ||
    initiate.query.name !== name ||
    initiate.query.ifGenerationMatch !== "0" ||
    initiate.responseCapture?.headers !== "all"
  )
    reject("INVALID_DECLARATION");
  const expectedReference = {
    kind: "gcs-resumable-location",
    initiateStep: "initiate",
    expectedOrigin: "https://storage.googleapis.com",
    expectedPath,
    expectedName: name,
    secretHandling: "private-only",
  };
  for (const [index, id] of ["chunk-0", "query-progress", "finish"].entries()) {
    const step = recipe.steps[index + 1];
    if (
      !plainObject(step) ||
      step.id !== id ||
      step.method !== "PUT" ||
      step.dialect !== "gcs" ||
      step.objectName !== name ||
      step.path !== undefined ||
      step.credential !== "admin" ||
      !plainObject(step.sessionUriReference) ||
      Object.keys(step.sessionUriReference).length !== Object.keys(expectedReference).length ||
      Object.entries(expectedReference).some(
        ([key, value]) => step.sessionUriReference[key] !== value,
      )
    )
      reject("INVALID_DECLARATION");
  }
  // Structural equality binds every request field and continuation to the locally generated recipe.
  let matchesCanonicalRecipe = false;
  try {
    const prefix = name.slice(0, -RESUMABLE_OBJECT_SUFFIX.length);
    const canonical = buildCorpus({ bucket, prefix }).recipes.find(
      (row) => row.id === "storage-object/gcs/resumable-upload",
    );
    matchesCanonicalRecipe = isDeepStrictEqual(recipe, canonical);
  } catch {
    reject("INVALID_DECLARATION");
  }
  if (!matchesCanonicalRecipe) reject("INVALID_DECLARATION");
  if (
    !plainObject(response) ||
    response.status !== 200 ||
    !plainObject(response.headers) ||
    response.bodyBase64 !== ""
  )
    reject("INVALID_EVIDENCE");
  const locationHeaders = Object.entries(response.headers).filter(
    ([key]) => key.toLowerCase() === "location",
  );
  if (locationHeaders.length !== 1) reject("INVALID_EVIDENCE");
  const location = locationHeaders[0][1];
  if (
    typeof location !== "string" ||
    !location ||
    Buffer.byteLength(location) > MAX_URI_BYTES ||
    /\s/.test(location) ||
    [...location].some((char) => char.codePointAt(0) < 32 || char.codePointAt(0) === 127)
  )
    reject("INVALID_EVIDENCE");
  let url;
  try {
    url = new URL(location);
  } catch {
    reject("INVALID_LOCATION");
  }
  if (
    url.href !== location ||
    url.protocol !== "https:" ||
    url.origin !== "https://storage.googleapis.com" ||
    url.username ||
    url.password ||
    url.port ||
    url.hash ||
    url.pathname !== expectedPath
  )
    reject("INVALID_LOCATION");
  const params = url.searchParams;
  const keys = [...params.keys()];
  const uploadId = params.get("upload_id");
  if (
    keys.length !== 3 ||
    new Set(keys).size !== 3 ||
    params.get("uploadType") !== "resumable" ||
    params.get("name") !== name ||
    typeof uploadId !== "string" ||
    !/^[A-Za-z0-9_-]{1,4096}$/.test(uploadId)
  )
    reject("INVALID_LOCATION");
  return Object.freeze({
    status: "MATCHED_SUPPLIED_PRIVATE_SESSION_LOCATION",
    sessionUriSha256: createHash("sha256").update(location).digest("hex"),
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
}
