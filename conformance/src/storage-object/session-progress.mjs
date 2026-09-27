import { isDeepStrictEqual } from "node:util";
import { buildCorpus } from "./corpus.mjs";

const RESUMABLE_OBJECT_SUFFIX = "gcs/resumable.bin";

function reject(code) {
  const error = new Error(`Storage object session progress rejected: ${code}`);
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

// This classifies supplied bytes only; it cannot admit a continuation request.
export function evaluateSuppliedExactStatusRange({ recipe, response, bucket }) {
  if (
    !plainObject(recipe) ||
    recipe.id !== "storage-object/gcs/resumable-upload" ||
    !Array.isArray(recipe.objects) ||
    recipe.objects.length !== 1 ||
    !Array.isArray(recipe.steps) ||
    recipe.steps.length !== 8 ||
    !recipe.steps.every(plainObject) ||
    recipe.sendAuthorized !== false ||
    recipe.cleanupAuthorized !== false ||
    typeof bucket !== "string"
  )
    reject("INVALID_DECLARATION");
  const name = recipe.objects[0];
  if (typeof name !== "string" || !name.endsWith(RESUMABLE_OBJECT_SUFFIX))
    reject("INVALID_DECLARATION");
  let expectedRange;
  try {
    const prefix = name.slice(0, -RESUMABLE_OBJECT_SUFFIX.length);
    const canonical = buildCorpus({ bucket, prefix }).recipes.find(
      (row) => row.id === "storage-object/gcs/resumable-upload",
    );
    if (!isDeepStrictEqual(recipe, canonical)) reject("INVALID_DECLARATION");
    expectedRange = canonical.steps[3].continuation.range;
  } catch {
    reject("INVALID_DECLARATION");
  }
  if (
    !plainObject(response) ||
    response.status !== 308 ||
    !plainObject(response.headers) ||
    response.bodyBase64 !== ""
  )
    reject("INVALID_EVIDENCE");
  let ranges;
  try {
    ranges = Object.getOwnPropertyNames(response.headers)
      .filter((key) => key.toLowerCase() === "range")
      .map((key) => response.headers[key]);
  } catch {
    reject("INVALID_RANGE");
  }
  if (ranges.length !== 1 || ranges[0] !== expectedRange) reject("INVALID_RANGE");
  return Object.freeze({
    status: "MATCHED_SUPPLIED_EXACT_STATUS_RANGE",
    persistedRange: expectedRange,
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
}
