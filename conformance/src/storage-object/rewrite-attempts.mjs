const MAX_BODY_BYTES = 1024 * 1024;
const MAX_TOKEN_BYTES = 4096;
const MAX_U64 = (1n << 64n) - 1n;
const decoder = new TextDecoder("utf-8", { fatal: true });

function reject(code) {
  const error = new Error(`Supplied rewrite sequence rejected: ${code}`);
  error.code = code;
  throw error;
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, keys) {
  return plain(value) && Object.keys(value).toSorted().join(",") === keys.toSorted().join(",");
}

function unsignedLong(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 20)
    reject("INVALID_PROGRESS");
  const number = BigInt(value);
  if (number > MAX_U64) reject("INVALID_PROGRESS");
  return number;
}

function positiveLong(value) {
  const number = unsignedLong(value);
  if (number === 0n) reject("INVALID_QUERY");
  return number;
}

function readBody(record) {
  if (
    !plain(record) ||
    record.status !== 200 ||
    typeof record.bodyBase64 !== "string" ||
    record.bodyBase64.length > Math.ceil(MAX_BODY_BYTES / 3) * 4
  )
    reject("INVALID_RESPONSE");
  const bytes = Buffer.from(record.bodyBase64, "base64");
  if (bytes.length > MAX_BODY_BYTES || bytes.toString("base64") !== record.bodyBase64)
    reject("INVALID_RESPONSE");
  let result;
  try {
    result = JSON.parse(decoder.decode(bytes));
  } catch {
    reject("INVALID_RESPONSE");
  }
  if (
    !plain(result) ||
    result.kind !== "storage#rewriteResponse" ||
    typeof result.done !== "boolean"
  )
    reject("INVALID_RESPONSE");
  return result;
}

function declaredSlots(recipe, bucket) {
  if (
    !plain(recipe) ||
    recipe.id !== "storage-object/gcs/copy-rewrite" ||
    !Array.isArray(recipe.objects) ||
    !Array.isArray(recipe.steps) ||
    !plain(recipe.rewritePagination) ||
    !Array.isArray(recipe.rewritePagination.stepIds) ||
    recipe.rewritePagination.maxCalls !== 8 ||
    recipe.rewritePagination.stepIds.length !== 8 ||
    recipe.rewritePagination.completeOnlyWhenDone !== true
  )
    reject("INVALID_DECLARATION");
  const ids = recipe.rewritePagination.stepIds;
  const slots = ids.map((id, index) => {
    if (id !== `rewrite-${index}`) reject("INVALID_DECLARATION");
    const found = recipe.steps.filter((step) => step.id === id);
    if (found.length !== 1) reject("INVALID_DECLARATION");
    return found[0];
  });
  const first = slots[0];
  if (
    !plain(first.transfer) ||
    first.transfer.operation !== "rewriteTo" ||
    !recipe.objects.includes(first.transfer.sourceName) ||
    !recipe.objects.includes(first.transfer.destinationName) ||
    first.transfer.sourceName === first.transfer.destinationName ||
    first.objectName !== first.transfer.destinationName ||
    !exactKeys(first.query, [
      "ifGenerationMatch",
      "ifSourceGenerationMatch",
      "ifSourceMetagenerationMatch",
    ]) ||
    first.query.ifGenerationMatch !== "0" ||
    !exactKeys(first.headers, ["content-type"]) ||
    first.headers["content-type"] !== "application/json" ||
    !exactKeys(first.body, ["json"]) ||
    !exactKeys(first.body.json, ["contentType", "metadata"]) ||
    first.body.json.contentType !== "text/plain" ||
    !exactKeys(first.body.json.metadata, ["marker"]) ||
    first.body.json.metadata.marker !== "rewrite-override"
  )
    reject("INVALID_DECLARATION");
  const sourceReadId = first.query.ifSourceGenerationMatch?.step;
  for (const [key, field] of [
    ["ifSourceGenerationMatch", "generation"],
    ["ifSourceMetagenerationMatch", "metageneration"],
  ]) {
    const ref = first.query[key];
    if (
      !exactKeys(ref, ["kind", "step", "field", "format"]) ||
      ref.kind !== "metadata-field" ||
      ref.step !== sourceReadId ||
      ref.field !== field ||
      ref.format !== "positive-decimal-string"
    )
      reject("INVALID_DECLARATION");
  }
  const firstIndex = recipe.steps.indexOf(first);
  const reads = recipe.steps.slice(0, firstIndex).filter((step) => step.id === sourceReadId);
  if (
    reads.length !== 1 ||
    reads[0].dialect !== "gcs" ||
    reads[0].method !== "GET" ||
    reads[0].objectName !== first.transfer.sourceName ||
    reads[0].path !==
      `/storage/v1/b/${bucket}/o/${encodeURIComponent(first.transfer.sourceName)}` ||
    !exactKeys(reads[0].query, [])
  )
    reject("INVALID_DECLARATION");
  for (const [index, step] of slots.entries()) {
    const expectedPath = `/storage/v1/b/${bucket}/o/${encodeURIComponent(first.transfer.sourceName)}/rewriteTo/b/${bucket}/o/${encodeURIComponent(first.transfer.destinationName)}`;
    if (
      step.dialect !== "gcs" ||
      step.method !== "POST" ||
      step.credential !== "admin" ||
      step.path !== expectedPath ||
      step.objectName !== first.objectName ||
      !plain(step.transfer) ||
      Object.keys(step.transfer).toSorted().join(",") !== "destinationName,operation,sourceName" ||
      Object.entries(first.transfer).some(([key, value]) => step.transfer[key] !== value)
    )
      reject("INVALID_DECLARATION");
    if (index === 0) continue;
    if (
      !exactKeys(step.query, []) ||
      !exactKeys(step.continuation, [
        "kind",
        "sourceStep",
        "targetQuery",
        "whenDone",
        "maxTokenBytes",
      ]) ||
      step.continuation.kind !== "rewrite-token" ||
      step.continuation.sourceStep !== ids[index - 1] ||
      step.continuation.targetQuery !== "rewriteToken" ||
      step.continuation.whenDone !== false ||
      step.continuation.maxTokenBytes !== MAX_TOKEN_BYTES ||
      !exactKeys(step.headers, []) ||
      step.body !== undefined
    )
      reject("INVALID_DECLARATION");
  }
  return slots;
}

// This checks caller-supplied records only; it cannot establish HTTP provenance or authorize a send.
function evaluateSequence({ recipe, attempts, bucket }, requireCompletion) {
  if (typeof bucket !== "string" || !bucket) reject("INVALID_INPUT");
  const slots = declaredSlots(recipe, bucket);
  if (!Array.isArray(attempts) || attempts.length === 0 || attempts.length > slots.length)
    reject("INVALID_SEQUENCE");
  let precedingToken;
  let previousTotal = 0n;
  let firstSize;
  for (const [index, record] of attempts.entries()) {
    if (!plain(record) || record.stepId !== slots[index].id || !plain(record.query))
      reject("INVALID_SEQUENCE");
    if (index === 0) {
      if (
        !exactKeys(record.query, [
          "ifGenerationMatch",
          "ifSourceGenerationMatch",
          "ifSourceMetagenerationMatch",
        ]) ||
        record.query.ifGenerationMatch !== "0"
      )
        reject("INVALID_QUERY");
      positiveLong(record.query.ifSourceGenerationMatch);
      positiveLong(record.query.ifSourceMetagenerationMatch);
    } else if (
      !exactKeys(record.query, ["rewriteToken"]) ||
      record.query.rewriteToken !== precedingToken
    )
      reject("INVALID_QUERY");
    const body = readBody(record);
    const total = unsignedLong(body.totalBytesRewritten);
    const size = unsignedLong(body.objectSize);
    if (total > size || total < previousTotal || (firstSize !== undefined && size !== firstSize))
      reject("INVALID_PROGRESS");
    if (firstSize === undefined) firstSize = size;
    previousTotal = total;
    if (body.done) {
      if (
        index !== attempts.length - 1 ||
        total !== size ||
        body.rewriteToken !== undefined ||
        !plain(body.resource) ||
        body.resource.kind !== "storage#object" ||
        body.resource.bucket !== bucket ||
        body.resource.name !== slots[0].transfer.destinationName ||
        body.resource.size !== body.objectSize
      )
        reject("INVALID_COMPLETION");
      positiveLong(body.resource.generation);
      const result = {
        status: "MATCHED_SUPPLIED_REWRITE",
        attempts: attempts.length,
        objectSize: body.objectSize,
        destinationName: body.resource.name,
        sendAuthorized: false,
        cleanupAuthorized: false,
      };
      return Object.freeze(requireCompletion ? result : { ...result, done: true });
    }
    if (
      typeof body.rewriteToken !== "string" ||
      body.rewriteToken.length === 0 ||
      Buffer.byteLength(body.rewriteToken, "utf8") > MAX_TOKEN_BYTES ||
      body.resource !== undefined
    )
      reject("INVALID_CONTINUATION");
    precedingToken = body.rewriteToken;
  }
  if (requireCompletion) reject("INCOMPLETE_REWRITE");
  return Object.freeze({
    status: "MATCHED_SUPPLIED_REWRITE_PROGRESS",
    done: false,
    attempts: attempts.length,
    rewriteToken: precedingToken,
    objectSize: firstSize.toString(),
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
}

export function evaluateRewriteAttempts(input) {
  return evaluateSequence(input, true);
}

/** Inspect supplied progress only. Any continuation token must remain private. */
export function evaluateRewriteProgress(input) {
  return evaluateSequence(input, false);
}

export function validateRewriteDeclaration({ recipe, bucket }) {
  return Object.freeze(declaredSlots(recipe, bucket).map((step) => step.id));
}
