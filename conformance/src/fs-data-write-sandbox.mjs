import { createHash } from "node:crypto";

import {
  WEBCHANNEL_PATH,
  WEBCHANNEL_RESET_PHASES,
  WEBCHANNEL_SESSION_SIZES,
  webchannelSessionProgram,
} from "./firestore-probe/webchannel-request-bytes.mjs";

const SANDBOX_DOCUMENTS = "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents";
const RECORDED_PROJECT = "demo-firestore-probe";
const MAX_REST_REQUESTS = 400;
const MAX_BODY_BYTES = 16_777_217;
const DELETE_RUN_MARKER = "DELETE_RUN_ID";
const DELETE_RUN_MARKER_VALUE = "a".repeat(32);
const DELETE_BOUNDARY_PREFIX = "writes/limits/near-limit-delete-refusal/";
const RESOURCE_NAME = /projects\/([^/]+)\/databases\/([^/?]+)/g;
const VOLATILE_STREAM_TRAILERS = new Set(["x-debug-tracking-id"]);
const DELTA_V3_DRIFT = new Set(
  ["rest", "batch-write"].flatMap((route) =>
    ["delete", "after-delete", "group-after-delete"].map(
      (step) => `writes/limits/near-limit-delete-refusal/${route}/12112#${step}`,
    ),
  ),
);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const BRACKET_SIZES = ["11534336", "11534337"];

/** The bracket recording: each unobserved request or value limit measured by one byte. */
export const BRACKET_REST_IDS = Object.freeze([
  "writes/limits/aggregate-map/1048487",
  "writes/limits/aggregate-map/1048488",
  "writes/limits/indexed-field-value-bytes/5200",
  "writes/limits/indexed-field-value-bytes/6128",
  ...["batch-write", "batch-get", "run-query", "create", "patch"].flatMap((route) =>
    BRACKET_SIZES.map((size) => `writes/limits/non-commit-rest-request-bytes/${route}/${size}`),
  ),
  ...BRACKET_SIZES.map((size) => `writes/limits/webchannel-request-bytes/${size}`),
]);

export const BRACKET_STREAM_IDS = Object.freeze(
  BRACKET_SIZES.map((size) => `writes/limits/grpc-unary-request-bytes/${size}`),
);

const indexedPairName = (pad) =>
  `ifvpair/r/p/${"z".repeat(800)}/p/${"z".repeat(800)}/p/${"z".repeat(pad)}/ifvtest/d`;

/** Every document the bracket recipes can create; cleanup deletes exactly these. */
export const BRACKET_OWNED_NAMES = Object.freeze(
  [
    ...["rawBatch", "rawBatchGet", "rawQuery", "rawCreate", "rawPatch"].flatMap((collection) =>
      BRACKET_SIZES.map((size) => `${collection}/${size}`),
    ),
    "aggregatePair/m1048487",
    "aggregatePair/m1048488",
    indexedPairName(960),
    indexedPairName(1424),
  ]
    .map((relative) => `projects/fireemu-oracle-sbx/databases/(default)/documents/${relative}`)
    .toSorted(),
);

/**
 * One bracket attempt: its 38 recipe requests, two preflight reads, one delete per owned name
 * and one typed-missing read. The child refuses any other cap.
 */
export const BRACKET_HTTP_CAP = 55;

/** The one collection a bracket probe reads whole; it must be empty before a recording. */
export const BRACKET_QUERIED_COLLECTION = "rawQuery";

/** `sandbox_expansion.name_of_length`: an even-segment relative name of exact UTF-8 length. */
export function nameOfLength(target, tag) {
  for (let pairs = 1; pairs < 12; pairs += 1) {
    const documentBytes = target - (2 * pairs - 1) - pairs;
    if (!(pairs <= documentBytes && documentBytes <= pairs * 1500)) continue;
    const segments = [];
    for (let index = 0; index < pairs; index += 1) {
      const length = Math.floor(documentBytes / pairs) + (index < documentBytes % pairs ? 1 : 0);
      segments.push("c", (index === 0 ? tag : "d").slice(0, length).padEnd(length, "d"));
    }
    const name = segments.join("/");
    if (Buffer.byteLength(name) === target) return name;
  }
  throw new Error(`cannot form a document name of ${target} bytes`);
}

/** (string bytes, relative name bytes) of the indexed-string follow-up points. */
export const INDEXED_STRING_NAME_POINTS = Object.freeze([
  [2999, 1142],
  [2999, 1143],
  [2999, 1500],
  [2999, 1800],
  [2999, 2100],
  [2999, 2400],
  [2999, 2606],
  [2999, 2607],
  [2000, 2141],
  [2000, 2142],
]);

const FOLLOWUP_WEBCHANNEL_SIZES = [12_582_912, 16_777_216, 16_777_217, 33_554_432, 33_554_433];

/** The follow-up to the bracket recording (D-2 WebChannel ladder, D-3 indexed strings). */
export const FOLLOWUP_REST_IDS = Object.freeze([
  ...FOLLOWUP_WEBCHANNEL_SIZES.map((size) => `writes/limits/webchannel-request-bytes/${size}`),
  ...INDEXED_STRING_NAME_POINTS.map(
    ([stringBytes, nameBytes]) => `writes/limits/indexed-string-name/${stringBytes}/${nameBytes}`,
  ),
]);

export const FOLLOWUP_OWNED_NAMES = Object.freeze(
  INDEXED_STRING_NAME_POINTS.map(
    ([stringBytes, nameBytes]) =>
      `projects/fireemu-oracle-sbx/databases/(default)/documents/${nameOfLength(nameBytes, `s${stringBytes}n${nameBytes}`)}`,
  ).toSorted(),
);

/**
 * A recording set pins its recipes, the documents its cleanup owns, its per-attempt HTTP cap
 * and its per-attempt ledger estimate. The runner and the child both check a recording
 * against exactly one set.
 */
export const RECORDING_SETS = Object.freeze({
  bracket: Object.freeze({
    restIds: BRACKET_REST_IDS,
    streamIds: BRACKET_STREAM_IDS,
    ownedNames: BRACKET_OWNED_NAMES,
    queriedCollection: BRACKET_QUERIED_COLLECTION,
    httpCap: BRACKET_HTTP_CAP,
    attemptEstimateUsd: 0.5,
  }),
  // Owner-approved follow-up: US$0.20 per attempt, two attempts within the remaining budget.
  followup: Object.freeze({
    restIds: FOLLOWUP_REST_IDS,
    streamIds: Object.freeze([]),
    ownedNames: FOLLOWUP_OWNED_NAMES,
    queriedCollection: null,
    httpCap: 52,
    attemptEstimateUsd: 0.2,
  }),
});

export function recordingSet(name) {
  const set = Object.hasOwn(RECORDING_SETS, name) ? RECORDING_SETS[name] : undefined;
  if (!set) throw new Error(`unknown recording set: ${name}`);
  return set;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

function comparableStream(result) {
  if (!result || typeof result !== "object") return result;
  const stripTransportTrailers = (value) =>
    value && Array.isArray(value.trailers)
      ? {
          ...value,
          trailers: value.trailers.filter((trailer) => !VOLATILE_STREAM_TRAILERS.has(trailer.key)),
        }
      : value;
  return {
    ...result,
    status: stripTransportTrailers(result.status),
    events: Array.isArray(result.events)
      ? result.events.map((event) =>
          ["status", "error"].includes(event?.type)
            ? { ...event, value: stripTransportTrailers(event.value) }
            : event,
        )
      : result.events,
  };
}

function assertSandboxReferences(value) {
  if (typeof value === "string") {
    for (const match of value.matchAll(RESOURCE_NAME)) {
      if (match[1] !== "fireemu-oracle-sbx" || match[2] !== "(default)") {
        throw new Error("request body escaped the sandbox project");
      }
    }
  } else if (Array.isArray(value)) {
    for (const item of value) assertSandboxReferences(item);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) assertSandboxReferences(item);
  }
}

/** A valid-session WebChannel program must be exactly its fixed four steps. */
function validateWebChannelSessionProgram(program) {
  const size = WEBCHANNEL_SESSION_SIZES.find(
    (candidate) => program.id === `writes/limits/webchannel-request-bytes/${candidate}`,
  );
  if (
    size === undefined ||
    JSON.stringify(program) !== JSON.stringify(webchannelSessionProgram(size))
  ) {
    throw new Error("invalid sandbox WebChannel session program");
  }
}

function validateDeleteBoundaryProgram(program) {
  const match =
    /^writes\/limits\/near-limit-delete-refusal\/(rest|commit|batch-write)\/(12112|12113)$/.exec(
      program.id,
    );
  if (!match) throw new Error("unsupported sandbox method");
  const [, route, countText] = match;
  const count = Number(countText);
  const [seed, before, deletion, after, group] = program.steps;
  const documentName = seed?.body?.writes?.[0]?.update?.name;
  const documentsPrefix = "projects/fireemu-oracle-sbx/databases/(default)/documents/";
  const normalizedName =
    typeof documentName === "string"
      ? documentName.replaceAll(DELETE_RUN_MARKER, DELETE_RUN_MARKER_VALUE)
      : "";
  const relativeName = normalizedName.startsWith(documentsPrefix)
    ? normalizedName.slice(documentsPrefix.length)
    : "";
  const [normalizedCollectionId, documentId, ...extra] = relativeName.split("/");
  const collectionId = documentName?.split("/documents/")[1]?.split("/")[0];
  const values = seed?.body?.writes?.[0]?.update?.fields?.a?.arrayValue?.values;
  const expectedCollectionPrefix = `del${route.replaceAll("-", "")}${countText}${DELETE_RUN_MARKER}`;
  if (
    program.steps.length !== 5 ||
    program.area !== "writes" ||
    !relativeName ||
    Buffer.byteLength(relativeName) !== 1000 ||
    extra.length !== 0 ||
    documentId !== "d" ||
    !normalizedCollectionId.startsWith(
      expectedCollectionPrefix.replace(DELETE_RUN_MARKER, DELETE_RUN_MARKER_VALUE),
    ) ||
    !/^[A-Za-z0-9_]+$/.test(normalizedCollectionId) ||
    seed?.id !== "seed" ||
    seed.method !== "POST" ||
    seed.path !== `${SANDBOX_DOCUMENTS}:commit` ||
    !Array.isArray(values) ||
    values.length !== count ||
    values.some((value, index) => value?.integerValue !== String(index)) ||
    before?.id !== "before-delete" ||
    before.method !== "GET" ||
    before.path !== `/v1/${documentName}` ||
    deletion?.id !== "delete" ||
    deletion.method !== (route === "rest" ? "DELETE" : "POST") ||
    deletion.path !==
      (route === "rest"
        ? `/v1/${documentName}`
        : `${SANDBOX_DOCUMENTS}:${route === "commit" ? "commit" : "batchWrite"}`) ||
    (route !== "rest" &&
      JSON.stringify(deletion.body) !== JSON.stringify({ writes: [{ delete: documentName }] })) ||
    after?.id !== "after-delete" ||
    after.method !== "POST" ||
    after.path !== `${SANDBOX_DOCUMENTS}:batchGet` ||
    JSON.stringify(after.body) !== JSON.stringify({ documents: [documentName] }) ||
    group?.id !== "group-after-delete" ||
    group.method !== "POST" ||
    group.path !== `${SANDBOX_DOCUMENTS}:runQuery` ||
    JSON.stringify(group.body) !==
      JSON.stringify({
        structuredQuery: {
          from: [{ collectionId, allDescendants: true }],
          select: { fields: [{ fieldPath: "__name__" }] },
          limit: 2,
        },
      })
  ) {
    throw new Error("invalid near-limit DELETE boundary recipe");
  }
}

/** Refuse any corpus that could address another Firestore project or escape its budget. */
/** Sizes whose bodies the corpus stores compact; the harness pads them before sending. */
export const PADDED_BODY_SIZES = new Set([11_534_336, 11_534_337]);

/** A compact JSON body padded with spaces before its last `}` to exactly `size` bytes. */
export function padJsonBody(body, size) {
  if (
    typeof body !== "string" ||
    !PADDED_BODY_SIZES.has(size) ||
    !body.endsWith("}") ||
    Buffer.byteLength(body) >= size
  ) {
    throw new Error("invalid padded sandbox body");
  }
  JSON.parse(body);
  const padded = `${body.slice(0, -1)}${" ".repeat(size - Buffer.byteLength(body))}}`;
  if (Buffer.byteLength(padded) !== size) throw new Error("padded sandbox body size differs");
  return padded;
}

export function validateSandboxCorpus(corpus) {
  if (corpus?.schemaVersion !== 1 || !Array.isArray(corpus.restPrograms)) {
    throw new Error("invalid sandbox corpus schema");
  }
  const programIds = new Set();
  let requestCount = 0;
  for (const program of corpus.restPrograms) {
    if (typeof program.id !== "string" || programIds.has(program.id)) {
      throw new Error("duplicate or missing sandbox program ID");
    }
    programIds.add(program.id);
    if (!Array.isArray(program.steps) || program.steps.length === 0) {
      throw new Error("empty sandbox program");
    }
    const isDeleteBoundary = program.id.startsWith(DELETE_BOUNDARY_PREFIX);
    if (isDeleteBoundary) validateDeleteBoundaryProgram(program);
    const sessionProgram =
      program.steps.some((step) => step.webchannelSession !== undefined) ||
      WEBCHANNEL_SESSION_SIZES.some(
        (size) => program.id === `writes/limits/webchannel-request-bytes/${size}`,
      );
    if (sessionProgram) validateWebChannelSessionProgram(program);
    const stepIds = new Set();
    for (const step of program.steps) {
      requestCount += 1;
      if (typeof step.id !== "string" || stepIds.has(step.id)) {
        throw new Error("duplicate or missing sandbox step ID");
      }
      stepIds.add(step.id);
      if (
        !["GET", "POST", "PATCH"].includes(step.method) &&
        !(isDeleteBoundary && program.id.endsWith("/rest/12112") && step.method === "DELETE") &&
        !(isDeleteBoundary && program.id.endsWith("/rest/12113") && step.method === "DELETE")
      ) {
        throw new Error("unsupported sandbox method");
      }
      const webchannel = sessionProgram || step.webchannelBodyBytes !== undefined;
      if (
        webchannel &&
        !sessionProgram &&
        (![10_485_760, 10_485_761].includes(step.webchannelBodyBytes) ||
          step.method !== "POST" ||
          step.id !== "unknown-session" ||
          program.steps.length !== 1 ||
          step.path !== WEBCHANNEL_PATH ||
          program.id !== `writes/limits/webchannel-request-bytes/${step.webchannelBodyBytes}` ||
          step.body !== undefined)
      ) {
        throw new Error("invalid sandbox WebChannel route or WebChannel body size");
      }
      if (
        typeof step.path !== "string" ||
        (!webchannel && !step.path.startsWith(SANDBOX_DOCUMENTS))
      ) {
        throw new Error("request escaped the sandbox project");
      }
      const pathname = step.path.split("?", 1)[0];
      if (new URL(step.path, "https://firestore.googleapis.com").pathname !== pathname) {
        throw new Error("request path traversal is not allowed");
      }
      assertSandboxReferences(step.path);
      if (step.headers && Object.keys(step.headers).length > 0) {
        throw new Error("sandbox corpus must not include credential headers");
      }
      if (step.padToBytes !== undefined) {
        if (
          !program.id.startsWith("writes/limits/non-commit-rest-request-bytes/") ||
          !["POST", "PATCH"].includes(step.method)
        ) {
          throw new Error("invalid padded sandbox body");
        }
        padJsonBody(step.body, step.padToBytes);
      }
      if (
        step.body !== undefined &&
        (step.padToBytes ?? Buffer.byteLength(JSON.stringify(step.body))) > MAX_BODY_BYTES
      ) {
        throw new Error("sandbox request exceeds the declared raw sentinel");
      }
      assertSandboxReferences(step.body);
    }
  }
  if (requestCount !== corpus.restRequestCount || requestCount > MAX_REST_REQUESTS) {
    throw new Error("sandbox request count differs from the bounded corpus");
  }
  return { requestCount };
}

/** A second recording must reproduce every normalized status, code and body. */
export function compareRecordings(first, second) {
  const differences = [];
  for (const programId of new Set([...Object.keys(first), ...Object.keys(second)])) {
    const left = first[programId]?.steps ?? {};
    const right = second[programId]?.steps ?? {};
    for (const stepId of new Set([...Object.keys(left), ...Object.keys(right)])) {
      if (JSON.stringify(canonical(left[stepId])) !== JSON.stringify(canonical(right[stepId]))) {
        differences.push(`${programId}#${stepId}`);
      }
    }
  }
  return differences.toSorted();
}

export function compareSandboxArtifact(production, localPrograms, localStreams, corpus) {
  const recipes = new Map((corpus?.restPrograms ?? []).map((program) => [program.id, program]));
  const batchGetName = (item) => item?.found?.name ?? item?.missing;
  const comparableBody = (body, programId, stepId) => {
    const recipe = recipes.get(programId)?.steps.find((step) => step.id === stepId);
    if (
      recipe?.method === "POST" &&
      recipe.path.split("?", 1)[0].endsWith(":batchGet") &&
      Array.isArray(body) &&
      body.length > 0 &&
      body.every((item) => typeof batchGetName(item) === "string")
    ) {
      return body.toSorted((left, right) =>
        batchGetName(left) < batchGetName(right)
          ? -1
          : batchGetName(left) > batchGetName(right)
            ? 1
            : 0,
      );
    }
    return body;
  };
  const differences = [];
  const expectedPrograms = production?.programs ?? {};
  for (const programId of new Set([
    ...Object.keys(expectedPrograms),
    ...Object.keys(localPrograms ?? {}),
  ])) {
    const actualSteps = localPrograms?.[programId]?.steps ?? {};
    const expected = expectedPrograms[programId];
    const alternatives = expected?.alternatives ?? [expected];
    const candidateDifferences = alternatives.map((alternative) => {
      const expectedSteps = alternative?.steps ?? {};
      const mismatches = [];
      for (const stepId of new Set([...Object.keys(expectedSteps), ...Object.keys(actualSteps)])) {
        const decision = (step) =>
          step?.code === "OK"
            ? {
                status: step.status,
                code: step.code,
                body: comparableBody(step.body, programId, stepId),
              }
            : { status: step?.status, code: step?.code, message: step?.message };
        if (
          JSON.stringify(canonical(decision(expectedSteps[stepId]))) !==
          JSON.stringify(canonical(decision(actualSteps[stepId])))
        ) {
          mismatches.push(`${programId}#${stepId}`);
        }
      }
      return mismatches;
    });
    differences.push(
      ...candidateDifferences.reduce((best, current) =>
        current.length < best.length ? current : best,
      ),
    );
  }
  const expectedStreams = production?.streams ?? {};
  for (const recipeId of new Set([
    ...Object.keys(expectedStreams),
    ...Object.keys(localStreams ?? {}),
  ])) {
    if (
      JSON.stringify(canonical(comparableStream(expectedStreams[recipeId]))) !==
      JSON.stringify(canonical(comparableStream(localStreams?.[recipeId])))
    ) {
      differences.push(`${recipeId}#grpc`);
    }
  }
  return differences.toSorted();
}

/** Freeze only reproducible sandbox responses; no fireemu source digest is bound here. */
/**
 * One recording holds a complete, typed answer for every step and live stream of the corpus.
 * The freeze applies it to both recordings; a runner applies it to its first recording so a
 * failed attempt stops before the second is sent.
 */
export function assertCompleteRecording(corpus, rest, stream) {
  for (const program of corpus.restPrograms) {
    const recordedSteps = rest?.[program.id]?.steps;
    if (!recordedSteps || program.steps.some((step) => !recordedSteps[step.id])) {
      throw new Error(`incomplete sandbox recording: ${program.id}`);
    }
    for (const step of program.steps) {
      const result = recordedSteps[step.id];
      // A WebChannel measured body may be answered by a dropped connection; that is a typed
      // observation, and the freeze still requires both recordings to agree on it.
      const typedReset =
        step.webchannelSession === "boundary" &&
        result.status === 0 &&
        result.code === "connection-reset" &&
        WEBCHANNEL_RESET_PHASES.includes(result.message) &&
        Object.keys(result).length === 3;
      if (typedReset) continue;
      if (
        !Number.isInteger(result.status) ||
        result.status < 200 ||
        result.status > 599 ||
        typeof result.code !== "string" ||
        !result.code ||
        ["no-response", "probe-error", "non-json"].includes(result.code) ||
        (result.status < 300 && (result.code !== "OK" || !Object.hasOwn(result, "body")))
      ) {
        throw new Error(`failed observation: ${program.id}#${step.id}`);
      }
    }
  }
  const liveStreams = (corpus.streamRecipes ?? []).filter((recipe) => recipe.transport === "grpc");
  if (liveStreams.length > 0 && !stream) throw new Error("incomplete stream recording");
  for (const recipe of liveStreams) {
    const result = stream[recipe.id];
    // A unary byte probe records one status for its exact wire size; a stream records its
    // events.
    const complete =
      recipe.action === "get-document-transaction-bytes"
        ? result?.wireBytes === recipe.wireBytes
        : Array.isArray(result?.events);
    if (!result || !Number.isInteger(result.status?.code) || !complete) {
      throw new Error(`incomplete stream recording: ${recipe.id}`);
    }
  }
}

export function freezeSandboxFixture({
  corpus,
  first,
  second,
  firstStream,
  secondStream,
  recordedAt,
  harnessRevision,
  sdkVersions,
  credentialToken,
  mode,
}) {
  validateSandboxCorpus(corpus);
  if (typeof credentialToken !== "string" || credentialToken.length === 0) {
    throw new Error("credential token is required for leak inspection");
  }
  if (JSON.stringify({ first, second, firstStream, secondStream }).includes(credentialToken)) {
    throw new Error("recorded response contains a credential token");
  }
  const differences = compareRecordings(first, second);
  if (
    differences.length > 0 &&
    (mode !== "delta-v3" || differences.some((id) => !DELTA_V3_DRIFT.has(id)))
  )
    throw new Error(`nondeterministic production rows: ${differences.join(", ")}`);
  const nondeterministicPrograms = [
    ...new Set(differences.map((id) => id.split("#", 1)[0])),
  ].toSorted();
  assertCompleteRecording(corpus, first, firstStream);
  assertCompleteRecording(corpus, second, secondStream);
  const liveStreams = (corpus.streamRecipes ?? []).filter((recipe) => recipe.transport === "grpc");
  if (liveStreams.length > 0) {
    if (JSON.stringify(canonical(firstStream)) !== JSON.stringify(canonical(secondStream))) {
      throw new Error("nondeterministic stream recording");
    }
  }
  if (
    !Array.isArray(recordedAt) ||
    recordedAt.length !== 2 ||
    !recordedAt.every((instant) => Number.isFinite(Date.parse(instant)))
  ) {
    throw new Error("two recording times are required");
  }
  if (!/^[0-9a-f]{40}$/.test(harnessRevision) || !sdkVersions || typeof sdkVersions !== "object") {
    throw new Error("harness revision and SDK versions are required");
  }
  if (JSON.stringify({ first, second, firstStream, secondStream }).includes("fireemu-oracle-sbx")) {
    throw new Error("production project identity was not normalized");
  }
  return {
    schemaVersion: 1,
    evidence: {
      corpusSha256: sha256(JSON.stringify(corpus)),
      project: RECORDED_PROJECT,
      database: "(default)",
      recordedAt,
      harnessRevision,
      sdkVersions,
      recordingDigests: [
        sha256(JSON.stringify(canonical(first))),
        sha256(JSON.stringify(canonical(second))),
      ],
      streamRecordingDigests:
        liveStreams.length === 0
          ? []
          : [
              sha256(JSON.stringify(canonical(firstStream))),
              sha256(JSON.stringify(canonical(secondStream))),
            ],
      nondeterministicPrograms,
    },
    programs: Object.fromEntries(
      Object.entries(first).map(([id, program]) => [
        id,
        nondeterministicPrograms.includes(id)
          ? { nondeterministic: true, alternatives: [program, second[id]] }
          : program,
      ]),
    ),
    streams: firstStream ?? {},
  };
}
