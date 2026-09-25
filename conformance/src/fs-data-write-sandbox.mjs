import { createHash } from "node:crypto";

import { WEBCHANNEL_PATH } from "./firestore-probe/webchannel-request-bytes.mjs";

const SANDBOX_DOCUMENTS = "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents";
const RECORDED_PROJECT = "demo-firestore-probe";
const MAX_REST_REQUESTS = 400;
const MAX_BODY_BYTES = 16_777_217;
const DELETE_RUN_MARKER = "DELETE_RUN_ID";
const DELETE_RUN_MARKER_VALUE = "a".repeat(32);
const DELETE_BOUNDARY_PREFIX = "writes/limits/near-limit-delete-refusal/";
const RESOURCE_NAME = /projects\/([^/]+)\/databases\/([^/?]+)/g;
const VOLATILE_STREAM_TRAILERS = new Set(["x-debug-tracking-id"]);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

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
      const webchannel = step.webchannelBodyBytes !== undefined;
      if (
        webchannel &&
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
      if (
        step.body !== undefined &&
        Buffer.byteLength(JSON.stringify(step.body)) > MAX_BODY_BYTES
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
    const expectedSteps = expectedPrograms[programId]?.steps ?? {};
    const actualSteps = localPrograms?.[programId]?.steps ?? {};
    for (const stepId of new Set([...Object.keys(expectedSteps), ...Object.keys(actualSteps)])) {
      const expected = expectedSteps[stepId];
      const actual = actualSteps[stepId];
      const decision = (step) =>
        step?.code === "OK"
          ? {
              status: step.status,
              code: step.code,
              body: comparableBody(step.body, programId, stepId),
            }
          : { status: step?.status, code: step?.code, message: step?.message };
      if (
        JSON.stringify(canonical(decision(expected))) !==
        JSON.stringify(canonical(decision(actual)))
      ) {
        differences.push(`${programId}#${stepId}`);
      }
    }
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
}) {
  validateSandboxCorpus(corpus);
  if (typeof credentialToken !== "string" || credentialToken.length === 0) {
    throw new Error("credential token is required for leak inspection");
  }
  if (JSON.stringify({ first, second, firstStream, secondStream }).includes(credentialToken)) {
    throw new Error("recorded response contains a credential token");
  }
  const differences = compareRecordings(first, second);
  if (differences.length > 0)
    throw new Error(`nondeterministic production rows: ${differences.join(", ")}`);
  for (const program of corpus.restPrograms) {
    const recordedSteps = first[program.id]?.steps;
    if (!recordedSteps || program.steps.some((step) => !recordedSteps[step.id])) {
      throw new Error(`incomplete sandbox recording: ${program.id}`);
    }
    for (const step of program.steps) {
      const result = recordedSteps[step.id];
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
  if (liveStreams.length > 0) {
    if (!firstStream || !secondStream) throw new Error("incomplete stream recording");
    for (const recipe of liveStreams) {
      for (const recording of [firstStream, secondStream]) {
        const result = recording[recipe.id];
        // A unary byte probe records one status for its exact wire size; a stream records
        // its events.
        const complete =
          recipe.action === "get-document-transaction-bytes"
            ? result?.wireBytes === recipe.wireBytes
            : Array.isArray(result?.events);
        if (!result || !Number.isInteger(result.status?.code) || !complete) {
          throw new Error(`incomplete stream recording: ${recipe.id}`);
        }
      }
    }
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
  if (JSON.stringify({ first, firstStream }).includes("fireemu-oracle-sbx")) {
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
    },
    programs: first,
    streams: firstStream ?? {},
  };
}
