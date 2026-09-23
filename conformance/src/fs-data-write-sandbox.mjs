import { createHash } from "node:crypto";

const SANDBOX_DOCUMENTS = "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents";
const RECORDED_PROJECT = "demo-firestore-probe";
const MAX_REST_REQUESTS = 400;
const MAX_BODY_BYTES = 16_777_217;

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
    const stepIds = new Set();
    for (const step of program.steps) {
      requestCount += 1;
      if (typeof step.id !== "string" || stepIds.has(step.id)) {
        throw new Error("duplicate or missing sandbox step ID");
      }
      stepIds.add(step.id);
      if (!["GET", "POST", "PATCH"].includes(step.method)) {
        throw new Error("unsupported sandbox method");
      }
      if (typeof step.path !== "string" || !step.path.startsWith(SANDBOX_DOCUMENTS)) {
        throw new Error("request escaped the sandbox project");
      }
      if (step.headers && Object.keys(step.headers).length > 0) {
        throw new Error("sandbox corpus must not include credential headers");
      }
      if (
        step.body !== undefined &&
        Buffer.byteLength(JSON.stringify(step.body)) > MAX_BODY_BYTES
      ) {
        throw new Error("sandbox request exceeds the declared raw sentinel");
      }
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

/** Freeze only reproducible sandbox responses; no fireemu source digest is bound here. */
export function freezeSandboxFixture({
  corpus,
  first,
  second,
  recordedAt,
  harnessRevision,
  sdkVersions,
}) {
  validateSandboxCorpus(corpus);
  const differences = compareRecordings(first, second);
  if (differences.length > 0)
    throw new Error(`nondeterministic production rows: ${differences.join(", ")}`);
  for (const program of corpus.restPrograms) {
    const recordedSteps = first[program.id]?.steps;
    if (!recordedSteps || program.steps.some((step) => !recordedSteps[step.id])) {
      throw new Error(`incomplete sandbox recording: ${program.id}`);
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
  if (JSON.stringify(first).includes("fireemu-oracle-sbx")) {
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
    },
    programs: first,
  };
}
