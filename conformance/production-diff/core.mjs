import { createHash } from "node:crypto";

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const blobSha = (bytes) =>
  createHash("sha1")
    .update(`blob ${Buffer.byteLength(bytes)}\0`)
    .update(bytes)
    .digest("hex");
export const object = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
export function requireThat(condition, code) {
  if (!condition) throw new Error(code);
}
export function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (object(value))
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((key) => JSON.stringify(key) + ":" + canonical(value[key]))
        .join(",") +
      "}"
    );
  requireThat(
    value !== undefined && (typeof value !== "number" || Number.isFinite(value)),
    "not-finite-json",
  );
  return JSON.stringify(value);
}
export const equal = (a, b) => canonical(a) === canonical(b);
export const digestJson = (value) => sha256(canonical(value));
export const safeCode = (error) =>
  /^[a-z0-9][a-z0-9-]{0,90}$/.test(error?.message ?? "") ? error.message : "operation-failed";

/** Resolve the pinned recorder's existing $from notation from earlier raw replies.
 * Never use normalized timestamps or caller supplied substitutions. */
export function resolveRecordedValue(value, replies) {
  if (Array.isArray(value)) return value.map((item) => resolveRecordedValue(item, replies));
  if (!object(value)) return value;
  if (typeof value.$from === "string") {
    requireThat(typeof value.path === "string" && replies.has(value.$from), "recorder-reference-unavailable");
    let found = replies.get(value.$from);
    for (const key of value.path.split(".")) {
      requireThat(found !== null && typeof found === "object" && Object.hasOwn(found, key), "recorder-reference-unavailable");
      found = found[key];
    }
    requireThat(found !== undefined, "recorder-reference-unavailable");
    return structuredClone(found);
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveRecordedValue(item, replies)]));
}

/** Resolve the pinned recorder's path references from this run's raw replies.
 * Encode each value once as a URL component; it never becomes a new route/origin.
 * Page/transaction references in this bounded adapter must be non-empty strings. */
export function resolveRecordedPath(path, replies) {
  requireThat(typeof path === "string", "recorder-path-reference-invalid");
  return path.replaceAll(/\{\{([^}]+)\}\}/g, (_, expression) => {
    const [id, ...segments] = expression.split(".");
    const value = resolveRecordedValue(
      { $from: id, path: segments.length ? segments.join(".") : "transaction" },
      replies,
    );
    requireThat(typeof value === "string" && value.length > 0, "recorder-path-reference-invalid");
    return encodeURIComponent(value);
  });
}

/** Dynamic cleanup names come only from a declared create reply on the owned daemon.
 * This is not production deletion authority. The full local DB is reset first. */
export function expectedCleanupDocuments(entry, requests) {
  const paths = [...entry.ownedDocuments];
  for (const [phase, collection] of Object.entries(entry.generatedDocumentSteps ?? {})) {
    const rows = requests.filter((row) => row.phase === phase);
    requireThat(rows.length <= 1, "generated-document-receipt-invalid");
    if (!rows.length) continue; // A stopped run may never have sent this operation.
    const row = rows[0];
    const prefix = `projects/${entry.project}/databases/(default)/documents/${collection}/`;
    requireThat(row.method === "POST" && row.path === `/v1/${prefix.slice(0, -1)}`, "generated-document-receipt-invalid");
    requireThat(row.status === null || (Number.isInteger(row.status) && row.status >= 200 && row.status <= 599), "generated-document-receipt-invalid");
    if (row.status === null || row.status < 200 || row.status >= 300) {
      requireThat(row.generatedDocument === undefined && row.generatedResponseText === undefined, "generated-document-receipt-invalid");
      continue;
    }
    requireThat(Number.isInteger(row.status) && typeof row.generatedDocument === "string" &&
      row.generatedDocument.startsWith(prefix) && /^[A-Za-z0-9]{20}$/.test(row.generatedDocument.slice(prefix.length)),
      "generated-document-receipt-invalid");
    requireThat(typeof row.generatedResponseText === "string" && Buffer.byteLength(row.generatedResponseText) <= 65536 &&
      sha256(row.generatedResponseText) === row.responseSha256, "generated-document-response-binding");
    let responseBody;
    try { responseBody = JSON.parse(row.generatedResponseText); } catch { throw new Error("generated-document-response-binding"); }
    requireThat(object(responseBody) && responseBody.name === row.generatedDocument, "generated-document-response-binding");
    const path = `${collection}/${row.generatedDocument.slice(prefix.length)}`;
    requireThat(!paths.includes(path), "generated-document-receipt-invalid");
    paths.push(path);
  }
  return paths;
}

export function validateProgram(program, entry) {
  requireThat(
    object(program) && program.id === entry.programId &&
      program.area === (entry.programArea ?? "writes"),
    "program-identity",
  );
  requireThat(
    Array.isArray(program.seed) && program.seed.length === (entry.seedCount ?? 1) &&
      Array.isArray(program.steps),
    "program-structure",
  );
  requireThat(
    equal(
      program.steps.map((step) => step.id),
      entry.stepIds,
    ),
    "program-step-set",
  );
  requireThat(!program.databases?.length, "unexpected-database");
  for (const step of program.steps) {
    requireThat(
      (entry.allowedMethods ?? ["GET", "POST"]).includes(step.method) &&
        typeof step.path === "string" &&
        step.path.startsWith("/v1/projects/PROJECT/databases/(default)/documents"),
      "program-route",
    );
    requireThat(
      step.credential === undefined && step.owner === undefined && step.headers === undefined,
      "program-principal",
    );
  }
  requireThat(digestJson(program) === entry.programDigest, "program-input-drift");
  return program;
}

export function selectProduction(matrix, entry) {
  const evidence = matrix?.evidence;
  const observation = evidence?.observations?.production;
  requireThat(
    matrix?.version === 1 &&
      evidence?.verified === true &&
      Array.isArray(evidence.validation) &&
      evidence.validation.length === 0,
    "oracle-validation",
  );
  requireThat(
    observation?.observation?.side === "production" && observation.observation.mode === "live",
    "oracle-not-production",
  );
  requireThat(
    observation.source?.gitSha === entry.observedSource &&
      observation.source.trackedTreeClean === true &&
      observation.inputs?.corpusDigest === entry.corpusDigest,
    "oracle-source-binding",
  );
  const db = observation.observation.database;
  requireThat(
    db?.type === "FIRESTORE_NATIVE" && db.databaseEdition === "STANDARD",
    "oracle-database",
  );
  requireThat(Array.isArray(matrix.programs), "oracle-programs");
  const programs = matrix.programs.filter((p) => p.id === entry.programId);
  requireThat(programs.length === 1, "oracle-program-identity");
  const program = programs[0];
  requireThat(
    !Object.hasOwn(program, "seedError") &&
      object(program.steps) &&
      equal(Object.keys(program.steps), entry.stepIds),
    "oracle-step-set",
  );
  const steps = {};
  for (const id of entry.stepIds) {
    const row = program.steps[id]?.production;
    requireThat(completed(row), "oracle-incomplete-row");
    // Never consult .emulator, .fireemu or historical three-way summary labels.
    steps[id] = { production: structuredClone(row) };
  }
  return { programs: [{ id: entry.programId, area: entry.programArea ?? "writes", steps }] };
}

export function completed(row) {
  return (
    object(row) &&
    row.missing !== true &&
    Number.isInteger(row.status) &&
    row.status >= 200 &&
    row.status <= 599 &&
    typeof row.code === "string" &&
    /^[A-Z][A-Z_]*$/.test(row.code) &&
    (row.code !== "OK" || Object.hasOwn(row, "body"))
  );
}

/** Wrap, do not reinterpret, the legacy comparator. Recount indeterminate separately. */
export function compareRecords({ entry, program, production, actual, comparator }) {
  validateProgram(program, entry);
  const issues = [];
  if (!object(actual) || !equal(Object.keys(actual), [entry.programId]))
    issues.push("local-program-set");
  const local = actual?.[entry.programId];
  if (!object(local) || Object.hasOwn(local, "seedError")) issues.push("local-setup-failed");
  if (!object(local?.steps) || !equal(Object.keys(local.steps), entry.stepIds))
    issues.push("local-step-set");
  const rows = [];
  // Call the original function for the whole program. Both paths use this identical function.
  const legacy = comparator({
    production,
    fireemu: object(actual) ? actual : {},
    programDefinitions: [program],
  });
  requireThat(
    Array.isArray(legacy?.rows) &&
      legacy.rows.length === entry.stepIds.length &&
      equal(
        legacy.rows.map((row) => row.id),
        entry.stepIds,
      ),
    "comparator-shape",
  );
  for (const row of legacy.rows) {
    requireThat(
      ["match", "mismatch", "indeterminate"].includes(row.comparison),
      "comparator-verdict",
    );
    const valid = completed(local?.steps?.[row.id]);
    rows.push({
      stepId: row.id,
      comparison: issues.length || !valid ? "INDETERMINATE" : row.comparison.toUpperCase(),
      production: row.production,
      local: row.local,
    });
  }
  const counts = { match: 0, mismatch: 0, indeterminate: 0 };
  for (const row of rows) counts[row.comparison.toLowerCase()]++;
  const verdict = counts.indeterminate ? "INDETERMINATE" : counts.mismatch ? "MISMATCH" : "MATCH";
  return {
    verdict,
    counts,
    rows,
    issues,
    legacySummary: {
      rowCount: legacy.rowCount,
      matches: legacy.matches,
      mismatches: legacy.mismatches,
    },
    legacyMismatchesIncludesIndeterminate: true,
  };
}

export function resultEnvelope({ entry, comparison, execution, provenance }) {
  requireThat(
    typeof entry.evidenceKind === "string" && typeof entry.oracleKind === "string",
    "case-missing-evidence-kind",
  );
  const complete =
    execution.state === "completed" &&
    execution.cleanup?.state === "confirmed" &&
    execution.process?.state === "stopped" &&
    comparison.counts.indeterminate === 0;
  return {
    schema: "fireemu-production-diff-result-v1",
    caseId: entry.id,
    parent: entry.parent,
    productionExecuted: false,
    // Carried from the case definition (registry.mjs), not hard-coded here: the two cases
    // publish different kinds of evidence (see registry.mjs's comment on COMMIT_TRANSFORM_CASE).
    evidenceKind: entry.evidenceKind,
    oracleKind: entry.oracleKind,
    profile: entry.profile,
    transport: entry.transport,
    comparison: { ...comparison, verdict: complete ? comparison.verdict : "INDETERMINATE" },
    execution,
    provenance,
    complete,
    gatePassed: complete && comparison.verdict === "MATCH",
    independentReview: "not-performed-by-this-run",
    parentPromotion: false,
    compared: entry.compared,
    notEstablished: entry.notEstablished,
  };
}
export const gateExitCode = (result) => (result.gatePassed ? 0 : result.complete ? 1 : 2);

export function renderReport(result) {
  return [
    "# Production differential replay",
    "",
    `Case: ${result.caseId}`,
    `Result: ${result.comparison.verdict}`,
    `Evidence: ${result.evidenceKind} (oracle: ${result.oracleKind}); new production requests: 0`,
    `Execution: ${result.execution.state}; cleanup: ${result.execution.cleanup?.state ?? "unknown"}`,
    `Counts: ${JSON.stringify(result.comparison.counts)}`,
    "",
    "## Compared",
    ...result.compared.map((s) => `- ${s}`),
    "",
    "## Not established",
    ...result.notEstablished.map((s) => `- ${s}`),
    "",
    "This is a scoped result, not parent promotion or independent approval.",
    "",
  ].join("\n");
}
