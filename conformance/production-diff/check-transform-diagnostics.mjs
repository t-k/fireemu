#!/usr/bin/env node
// FS-TRANSFORM-DIAGNOSTICS-023: supplement the existing replay; never invent an oracle.
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { blobSha, completed, object, requireThat, safeCode, sha256 } from "./core.mjs";
import { publishJson, readSource } from "./io.mjs";

export const TRANSFORM_CASE_ID = "fs.transforms.saved-20260907.v1";
export const PROGRAM_ID = "writes/transforms";
export const MATRIX_BLOB = "507a3412005c3b0a1b8c1f0a4a150dca101dac3b";
export const OBSERVED_SOURCE = "2526c61eda5fc53ac91250307786127ae3c601be";
export const DIAGNOSTIC_STEPS = Object.freeze([
  "increment-with-non-numeric-operand",
  "server-timestamp-on-a-delete",
]);

/** Pure row comparison. Byte/provenance admission belongs to runDiagnosticCheck(),
 * which invokes the existing pilot compare before calling this function. */
export function compareDiagnosticRows(productionProgram, actual) {
  requireThat(
    productionProgram?.id === PROGRAM_ID && object(productionProgram.steps),
    "diagnostic-production-program",
  );
  const local = actual?.[PROGRAM_ID];
  const rows = DIAGNOSTIC_STEPS.map((stepId) => {
    // Deliberately select only .production, not .emulator/.fireemu or summary labels.
    const expected = productionProgram.steps[stepId]?.production;
    requireThat(
      completed(expected) && expected.status === 400 && expected.code === "INVALID_ARGUMENT" &&
        typeof expected.message === "string" && expected.message.length > 0,
      "diagnostic-production-row",
    );
    const observed = local?.steps?.[stepId];
    const available = object(local) && !Object.hasOwn(local, "seedError") && completed(observed);
    const matches = available && observed.status === expected.status &&
      observed.code === expected.code && observed.message === expected.message;
    return {
      stepId,
      comparison: !available ? "INDETERMINATE" : matches ? "MATCH" : "MISMATCH",
      expected: { status: expected.status, code: expected.code, message: expected.message },
      // Avoid echoing arbitrary response text; the private local.json retains the evidence.
      observed: available ? {
        status: observed.status,
        code: observed.code,
        messagePresent: Object.hasOwn(observed, "message"),
        messageType: typeof observed.message,
        messageSha256: typeof observed.message === "string" ? sha256(observed.message) : null,
      } : null,
    };
  });
  const counts = { match: 0, mismatch: 0, indeterminate: 0 };
  for (const row of rows) counts[row.comparison.toLowerCase()]++;
  return {
    verdict: counts.indeterminate ? "INDETERMINATE" : counts.mismatch ? "MISMATCH" : "MATCH",
    counts,
    rows,
  };
}

export function supplementResult(primary, diagnostics, binding) {
  requireThat(
    primary?.schema === "fireemu-production-diff-result-v1" &&
      primary.caseId === TRANSFORM_CASE_ID && primary.productionExecuted === false &&
      typeof primary.complete === "boolean" && typeof primary.gatePassed === "boolean" &&
      ["MATCH", "MISMATCH", "INDETERMINATE"].includes(primary.comparison?.verdict) &&
      primary.gatePassed === (primary.complete && primary.comparison.verdict === "MATCH"),
    "diagnostic-primary-result",
  );
  const complete = primary.complete && primary.comparison.verdict !== "INDETERMINATE" &&
    diagnostics.counts.indeterminate === 0;
  const verdict = !complete ? "INDETERMINATE" :
    primary.comparison.verdict === "MISMATCH" || diagnostics.verdict === "MISMATCH" ?
      "MISMATCH" : "MATCH";
  return {
    schema: "fireemu-transform-diagnostics-v1",
    caseId: TRANSFORM_CASE_ID,
    parent: "FS-DATA-WRITE",
    primaryComparison: { verdict: primary.comparison.verdict, complete: primary.complete },
    diagnosticComparison: diagnostics,
    verdict,
    complete,
    gatePassed: complete && verdict === "MATCH",
    binding,
    productionExecuted: false,
    newProductionRequests: 0,
    independentReview: "not-performed-by-this-run",
    parentPromotion: false,
    conditionAcceptance: false,
    limitations: [
      "Only two message strings supplement the existing 18-step transform comparison.",
      "The primary pilot's artifact/source admission and normalization limits remain in force.",
      "No new production observation, exact error-details comparison or parent acceptance.",
    ],
  };
}

export function parseDiagnosticArgs(args) {
  if (args.length === 1 && args[0] === "--help") return { help: true };
  const options = {};
  const names = new Map([["--repo", "repo"], ["--run-dir", "runDir"], ["--out", "out"]]);
  for (let i = 0; i < args.length; i += 2) {
    const name = names.get(args[i]);
    requireThat(name && !Object.hasOwn(options, name) && typeof args[i + 1] === "string" &&
      args[i + 1].length > 0 && !args[i + 1].startsWith("--"), "diagnostic-arguments");
    options[name] = resolve(args[i + 1]);
  }
  requireThat(options.repo && options.runDir && options.out, "diagnostic-arguments");
  return options;
}

/** No network or native launch: existing pilot compare admits the stored replay first.
 * The new --out is created by that pilot; no prior result/receipt is overwritten. */
export async function runDiagnosticCheck(options) {
  const { selectCase } = await import("./registry.mjs");
  const entry = selectCase(TRANSFORM_CASE_ID); // Requires the already submitted 021 case.
  requireThat(entry.programId === PROGRAM_ID && entry.matrixBlob === MATRIX_BLOB &&
    entry.observedSource === OBSERVED_SOURCE && entry.stepIds.length === 18,
    "diagnostic-case-binding");
  const { main: pilotMain } = await import("./pilot.mjs");
  const code = await pilotMain([
    "compare", "--repo", options.repo, "--case", entry.id,
    "--run-dir", options.runDir, "--out", options.out,
  ]);
  requireThat(code === 0 || code === 1, "diagnostic-primary-incomplete");
  const primaryBytes = await readSource(options.out, "result.json");
  const primary = JSON.parse(primaryBytes);
  const localBytes = await readSource(options.runDir, "local.json", 4 * 1024 * 1024);
  const recordingBytes = await readSource(options.runDir, "recording.json");
  requireThat(sha256(localBytes) === primary.execution?.localSha256 &&
    sha256(recordingBytes) === primary.provenance?.recordingSha256,
    "diagnostic-record-changed");
  const matrixBytes = await readSource(options.repo, entry.matrixPath);
  requireThat(blobSha(matrixBytes) === MATRIX_BLOB, "diagnostic-matrix-pin");
  const matrix = JSON.parse(matrixBytes);
  const programs = matrix.programs.filter((program) => program.id === PROGRAM_ID);
  requireThat(programs.length === 1, "diagnostic-production-program");
  const result = supplementResult(primary,
    compareDiagnosticRows(programs[0], JSON.parse(localBytes)), {
      primaryResultSha256: sha256(primaryBytes),
      localSha256: sha256(localBytes),
      recordingSha256: sha256(recordingBytes),
      productionMatrixGitBlob: MATRIX_BLOB,
      productionObservedSource: OBSERVED_SOURCE,
      artifactSha256: primary.execution?.artifact?.sha256 ?? null,
    });
  await publishJson(join(options.out, "transform-diagnostics.json"), result);
  console.log(JSON.stringify({ caseId: entry.id, verdict: result.verdict,
    diagnostics: result.diagnosticComparison.counts, productionExecuted: false }));
  return result.gatePassed ? 0 : result.complete ? 1 : 2;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const options = parseDiagnosticArgs(process.argv.slice(2));
    if (options.help) console.log("check-transform-diagnostics.mjs --repo REPO --run-dir STORED-TRANSFORM-RUN --out NEW-PRIVATE-DIR");
    else process.exitCode = await runDiagnosticCheck(options);
  } catch (error) {
    console.error(JSON.stringify({ verdict: "INDETERMINATE", code: safeCode(error),
      gatePassed: false, productionExecuted: false, parentPromotion: false }));
    process.exitCode = 2;
  }
}
