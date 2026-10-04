// The closure evidence of STORAGE-OBJECT, made from a finished comparison:
//
//   node src/storage-object-compare/closure-evidence.mjs --report <report.json> --receipt <receipt.json>
//        --fixture <fixture dir> --sandbox-ledger <sandbox-ledger.jsonl>
//        --closure spec/compatibility/closure/STORAGE-OBJECT.json
//        --out spec/compatibility/closure/evidence/STORAGE-OBJECT-comparison.json
//        --comparison-path spec/compatibility/closure/evidence/STORAGE-OBJECT-comparison.json
//        [--hold <condition id>[,<condition id>...]]
//        [--build-record <build record.json> --build-record-out <repo copy> --build-record-path <cited path>]
//
// It refuses anything but a complete comparison: every fixture row compared and a MATCH, the
// rehearsal finished, the report, the receipt and the fixture naming the same binary, commit, recorder
// and fixture, and the two production recordings found in the sandbox ledger (one started and one
// recorded row each, in the query project, at one commit). Then it writes the comparison evidence (one
// row per compared exchange, bound to the binary) and sets VERIFIED and the evidence on every recipe
// condition of the closure that is not held. The final-artifact and review conditions are never
// touched unless a build record is given: the record of the binary's build (commit, a tree clean
// outside the build output, the cargo version, --locked, the SHA-256), which must name the compared
// binary and commit. Then it also sets the final-artifact condition from the comparison and the record,
// copies the record into the repository and cites its digest. Running it again for another binary replaces the evidence of every condition together,
// and an existing note on a condition stays.

import { createHash } from "node:crypto";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { loadFixture } from "./run.mjs";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const TIMESTAMP = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const PROJECT = "fireemu-oracle-query";
const GATES = new Set(["final-artifact-regression", "closure-review"]);
const OUTCOMES = [
  "DIVERGENCE",
  "LOCAL_UNIMPLEMENTED",
  "TAINTED",
  "ONLY_PRODUCTION",
  "ONLY_LOCAL",
  "NOT_RUN",
];

const refuse = (message) => {
  throw new Error(message);
};
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

/** The two recordings of the fixture, from the sandbox ledger: when and at which commit each was started. */
export function recordingsFromLedger(text, runIds) {
  if (!Array.isArray(runIds) || runIds.length !== 2 || new Set(runIds).size !== 2)
    refuse("the closure needs two distinct recordings");
  const rows = [];
  for (const line of String(text).split("\n")) {
    if (line.trim() === "") continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      refuse("the sandbox ledger has a line that is not JSON");
    }
  }
  const recordings = runIds.map((runId) => {
    const own = rows.filter((row) => row?.runId === runId);
    const started = own.filter((row) => row.event === "started");
    const finished = own.filter((row) => row.event === "finished");
    if (started.length !== 1 || finished.length !== 1)
      refuse(`the sandbox ledger needs one started and one finished row for run ${runId}`);
    const [begin] = started;
    const [end] = finished;
    if (end.outcome !== "recorded") refuse(`run ${runId} did not end as recorded`);
    for (const row of [begin, end])
      if (row.project !== PROJECT || !HEX40.test(row.gitSha ?? ""))
        refuse(`the ledger rows of run ${runId} are not a recording in ${PROJECT} at a commit`);
    if (begin.gitSha !== end.gitSha) refuse(`the ledger rows of run ${runId} name two commits`);
    if (!TIMESTAMP.test(begin.ts ?? "")) refuse(`the started row of run ${runId} has no time`);
    return { recordedAt: begin.ts, gitSha: begin.gitSha, runId, project: PROJECT };
  });
  if (recordings[0].gitSha !== recordings[1].gitSha)
    refuse("the two recordings were made at two commits");
  return recordings;
}

function checkBinding({ report, receipt, fixture }) {
  if (!Array.isArray(fixture.index?.runIds) || fixture.index.runIds.length !== 2)
    refuse("the fixture has no two recordings");
  if (!same(report.fixtureRunIds, fixture.index.runIds))
    refuse("the report is of other recordings than the fixture's");
  if (
    !HEX64.test(fixture.indexSha256 ?? "") ||
    report.fixtureIndexSha256 !== fixture.indexSha256 ||
    receipt.fixtureIndexSha256 !== fixture.indexSha256
  )
    refuse("the report, the receipt and the fixture name different fixtures");
  const { binarySha256, commit } = report.fireemu ?? {};
  if (!HEX64.test(binarySha256 ?? "") || !HEX40.test(commit ?? ""))
    refuse("the report names no binary and commit");
  if (receipt.fireemu?.binarySha256 !== binarySha256 || receipt.fireemu?.commit !== commit)
    refuse("the report and the receipt name different binaries");
  if (report.recorder?.clean !== true || !HEX40.test(report.recorder?.commit ?? ""))
    refuse("the recorder was not a clean commit");
  if (receipt.recorder?.clean !== true || receipt.recorder?.commit !== report.recorder.commit)
    refuse("the report and the receipt name different recorders");
  for (const [name, result] of [
    ["report", report.rehearsalResult],
    ["receipt", receipt.result],
  ])
    if (result?.status !== "LOCAL_COMPLETE" || result?.exitCode !== 0)
      refuse(`the rehearsal of the ${name} did not finish`);
}

/**
 * The comparison evidence of a finished comparison, or a refusal. `report` is the compare tool's report,
 * `receipt` the rehearsal's, `fixture` what `loadFixture` returns.
 */
export function buildEvidence({ report, receipt, fixture }) {
  checkBinding({ report, receipt, fixture });
  const expected = [...fixture.recipes.entries()];
  const total = expected.reduce((sum, [, rows]) => sum + rows.length, 0);
  if (report.total?.MATCH !== total || OUTCOMES.some((name) => report.total?.[name] !== 0))
    refuse("the comparison is not a MATCH of every row of the fixture");
  const byId = new Map((report.recipes ?? []).map((recipe) => [recipe.recipeId, recipe]));
  if (byId.size !== expected.length || expected.some(([id]) => !byId.has(id)))
    refuse("the report does not cover the fixture's recipes");
  const rows = [];
  const layoutUnjudged = [];
  for (const [recipeId, fixtureRows] of expected) {
    const recipe = byId.get(recipeId);
    if (recipe.ran !== true) refuse(`recipe ${recipeId} did not run`);
    if (
      recipe.counts?.MATCH !== fixtureRows.length ||
      OUTCOMES.some((name) => recipe.counts?.[name] !== 0)
    )
      refuse(`recipe ${recipeId} is not a MATCH of every row`);
    const wanted = new Set(fixtureRows.map((row) => row.n));
    const seen = new Set();
    for (const result of recipe.results ?? []) {
      if (result.outcome !== "MATCH" || !wanted.has(result.n) || seen.has(result.n))
        refuse(`recipe ${recipeId} has a result that is not one MATCH of a row of the fixture`);
      seen.add(result.n);
    }
    if (seen.size !== wanted.size) refuse(`recipe ${recipeId} has a row without a result`);
    for (const row of fixtureRows) {
      rows.push({ row: `${recipeId}#${row.n}`, status: "MATCH" });
      if (!Number.isSafeInteger(row.layout)) layoutUnjudged.push(`${recipeId}#${row.n}`);
    }
  }
  if (report.layoutUnjudgedProductionRows !== layoutUnjudged.length)
    refuse("the report's count of rows without a layout is not the fixture's");
  return {
    comparison: {
      kind: "storage-object-comparison-v1",
      artifactSha256: report.fireemu.binarySha256,
      sourceCommit: report.fireemu.commit,
      fixtureSha256: fixture.indexSha256,
      recorderCommit: report.recorder.commit,
      summary: { MATCH: total },
      layoutUnjudged,
      rows,
    },
  };
}

const BUILD_RECORD_KEYS = [
  "sourceCommit",
  "gitStatusOutsideBuildOutput",
  "cargoVersion",
  "locked",
  "binarySha256",
];

/** The build record of the compared binary, or a refusal: its commit, a clean tree, the cargo version, --locked, the digest. */
export function finalArtifactEvidence({ buildRecord, comparison }) {
  const record = buildRecord;
  const plain = record !== null && typeof record === "object" && !Array.isArray(record);
  if (
    !plain ||
    Object.keys(record).length !== BUILD_RECORD_KEYS.length ||
    !BUILD_RECORD_KEYS.every((key) => Object.hasOwn(record, key))
  )
    refuse("the build record has the wrong fields");
  if (typeof record.sourceCommit !== "string" || !HEX40.test(record.sourceCommit))
    refuse("the build record has no source commit");
  if (typeof record.binarySha256 !== "string" || !HEX64.test(record.binarySha256))
    refuse("the build record has no binary digest");
  if (
    !Array.isArray(record.gitStatusOutsideBuildOutput) ||
    record.gitStatusOutsideBuildOutput.length !== 0
  )
    refuse("the build record's tree was not clean outside the build output");
  if (typeof record.cargoVersion !== "string" || record.cargoVersion.trim() === "")
    refuse("the build record has no cargo version");
  if (record.locked !== true) refuse("the build record was not built with --locked");
  if (
    record.binarySha256 !== comparison.artifactSha256 ||
    record.sourceCommit !== comparison.sourceCommit
  )
    refuse("the build record is of another binary or commit than the comparison");
  return Object.freeze({ ...record, gitStatusOutsideBuildOutput: [] });
}

/** A copy of the closure with VERIFIED and the evidence on every compared recipe condition that is not held. */
export function applyClosure({
  closure,
  comparison,
  recordings,
  comparisonPath,
  hold = [],
  finalArtifact = undefined,
}) {
  if (typeof comparisonPath !== "string" || comparisonPath === "")
    refuse("the comparison path is empty");
  if (!Array.isArray(recordings) || recordings.length !== 2)
    refuse("the closure needs two recordings");
  if (!Array.isArray(closure?.conditions) || closure.conditions.length === 0)
    refuse("the closure has no conditions");
  const ids = new Set(closure.conditions.map((condition) => condition.conditionId));
  for (const id of hold)
    if (!ids.has(id)) refuse(`cannot hold ${id}: the closure has no such condition`);
  if (finalArtifact !== undefined) {
    finalArtifactEvidence({ buildRecord: finalArtifact.buildRecord, comparison });
    if (typeof finalArtifact.buildRecordPath !== "string" || finalArtifact.buildRecordPath === "")
      refuse("the build record path is empty");
    if (
      typeof finalArtifact.buildRecordSha256 !== "string" ||
      !HEX64.test(finalArtifact.buildRecordSha256)
    )
      refuse("the build record digest is malformed");
    if (![...ids].some((id) => id.endsWith("/final-artifact-regression")))
      refuse("the closure has no final artifact condition for the build record");
  }
  const perRecipe = new Map();
  for (const { row, status } of comparison.rows) {
    const recipe = row.split("#")[0];
    const entry = perRecipe.get(recipe) ?? { rows: 0, matches: 0 };
    entry.rows += 1;
    if (status === "MATCH") entry.matches += 1;
    perRecipe.set(recipe, entry);
  }
  const copy = structuredClone(closure);
  for (const condition of copy.conditions) {
    if (hold.includes(condition.conditionId)) continue;
    if (
      condition.conditionId.endsWith("/final-artifact-regression") &&
      finalArtifact !== undefined
    ) {
      condition.status = "VERIFIED";
      condition.evidence = {
        productionRecordings: structuredClone(recordings),
        finalArtifactSha256: comparison.artifactSha256,
        sourceCommit: comparison.sourceCommit,
        comparisonPath,
        rows: { MATCH: comparison.rows.length },
        buildRecordPath: finalArtifact.buildRecordPath,
        buildRecordSha256: finalArtifact.buildRecordSha256,
      };
      continue;
    }
    if (GATES.has(condition.conditionId.split("/").at(-1))) continue;
    let rows = 0;
    for (const recipe of condition.recipeIds ?? []) {
      const entry = perRecipe.get(recipe);
      if (!entry) refuse(`${condition.conditionId}: recipe ${recipe} was not compared`);
      if (entry.matches !== entry.rows)
        refuse(`${condition.conditionId}: recipe ${recipe} has rows that are not a MATCH`);
      rows += entry.rows;
    }
    if (rows === 0) refuse(`${condition.conditionId}: no recipe was compared`);
    condition.status = "VERIFIED";
    condition.evidence = {
      productionRecordings: structuredClone(recordings),
      finalArtifactSha256: comparison.artifactSha256,
      sourceCommit: comparison.sourceCommit,
      comparisonPath,
      rows: { MATCH: rows },
    };
  }
  return copy;
}

/** JSON on one line, in the style of the conditions of the closure files: `{ "a": 1, "b": ["x"] }`. */
export function inlineJson(value) {
  if (Array.isArray(value)) return `[${value.map(inlineJson).join(", ")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length === 0) return "{}";
    return `{ ${entries.map(([key, item]) => `${JSON.stringify(key)}: ${inlineJson(item)}`).join(", ")} }`;
  }
  return JSON.stringify(value);
}

/**
 * The closure file with the line of each condition rewritten, and every other line as it was: a closure
 * file keeps one condition on one line, so a change shows as a change of that line and nothing else.
 */
export function replaceConditionLines(text, closure) {
  const lines = text.split("\n");
  for (const condition of closure.conditions) {
    const marker = `{ "conditionId": ${JSON.stringify(condition.conditionId)},`;
    const found = lines.flatMap((line, index) =>
      line.trimStart().startsWith(marker) ? [index] : [],
    );
    if (found.length !== 1)
      refuse(`the closure file has no single line for condition ${condition.conditionId}`);
    const [index] = found;
    const indent = lines[index].slice(0, lines[index].length - lines[index].trimStart().length);
    const comma = lines[index].trimEnd().endsWith(",") ? "," : "";
    lines[index] = `${indent}${inlineJson(condition)}${comma}`;
  }
  return lines.join("\n");
}

/** The command, with its collaborators injected. */
export function closureEvidenceCommand(
  options,
  { loadFixture: load = loadFixture, log = console.log } = {},
) {
  for (const name of [
    "report",
    "receipt",
    "fixture",
    "sandbox-ledger",
    "closure",
    "out",
    "comparison-path",
  ])
    if (!options[name]) refuse(`--${name} is required`);
  const report = JSON.parse(readFileSync(options.report, "utf8"));
  const receipt = JSON.parse(readFileSync(options.receipt, "utf8"));
  const fixture = load(options.fixture);
  const recordings = recordingsFromLedger(
    readFileSync(options["sandbox-ledger"], "utf8"),
    fixture.index.runIds,
  );
  const { comparison } = buildEvidence({ report, receipt, fixture });
  const hold = options.hold ? options.hold.split(",").filter(Boolean) : [];
  // The build record, its copy in the repository and the path the closure cites go together.
  const recordOptions = ["build-record", "build-record-out", "build-record-path"];
  let finalArtifact;
  let recordBytes;
  if (recordOptions.some((name) => options[name])) {
    for (const name of recordOptions)
      if (!options[name]) refuse(`--${name} is required with the build record options`);
    recordBytes = readFileSync(options["build-record"]);
    finalArtifact = {
      buildRecord: JSON.parse(recordBytes.toString("utf8")),
      buildRecordPath: options["build-record-path"],
      buildRecordSha256: createHash("sha256").update(recordBytes).digest("hex"),
    };
  }
  const closureText = readFileSync(options.closure, "utf8");
  const closure = applyClosure({
    closure: JSON.parse(closureText),
    comparison,
    recordings,
    comparisonPath: options["comparison-path"],
    hold,
    finalArtifact,
  });
  if (recordBytes !== undefined) {
    mkdirSync(dirname(options["build-record-out"]), { recursive: true });
    writeFileSync(options["build-record-out"], recordBytes);
  }
  mkdirSync(dirname(options.out), { recursive: true });
  writeFileSync(options.out, `${JSON.stringify(comparison, null, 1)}\n`);
  writeFileSync(options.closure, replaceConditionLines(closureText, closure));
  log(
    `closure evidence: ${comparison.rows.length} rows of ${comparison.artifactSha256} written; ${closure.conditions.filter((c) => c.status === "VERIFIED").length} conditions verified`,
  );
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined) refuse(`bad argument: ${flag}`);
    options[flag.slice(2)] = value;
  }
  return options;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  try {
    closureEvidenceCommand(parseArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
