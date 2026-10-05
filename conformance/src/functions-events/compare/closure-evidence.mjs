// The closure evidence of FUNCTIONS-EVENTS, made from a finished comparison (compare-cli.mjs), the production run record
// it was made from, and the build record of the final binary. Modelled on STORAGE-OBJECT's closure-evidence.mjs.
//
//   node closure-evidence.mjs --comparison <comparison.json> --production-run <production-run.json>
//        --closure spec/compatibility/closure/FUNCTIONS-EVENTS.json --corpus conformance/functions-events/corpus.json
//        [--build-record <build.json>] [--workspace-regression <receipt.json>] [--sandbox-ledger <ledger.jsonl>]
//        [--report-out <report.json>]
//        [--write --out spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-comparison.json
//                 --comparison-path <the path the closure cites for --out>
//                 --build-record-out <repo copy> --build-record-path <cited path>]
//
// The closure is judged on the strict profile against production (owner ledger 811): a condition is VERIFIED when every one of its
// rows is MATCH in the strict profile (the worse of the production observation and the strict comparison, so a fault of the
// recording itself still blocks) in both recordings. The emulator profile's rows are compared and reported in their own section,
// "emulator-profile versus production", and never block VERIFIED. A comparison must carry the per-profile status of every row.
//
// Without --write it only reports: for each of the 20 business conditions of the closure, the comparison rows that settle
// it (every case of every generation, `<recipe>#<case>#v<generation>`), whether every one MATCHes in both recordings, and
// otherwise the specific DIFF and INCOMPLETE rows with their reasons, and the rows the comparison does not have. With
// --write it refuses anything but a complete, final comparison, and then writes the comparison evidence and the closure:
//   - VERIFIED, with the two recordings, the artifact and the comparison path, on each condition whose rows all MATCH;
//   - nothing on any other condition: it keeps its current status and gets no evidence block (its DIFF and INCOMPLETE rows
//     are in the report only), so a write never changes a status without closing the condition;
//   - final-artifact-regression VERIFIED only when every row of the comparison MATCHes, the build record names the
//     compared binary, and a workspace regression receipt names the same binary and commit (its three gate rows are then
//     added to the evidence); closure-review and the parent status are never touched.
// A comparison labelled preliminary is never written. "Both recordings" are the two passes of the one production run: the
// same deploy, two source-script passes, which is what owner ledger 812 counts as two recordings.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/;
const PROJECT = "fireemu-oracle-events";
const COMPARISON_KIND = "functions-events-comparison";
const GATES = ["final-artifact-regression", "closure-review"];
const STATUSES = new Set(["MATCH", "DIFF", "INCOMPLETE"]);
const WORKSPACE_COMMAND = "cargo nextest run --workspace --profile pr";
const GATE_CASES = [
  "two-production-recordings",
  "same-source-final-artifact-comparison",
  "workspace-regression",
];

const refuse = (message) => {
  throw new Error(message);
};
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const gateOf = (condition) => condition.conditionId.split("/").at(-1);
const isGate = (condition) => GATES.includes(gateOf(condition));

// ---- the comparison ---------------------------------------------------------------------------

const PROFILE_NAMES = ["emulator", "strict"];
const RANK = { MATCH: 0, INCOMPLETE: 1, DIFF: 2 };
const worst = (statuses) =>
  statuses.reduce((found, status) => (RANK[status] > RANK[found] ? status : found), "MATCH");

/** A row must carry the status and reasons of the production side and of each profile; each profile is at least as bad as the production side, and the combined status is the worse of the two profiles. */
function checkProfiles(row) {
  if (!plain(row.profiles) || !PROFILE_NAMES.every((name) => plain(row.profiles[name])))
    refuse(
      `row ${row.row} has no per-profile status: the comparison is from a comparator without the strict/emulator split`,
    );
  for (const name of PROFILE_NAMES) {
    const profile = row.profiles[name];
    if (!STATUSES.has(profile.status) || !Array.isArray(profile.reasons))
      refuse(`row ${row.row} has a bad ${name} status or reasons`);
  }
  // A fault of the recording itself (a production pass) is no profile's: it counts against both. A profile whose status is
  // better than the production side's, or that lacks its reasons, was made by a comparator that attributed it to one profile.
  const production = row.production;
  if (!plain(production) || !STATUSES.has(production.status) || !Array.isArray(production.reasons))
    refuse(`row ${row.row} has no production-side status`);
  for (const name of PROFILE_NAMES) {
    const profile = row.profiles[name];
    if (worst([production.status, profile.status]) !== profile.status)
      refuse(
        `row ${row.row}: the ${name} status is better than the production-side status, which counts against both profiles`,
      );
    if (!production.reasons.every((reason) => profile.reasons.includes(reason)))
      refuse(`row ${row.row}: the ${name} reasons lack the production-side reasons`);
  }
  if (worst(PROFILE_NAMES.map((name) => row.profiles[name].status)) !== row.status)
    refuse(`row ${row.row}: the combined status is not the worse of its two profiles`);
}

/** The comparison document, or a refusal: its kind, the artifact, and rows that are what the closure's inventory expects. */
export function checkComparison(comparison) {
  if (!plain(comparison) || comparison.kind !== COMPARISON_KIND)
    refuse(`the comparison is not a ${COMPARISON_KIND}`);
  if (!HEX64.test(comparison.artifactSha256 ?? ""))
    refuse("the comparison names no artifact digest");
  if (typeof comparison.execution !== "string" || comparison.execution === "")
    refuse("the comparison has no execution label");
  if (!Array.isArray(comparison.rows) || comparison.rows.length === 0)
    refuse("the comparison has no rows");
  const seen = new Set();
  for (const row of comparison.rows) {
    if (!plain(row) || typeof row.row !== "string" || typeof row.conditionId !== "string")
      refuse("a comparison row has no row id or condition");
    if (!STATUSES.has(row.status))
      refuse(`row ${row.row} has the status ${JSON.stringify(row.status)}`);
    if (!Array.isArray(row.reasons)) refuse(`row ${row.row} has no reasons list`);
    checkProfiles(row);
    if (seen.has(row.row)) refuse(`row ${row.row} appears twice`);
    seen.add(row.row);
  }
  const count = (status) => comparison.rows.filter((row) => row.status === status).length;
  const { summary } = comparison;
  if (
    !plain(summary) ||
    summary.rows !== comparison.rows.length ||
    summary.match !== count("MATCH") ||
    summary.diff !== count("DIFF") ||
    summary.incomplete !== count("INCOMPLETE")
  )
    refuse("the comparison's summary is not its rows' count");
  return comparison;
}

/**
 * The masks a comparison used, against the masks the closure record declares, or a refusal. A mask is declared by an APPROVED scope
 * decision that lists it in `masks`; the comparison names the decision it cites for each mask, and the two must agree. A comparison
 * that does not record its masks (summary.declaredMasks, even an empty list) cannot be judged and is refused too: an undeclared
 * mask would otherwise turn a difference into a MATCH with nothing in the record to say so.
 */
export function checkDeclaredMasks(comparison, closure) {
  const used = comparison.summary?.declaredMasks;
  if (!Array.isArray(used))
    refuse("the comparison does not record the masks it used (summary.declaredMasks)");
  const declaredBy = new Map();
  for (const decision of closure.scopeDecisions ?? []) {
    if (decision?.status !== "APPROVED" || !Array.isArray(decision.masks)) continue;
    for (const mask of decision.masks) declaredBy.set(mask, decision.id);
  }
  const check = (mask, reason) => {
    if (!declaredBy.has(mask))
      refuse(
        `the comparison used an undeclared mask ${mask}: no approved scope decision of the closure record lists it`,
      );
    if (reason !== declaredBy.get(mask))
      refuse(
        `the comparison cites ${reason} for the mask ${mask}, which the closure record declares under ${declaredBy.get(mask)}`,
      );
  };
  for (const { mask, reason } of used) check(mask, reason);
  const listed = new Set(used.map(({ mask }) => mask));
  for (const row of comparison.rows)
    for (const { mask, reason } of row.declaredMasks ?? []) {
      check(mask, reason);
      if (!listed.has(mask))
        refuse(
          `row ${row.row} used the mask ${mask}, which the comparison's summary does not list`,
        );
    }
}

/** The ids of the rows that settle a condition: every recipe x case x generation (a condition without generations has none). */
export function expectedRows(condition) {
  const generations = condition.generations ?? [];
  return (condition.recipeIds ?? []).flatMap((recipe) =>
    (condition.cases ?? []).flatMap((name) =>
      generations.map((generation) => `${recipe}#${name}#v${generation}`),
    ),
  );
}

/**
 * For each business condition of the closure: its expected rows, how many MATCH, and the specific DIFF, INCOMPLETE and
 * missing rows. The two gates (final artifact, review) are not business conditions and are left out. A row that belongs to
 * another condition than the one the closure maps it to, and a row no condition expects, are refusals: the comparison is
 * of another inventory.
 */
export function mapConditions(closure, comparison) {
  if (!Array.isArray(closure?.conditions) || closure.conditions.length === 0)
    refuse("the closure has no conditions");
  const byRow = new Map(comparison.rows.map((row) => [row.row, row]));
  const claimed = new Set();
  const conditions = [];
  for (const condition of closure.conditions) {
    if (isGate(condition)) continue;
    const expected = expectedRows(condition);
    if (expected.length === 0)
      refuse(`${condition.conditionId} has no case x generation to compare`);
    const entry = {
      conditionId: condition.conditionId,
      expected: expected.length,
      match: 0,
      diffRows: [],
      incompleteRows: [],
      missingRows: [],
      // the emulator profile against production: reported, never blocking
      emulatorProfile: { match: 0, diffRows: [], incompleteRows: [] },
    };
    for (const id of expected) {
      const row = byRow.get(id);
      if (!row) {
        entry.missingRows.push(id);
        continue;
      }
      if (row.conditionId !== condition.conditionId)
        refuse(`row ${id} belongs to ${row.conditionId}, not to ${condition.conditionId}`);
      claimed.add(id);
      const strict = row.profiles.strict;
      if (strict.status === "MATCH") entry.match += 1;
      else if (strict.status === "DIFF") entry.diffRows.push({ row: id, reasons: strict.reasons });
      else entry.incompleteRows.push({ row: id, reasons: strict.reasons });
      const emulator = row.profiles.emulator;
      if (emulator.status === "MATCH") entry.emulatorProfile.match += 1;
      else if (emulator.status === "DIFF")
        entry.emulatorProfile.diffRows.push({ row: id, reasons: emulator.reasons });
      else entry.emulatorProfile.incompleteRows.push({ row: id, reasons: emulator.reasons });
    }
    entry.status =
      entry.missingRows.length > 0
        ? "MISSING"
        : entry.diffRows.length > 0
          ? "MISMATCH"
          : entry.incompleteRows.length > 0
            ? "PRODUCTION_RECORDED"
            : "VERIFIED";
    conditions.push(entry);
  }
  const stray = comparison.rows.filter((row) => !claimed.has(row.row)).map((row) => row.row);
  if (stray.length > 0)
    refuse(`the comparison has rows the closure does not expect: ${stray.slice(0, 5).join(", ")}`);
  return conditions;
}

// ---- the production run, the build, the workspace ------------------------------------------------

/**
 * The two recordings of a production run record, or a refusal: a run that was recorded (no stops, a verified cleanup),
 * two passes in order with distinct times, frames captured, the project, and the corpus the closure is bound to.
 */
export function recordingsFromRun(run, { corpusSha256 } = {}) {
  if (!plain(run) || run.kind !== "functions-events-production-run")
    refuse("the file is not a production run record");
  if (run.project !== PROJECT)
    refuse(`the run is of ${JSON.stringify(run.project)}, not ${PROJECT}`);
  if (!HEX64.test(run.corpusDigest ?? "")) refuse("the run names no corpus digest");
  if (corpusSha256 !== undefined && run.corpusDigest !== corpusSha256)
    refuse("the run was recorded against another corpus than the closure's");
  const passes = run.passes;
  if (!Array.isArray(passes) || passes.length !== 2)
    refuse(
      `the run has ${Array.isArray(passes) ? passes.length : "no"} passes (a pass is skipped when the deploy does not become ready), the closure needs two`,
    );
  if (!Array.isArray(run.stops) || run.stops.length > 0)
    refuse("the run stopped before it was complete");
  if (run.cleanup?.verified !== true) refuse("the run's cleanup is not verified");
  if (!Array.isArray(run.frames) || run.frames.length === 0) refuse("the run captured no frames");
  passes.forEach((pass, index) => {
    if (pass?.pass !== index + 1) refuse(`pass ${index + 1} is not numbered ${index + 1}`);
    if (!ISO.test(pass.startedAt ?? "") || !ISO.test(pass.endedAt ?? ""))
      refuse(`pass ${index + 1} has no readable times`);
    if (Date.parse(pass.endedAt) < Date.parse(pass.startedAt))
      refuse(`pass ${index + 1} ends before it starts`);
    if (!Array.isArray(pass.operations) || pass.operations.length === 0)
      refuse(`pass ${index + 1} has no operations`);
  });
  if (passes[0].startedAt === passes[1].startedAt) refuse("the two passes start at the same time");
  if (Date.parse(passes[1].startedAt) < Date.parse(passes[0].endedAt))
    refuse("the second pass starts before the first ends");
  return passes.map((pass) => ({
    recordedAt: pass.startedAt,
    project: run.project,
    corpusDigest: run.corpusDigest,
    pass: pass.pass,
  }));
}

const BUILD_KEYS = [
  "sourceCommit",
  "gitStatusOutsideBuildOutput",
  "cargoVersion",
  "locked",
  "binarySha256",
];

/** The build record of the compared binary, or a refusal: five keys, a clean tree outside the build output, --locked, the digest. */
export function checkBuildRecord(record, comparison) {
  if (
    !plain(record) ||
    Object.keys(record).length !== BUILD_KEYS.length ||
    !BUILD_KEYS.every((key) => Object.hasOwn(record, key))
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
  if (record.binarySha256 !== comparison.artifactSha256)
    refuse("the build record is of another binary than the comparison");
  return record;
}

/** The workspace regression receipt of that binary and commit: `cargo nextest run --workspace --profile pr`, exit 0, nothing failed. */
export function checkWorkspaceReceipt(receipt, build) {
  if (!plain(receipt)) refuse("the workspace regression receipt is not an object");
  if (receipt.sourceCommit !== build.sourceCommit || receipt.binarySha256 !== build.binarySha256)
    refuse("the workspace regression receipt is of another commit or binary than the build record");
  if (receipt.command !== WORKSPACE_COMMAND)
    refuse(`the workspace regression receipt did not run ${WORKSPACE_COMMAND}`);
  if (receipt.exitCode !== 0) refuse("the workspace regression did not exit 0");
  const { passed, failed } = receipt.tests ?? {};
  if (!Number.isInteger(passed) || passed <= 0 || failed !== 0)
    refuse("the workspace regression receipt shows failed or no tests");
  return receipt;
}

/** The ledger rows of the run: one started, one finished as recorded with no lock kept, a close row at the baseline. */
export function checkLedger(text, runDir) {
  const rows = [];
  for (const line of String(text).split("\n")) {
    if (line.trim() === "") continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      refuse("the sandbox ledger has a line that is not JSON");
    }
  }
  const own = rows.filter((row) => row?.runDir === runDir);
  const one = (event) => {
    const found = own.filter((row) => row.event === event);
    if (found.length !== 1)
      refuse(`the sandbox ledger needs exactly one ${event} row for ${runDir}`);
    return found[0];
  };
  const started = one("started");
  const finished = one("finished");
  const closed = one("cleanup-verified");
  if (finished.outcome !== "recorded" || finished.lockRetained !== false)
    refuse("the run did not end recorded with its lock freed");
  if (!HEX40.test(started.gitSha ?? "") || started.gitSha !== finished.gitSha)
    refuse("the started and finished rows do not name one commit");
  if (closed.sandboxAtBaseline !== true) refuse("the sandbox is not at its baseline after the run");
  return { gitSha: started.gitSha, packetSha256: started.packetSha256 ?? null };
}

// ---- binding the comparison to what it is written with ------------------------------------------

/**
 * The comparison must be of the files it is written with: the corpus (its own digest, the `--corpus` file, the run's digest and
 * the repository's corpus all agree) and the production run (project, recordedAt and corpus digest). A comparison of another run
 * or another corpus is refused, never written as these recordings' evidence.
 */
export function checkComparisonBinding(comparison, { run, corpusSha256, repoCorpusSha256 }) {
  if (!HEX64.test(comparison.corpusSha256 ?? "")) refuse("the comparison names no corpus digest");
  if (corpusSha256 !== repoCorpusSha256)
    refuse("--corpus is not the repository's conformance/functions-events/corpus.json");
  if (comparison.corpusSha256 !== corpusSha256)
    refuse("the comparison was made against another corpus than --corpus");
  if (run.corpusDigest !== comparison.corpusSha256)
    refuse("the comparison was made against another corpus than the production run's");
  const recorded = comparison.productionRun;
  if (!plain(recorded)) refuse("the comparison names no production run");
  if (recorded.project !== run.project)
    refuse("the comparison is of another project than --production-run");
  if (recorded.recordedAt !== run.recordedAt)
    refuse(
      "the comparison is of another production run than --production-run (recordedAt differs)",
    );
  if (recorded.corpusDigest !== run.corpusDigest)
    refuse("the comparison's production run names another corpus than --production-run");
}

const defaultGit = (args) =>
  execFileSync("git", ["-C", fileURLToPath(new URL("../../../../", import.meta.url)), ...args]);

/**
 * The local sessions must have run the artifact: the comparison's `localBinary` is that binary (hashed by run.mjs from the file it
 * spawned), from a clean harness tree whose commit is the build's commit, with the Node runner that commit holds (the daemon takes
 * its runner from a checkout, so a runner of another tree would run other code than the binary was built with).
 */
export function checkLocalBinary(comparison, build, { git = defaultGit } = {}) {
  const local = comparison.localBinary;
  if (!plain(local))
    refuse("the comparison names no local binary: its sessions were not made by run.mjs");
  if (local.sha256 !== comparison.artifactSha256 || local.sha256 !== build.binarySha256)
    refuse("the sessions ran another binary than the artifact and the build record");
  if (local.dirty !== false) refuse("the sessions ran from a tree with uncommitted changes");
  if (local.sourceCommit !== build.sourceCommit)
    refuse("the sessions ran from another commit than the build record's source commit");
  const tree = String(git(["rev-parse", `${build.sourceCommit}:tools/runner-node`])).trim();
  if (local.runnerTree !== tree)
    refuse("the runner the sessions used is not the runner tree of the build's source commit");
  const bytes = git(["cat-file", "blob", `${build.sourceCommit}:tools/runner-node/index.mjs`]);
  if (local.runnerSha256 !== sha256(bytes))
    refuse("the runner file the sessions used is not index.mjs of the build's source commit");
}

// ---- applying it ------------------------------------------------------------------------------------

/** The gate rows of the comparison evidence: three MATCH rows, only when every precondition of the final-artifact gate holds. */
export function gateRows() {
  return GATE_CASES.map((name) => ({
    row: `functions-events/gate#${name}`,
    case: name,
    conditionId: "FUNCTIONS-EVENTS/final-artifact-regression",
    status: "MATCH",
    reasons: [],
    production: { status: "MATCH", reasons: [] },
    profiles: {
      emulator: { status: "MATCH", reasons: [] },
      strict: { status: "MATCH", reasons: [] },
    },
  }));
}

/**
 * A copy of the closure with the evidence of every VERIFIED business condition (the others are left as they are) and, when its preconditions hold, of the final-artifact
 * gate. `mapping` is `mapConditions`' answer, `recordings` the two recordings, `finalArtifact` the build record (or undefined),
 * `workspace` the workspace receipt (or undefined), `comparison` the comparison evidence (the checked comparison, with the three
 * gate rows added when the gate applies).
 */
export function applyClosure({
  closure,
  mapping,
  comparison,
  recordings,
  comparisonPath,
  finalArtifact,
  workspace,
}) {
  if (typeof comparisonPath !== "string" || comparisonPath === "")
    refuse("the comparison path is empty");
  if (!Array.isArray(recordings) || recordings.length !== 2)
    refuse("the closure needs two recordings");
  if (mapping.some((entry) => entry.status === "MISSING"))
    refuse(
      `the comparison does not cover ${mapping
        .filter((entry) => entry.status === "MISSING")
        .map((entry) => entry.conditionId)
        .join(", ")}`,
    );
  const byId = new Map(mapping.map((entry) => [entry.conditionId, entry]));
  const copy = structuredClone(closure);
  const everyMatch = comparison.rows.every((row) => row.profiles?.strict?.status === "MATCH");
  for (const condition of copy.conditions) {
    if (gateOf(condition) === "closure-review") continue;
    if (gateOf(condition) === "final-artifact-regression") {
      if (!everyMatch || finalArtifact === undefined || workspace === undefined) continue;
      condition.status = "VERIFIED";
      condition.evidence = {
        productionRecordings: structuredClone(recordings),
        finalArtifactSha256: comparison.artifactSha256,
        sourceCommit: finalArtifact.sourceCommit,
        comparisonPath,
        rows: { MATCH: comparison.rows.length },
      };
      continue;
    }
    const entry = byId.get(condition.conditionId);
    if (!entry) refuse(`${condition.conditionId} was not mapped`);
    // Only VERIFIED is written: any other condition keeps its status and gets no evidence (its rows are in the report).
    if (entry.status !== "VERIFIED") continue;
    condition.status = "VERIFIED";
    condition.evidence = {
      productionRecordings: structuredClone(recordings),
      finalArtifactSha256: comparison.artifactSha256,
      comparisonPath,
      rows: { MATCH: entry.match, DIFF: 0, INCOMPLETE: 0 },
      ...(finalArtifact ? { sourceCommit: finalArtifact.sourceCommit } : {}),
    };
  }
  return copy;
}

/** The report of a mapping: what a coordinator reads to see which product fixes the comparison still asks for. */
export function buildReport({ comparison, mapping }) {
  const count = (status) => mapping.filter((entry) => entry.status === status).length;
  const emulatorRows = (key) =>
    mapping.reduce((sum, entry) => sum + entry.emulatorProfile[key].length, 0);
  return {
    kind: "functions-events-closure-report",
    artifactSha256: comparison.artifactSha256,
    execution: comparison.execution,
    preliminary: /preliminary/i.test(comparison.execution),
    comparison: comparison.summary,
    judgedOn: "strict profile against production (owner ledger 811)",
    conditions: {
      total: mapping.length,
      verified: count("VERIFIED"),
      mismatch: count("MISMATCH"),
      productionRecorded: count("PRODUCTION_RECORDED"),
      missing: count("MISSING"),
    },
    // the emulator profile against PRODUCTION frames (not against the official emulator): reported, it never blocks VERIFIED
    emulatorProfileVersusProduction: {
      match: mapping.reduce((sum, entry) => sum + entry.emulatorProfile.match, 0),
      diff: emulatorRows("diffRows"),
      incomplete: emulatorRows("incompleteRows"),
    },
    details: mapping,
  };
}

/** One line per condition that is not VERIFIED (strict profile), then the totals and the emulator-profile section, for the terminal. */
export function reportText(report) {
  const lines = [
    `closure report of ${report.artifactSha256} (${report.execution})${report.preliminary ? " [preliminary]" : ""}`,
    `rows: ${report.comparison.match} MATCH, ${report.comparison.diff} DIFF, ${report.comparison.incomplete} INCOMPLETE of ${report.comparison.rows} (both profiles, as combined)`,
    `judged on: ${report.judgedOn}`,
  ];
  for (const entry of report.details) {
    if (entry.status === "VERIFIED") continue;
    lines.push(
      `${entry.status} ${entry.conditionId}: ${entry.match}/${entry.expected} MATCH (strict)`,
    );
    for (const row of entry.diffRows) lines.push(`  DIFF ${row.row}: ${row.reasons.join("; ")}`);
    for (const row of entry.incompleteRows)
      lines.push(`  INCOMPLETE ${row.row}: ${row.reasons.join("; ")}`);
    for (const id of entry.missingRows) lines.push(`  MISSING ${id}`);
  }
  const c = report.conditions;
  lines.push(
    `conditions: ${c.verified} VERIFIED, ${c.mismatch} MISMATCH, ${c.productionRecorded} PRODUCTION_RECORDED, ${c.missing} MISSING of ${c.total}`,
  );
  const e = report.emulatorProfileVersusProduction;
  lines.push(
    `emulator-profile versus production (reported, not blocking): ${e.match} MATCH, ${e.diff} DIFF, ${e.incomplete} INCOMPLETE rows`,
  );
  for (const entry of report.details) {
    const { diffRows, incompleteRows } = entry.emulatorProfile;
    if (diffRows.length + incompleteRows.length === 0) continue;
    lines.push(
      `  ${entry.conditionId}: ${diffRows.length} DIFF, ${incompleteRows.length} INCOMPLETE (emulator profile)`,
    );
  }
  return lines.join("\n");
}

/** The command, with its collaborators injected. */
export function closureEvidenceCommand(
  options,
  {
    read = (path) => readFileSync(path, "utf8"),
    write = defaultWrite,
    log = console.log,
    git = defaultGit,
    repoCorpus = () =>
      readFileSync(new URL("../../../functions-events/corpus.json", import.meta.url), "utf8"),
  } = {},
) {
  for (const name of ["comparison", "production-run", "closure", "corpus"])
    if (!options[name]) refuse(`--${name} is required`);
  const comparison = checkComparison(JSON.parse(read(options.comparison)));
  const closureText = read(options.closure);
  const closure = JSON.parse(closureText);
  checkDeclaredMasks(comparison, closure);
  const mapping = mapConditions(closure, comparison);
  const report = buildReport({ comparison, mapping });
  if (options["report-out"]) write(options["report-out"], `${JSON.stringify(report, null, 2)}\n`);
  log(reportText(report));
  if (options.write !== true) return { report };

  if (/preliminary/i.test(comparison.execution))
    refuse("a preliminary comparison is never written into the closure");
  for (const name of [
    "out",
    "comparison-path",
    "build-record",
    "build-record-out",
    "build-record-path",
    "sandbox-ledger",
  ])
    if (!options[name]) refuse(`--${name} is required with --write`);
  const run = JSON.parse(read(options["production-run"]));
  const corpusSha256 = sha256(read(options.corpus));
  const recordings = recordingsFromRun(run, { corpusSha256 });
  checkComparisonBinding(comparison, {
    run,
    corpusSha256,
    repoCorpusSha256: sha256(repoCorpus()),
  });
  checkLedger(read(options["sandbox-ledger"]), resolve(dirname(options["production-run"])));
  const buildBytes = read(options["build-record"]);
  const finalArtifact = checkBuildRecord(JSON.parse(buildBytes), comparison);
  checkLocalBinary(comparison, finalArtifact, { git });
  const workspace = options["workspace-regression"]
    ? checkWorkspaceReceipt(JSON.parse(read(options["workspace-regression"])), finalArtifact)
    : undefined;
  const everyMatch = comparison.rows.every((row) => row.profiles.strict.status === "MATCH");
  const withGates = everyMatch && workspace !== undefined;
  const evidence = {
    ...comparison,
    rows: withGates ? [...comparison.rows, ...gateRows()] : comparison.rows,
    buildRecordPath: options["build-record-path"],
    buildRecordSha256: sha256(buildBytes),
  };
  const next = applyClosure({
    closure,
    mapping,
    comparison: evidence,
    recordings,
    comparisonPath: options["comparison-path"],
    finalArtifact,
    workspace,
  });
  write(options["build-record-out"], buildBytes);
  write(options.out, `${JSON.stringify(evidence, null, 2)}\n`);
  write(options.closure, `${JSON.stringify(next, null, 2)}\n`);
  log(
    `closure evidence written: ${next.conditions.filter((c) => c.status === "VERIFIED").length} conditions VERIFIED`,
  );
  return { report, closure: next, evidence };
}

function defaultWrite(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!flag?.startsWith("--")) refuse(`bad argument: ${flag}`);
    if (flag === "--write") {
      options.write = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined) refuse(`bad argument: ${flag}`);
    options[flag.slice(2)] = value;
    index += 1;
  }
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  try {
    closureEvidenceCommand(parseArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
