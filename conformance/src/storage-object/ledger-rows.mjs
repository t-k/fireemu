// The rows a STORAGE-OBJECT run appends to the shared sandbox ledger (`sandbox-ledger.jsonl`).
//
// Every runner reads that ledger with its own parser, and some refuse a row they cannot
// classify, so a run writes only what other lanes already write: a `started` line, then one
// closing line, and a `needs-recovery` line when it stops with the sandbox possibly off its
// baseline. No new event and no new outcome is defined here
// (`storage-object-ledger-compat.test.mjs` feeds these rows to every reader).
//
// Two rules the readers force:
// - `needs-recovery` is both the event and the outcome. One reader ends a run on any outcome
//   unless the event says `needs-recovery`, and another also looks at the outcome.
// - a closing row is written only after the run's own objects were read back as absent, so it
//   says `sandboxAtBaseline: true`; a run that cannot say so writes `needs-recovery`.

export const TASK_ID = "STORAGE-OBJECT-SANDBOX";
export const SANDBOX_PROJECT = "fireemu-oracle-query";

/** Outcomes that close a run; each is already used by other lanes' finished rows. */
export const CLOSING_OUTCOMES = Object.freeze([
  "recorded",
  "recovered-no-observation",
  "stopped-clean",
]);

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/;

/**
 * A UTC timestamp every reader parses. The pattern fixes the shape, `Date.parse` rejects a month,
 * minute or second out of range, and the two checks below cover what it accepts: hour 24 and a
 * day past the end of the month.
 */
function validTimestamp(ts) {
  const match = TIMESTAMP.exec(ts);
  if (!match || !Number.isFinite(Date.parse(ts))) return false;
  const [, year, month, day, hour] = match;
  return +hour <= 23 && +day <= new Date(Date.UTC(+year, +month, 0)).getUTCDate();
}

function identity(input) {
  const { ts, runId, packetId, packetSha256, gitSha, corpusDigest } = input;
  if (!validTimestamp(ts)) throw new Error("ledger row needs a UTC timestamp");
  if (typeof runId !== "string" || !IDENTIFIER.test(runId)) throw new Error("invalid run ID");
  if (typeof packetId !== "string" || !IDENTIFIER.test(packetId))
    throw new Error("invalid packet ID");
  if (typeof packetSha256 !== "string" || !SHA256.test(packetSha256))
    throw new Error("invalid packet SHA-256");
  if (typeof gitSha !== "string" || !GIT_SHA.test(gitSha)) throw new Error("invalid git SHA");
  if (typeof corpusDigest !== "string" || !SHA256.test(corpusDigest))
    throw new Error("invalid corpus digest");
  return {
    ts,
    taskId: TASK_ID,
    project: SANDBOX_PROJECT,
    runId,
    packetId,
    packetSha256,
    gitSha,
    corpusDigest,
  };
}

function cost(value) {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error("estimatedUsd must be a finite number of at least 0");
  }
  return value;
}

function count(value, name, minimum) {
  if (!Number.isSafeInteger(value) || value < minimum)
    throw new Error(`${name} must be an integer of at least ${minimum}`);
  return value;
}

/** The line that opens a run: the reservation of the requests and the estimate. */
export function startedRow(input) {
  const { ts, taskId, project, runId, packetId, packetSha256, gitSha, corpusDigest } =
    identity(input);
  return {
    ts,
    event: "started",
    taskId,
    project,
    runId,
    packetId,
    packetSha256,
    gitSha,
    corpusDigest,
    maxRequests: count(input.maxRequests, "maxRequests", 1),
    estimatedUsd: cost(input.estimatedUsd),
  };
}

/** The line that closes a run whose own objects were read back as absent. */
export function finishedRow(input) {
  const base = identity(input);
  if (!CLOSING_OUTCOMES.includes(input.outcome)) throw new Error("not a closing outcome");
  return {
    ts: base.ts,
    event: "finished",
    outcome: input.outcome,
    taskId: base.taskId,
    project: base.project,
    runId: base.runId,
    packetId: base.packetId,
    packetSha256: base.packetSha256,
    gitSha: base.gitSha,
    corpusDigest: base.corpusDigest,
    requests: count(input.requests, "requests", 0),
    estimatedUsd: cost(input.estimatedUsd),
    sandboxAtBaseline: true,
  };
}

/** The line that keeps a run open: the sandbox may hold this run's objects or a changed state. */
export function needsRecoveryRow(input) {
  const base = identity(input);
  return {
    ts: base.ts,
    event: "needs-recovery",
    outcome: "needs-recovery",
    taskId: base.taskId,
    project: base.project,
    runId: base.runId,
    packetId: base.packetId,
    packetSha256: base.packetSha256,
    gitSha: base.gitSha,
    corpusDigest: base.corpusDigest,
    requests: count(input.requests, "requests", 0),
    estimatedUsd: cost(input.estimatedUsd),
    sandboxAtBaseline: false,
  };
}

/** One line of the ledger: a JSON object (JSON.stringify escapes any newline) and its newline. */
export function encodeRow(row) {
  return `${JSON.stringify(row)}\n`;
}

const projectNames = (row) => [
  ...new Set(
    [
      ...(typeof row.project === "string" ? row.project.split(",") : []),
      ...(Array.isArray(row.projects) ? row.projects.filter((p) => typeof p === "string") : []),
    ]
      .map((name) => name.trim())
      .filter(Boolean),
  ),
];

/**
 * The ledger with every row that names several projects written once per project. A row names
 * several as a comma-separated `project` ("a,b") or as a `projects` array; the admission checks
 * read `row.project` as one name, so they would not see such a row on either project. A row of one
 * project, a line that is not a JSON row and a row that names no project are kept as they were.
 */
export function expandProjectRows(ledgerText) {
  return ledgerText
    .split("\n")
    .flatMap((line) => {
      let row;
      try {
        row = JSON.parse(line);
      } catch {
        return [line];
      }
      if (row === null || typeof row !== "object" || Array.isArray(row)) return [line];
      const names = projectNames(row);
      const plain = typeof row.project === "string" && !row.project.includes(",");
      if (names.length === 0 || (plain && !("projects" in row))) return [line];
      const { projects: _projects, ...rest } = row;
      return names.map((project) => JSON.stringify({ ...rest, project }));
    })
    .join("\n");
}
