// The recovery of one leftover Hosting version (recovery-v1). A recording run (HOSTING-PRODUCTION)
// that halted after its version create answered 2xx can leave that version behind. This module reads
// the version, proves it is the run's own, sends ONE delete and reads the result back. No other
// write: it creates, releases and finalizes nothing and touches no channel and no Auth setting.
//
//   node recover-version.mjs recover-production --run <six hex> --version-id <id>
//
// Rules (pre-submission checklist section 3): an unknown read stops before any write; a delete is
// sent once and never re-sent; a delete that does not answer 2xx (404 included) settles nothing; a
// settled delete is an own 2xx followed by a DELETED read and a list that no longer shows the
// version. The module never writes a closing ledger row: it writes `recovery-read`, and the
// coordinator closes the failed run after its own read-back (the rows here are not admitted by the
// recorder's `admit`).
import { fileURLToPath } from "node:url";

import {
  PROJECT,
  SITE,
  createBudget,
  makeApi,
  productionDeps,
  projectNumberOf,
  secretsFromWebConfig,
} from "./record.mjs";
import { maskSecrets } from "./rows.mjs";

export const RECOVERY_TASK_ID = "HOSTING-PRODUCTION-RECOVERY";
export const RECORDING_TASK_ID = "HOSTING-PRODUCTION";
export const RECOVERY_CAPS = { token: 3, read: 8, delete: 1, list: 3 };
const MAX_RECOVERY_ATTEMPTS = 2;
const POLLS = 5;
const POLL_GAP_MS = 10_000;
const WINDOW_SLACK_MS = 60_000;
const HOSTING = "https://firebasehosting.googleapis.com/v1beta1";
const RUN_TAG = /^[0-9a-f]{6}$/;
const VERSION_ID = /^[A-Za-z0-9]{8,64}$/;

const rowsOf = (ledgerText) =>
  ledgerText
    .split("\n")
    .filter((text) => text.trim())
    .map((text) => JSON.parse(text))
    .filter((line) => line.project === PROJECT);

/**
 * Admission: the last project row is the failed recording run's own terminal `needs-recovery` row
 * (so nothing has closed or superseded it), no recovery of it is half done, and at most
 * MAX_RECOVERY_ATTEMPTS recoveries were started. Returns the run's time window and the attempt.
 */
export function admitRecovery({ ledgerText, run }) {
  const lines = rowsOf(ledgerText);
  const last = lines.at(-1);
  if (
    !last ||
    last.taskId !== RECORDING_TASK_ID ||
    last.run !== run ||
    last.event !== "needs-recovery"
  ) {
    throw new Error("the last row for the project is not the run's own needs-recovery row");
  }
  const started = lines.findLast(
    (line) => line.taskId === RECORDING_TASK_ID && line.run === run && line.event === "started",
  );
  const startedAt = Date.parse(started?.ts ?? "");
  const endedAt = Date.parse(last.ts ?? "");
  if (!Number.isFinite(startedAt) || !Number.isFinite(endedAt)) {
    throw new Error("the run's rows have no time");
  }
  const mine = lines.filter((line) => line.taskId === RECOVERY_TASK_ID && line.run === run);
  mine.forEach((line, index) => {
    if (line.event === "started" && !mine[index + 1]) {
      throw new Error("a recovery of this run was started and has no result row");
    }
  });
  const attempt = mine.filter((line) => line.event === "started").length + 1;
  if (attempt > MAX_RECOVERY_ATTEMPTS) {
    throw new Error(`recovery attempt ${attempt} exceeds ${MAX_RECOVERY_ATTEMPTS}`);
  }
  return { startedAt, endedAt, attempt };
}

/** The form of a version name, with nothing private in it. */
export function nameFormat(name, id, number) {
  if (name === `sites/${SITE}/versions/${id}`) return "site";
  if (name === `projects/${PROJECT}/sites/${SITE}/versions/${id}`) return "project-id";
  if (/^\d+$/.test(number) && name === `projects/${number}/sites/${SITE}/versions/${id}`) {
    return "project-number";
  }
  return "other";
}

/**
 * Whether a version read proves the version is this run's own, unreleased leftover: the id, both
 * labels, the CREATED status and a create time inside the run (with a minute of slack).
 */
export function isRunsLeftover({ read, run, versionId, window, number }) {
  const problems = [];
  if (nameFormat(String(read.name ?? ""), versionId, number) === "other") problems.push("name");
  if (read.labels?.["fireemu-run"] !== run) problems.push("run label");
  if (read.labels?.["fireemu-version"] !== "v01") problems.push("version label");
  if (read.status !== "CREATED") problems.push(`status ${read.status}`);
  const created = Date.parse(read.createTime ?? "");
  if (
    !Number.isFinite(created) ||
    created < window.startedAt - WINDOW_SLACK_MS ||
    created > window.endedAt + WINDOW_SLACK_MS
  ) {
    problems.push("create time outside the run");
  }
  return problems;
}

/**
 * @param {object} deps now, readLedger, appendLedger, ownerAdc, webConfig, makeRunDir, writeRunFile,
 *   appendRunFile, token, http, sleep, log
 */
export async function recoverVersion({ run, versionId }, deps) {
  if (!RUN_TAG.test(run ?? "")) throw new Error("run must be six hex digits");
  if (!VERSION_ID.test(versionId ?? "")) throw new Error("version id is not a Hosting version id");
  const window = admitRecovery({ ledgerText: await deps.readLedger(), run });
  const adc = await deps.ownerAdc();
  const webConfig = await deps.webConfig();
  const secrets = secretsFromWebConfig(webConfig);
  const number = projectNumberOf(webConfig);
  const runDir = await deps.makeRunDir(`hosting-recovery-v1-${run}-${deps.now()}`);
  const budget = createBudget(RECOVERY_CAPS);
  const api = makeApi({ deps, budget, adc, runDir, secrets });
  const base = {
    project: PROJECT,
    database: null,
    taskId: RECOVERY_TASK_ID,
    run,
    versionId,
    runDir,
    attempt: window.attempt,
  };
  await deps.appendLedger(
    `${JSON.stringify({ ts: new Date(deps.now()).toISOString(), ...base, event: "started" })}\n`,
  );
  const out = {
    run,
    versionId,
    read: undefined,
    problems: [],
    delete: "not-sent",
    polls: [],
    listLeft: undefined,
    reason: undefined,
  };
  const versionUrl = `${HOSTING}/sites/${SITE}/versions/${versionId}`;
  try {
    const read = await api.call("read", "GET", versionUrl);
    if (read.kind !== "ok") {
      out.reason = read.kind === "unknown" ? "version read unknown" : `version read ${read.status}`;
    } else {
      out.read = {
        nameFormat: nameFormat(String(read.value.name ?? ""), versionId, number),
        status: read.value.status,
        labels: read.value.labels,
        createTime: read.value.createTime,
        fileCount: read.value.fileCount,
      };
      out.problems = isRunsLeftover({ read: read.value, run, versionId, window, number });
      if (out.problems.length) out.reason = `not the run's leftover: ${out.problems.join(", ")}`;
    }
    if (!out.reason) {
      // The one and only write. Never re-sent, whatever it answers.
      const deleted = await api.call("delete", "DELETE", versionUrl);
      out.delete = deleted.kind === "ok" ? "ok" : `${deleted.kind} (${deleted.status})`;
      for (let poll = 0; poll < POLLS; poll += 1) {
        if (poll > 0) await deps.sleep(POLL_GAP_MS);
        const again = await api.call("read", "GET", versionUrl);
        const state =
          again.kind === "ok" ? again.value.status : again.status === 404 ? "404" : "unknown";
        out.polls.push(state);
        if (state === "DELETED" || state === "404") break;
      }
      out.listLeft = await listLeft(api, run, versionId);
    }
  } catch (error) {
    out.reason = `stopped: ${maskSecrets(String(error.message), secrets)}`;
  }
  // Settled only by the run's own 2xx delete, then a DELETED read (a 404 poll is a read too) and a
  // list that no longer shows the version. An unknown or refused delete settles nothing.
  const last = out.polls.at(-1);
  const settled =
    out.delete === "ok" && (last === "DELETED" || last === "404") && out.listLeft === false;
  const at = deps.now();
  const text = `${JSON.stringify(out, null, 2)}\n`;
  if (secrets.some((secret) => secret.length >= 6 && text.includes(secret))) {
    throw new Error("the recovery result would retain a private value");
  }
  await deps.writeRunFile(runDir, "recovery.json", text);
  await deps.appendLedger(
    `${JSON.stringify({
      ts: new Date(at).toISOString(),
      ...base,
      // Never a closing event: the coordinator closes the failed run after its own read-back.
      event: "recovery-read",
      outcome: settled ? "recovery-read-clean" : "needs-recovery",
      delete: out.delete,
      polls: out.polls,
      listLeft: out.listLeft,
      reason: out.reason,
      a2ReadNotBefore: new Date(at + 10 * 60_000).toISOString(),
      requests: budget.snapshot(),
      estimatedUsd: 0,
    })}\n`,
  );
  return {
    outcome: settled ? "recovery-read-clean" : "needs-recovery",
    ...out,
    exitCode: settled ? 0 : 1,
  };
}

async function listLeft(api, run, versionId) {
  let token = "";
  for (let page = 0; page < 3; page += 1) {
    const query = `pageSize=100${token ? `&pageToken=${encodeURIComponent(token)}` : ""}`;
    const listed = await api.call("list", "GET", `${HOSTING}/sites/${SITE}/versions?${query}`);
    if (listed.kind !== "ok") return undefined;
    for (const version of listed.value.versions ?? []) {
      if (
        version.labels?.["fireemu-run"] === run &&
        String(version.name).split("/").at(-1) === versionId &&
        version.status !== "DELETED"
      ) {
        return true;
      }
    }
    token = listed.value.nextPageToken ?? "";
    if (!token) return false;
  }
  return undefined;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  const option = (name) => rest[rest.indexOf(name) + 1];
  if (mode !== "recover-production") {
    throw new Error("usage: recover-version.mjs recover-production --run <hex> --version-id <id>");
  }
  const deps = await productionDeps();
  const result = await recoverVersion(
    { run: option("--run"), versionId: option("--version-id") },
    deps,
  );
  console.log(
    JSON.stringify({
      outcome: result.outcome,
      delete: result.delete,
      polls: result.polls,
      listLeft: result.listLeft,
      exitCode: result.exitCode,
    }),
  );
  process.exitCode = result.exitCode;
}
