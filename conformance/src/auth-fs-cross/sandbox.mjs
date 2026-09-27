// The sandbox protocol of an AUTH-FS-CROSS recording: the shared lock, the admission read of the
// shared ledger for both projects the run touches, the final readback against the baseline
// (FS-RULES' cleanup items and AUTH-TENANT-BLOCKING's admission conditions), and the ledger lines.
// Pure where it can be, so the rules are tested without a network.

import { createHash } from "node:crypto";
import { lstat, open, readFile, unlink } from "node:fs/promises";

export const TASK_ID = "AUTH-FS-CROSS-SANDBOX";
export const SANDBOX_PROJECT = "fireemu-oracle-idp";
export const FOREIGN_PROJECT = "fireemu-oracle-query";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

// ---- ledger --------------------------------------------------------------------------------

export function ledgerEntries(text) {
  const entries = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (entry && typeof entry === "object") entries.push(entry);
    } catch {
      // A line that does not parse is left to the lanes that wrote it.
    }
  }
  return entries;
}

/** A line that ends a task's run on a project cleanly (the rule AUTH-TENANT-BLOCKING applies). */
export function isCleanTerminal(row) {
  if (row.event === "started" || row.event === "needs-recovery") return false;
  if (row.event === "cleanup-verified") return row.outcome === undefined;
  if (row.sandboxAtBaseline === false) return false;
  if (row.outcome === "recorded") return true;
  return row.sandboxAtBaseline === true && row.outcome !== undefined;
}

/** A line that ends a run: anything but a start, a recovery request or a mid-run note or change. */
const endsRun = (row) =>
  row.event !== "started" &&
  row.event !== "needs-recovery" &&
  (row.outcome !== undefined || row.event === "finished" || row.event === "cleanup-verified");

/**
 * Why this task may not start on `project` now (the FS-RULES convention on both projects):
 * - another task's `started` line of the last 6 hours with no later line of that task;
 * - another task's `needs-recovery` line (of any age) with no later line that ends the run;
 * - another task's line there in the last 30 minutes;
 * - this task's own last run there not ended cleanly (`isCleanTerminal`).
 * Lines without a task id name no run and are skipped.
 */
export function admissionProblems(ledgerText, project, now = Date.now()) {
  const problems = [];
  const lines = ledgerEntries(ledgerText).filter(
    (entry) => entry.project === project && typeof entry.taskId === "string",
  );
  const unfinished = new Map();
  for (const entry of lines) {
    const task = entry.taskId;
    if (task === TASK_ID) {
      if (entry.event === "started" || entry.event === "needs-recovery" || !isCleanTerminal(entry))
        unfinished.set(task, entry);
      else unfinished.delete(task);
      continue;
    }
    if (entry.event === "started" || entry.event === "needs-recovery") unfinished.set(task, entry);
    else if (unfinished.get(task)?.event === "started" || endsRun(entry)) unfinished.delete(task);
  }
  for (const [task, entry] of unfinished) {
    if (task === TASK_ID)
      problems.push(`this task's run of ${entry.ts} on ${project} did not end cleanly`);
    else if (entry.event === "needs-recovery")
      problems.push(`${task} on ${project} needs recovery since ${entry.ts}`);
    else if (now - Date.parse(entry.ts) < 6 * 3_600_000)
      problems.push(`${task} on ${project} is open since ${entry.ts}`);
  }
  for (const entry of lines)
    if (entry.taskId !== TASK_ID && now - Date.parse(entry.ts) < 30 * 60_000)
      problems.push(`${entry.taskId} wrote a line on ${project} at ${entry.ts}`);
  return problems;
}

// ---- lock ----------------------------------------------------------------------------------

/**
 * Takes the shared ledger lock with O_EXCL. A lock that exists (another lane's, or a run of
 * this task that did not finish) is never touched: the run does not start.
 */
export async function acquireLock(ledger, sourceCommit, now = new Date()) {
  const path = `${ledger}.lock`;
  const body = JSON.stringify({ taskId: TASK_ID, sourceCommit, acquiredAt: now.toISOString() });
  let handle;
  try {
    handle = await open(path, "wx", 0o600);
  } catch (error) {
    if (error.code === "EEXIST")
      throw new Error(`the shared lock ${path} is held; not starting`, { cause: error });
    throw error;
  }
  try {
    await handle.writeFile(body);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const { ino } = await lstat(path);
  return { path, inode: ino, sha256: sha256(body) };
}

/** Removes the lock only while it is still this run's file (same inode, same body). */
export async function releaseLock(lock) {
  const stat = await lstat(lock.path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.ino !== lock.inode)
    throw new Error("the shared lock was replaced; left in place");
  if (sha256(await readFile(lock.path, "utf8")) !== lock.sha256)
    throw new Error("the shared lock was rewritten; left in place");
  await unlink(lock.path);
}

// ---- final readback ------------------------------------------------------------------------

export const ATB_TEST_PHONES = Object.fromEntries(
  [1, 2, 3, 4, 5, 6].map((i) => [`+1650555010${i}`, "123456"]),
);
export const ATB_AUTHORIZED_DOMAINS = [
  `${SANDBOX_PROJECT}.firebaseapp.com`,
  `${SANDBOX_PROJECT}.web.app`,
];
const SIGNER_ROLE = `projects/${SANDBOX_PROJECT}/roles/fireemuCustomTokenSigner`;

/**
 * The named differences of the final readback from the baseline the lanes leave the sandbox in:
 * FS-RULES' cleanup items and the six AUTH-TENANT-BLOCKING admission conditions. With
 * multi-tenancy off production refuses the tenant list, which counts as empty.
 */
export function finalMismatches(reads) {
  const config = reads.config ?? {};
  const signIn = config.signIn ?? {};
  const phone = signIn.phoneNumber ?? {};
  const tenantsOff = config.multiTenant?.allowTenants !== true;
  const tenantsEmpty = reads.tenantsUnlistable
    ? tenantsOff
    : Array.isArray(reads.tenants) && reads.tenants.length === 0;
  const domains = [...(config.authorizedDomains ?? [])].toSorted();
  const checks = [
    ["atb-1 tenants", tenantsEmpty],
    ["atb-2 allowTenants", tenantsOff],
    ["atb-2 improvedEmailPrivacy", config.emailPrivacyConfig?.enableImprovedEmailPrivacy === true],
    ["atb-2 disabledUserSignup", config.client?.permissions?.disabledUserSignup !== true],
    ["atb-2 disabledUserDeletion", config.client?.permissions?.disabledUserDeletion !== true],
    ["atb-2 allowDuplicateEmails", signIn.allowDuplicateEmails !== true],
    ["atb-2 mfa", (config.mfa?.state ?? "DISABLED") === "DISABLED"],
    ["atb-3 email", signIn.email?.enabled === true && signIn.email?.passwordRequired === true],
    ["atb-3 anonymous", signIn.anonymous?.enabled === true],
    ["atb-3 phone", phone.enabled === true],
    [
      "atb-3 testPhoneNumbers",
      JSON.stringify(Object.entries(phone.testPhoneNumbers ?? {}).toSorted()) ===
        JSON.stringify(Object.entries(ATB_TEST_PHONES).toSorted()),
    ],
    ["atb-4 authorizedDomains", JSON.stringify(domains) === JSON.stringify(ATB_AUTHORIZED_DOMAINS)],
    ["atb-5 project accounts", reads.projectAccounts === 0],
    ["atb-6 signer bindings", !(reads.bindings ?? []).some(({ role }) => role === SIGNER_ROLE)],
    ["releases", Array.isArray(reads.releases) && reads.releases.length === 0],
    ["rulesets", Array.isArray(reads.rulesets) && reads.rulesets.length === 0],
    ["databases", JSON.stringify(reads.databases) === JSON.stringify(["(default)"])],
    ["default documents", reads.defaultHasDocuments === false],
  ];
  return checks.filter(([, ok]) => !ok).map(([name]) => name);
}

// ---- ledger lines --------------------------------------------------------------------------

/** The `started` lines of both projects, written together after admission, under the lock. */
export function startedLines({ ts, sha, programs, operatorConfirmation, lock }) {
  return [SANDBOX_PROJECT, FOREIGN_PROJECT].map((project) => ({
    ts,
    event: "started",
    taskId: TASK_ID,
    project,
    stage: 1,
    gitSha: sha,
    programs,
    operatorConfirmation,
    lockSha256: lock.sha256,
  }));
}

/**
 * The closing lines of both projects. A run whose final readback matched ends with its outcome and
 * `sandboxAtBaseline: true`; otherwise both projects get `needs-recovery` and the lock stays.
 */
export function closingLines({ ts, sha, corpusDigest, outcome, atBaseline, idp, query, error }) {
  const common = { ts, taskId: TASK_ID, stage: 1, gitSha: sha, corpusDigest };
  const line = (project, counts) =>
    atBaseline
      ? { ...common, event: "finished", project, outcome, sandboxAtBaseline: true, ...counts }
      : {
          ...common,
          event: "needs-recovery",
          project,
          sandboxAtBaseline: false,
          ...counts,
          ...(error ? { error } : {}),
        };
  const lines = [line(SANDBOX_PROJECT, idp), line(FOREIGN_PROJECT, query)];
  // Some lanes count only `recorded` as a clean end; a verified baseline after any other outcome
  // is said once more in the form every lane accepts.
  if (atBaseline && outcome !== "recorded")
    for (const project of [SANDBOX_PROJECT, FOREIGN_PROJECT])
      lines.push({
        ts,
        event: "cleanup-verified",
        taskId: TASK_ID,
        project,
        sandboxAtBaseline: true,
        requests: 0,
        estimatedUsd: 0,
        note: `the final readback matched the baseline after outcome ${outcome}`,
      });
  return lines;
}
