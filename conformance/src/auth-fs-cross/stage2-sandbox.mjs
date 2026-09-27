// The sandbox protocol of an AUTH-FS-CROSS stage-2 recording: project-scoped locks (owner
// decision A, 2026-09-28), the owner's approval of the packet or of its envelope (owner decision
// C, 2026-09-28), the destinations a run may reach, and the stage-2 ledger lines. Stage 2
// declares one project, the idp sandbox. Pure where it can be, so the rules are tested without
// a network.

import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile, stat, unlink } from "node:fs/promises";
import { join } from "node:path";

import { ledgerEntries, SANDBOX_PROJECT, TASK_ID } from "./sandbox.mjs";

export { SANDBOX_PROJECT, TASK_ID };
export const STAGE = 2;
export const PARENT = "AUTH-FS-CROSS";
export const PACKET = "stage-2 packet";
/** The projects a stage-2 run declares; it sends nothing to any other. */
export const DECLARED_PROJECTS = [SANDBOX_PROJECT];
/** The hosts a stage-2 run's harness may reach (the SDK clients have their own list). */
export const HARNESS_HOSTS = [
  "identitytoolkit.googleapis.com",
  "securetoken.googleapis.com",
  "firestore.googleapis.com",
  "firebaserules.googleapis.com",
  "iam.googleapis.com",
  // One read of the project's API keys' restrictions; never their key strings.
  "apikeys.googleapis.com",
];
/** A recording is one run; the packet approves two, in order (decision D2). */
export const RECORDINGS = [1, 2];
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

// ---- destinations --------------------------------------------------------------------------

/**
 * Why `url` may not be sent: a host outside `hosts`, or a `projects/<id>` segment naming a
 * project outside `projects` (including the `-` wildcard). `null` when it may.
 */
export function destinationProblem(
  url,
  { hosts = HARNESS_HOSTS, projects = DECLARED_PROJECTS } = {},
) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return `not a URL: ${String(url).slice(0, 80)}`;
  }
  if (parsed.protocol !== "https:") return `not https: ${parsed.protocol}`;
  if (!hosts.includes(parsed.hostname)) return `undeclared host ${parsed.hostname}`;
  const path = decodeURIComponent(parsed.pathname);
  for (const [, project] of path.matchAll(/(?:^|\/)projects\/([^/]+)/g))
    if (!projects.includes(project)) return `undeclared project ${project}`;
  return null;
}

// ---- API keys ------------------------------------------------------------------------------

/** The restrictions that would make a key refuse the browser page's origin or this host. */
const APPLICATION_RESTRICTIONS = [
  "browserKeyRestrictions",
  "serverKeyRestrictions",
  "androidKeyRestrictions",
  "iosKeyRestrictions",
];

/**
 * Why the project's keys may refuse the run's clients: a failed read, or any key with an
 * application restriction (the web config's key cannot be told apart without its key string,
 * which is never read, so every key counts).
 */
export function keyRestrictionProblems({ status, json }) {
  if (status !== 200) return [`API keys read failed (HTTP ${status})`];
  if (json?.nextPageToken) return ["API keys read has more than one page"];
  return (json?.keys ?? [])
    .filter((key) => APPLICATION_RESTRICTIONS.some((r) => key.restrictions?.[r] !== undefined))
    .map((key) => `API key ${key.displayName ?? key.uid ?? "?"} has an application restriction`);
}

// ---- locks ---------------------------------------------------------------------------------

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

/** Removes a lock only while it is still this run's file (same inode, same body). */
export async function releaseProjectLock(lock) {
  const found = await lstat(lock.path);
  if (!found.isFile() || found.isSymbolicLink() || found.ino !== lock.inode)
    throw new Error(`the lock of ${lock.project} was replaced; left in place`);
  if (sha256(await readFile(lock.path, "utf8")) !== lock.sha256)
    throw new Error(`the lock of ${lock.project} was rewritten; left in place`);
  await unlink(lock.path);
}

/**
 * Takes the locks of `projects` in ascending project-ID order with O_EXCL, all or none. The
 * legacy shared lock must be absent before and after. A lock that exists is never touched; on
 * any refusal the locks this call took are removed and nothing was sent.
 */
export async function acquireProjectLocks({ lockDir, legacyLock, projects, body }) {
  if (await exists(legacyLock)) throw new Error("the legacy shared lock is held; not starting");
  await mkdir(lockDir, { recursive: true, mode: 0o700 });
  if ((await stat(lockDir)).mode & 0o077) throw new Error(`${lockDir} is not private (mode 700)`);
  const text = JSON.stringify(body);
  const taken = [];
  const undo = async () => {
    for (const lock of taken.toReversed()) await releaseProjectLock(lock);
  };
  for (const project of [...projects].toSorted()) {
    const path = join(lockDir, `${project}.lock`);
    let handle;
    try {
      handle = await open(path, "wx", 0o600);
    } catch (error) {
      await undo();
      if (error.code === "EEXIST")
        throw new Error(`the lock of ${project} is held; not starting`, { cause: error });
      throw error;
    }
    try {
      await handle.writeFile(text);
      await handle.sync();
    } finally {
      await handle.close();
    }
    taken.push({ project, path, inode: (await lstat(path)).ino, sha256: sha256(text) });
  }
  if (await exists(legacyLock)) {
    await undo();
    throw new Error("the legacy shared lock appeared; not starting");
  }
  return taken;
}

// ---- owner approval ------------------------------------------------------------------------

const DATE_LINE = /^- \d{4}-\d{2}-\d{2} \| /;

/** `key=value; key=value` as an object (values trimmed). */
export function fields(text) {
  return Object.fromEntries(
    text
      .split(";")
      .map((part) => part.trim())
      .filter((part) => part.includes("="))
      .map((part) => [
        part.slice(0, part.indexOf("=")).trim(),
        part.slice(part.indexOf("=") + 1).trim(),
      ]),
  );
}

/** Whether an envelope covers the runner: the same project, limits at least the runner's. */
export function covers(envelope, runner) {
  const number = (value) => (/^\d+(\.\d+)?$/.test(value ?? "") ? Number(value) : Number.NaN);
  return (
    envelope.project === runner.project &&
    number(envelope.maxRequests) >= runner.maxRequests &&
    number(envelope.reserveUsd) >= runner.reserveUsd
  );
}

/**
 * The approval of this stage-2 packet version, or the reason there is none. Accepted forms:
 * (1) the owner's line `- date | AUTH-FS-CROSS stage-2 packet | decision=APPROVE;
 *     packetSha256=…; sourceCommit=…; harnessDigest=… | オーナー… | …`;
 * (2) the owner's envelope line `- date | AUTH-FS-CROSS stage-2 packet envelope |
 *     envelopeId=…; project=…; maxRequests=…; reserveUsd=…; … | オーナー… | …` and, after it,
 *     the coordinator's line `- date | AUTH-FS-CROSS stage-2 packet | decision=APPROVE;
 *     envelopeId=…; packetSha256=…; sourceCommit=…; harnessDigest=… | Claude（委任… | …`,
 *     where the envelope covers `runner` ({project, maxRequests, reserveUsd}).
 * A later line of the packet (or its envelope) saying REVOKED withdraws the version or the
 * envelope it names.
 */
export function packetApproval(ownerText, { packetSha256, sourceCommit, harnessDigest, runner }) {
  const subject = `${PARENT} ${PACKET}`;
  const pinned = (entry) =>
    entry.decision === "APPROVE" &&
    entry.packetSha256 === packetSha256 &&
    entry.sourceCommit === sourceCommit &&
    entry.harnessDigest === harnessDigest;
  const envelopes = new Map();
  let approval;
  for (const raw of ownerText.split("\n")) {
    const line = raw.trim();
    if (!DATE_LINE.test(line)) continue;
    const [, topic = "", body = "", decider = ""] = line
      .slice(2)
      .split(" | ")
      .map((c) => c.trim());
    if (topic !== subject && topic !== `${subject} envelope` && topic !== PARENT) continue;
    const entry = fields(body);
    if (/\bREVOKED\b/.test(body)) {
      if (body.includes(packetSha256)) approval = undefined;
      const id = entry.envelopeId ?? /\benvelopeId=([A-Za-z0-9_-]+)/.exec(body)?.[1];
      if (id) {
        envelopes.delete(id);
        if (approval?.envelopeId === id) approval = undefined;
      }
      continue;
    }
    if (topic === `${subject} envelope` && decider.startsWith("オーナー")) {
      if (entry.envelopeId) envelopes.set(entry.envelopeId, entry);
    } else if (topic === subject && decider.startsWith("オーナー") && pinned(entry)) {
      approval = { kind: "owner", line };
    } else if (topic === subject && decider.startsWith("Claude（委任") && pinned(entry)) {
      const envelope = envelopes.get(entry.envelopeId);
      if (envelope && covers(envelope, runner))
        approval = { kind: "envelope", line, envelopeId: entry.envelopeId, envelope };
    }
  }
  return approval
    ? { approval, problems: [] }
    : { problems: ["no owner approval of this packet version or its envelope"] };
}

// ---- ledger --------------------------------------------------------------------------------

const clean = (entry) =>
  entry.event === "finished" && entry.sandboxAtBaseline === true && entry.outcome === "recorded";

/**
 * Why recording `n` of this packet may not start: recording 1 starts once; recording 2 starts
 * once, after recording 1 of the same packet ended `recorded` at baseline.
 */
export function recordingProblems(ledgerText, packetSha256, n) {
  if (!RECORDINGS.includes(n)) return [`recording ${n} is not 1 or 2`];
  const ours = ledgerEntries(ledgerText).filter(
    (e) => e.taskId === TASK_ID && e.stage === STAGE && e.packetSha256 === packetSha256,
  );
  const problems = [];
  if (ours.some((e) => e.event === "started" && e.recording === n))
    problems.push(`recording ${n} of this packet already started`);
  if (n === 2) {
    const first = ours.findLast((e) => e.recording === 1 && e.event !== "started");
    if (!first || !clean(first))
      problems.push("recording 1 of this packet did not end recorded at baseline");
  }
  return problems;
}

/** The `started` line of the run's project, written after admission, under the locks. */
export function startedLine({
  ts,
  sha,
  packetSha256,
  recording,
  programDigest,
  locks,
  approval,
  reserveUsd,
}) {
  return {
    ts,
    event: "started",
    taskId: TASK_ID,
    project: SANDBOX_PROJECT,
    stage: STAGE,
    recording,
    gitSha: sha,
    packetSha256,
    programDigest,
    approval: approval.kind,
    ...(approval.envelopeId ? { envelopeId: approval.envelopeId } : {}),
    lockSha256: locks.map(({ sha256: digest }) => digest),
    // The packet's reservation, counted even if the run fails.
    maxEstimatedUsd: reserveUsd,
  };
}

/**
 * The closing lines. A run whose final readback matched ends with its outcome and
 * `sandboxAtBaseline: true`; otherwise `needs-recovery`, and the lock stays.
 */
export function closingLines({
  ts,
  sha,
  recording,
  programDigest,
  outcome,
  atBaseline,
  counts,
  error,
}) {
  const common = {
    ts,
    taskId: TASK_ID,
    project: SANDBOX_PROJECT,
    stage: STAGE,
    recording,
    gitSha: sha,
    programDigest,
  };
  if (!atBaseline)
    return [
      {
        ...common,
        event: "needs-recovery",
        sandboxAtBaseline: false,
        ...counts,
        ...(error ? { error } : {}),
      },
    ];
  const lines = [{ ...common, event: "finished", outcome, sandboxAtBaseline: true, ...counts }];
  // Some lanes count only `recorded` as a clean end; a verified baseline after any other outcome
  // is said once more in the form every lane accepts.
  if (outcome !== "recorded")
    lines.push({
      ts,
      event: "cleanup-verified",
      taskId: TASK_ID,
      project: SANDBOX_PROJECT,
      sandboxAtBaseline: true,
      requests: 0,
      estimatedUsd: 0,
      note: `the final readback matched the baseline after outcome ${outcome}`,
    });
  return lines;
}
