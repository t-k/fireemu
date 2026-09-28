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
  let path;
  try {
    path = decodeURIComponent(parsed.pathname);
  } catch {
    return "malformed percent-encoding in the path";
  }
  for (const [, project] of path.matchAll(/(?:^|\/)projects\/([^/]+)/g))
    if (!projects.includes(project)) return `undeclared project ${project}`;
  return null;
}

// ---- API keys ------------------------------------------------------------------------------

/** The application restrictions that refuse this host and the browser page whatever they name. */
const APPLICATION_RESTRICTIONS = [
  ["serverKeyRestrictions", "server"],
  ["androidKeyRestrictions", "android"],
  ["iosKeyRestrictions", "ios"],
];

/** The services the run's clients reach with the web key. */
const KEY_SERVICES = [
  "identitytoolkit.googleapis.com",
  "securetoken.googleapis.com",
  "firestore.googleapis.com",
];

/**
 * Why one key may refuse the run's clients. A browser restriction refuses them only when it
 * lists referrers (Firebase creates its browser key with an empty one); any other application
 * restriction refuses them. API targets must include every service the run uses, each without
 * a method list.
 */
function keyRefusals(restrictions) {
  const why = [];
  if ((restrictions?.browserKeyRestrictions?.allowedReferrers ?? []).length)
    why.push("browser-referrers");
  for (const [field, name] of APPLICATION_RESTRICTIONS)
    if (restrictions?.[field] !== undefined) why.push(name);
  const targets = restrictions?.apiTargets;
  if (targets !== undefined)
    for (const service of KEY_SERVICES) {
      const target = targets.find((t) => t.service === service);
      if (!target) why.push(`api-target-missing:${service}`);
      else if ((target.methods ?? []).length) why.push(`api-target-methods:${service}`);
    }
  return why;
}

/**
 * Why the project's keys may refuse the run's clients: a failed read, or any key whose
 * restrictions refuse them (the web config's key cannot be told apart without its key string,
 * which is never read, so every key counts).
 */
export function keyRestrictionProblems({ status, json }) {
  if (status !== 200) return [`API keys read failed (HTTP ${status})`];
  if (json?.nextPageToken) return ["API keys read has more than one page"];
  return restrictedKeys(json).map(
    ({ displayName, uid, why }) =>
      `API key ${displayName ?? uid ?? "?"} may refuse the run's clients (${why.join(", ")})`,
  );
}

/** The keys that may refuse the run's clients, by display name and uid (never the key string). */
export function restrictedKeys(json) {
  return (json?.keys ?? [])
    .map((key) => ({
      displayName: key.displayName ?? null,
      uid: key.uid ?? null,
      why: keyRefusals(key.restrictions),
    }))
    .filter(({ why }) => why.length);
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
    // Only this lane's topics count. Approvals are read under the exact topics; a revocation
    // under any of this lane's topics withdraws what it names (the safe side: a revocation once
    // went under a topic no approval uses).
    if (topic !== PARENT && !topic.startsWith(`${PARENT} `)) continue;
    const known = topic === subject || topic === `${subject} envelope` || topic === PARENT;
    const entry = fields(body);
    // A later line naming this version or an envelope that is not an approval of it (REVOKED,
    // another decision) withdraws what it names, as stage 1 refuses after any later line.
    const revoked = /\bREVOKED\b/i.test(body);
    if (!known && !revoked) continue;
    const withdraws =
      revoked ||
      (entry.decision !== undefined &&
        entry.decision !== "APPROVE" &&
        topic !== `${subject} envelope`);
    if (withdraws) {
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
 * The line of a run stopped before it wrote anything, for a reason the owner decides on (a key
 * that may refuse the browser): it names the reason and what caused it, and ends nothing open.
 */
export function stoppedLine({
  ts,
  sha,
  packetSha256,
  recording,
  programDigest,
  reason,
  detail,
  requests,
}) {
  return {
    ts,
    event: "finished",
    taskId: TASK_ID,
    project: SANDBOX_PROJECT,
    stage: STAGE,
    recording,
    packetSha256,
    gitSha: sha,
    programDigest,
    outcome: "stopped-before-write",
    sandboxAtBaseline: true,
    reason,
    ...detail,
    requests,
    estimatedUsd: 0,
  };
}

/**
 * The closing lines. A run whose final readback matched ends with its outcome and
 * `sandboxAtBaseline: true`; otherwise `needs-recovery`, and the lock stays.
 */
export function closingLines({
  ts,
  sha,
  packetSha256,
  recording,
  programDigest,
  outcome,
  atBaseline,
  counts,
  error,
}) {
  // Every line names its packet: recording 2 is admitted by recording 1's closing line.
  const common = {
    ts,
    taskId: TASK_ID,
    project: SANDBOX_PROJECT,
    stage: STAGE,
    recording,
    packetSha256,
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
