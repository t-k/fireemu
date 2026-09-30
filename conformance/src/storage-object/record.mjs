// The lean recorder: one STORAGE-OBJECT recording per run (owner ledger, "STORAGE-OBJECT scope
// (lean)"). A run is admitted on its own: the environment, the approved packet, a clean tree at the
// approved commit, the shared ledger and the project lock. The ledger is judged again once the lock
// is held, because only then can no other lane write a line between the judgement and the start.
// Then it writes a `started` row, runs the trusted local aggregate for one recording through the
// lean wire, and writes one closing row. A run that may have left objects writes `needs-recovery`
// and keeps the project lock; recovery is a separate packet. Nothing here retries. If the closing
// row (or the private summary) cannot be written, the `started` row stays open and the lock is
// kept: that is the safe state, and the error says a run had started.
//
// Every collaborator is passed in, so the order of these steps is tested without a network.

import { createHash } from "node:crypto";
import { randomBytes } from "node:crypto";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";
import { validatePresendApproval } from "./approval.mjs";
import { withProjectLocks } from "./project-locks.mjs";
import {
  expandProjectRows,
  finishedRow,
  needsRecoveryRow,
  SANDBOX_PROJECT,
  startedRow,
  TASK_ID,
} from "./ledger-rows.mjs";
import {
  createLeanWire,
  LEAN_PLACEHOLDER_ADMIN,
  LEAN_PLACEHOLDER_API_KEY,
  sanitizeRecord,
} from "./lean-wire.mjs";
import { createObjectMutationPacer } from "./production-pacing.mjs";

export const RECORD_PROJECT = SANDBOX_PROJECT;
export const RECORD_BUCKET = "fireemu-oracle-query.firebasestorage.app";
export const EXPECTED_NODE = "v24.14.0";

// The counter caps a run at 3,000 attempts, and the two Rules reads it counts once each are two
// real requests each, so a run sends at most 3,002 (and a packet of two runs at most 6,004).
const RUN_MAX_REQUESTS = 3002;
const RUN_RESERVE_USD = 0.5;
const RUN_ESTIMATE_USD = 0.15;
export const PACKET_MAX_REQUESTS = 6004;
export const PACKET_RESERVE_USD = 1;
const RUN_DEADLINE_MS = 2 * 60 * 60_000;
const QUIET_MS = 30 * 60_000;
const RUN_ID = /^[0-9a-f]{20}$/;
const TOKEN = /^[A-Za-z0-9._~+/=-]{20,}$/;
const RULESET_NAME = /^projects\/[^/]+\/rulesets\/[0-9a-f-]{36}$/;
const PLACEHOLDERS = Object.freeze({
  storage: "http://127.0.0.1:19199",
  auth: "http://127.0.0.1:19099",
  control: "http://127.0.0.1:19198",
});

/**
 * The Storage Rules release the run expects: the one STORAGE-RULES 2c-post restored on the query
 * project (owner ledger line 535), read back at 2026-09-30T13:13:42Z (run
 * `storage-rules-release-stage2c-post-20260930a`, operation `release/bucket/after`). A run stops if
 * the release it reads differs from this in name, ruleset, `createTime` or `updateTime`. A release
 * written again changes these, and pinning the new values is a new commit and a new review.
 */
export const RELEASE_BASELINE = Object.freeze({
  rulesetName: `projects/${SANDBOX_PROJECT}/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8`,
  createTime: "2026-09-30T13:13:41.329229Z",
  updateTime: "2026-09-30T13:13:41.329229Z",
});

const UNSAFE_ENVIRONMENT = Object.freeze(
  new Set([
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "STORAGE_EMULATOR_HOST",
    "FIREBASE_STORAGE_EMULATOR_HOST",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "FIRESTORE_EMULATOR_HOST",
  ]),
);

/**
 * Refuse anything that could redirect, intercept, re-trust or log the run's own connections, or
 * change who `gcloud` says the owner is. Every `NODE_*` variable but `NODE_ENV` and every
 * `CLOUDSDK_*` variable counts: Node reads `NODE_DEBUG`, `NODE_USE_SYSTEM_CA`, `NODE_OPTIONS` and
 * more, and `gcloud` reads its configuration and account from `CLOUDSDK_*`.
 */
export function refuseUnsafeEnvironment(env, nodeVersion) {
  if (nodeVersion !== EXPECTED_NODE) throw new Error(`Node ${EXPECTED_NODE} is required`);
  for (const name of Object.keys(env)) {
    if (
      UNSAFE_ENVIRONMENT.has(name) ||
      (name.startsWith("NODE_") && name !== "NODE_ENV") ||
      name.startsWith("CLOUDSDK_")
    )
      throw new Error(`unsafe environment: ${name} is set`);
  }
}

/** One digest of the runner's sources: their names and hashes, in a fixed order. */
export function runnerDigest(files) {
  const sorted = files
    .map(({ file, sha256 }) => ({ file, sha256 }))
    .toSorted((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return createHash("sha256").update(JSON.stringify(sorted)).digest("hex");
}

/**
 * The owner's access token, from `gcloud auth application-default print-access-token`, held in
 * memory only and taken again once it is about to expire. `run` returns the command's output.
 */
export function createTokenProvider({ run, now, ttlMs = 40 * 60_000 } = {}) {
  if (
    typeof run !== "function" ||
    typeof now !== "function" ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs < 1 ||
    ttlMs > 3_600_000
  )
    throw new Error("invalid token provider configuration");
  let token = null;
  let obtainedAt = 0;
  return async function getToken() {
    if (token !== null && now() - obtainedAt < ttlMs) return token;
    let output;
    try {
      output = await run();
    } catch {
      // The command's own message may quote what it printed.
      throw new Error("owner access token is unavailable");
    }
    const next = typeof output === "string" ? output.trim() : "";
    if (!TOKEN.test(next)) throw new Error("owner access token is unavailable");
    token = next;
    obtainedAt = now();
    return token;
  };
}

/**
 * The bucket's Storage Rules release and the ruleset it names, read from the Firebase Rules API
 * and held to `baseline`. Every real request is counted through `countRequest` before it is sent,
 * so a read that fails is counted too.
 */
export function createRulesReader({
  projectId,
  bucket,
  getToken,
  fetchImpl,
  record,
  baseline,
} = {}) {
  if (
    typeof projectId !== "string" ||
    typeof bucket !== "string" ||
    typeof getToken !== "function" ||
    typeof fetchImpl !== "function" ||
    typeof baseline?.rulesetName !== "string"
  )
    throw new Error("invalid Rules reader configuration");
  const base = "https://firebaserules.googleapis.com/v1";
  async function get(path, countRequest) {
    const token = await getToken();
    const url = `${base}/${path}`;
    countRequest?.();
    const response = await fetchImpl(url, {
      method: "GET",
      headers: { authorization: `Bearer ${token}`, "x-goog-user-project": projectId },
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    await record?.({
      kind: "rules-read",
      url,
      status: response.status,
      bodySha256: createHash("sha256").update(bytes).digest("hex"),
    });
    if (response.status !== 200) throw new Error("Rules read failed");
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error("Rules read failed");
    }
  }
  return async function readRules({ countRequest } = {}) {
    const release = await get(
      `projects/${projectId}/releases/firebase.storage/${bucket}`,
      countRequest,
    );
    const rulesetName = release?.rulesetName;
    if (
      typeof rulesetName !== "string" ||
      !RULESET_NAME.test(rulesetName) ||
      !rulesetName.startsWith(`projects/${projectId}/rulesets/`)
    )
      throw new Error("Rules release names no ruleset of this project");
    // What the release is, kept in the private record whether or not it is the expected one.
    await record?.({
      kind: "rules-release",
      rulesetName,
      createTime: release.createTime ?? null,
      updateTime: release.updateTime ?? null,
    });
    if (
      rulesetName !== baseline.rulesetName ||
      (release.createTime ?? null) !== baseline.createTime ||
      (release.updateTime ?? null) !== baseline.updateTime
    )
      throw new Error("Rules release differs from its pinned baseline");
    const ruleset = await get(rulesetName, countRequest);
    const files = ruleset?.source?.files;
    if (!Array.isArray(files) || files.length !== 1 || typeof files[0]?.content !== "string")
      throw new Error("Rules ruleset is not one source file");
    return { source: files[0].content, rulesetName };
  };
}

/**
 * What the ledger says about earlier runs of this packet. An open run is not counted: the
 * admission check has already refused to start while any run of this task is open.
 */
function priorRuns(ledgerText, packetSha256) {
  const closing = ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    })
    .filter(
      (row) =>
        row?.taskId === TASK_ID &&
        row.project === RECORD_PROJECT &&
        row.packetSha256 === packetSha256 &&
        row.event !== "started",
    );
  return {
    recorded: closing.filter((row) => row.event === "finished" && row.outcome === "recorded")
      .length,
    // A closing row without a request count is charged as a whole run.
    requests: closing.reduce(
      (total, row) =>
        total + (Number.isSafeInteger(row.requests) ? row.requests : RUN_MAX_REQUESTS),
      0,
    ),
  };
}

const iso = (date) => date.toISOString();
const usd = (requests) => Number(((requests / RUN_MAX_REQUESTS) * RUN_ESTIMATE_USD).toFixed(6));

/** Any line on the project with a task ID inside the quiet interval, whichever task wrote it. */
export function recentLineProblems(ledgerText, project, nowMs) {
  const problems = [];
  for (const line of ledgerText.split("\n")) {
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    if (
      row?.project === project &&
      typeof row.taskId === "string" &&
      nowMs - Date.parse(row.ts) < QUIET_MS
    )
      problems.push(`${row.taskId} wrote a line on ${project} at ${row.ts}`);
  }
  return problems;
}

/** Run one recording. Resolves with `{ outcome, requests }`; see the file comment. */
export async function recordRun(deps) {
  const {
    ids,
    recording,
    packet,
    review,
    ownerDecisionsText,
    env,
    nodeVersion,
    ledger,
    git,
    admission,
    locks,
    privateRun,
    getToken,
    apiKey,
    fetch: fetchImpl,
    replay,
    now,
  } = deps;
  const baseline = deps.releaseBaseline ?? RELEASE_BASELINE;
  refuseUnsafeEnvironment(env, nodeVersion);
  if (
    !RUN_ID.test(ids?.runId ?? "") ||
    !RUN_ID.test(ids?.otherRunId ?? "") ||
    ids.runId === ids.otherRunId
  )
    throw new Error("invalid run ID");
  if (recording !== 1 && recording !== 2) throw new Error("recording must be 1 or 2");
  validatePresendApproval({
    ledgerText: ownerDecisionsText,
    packet,
    review,
    runner: {
      projectId: RECORD_PROJECT,
      maxRequests: PACKET_MAX_REQUESTS,
      reserveUsd: PACKET_RESERVE_USD,
    },
  });
  for (const key of ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"]) {
    if (deps.actualPins?.[key] !== packet[key]) throw new Error(`pin mismatch: ${key}`);
  }
  if (!baseline.createTime || !baseline.updateTime)
    throw new Error("the Rules release baseline is not pinned (owner ledger line 535)");
  const tree = await git();
  if (!tree.clean) throw new Error("record-production needs a clean tree");
  if (tree.commit !== packet.sourceCommit)
    throw new Error("the checked-out commit is not the approved commit");

  // The shared ledger, judged: no open run, nothing inside the quiet interval, and a packet
  // history that leaves room for this recording.
  async function admit() {
    // A row may name several projects; judge it once for each.
    const ledgerText = expandProjectRows(await ledger.read());
    const nowMs = now().getTime();
    const problems = [
      ...new Set([
        ...admission(ledgerText, RECORD_PROJECT, nowMs),
        ...recentLineProblems(ledgerText, RECORD_PROJECT, nowMs),
      ]),
    ];
    if (problems.length > 0) throw new Error(`ledger admission: ${problems.join("; ")}`);
    const prior = priorRuns(ledgerText, packet.packetSha256);
    if (prior.recorded >= 2) throw new Error("this packet is already recorded twice");
    if (recording === 1 && prior.recorded === 1)
      throw new Error("this packet's first recording is already recorded");
    if (recording === 2 && prior.recorded !== 1)
      throw new Error("the second recording needs the first recording recorded");
    if (prior.requests + RUN_MAX_REQUESTS > packet.maxRequests)
      throw new Error("the packet's request budget would be exceeded");
  }
  // Once before the lock, to refuse cheaply; once under it, which is the judgement that counts.
  await admit();

  const plan = buildStage3DraftPlan({
    projectId: RECORD_PROJECT,
    bucket: RECORD_BUCKET,
    runIds: [ids.runId, ids.otherRunId],
  });
  const prefix = plan.recordings[0].prefix;
  const identity = (date) => ({
    ts: iso(date),
    runId: ids.runId,
    packetId: packet.packetName,
    packetSha256: packet.packetSha256,
    gitSha: packet.sourceCommit,
    corpusDigest: packet.corpusSha256,
  });

  let terminal = null;
  let wire = null;
  try {
    return await withProjectLocks(
      {
        projects: [RECORD_PROJECT],
        taskId: "STORAGE-OBJECT",
        packetId: packet.packetName,
        sourceCommit: packet.sourceCommit,
        pid: locks.pid,
        acquiredAt: iso(now()),
        lockDir: locks.lockDir,
        legacyLockPath: locks.legacyLockPath,
      },
      async (lease) => {
        await admit();
        const priv = await privateRun(ids.runId);
        // Every secret this run learns, so that nothing written to disk holds one.
        const known = [apiKey];
        const owned = async () => {
          const token = await getToken();
          if (!known.includes(token)) known.push(token);
          return token;
        };
        const safe = (value) => sanitizeRecord(value, known);
        const password = randomBytes(24).toString("base64url");
        known.push(password);
        const startedAtMs = now().getTime();
        lease.markStarted();
        try {
          await ledger.append(
            startedRow({
              ...identity(now()),
              maxRequests: RUN_MAX_REQUESTS,
              estimatedUsd: RUN_RESERVE_USD,
            }),
          );
          const journal = (type) => (event) => priv.event(safe({ type, ...event }));
          const options = {
            plan,
            recordings: 1,
            storageOrigin: PLACEHOLDERS.storage,
            authOrigin: PLACEHOLDERS.auth,
            localControl: { origin: PLACEHOLDERS.control, token: "synthetic-control-token" },
            localAuth: { apiKey: LEAN_PLACEHOLDER_API_KEY, password },
            credentials: { admin: LEAN_PLACEHOLDER_ADMIN },
            captureDirectory: priv.dir,
            stopAfter: () => now().getTime() - startedAtMs >= RUN_DEADLINE_MS,
            onStart: journal("started"),
            onReserve: journal("reserved"),
            onRecipeBegin: journal("recipe-begin"),
            onRecipeFinish: journal("recipe-finish"),
            onJournal: (event) => priv.event(safe(event)),
            onCapture: journal("response"),
            onByteReserve: async () => {},
            wireFactory: ({ origins }) => {
              wire = createLeanWire({
                bucket: RECORD_BUCKET,
                projectId: RECORD_PROJECT,
                prefix,
                origins: { storage: origins[0], auth: origins[1], control: origins[2] },
                adminToken: owned,
                authApiKey: apiKey,
                readRules: createRulesReader({
                  projectId: RECORD_PROJECT,
                  bucket: RECORD_BUCKET,
                  getToken: owned,
                  fetchImpl,
                  baseline,
                  record: (entry) => priv.capture(safe({ ...entry, at: iso(now()) })),
                }),
                fetchImpl,
                capture: (record) => priv.capture(safe(record)),
                pacer: createObjectMutationPacer({ ownedPrefixes: [prefix] }),
              });
              return wire;
            },
          };
          let result;
          try {
            result = await lease.dispatch(() => replay(options));
          } catch (error) {
            const sent = wire?.snapshot().realRequests ?? 0;
            const reason = safe(
              String(error?.message ?? error)
                .split("\n")[0]
                .slice(0, 200),
            );
            await priv
              .meta(
                safe({
                  runId: ids.runId,
                  recording,
                  outcome: "needs-recovery",
                  status: "THROWN",
                  reason,
                  requests: sent,
                  plan: { runId: ids.runId, prefix },
                }),
              )
              .catch(() => {});
            await ledger
              .append(
                needsRecoveryRow({ ...identity(now()), requests: sent, estimatedUsd: usd(sent) }),
              )
              .catch(() => {});
            throw error;
          }
          const requests = result?.wire?.realRequests ?? wire?.snapshot().realRequests ?? 0;
          const clean =
            (result?.unresolved ?? []).length === 0 && (result?.cleanupFailures ?? []).length === 0;
          const outcome =
            result?.status === "LOCAL_COMPLETE" && clean
              ? "recorded"
              : result?.status === "LOCAL_BLOCKED" && clean
                ? "stopped-clean"
                : "needs-recovery";
          await priv.meta(
            safe({
              runId: ids.runId,
              recording,
              outcome,
              status: result?.status,
              reason: result?.reason ?? null,
              requests,
              plan: { runId: ids.runId, prefix },
              ...(outcome === "needs-recovery"
                ? {
                    unresolved: result?.unresolved ?? null,
                    cleanupFailures: result?.cleanupFailures ?? null,
                  }
                : {}),
            }),
          );
          if (outcome === "needs-recovery") {
            await ledger.append(
              needsRecoveryRow({ ...identity(now()), requests, estimatedUsd: usd(requests) }),
            );
            terminal = { outcome, requests };
            return terminal;
          }
          await ledger.append(
            finishedRow({
              ...identity(now()),
              outcome,
              requests,
              estimatedUsd: usd(requests),
            }),
          );
          lease.confirmClosed();
          terminal = { outcome, requests };
          return terminal;
        } catch (error) {
          // From `markStarted` on, the lock is kept whatever goes wrong: say that a run had
          // started, so the caller does not report a refusal.
          if (error && typeof error === "object") error.afterStart = true;
          throw error;
        }
      },
    );
  } catch (error) {
    // The lock rule refuses to release after a run that is not closed; that is the intended state
    // of a run that needs recovery, and its row was written.
    if (terminal?.outcome === "needs-recovery" && /locks retained/.test(String(error?.message)))
      return terminal;
    throw error;
  }
}
