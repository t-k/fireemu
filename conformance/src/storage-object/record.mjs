// The lean recorder: one STORAGE-OBJECT recording per run (owner ledger, "STORAGE-OBJECT scope
// (lean)"). A run is admitted on its own: the environment, the approved packet, a clean tree at the
// approved commit, the shared ledger and the project lock. Then it writes a `started` row,
// runs the trusted local aggregate for one recording through the lean wire, and writes exactly one
// closing row. A run that may have left objects writes `needs-recovery` and keeps the project lock;
// recovery is a separate packet. Nothing here retries.
//
// Every collaborator is passed in, so the order of these steps is tested without a network.

import { createHash } from "node:crypto";
import { randomBytes } from "node:crypto";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";
import { validatePresendApproval } from "./approval.mjs";
import { withProjectLocks } from "./project-locks.mjs";
import {
  finishedRow,
  needsRecoveryRow,
  SANDBOX_PROJECT,
  startedRow,
  TASK_ID,
} from "./ledger-rows.mjs";
import { createLeanWire, LEAN_PLACEHOLDER_ADMIN, LEAN_PLACEHOLDER_API_KEY } from "./lean-wire.mjs";
import { createObjectMutationPacer } from "./production-pacing.mjs";

export const RECORD_PROJECT = SANDBOX_PROJECT;
export const RECORD_BUCKET = "fireemu-oracle-query.firebasestorage.app";
export const EXPECTED_NODE = "v24.14.0";

const RUN_MAX_REQUESTS = 3000;
const RUN_RESERVE_USD = 0.5;
const RUN_ESTIMATE_USD = 0.15;
const PACKET_MAX_REQUESTS = 6000;
const PACKET_RESERVE_USD = 1;
const RUN_ID = /^[0-9a-f]{20}$/;
const TOKEN = /^[^\s]{20,}$/;
const PLACEHOLDERS = Object.freeze({
  storage: "http://127.0.0.1:19199",
  auth: "http://127.0.0.1:19099",
  control: "http://127.0.0.1:19198",
});
const UNSAFE_ENVIRONMENT = Object.freeze([
  "NODE_OPTIONS",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "ALL_PROXY",
  "https_proxy",
  "http_proxy",
  "all_proxy",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "STORAGE_EMULATOR_HOST",
  "FIREBASE_STORAGE_EMULATOR_HOST",
  "FIREBASE_AUTH_EMULATOR_HOST",
]);

/** Refuse anything that could redirect, intercept or re-trust the run's own connections. */
export function refuseUnsafeEnvironment(env, nodeVersion) {
  if (nodeVersion !== EXPECTED_NODE) throw new Error(`Node ${EXPECTED_NODE} is required`);
  for (const name of UNSAFE_ENVIRONMENT) {
    if (Object.hasOwn(env, name)) throw new Error(`unsafe environment: ${name} is set`);
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
 * The bucket's Storage Rules release and the ruleset it names, read from the Firebase Rules API.
 * The answer is what the aggregate compares with the fixed Rules source; it counts two requests.
 */
export function createRulesReader({ projectId, bucket, getToken, fetchImpl, record } = {}) {
  if (
    typeof projectId !== "string" ||
    typeof bucket !== "string" ||
    typeof getToken !== "function" ||
    typeof fetchImpl !== "function"
  )
    throw new Error("invalid Rules reader configuration");
  const base = "https://firebaserules.googleapis.com/v1";
  async function get(path) {
    const token = await getToken();
    const url = `${base}/${path}`;
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
  return async function readRules() {
    const release = await get(`projects/${projectId}/releases/firebase.storage/${bucket}`);
    const rulesetName = release?.rulesetName;
    if (
      typeof rulesetName !== "string" ||
      !rulesetName.startsWith(`projects/${projectId}/rulesets/`)
    )
      throw new Error("Rules release names no ruleset of this project");
    const ruleset = await get(rulesetName);
    const files = ruleset?.source?.files;
    if (!Array.isArray(files) || files.length !== 1 || typeof files[0]?.content !== "string")
      throw new Error("Rules ruleset is not one source file");
    return {
      source: files[0].content,
      requests: 2,
      rulesetName,
      releaseCreateTime: release.createTime,
      releaseUpdateTime: release.updateTime,
    };
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
  const tree = await git();
  if (!tree.clean) throw new Error("record-production needs a clean tree");
  if (tree.commit !== packet.sourceCommit)
    throw new Error("the checked-out commit is not the approved commit");

  const ledgerText = await ledger.read();
  const problems = admission(ledgerText, RECORD_PROJECT, now().getTime());
  if (problems.length > 0) throw new Error(`ledger admission: ${problems.join("; ")}`);
  const prior = priorRuns(ledgerText, packet.packetSha256);
  if (prior.recorded >= 2) throw new Error("this packet is already recorded twice");
  if (recording === 1 && prior.recorded === 1)
    throw new Error("this packet's first recording is already recorded");
  if (recording === 2 && prior.recorded !== 1)
    throw new Error("the second recording needs the first recording recorded");
  if (prior.requests + RUN_MAX_REQUESTS > packet.maxRequests)
    throw new Error("the packet's request budget would be exceeded");

  const priv = await privateRun(ids.runId);
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
        lease.markStarted();
        await ledger.append(
          startedRow({
            ...identity(now()),
            maxRequests: RUN_MAX_REQUESTS,
            estimatedUsd: RUN_RESERVE_USD,
          }),
        );
        const journal = (type) => (event) => priv.event({ type, ...event });
        const options = {
          plan,
          recordings: 1,
          storageOrigin: PLACEHOLDERS.storage,
          authOrigin: PLACEHOLDERS.auth,
          localControl: { origin: PLACEHOLDERS.control, token: "synthetic-control-token" },
          localAuth: {
            apiKey: LEAN_PLACEHOLDER_API_KEY,
            password: randomBytes(24).toString("base64url"),
          },
          credentials: { admin: LEAN_PLACEHOLDER_ADMIN },
          captureDirectory: priv.dir,
          onStart: journal("started"),
          onReserve: journal("reserved"),
          onRecipeBegin: journal("recipe-begin"),
          onRecipeFinish: journal("recipe-finish"),
          onJournal: (event) => priv.event(event),
          onCapture: journal("response"),
          onByteReserve: async () => {},
          wireFactory: ({ origins }) => {
            wire = createLeanWire({
              bucket: RECORD_BUCKET,
              projectId: RECORD_PROJECT,
              prefix,
              origins: { storage: origins[0], auth: origins[1], control: origins[2] },
              adminToken: getToken,
              authApiKey: apiKey,
              readRules: createRulesReader({
                projectId: RECORD_PROJECT,
                bucket: RECORD_BUCKET,
                getToken,
                fetchImpl,
                record: (entry) => priv.capture({ ...entry, at: iso(now()) }),
              }),
              fetchImpl,
              capture: (record) => priv.capture(record),
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
        await priv.meta({
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
        });
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
