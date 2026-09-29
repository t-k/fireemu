// One run of the probe (see probe.mjs): the same admission as a recording (environment,
// approved packet, pins, clean tree at the approved commit, the shared ledger, the project lock)
// around up to seventeen requests through the lean wire. It writes a `started` row, sends the plan, and writes
// one closing row. A run that cannot finish its requests writes `needs-recovery` and keeps
// the project lock, as a recording does; nothing here retries, and a packet runs once.
//
// Every collaborator is passed in, so the order is tested without a network.

import { validatePresendApproval } from "./approval.mjs";
import { createLeanWire, sanitizeRecord } from "./lean-wire.mjs";
import {
  expandProjectRows,
  finishedRow,
  needsRecoveryRow,
  startedRow,
  TASK_ID,
} from "./ledger-rows.mjs";
import {
  buildProbePlan,
  PROBE_ESTIMATE_USD,
  PROBE_MAX_REQUESTS,
  PROBE_RESERVE_USD,
  sendProbe,
} from "./probe.mjs";
import { withProjectLocks } from "./project-locks.mjs";
import {
  RECORD_BUCKET,
  RECORD_PROJECT,
  recentLineProblems,
  refuseUnsafeEnvironment,
} from "./record.mjs";

const RUN_ID = /^[0-9a-f]{20}$/;
const ORIGINS = Object.freeze({
  storage: "http://127.0.0.1:19199",
  auth: "http://127.0.0.1:19099",
  control: "http://127.0.0.1:19198",
});
// The probe sends no user route, so it holds no Web API key. The wire wants a well-formed one; this
// is not a credential and matches no project's key.
const INERT_API_KEY = "probe-holds-no-web-api-key";

const iso = (date) => date.toISOString();

/** Whether any earlier run of this packet has a closing row: a probe packet runs once. */
function packetHasClosingRow(ledgerText, packetSha256) {
  return ledgerText.split("\n").some((line) => {
    try {
      const row = JSON.parse(line);
      return (
        row?.taskId === TASK_ID &&
        row.project === RECORD_PROJECT &&
        row.packetSha256 === packetSha256 &&
        row.event !== "started"
      );
    } catch {
      return false;
    }
  });
}

/** Run the probe once. Resolves with `{ outcome, requests, answers }`. */
export async function probeRun(deps) {
  const {
    ids,
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
    fetch: fetchImpl,
    now,
  } = deps;
  refuseUnsafeEnvironment(env, nodeVersion);
  if (
    !RUN_ID.test(ids?.runId ?? "") ||
    !RUN_ID.test(ids?.otherRunId ?? "") ||
    ids.runId === ids.otherRunId
  )
    throw new Error("invalid run ID");
  validatePresendApproval({
    ledgerText: ownerDecisionsText,
    packet,
    review,
    runner: {
      projectId: RECORD_PROJECT,
      maxRequests: PROBE_MAX_REQUESTS,
      reserveUsd: PROBE_RESERVE_USD,
    },
  });
  for (const key of ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"]) {
    if (deps.actualPins?.[key] !== packet[key]) throw new Error(`pin mismatch: ${key}`);
  }
  const tree = await git();
  if (!tree.clean) throw new Error("probe-production needs a clean tree");
  if (tree.commit !== packet.sourceCommit)
    throw new Error("the checked-out commit is not the approved commit");

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
    if (packetHasClosingRow(ledgerText, packet.packetSha256))
      throw new Error("this probe packet has already run");
  }
  await admit();

  const plan = buildProbePlan({
    projectId: RECORD_PROJECT,
    bucket: RECORD_BUCKET,
    runId: ids.runId,
    otherRunId: ids.otherRunId,
  });
  const identity = (date) => ({
    ts: iso(date),
    runId: ids.runId,
    packetId: packet.packetName,
    packetSha256: packet.packetSha256,
    gitSha: packet.sourceCommit,
    corpusDigest: packet.corpusSha256,
  });

  // A run that had started and stopped keeps its lock and wrote `needs-recovery`; the error it
  // throws says `afterStart`, and the caller reports that rather than a refusal.
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
      const known = [];
      const owned = async () => {
        const token = await getToken();
        if (!known.includes(token)) known.push(token);
        return token;
      };
      const safe = (value) => sanitizeRecord(value, known);
      lease.markStarted();
      try {
        await ledger.append(
          startedRow({
            ...identity(now()),
            maxRequests: PROBE_MAX_REQUESTS,
            estimatedUsd: PROBE_ESTIMATE_USD,
          }),
        );
        const wire = createLeanWire({
          bucket: RECORD_BUCKET,
          projectId: RECORD_PROJECT,
          prefix: plan.prefix,
          origins: ORIGINS,
          adminToken: owned,
          authApiKey: INERT_API_KEY,
          readRules: async () => {
            throw new Error("the probe reads no Rules");
          },
          fetchImpl,
          capture: (record) => priv.capture(safe(record)),
          pacer: { dispatch: (_name, attempt) => attempt() },
        });
        let answers;
        try {
          answers = await lease.dispatch(() => sendProbe({ wire, plan, origins: ORIGINS }));
        } catch (error) {
          const sent = wire.snapshot().realRequests;
          const reason = safe(
            String(error?.message ?? error)
              .split("\n")[0]
              .slice(0, 200),
          );
          await priv
            .meta(
              safe({
                runId: ids.runId,
                outcome: "needs-recovery",
                status: "THROWN",
                reason,
                stoppedAt: error?.probeStep ?? null,
                answered: error?.answered ?? [],
                requests: sent,
                plan: { runId: ids.runId, prefix: plan.prefix },
              }),
            )
            .catch(() => {});
          await ledger
            .append(
              needsRecoveryRow({
                ...identity(now()),
                requests: sent,
                estimatedUsd: PROBE_ESTIMATE_USD,
              }),
            )
            .catch(() => {});
          throw error;
        }
        const requests = wire.snapshot().realRequests;
        await priv.meta(
          safe({
            runId: ids.runId,
            outcome: "recorded",
            status: "PROBE_COMPLETE",
            answers,
            requests,
            plan: { runId: ids.runId, prefix: plan.prefix },
          }),
        );
        await ledger.append(
          finishedRow({
            ...identity(now()),
            outcome: "recorded",
            requests,
            estimatedUsd: PROBE_ESTIMATE_USD,
          }),
        );
        lease.confirmClosed();
        return { outcome: "recorded", requests, answers };
      } catch (error) {
        if (error && typeof error === "object") error.afterStart = true;
        throw error;
      }
    },
  );
}
