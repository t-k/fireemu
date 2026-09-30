// One run of a probe (probe-v2 in probe.mjs, probe-v3 in probe3.mjs, each a "kit"): the same
// admission as a recording (environment, approved packet, pins, clean tree at the approved commit,
// the shared ledger, the project lock) around the kit's requests through the lean wire. It writes a
// `started` row, sends the plan, and writes one closing row: `recorded`, or `stopped-clean` when
// the kit's recording was cut short and its prefix is still read back empty. A run that cannot
// finish, or whose prefix is not read back empty, writes `needs-recovery` and keeps the project
// lock, as a recording does; nothing here retries, and a packet runs once.
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
import {
  buildProbe3Plan,
  PROBE3_ESTIMATE_USD,
  PROBE3_MAX_REQUESTS,
  PROBE3_RESERVE_USD,
  probe3ClosingRow,
  sendProbe3,
} from "./probe3.mjs";
import {
  buildProbe4Plan,
  PROBE4_ESTIMATE_USD,
  PROBE4_MAX_REQUESTS,
  PROBE4_RESERVE_USD,
  probe4ClosingRow,
  sendProbe4,
} from "./probe4.mjs";
import { createObjectMutationPacer } from "./production-pacing.mjs";
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

/** probe-v2: nine reads and two cancelled sessions, no object; closes on its final GCS list. */
export const PROBE_V2_KIT = Object.freeze({
  name: "probe-v2",
  command: "probe-production",
  maxRequests: PROBE_MAX_REQUESTS,
  reserveUsd: PROBE_RESERVE_USD,
  estimateUsd: PROBE_ESTIMATE_USD,
  buildPlan: buildProbePlan,
  run: async (input) => ({ answers: await sendProbe(input), interrupted: null }),
  closingRow: (answers) => answers.find((row) => row.id === "gcs-list-owner"),
  pacer: () => ({ dispatch: (_name, attempt) => attempt() }),
});

/** probe-v3: seven small objects, recorded and removed; closes on its last list of the prefix. */
export const PROBE_V3_KIT = Object.freeze({
  name: "probe-v3",
  command: "probe3-production",
  maxRequests: PROBE3_MAX_REQUESTS,
  reserveUsd: PROBE3_RESERVE_USD,
  estimateUsd: PROBE3_ESTIMATE_USD,
  buildPlan: buildProbe3Plan,
  run: sendProbe3,
  closingRow: probe3ClosingRow,
  // Writes to one object are spaced, as the recorder's are.
  pacer: (plan) => createObjectMutationPacer({ ownedPrefixes: [plan.prefix] }),
});

/**
 * probe-v4: the refusals whose absence could turn an accepted-when-refused write into needs-recovery
 * (three small objects, recorded and removed); closes on its last list of the prefix.
 */
export const PROBE_V4_KIT = Object.freeze({
  name: "probe-v4",
  command: "probe4-production",
  maxRequests: PROBE4_MAX_REQUESTS,
  reserveUsd: PROBE4_RESERVE_USD,
  estimateUsd: PROBE4_ESTIMATE_USD,
  buildPlan: buildProbe4Plan,
  run: sendProbe4,
  closingRow: probe4ClosingRow,
  pacer: (plan) => createObjectMutationPacer({ ownedPrefixes: [plan.prefix] }),
});

/** The packet names the kit it approves: a packet for one kit never runs another kit's requests. */
export function refuseKitMismatch(packet, kit) {
  if (packet?.packetName !== kit.name)
    throw new Error(`the packet is ${packet?.packetName}, this run is ${kit.name}`);
}

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
export async function probeRun(deps, kit = PROBE_V2_KIT) {
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
  refuseKitMismatch(packet, kit);
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
      maxRequests: kit.maxRequests,
      reserveUsd: kit.reserveUsd,
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

  const plan = kit.buildPlan({
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
            maxRequests: kit.maxRequests,
            estimatedUsd: kit.estimateUsd,
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
          pacer: kit.pacer(plan),
        });
        let answers;
        let interrupted;
        try {
          ({ answers, interrupted } = await lease.dispatch(() =>
            kit.run({ wire, plan, origins: ORIGINS }),
          ));
          // The closing row says the sandbox is at its baseline, so it is written only after the
          // run's own prefix was read back empty (a probe that makes nothing checks that it made
          // nothing; one that makes objects checks that it removed them).
          const readback = kit.closingRow(answers);
          if (readback?.prefixEmpty !== true)
            throw Object.assign(new Error("the probe prefix was not read back as empty"), {
              probeStep: readback?.id ?? null,
              answered: answers,
            });
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
                estimatedUsd: kit.estimateUsd,
              }),
            )
            .catch(() => {});
          throw error;
        }
        const requests = wire.snapshot().realRequests;
        // A recording that was cut short, with its prefix read back empty, is not a recording.
        const outcome = interrupted ? "stopped-clean" : "recorded";
        await priv.meta(
          safe({
            runId: ids.runId,
            outcome,
            status: interrupted ? "PROBE_INTERRUPTED" : "PROBE_COMPLETE",
            ...(interrupted ? { interrupted } : {}),
            answers,
            requests,
            plan: { runId: ids.runId, prefix: plan.prefix },
          }),
        );
        await ledger.append(
          finishedRow({
            ...identity(now()),
            outcome,
            requests,
            estimatedUsd: kit.estimateUsd,
          }),
        );
        lease.confirmClosed();
        return { outcome, requests, answers };
      } catch (error) {
        if (error && typeof error === "object") error.afterStart = true;
        throw error;
      }
    },
  );
}
