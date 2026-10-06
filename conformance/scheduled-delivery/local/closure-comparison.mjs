// Offline closure evidence: node closure-comparison.mjs --table <run-compare.json> --fireemu <binary> --out <json>
// This records comparisons and proposal limitations; it never promotes closure conditions.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDigest, productionChains, productionDeliveryFacts } from "./compare.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const proposal = "docs.local/proposals/2026-10-06-scheduled-functions-closure-proposal.md";
// Only measurements actually present in run-compare are mapped. Missing measurements stay unjudged.
const sources = {
  "v2-http-delivery": {
    "handler-success-ack": ["delivery.handler-success-ack"],
    "handler-throw-ack": ["delivery.handler-throw-ack"],
    "request-method": ["v2.request.method", "v2.request.url"],
    "jobName-header": ["v2.request.headers", "v2.event.jobName"],
    "scheduleTime-header": ["v2.request.headers", "v2.event.scheduleTime-form"],
    body: ["v2.request.body"],
    "SDK-ScheduledEvent": ["v2.event.keys"],
    "SDK-context-getter": ["v2.event.context"],
    "SDK-event-enumerability": ["v2.event.context", "v2.event.context-values"],
  },
  "v1-pubsub-delivery": {
    "published-data": ["v1.published.data"],
    "published-attributes": ["v1.published.attributes"],
    "message-id-presence": ["v1.context.eventId", "v1.published.messageId"],
    publishTime: ["v1.context.timestamp", "v1.published.publishTime"],
    "v1-handler-context": ["v1.context.keys"],
    "context-only-handler": ["v1.argumentCount"],
    "context-resource-topic-versus-job": ["v1.context.resource", "v1.published.topic"],
  },
  "forced-and-natural-invocation": {
    "natural-scheduled-run": ["cadence.every-1-minutes.spacing"],
    "Cloud-Scheduler-run-now": ["forced-run"],
    "success-next-occurrence": ["cadence.every-1-minutes.spacing"],
    "retry-stable-occurrence-identity": [
      "retry.retryFour",
      "delivery.retry-stable-occurrence-identity",
    ],
  },
  "retry-config-validation": {},
  "v2-retry-limits": {
    "success-stops-retry": ["delivery.success-stops-retry"],
    "next-schedule-after-failure": ["delivery.next-schedule-after-failure"],
    "zero-no-retry": ["retry.retryZero"],
    "finite-retry-count": ["retry.retryFour"],
    "duration-only": ["retry.retryDuration"],
    "count-and-duration-interaction": ["retry.retryCountWindow"],
  },
  "v2-backoff": {
    "first-delay": ["retry.retryFour"],
    "exponential-doubling": ["retry.retryDouble0"],
    "linear-after-doublings": ["retry.retryDouble1", "retry.retryDouble3"],
    "max-backoff-cap": ["retry.retryDuration"],
    "stable-scheduleTime": ["retry.retryFour", "delivery.retry-stable-occurrence-identity"],
  },
  "v1-two-stage-retry": {
    "handler-no-retry": ["v1.failure-no-retry"],
    "handler-retry-declaration": ["v1.retry-declaration-no-retry"],
  },
  "deadline-and-overlap": { "next-occurrence-during-work": ["cadence.in-flight-skip"] },
  "declarations-v1-v2": {},
  "timezone-validation-defaults": {},
};
const resourceCases = new Set([
  "attempt-deadline",
  "omitted-versus-null-reset",
  "SDK-attemptDeadline-versus-CLI-timeout",
  "v1-App-Engine-job-location",
  "v2-function-region-job-location",
  "attemptDeadline-readback",
  "attemptDeadline-boundary",
]);
const implicitFields = {
  "handler-success-ack": [
    "attempts.*.kind",
    "attempts.*.status",
    "attempts.*.debugInfo",
    "frames.handler",
  ],
  "handler-throw-ack": [
    "attempts.*.kind",
    "attempts.*.status",
    "attempts.*.debugInfo",
    "frames.failing",
    "frames.at",
  ],
  "success-stops-retry": [
    "frames.failing",
    "frames.at",
    "frames.event.jobName",
    "frames.event.scheduleTime",
  ],
  "next-schedule-after-failure": [
    "frames.failing",
    "frames.at",
    "frames.event.scheduleTime",
    "forced.job",
    "forced.atMs",
  ],
  "retry-stable-occurrence-identity": [
    "frames.headers.x-cloudscheduler-jobname",
    "frames.headers.x-cloudscheduler-scheduletime",
    "frames.event.jobName",
    "frames.event.scheduleTime",
    "retry.retryFour.production",
    "retry.retryFour.strict.local",
    "delivery.retry-stable-occurrence-identity.strict.local",
  ],
};

export function buildComparison({ report, recordings, artifactSha256, runnerTreeManifest }) {
  if (!report.fireemu?.binarySha256 || !report.fireemu.runnerTreeManifest)
    throw new Error("unattested-table");
  if (report.fireemu.binarySha256 !== artifactSha256) throw new Error("comparison binary mismatch");
  if (report.fireemu.runnerTreeManifest !== runnerTreeManifest)
    throw new Error("comparison runner mismatch");
  const primary = recordings.find((r) => r.data.run.id === report.run?.id);
  if (!primary) throw new Error("comparison names an unknown recording");
  const table = new Map();
  for (const r of report.table) {
    if (table.has(r.id)) throw new Error(`duplicate comparison id: ${r.id}`);
    if (!["MATCH", "DIVERGES", "NOT_COMPARABLE"].includes(r.strict?.verdict))
      throw new Error(`invalid verdict: ${r.id}`);
    table.set(r.id, r);
  }
  const { observations } = productionDeliveryFacts(primary.data);
  const closure = loadDigest(resolve(root, "spec/compatibility/closure/SCHEDULED-FUNCTIONS.json"));
  const rows = [];
  for (const c of closure.conditions.filter((condition) =>
    Object.hasOwn(sources, condition.conditionId.split("/")[1]),
  )) {
    const area = c.conditionId.split("/")[1];
    for (const caseId of c.cases) {
      const supplementalId = `${area}.${caseId}`;
      const ids = table.has(supplementalId) ? [supplementalId] : (sources[area][caseId] ?? []);
      const compared = ids.map((id) => table.get(id));
      let status = compared.some((r) => r?.strict.verdict === "DIVERGES")
        ? "DIVERGES"
        : compared.length && compared.every((r) => r?.strict.verdict === "MATCH")
          ? "MATCH"
          : "NOT_COMPARABLE";
      const used = new Set(ids.length ? [] : [resourceCases.has(caseId) ? recordings[2] : primary]);
      for (const r of compared.filter(Boolean)) {
        if (!r.id.startsWith("retry.")) {
          used.add(primary);
          continue;
        }
        const name = r.id.slice(6);
        const recording = [primary, ...recordings].find(
          (d) => productionChains(d.data)[name] !== undefined,
        );
        if (
          !recording ||
          JSON.stringify(productionChains(recording.data)[name]) !== JSON.stringify(r.production)
        )
          throw new Error(`retry row disagrees with recording: ${r.id}`);
        used.add(recording);
      }
      if (!used.size || implicitFields[caseId]) used.add(primary);
      if (caseId === "retry-stable-occurrence-identity" || caseId === "stable-scheduleTime") {
        if (observations["retry-stable-occurrence-identity"] !== true)
          status =
            observations["retry-stable-occurrence-identity"] === false
              ? "DIVERGES"
              : "NOT_COMPARABLE";
      }
      const implicit = Object.hasOwn(implicitFields, caseId);
      if (
        implicit &&
        caseId !== "retry-stable-occurrence-identity" &&
        observations[caseId] !== null &&
        compared[0] &&
        compared[0].production !== null &&
        compared[0].production !== observations[caseId]
      )
        throw new Error(`delivery row disagrees with recording: ${caseId}`);
      if (
        implicit &&
        caseId !== "retry-stable-occurrence-identity" &&
        observations[caseId] === null
      )
        status = "NOT_COMPARABLE";
      const section = resourceCases.has(caseId)
        ? "3.5"
        : caseId === "Cloud-Scheduler-run-now"
          ? "3.4"
          : caseId === "scheduler-attempt-versus-handler-instance"
            ? "3.3"
            : null;
      if (section) status = "NOT_COMPARABLE";
      rows.push({
        row: `${c.conditionId}/${caseId}`,
        conditionId: c.conditionId,
        caseId,
        frozenCase: true,
        status,
        recordings: [...used].map(({ path, sha256 }) => ({ path, sha256 })),
        recordedFields: implicit
          ? implicitFields[caseId]
          : resourceCases.has(caseId)
            ? ["jobs.*.attemptDeadline", "jobs.*.retryConfig", "jobs.*.name", "jobs.*.timeZone"]
            : ids.map((id) => `table.${id}.production/strict.local`),
        comparedRows: compared.filter(Boolean),
        ...(implicit
          ? {
              observation: observations[caseId],
              note:
                caseId === "retry-stable-occurrence-identity"
                  ? "Present, valid occurrence identities and retry offsets are compared on both timelines."
                  : observations[caseId] === null
                    ? `Missing production measurement: ${implicitFields[caseId].join(", ")}.`
                    : (compared[0]?.note ??
                      `Missing local comparison row: delivery.${caseId}; production observation is recorded.`),
            }
          : {}),
        ...(section
          ? {
              proposalRef: `${proposal}#${section}`,
              note:
                section === "3.5"
                  ? "S4: job readback has no local management API counterpart; approval is pending."
                  : "Proposal limitation; approval is pending.",
            }
          : {}),
        ...(!ids.length && !implicit && !section
          ? {
              note: "No measurement of this frozen case in the comparison table.",
              recordedFields: ["jobs", "frames", "attempts"],
            }
          : {}),
        ...(!ids.length && ["declarations-v1-v2", "retry-config-validation"].includes(area)
          ? { note: "covered outside the delivery comparison" }
          : {}),
      });
    }
  }
  for (const [caseId, section, id, note] of [
    [
      "header-names",
      "3.1",
      "v2.request.header-names",
      "OIDC, trace and client-address header names are not reproduced.",
    ],
    [
      "interval-phase-versus-creation-anchor",
      "3.2",
      "cadence.every-1-minutes.phase",
      "The production phase is stable per job, not its creation anchor.",
    ],
    [
      "in-flight-boundary",
      "3.3",
      null,
      "The recording cannot distinguish the 504 boundary from the handler end.",
    ],
    [
      "synchronized-window",
      "3.6",
      "cadence.every-5-minutes.alignment",
      "The production synchronization rule is undetermined.",
    ],
    [
      "user-publish-to-gen1-topic",
      "3.7",
      null,
      "Strict stores a user publish without delivering the scheduled handler; not a frozen case.",
    ],
  ]) {
    const r = table.get(id);
    rows.push({
      row: `declared/${caseId}`,
      caseId,
      frozenCase: false,
      status: r?.strict.verdict === "DIVERGES" ? "DIVERGES" : "NOT_COMPARABLE",
      proposalRef: `${proposal}#${section}`,
      note,
      recordings: [{ path: primary.path, sha256: primary.sha256 }],
      recordedFields: id ? [`table.${id}.production/strict.local`] : ["frames", "attempts"],
      comparedRows: r ? [r] : [],
    });
  }
  const summary = {};
  for (const r of rows) summary[r.status] = (summary[r.status] ?? 0) + 1;
  return {
    kind: "scheduled-functions-comparison-v1",
    artifactSha256,
    runnerSha256: sha(runnerTreeManifest),
    runnerTreeManifest,
    recordings: recordings.map(({ path, sha256 }) => ({ path, sha256 })),
    runnerTreeManifestFormat:
      "Tracked tools/runner-node files except *.test.mjs, sorted in ASCII order: UTF-8 path, TAB, lowercase SHA-256 of file bytes, LF; hash the concatenation.",
    executionBinding: "report",
    summary,
    rows,
  };
}

export function generateComparison({ reportPath, fireemu }) {
  const bytes = readFileSync(reportPath);
  const paths = execFileSync("git", ["ls-files", "tools/runner-node"], {
    cwd: root,
    encoding: "utf8",
  })
    .trim()
    .split("\n")
    .filter((p) => !p.endsWith(".test.mjs"))
    .toSorted();
  const runnerTreeManifest = paths
    .map((p) => `${p}\t${sha(readFileSync(resolve(root, p)))}\n`)
    .join("");
  const recordings = [2, 3, 4].map((n) => {
    const path = `conformance/scheduled-delivery/local/production-run${n}.json`;
    const digest = readFileSync(resolve(root, path));
    return { path, sha256: sha(digest), data: JSON.parse(digest) };
  });
  return {
    ...buildComparison({
      report: JSON.parse(bytes),
      recordings,
      artifactSha256: sha(readFileSync(fireemu)),
      runnerTreeManifest,
    }),
    tableSha256: sha(bytes),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = Object.fromEntries(
    process.argv
      .slice(2)
      .flatMap((a, i, all) => (a.startsWith("--") ? [[a.slice(2), all[i + 1]]] : [])),
  );
  for (const key of ["table", "fireemu", "out"])
    if (!args[key]) throw new Error(`--${key} is required`);
  const result = generateComparison({ reportPath: args.table, fireemu: args.fireemu });
  mkdirSync(dirname(args.out), { recursive: true });
  writeFileSync(args.out, JSON.stringify(result, null, 1) + "\n");
  console.log(JSON.stringify(result.summary));
}
