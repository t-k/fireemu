// Stage 1 of the Gen2 upload work: one minimal 2nd gen deploy whose only goal is to record the two
// `firebase deploy --debug` line forms the upload helper depends on (the generateUploadUrl answer and
// the status of the upload's PUT), then clean up everything that deploy created. Nothing about RTDB,
// Rules, Auth or public invocation is touched. This module has no side effects on import; the
// recorder writes only inside its private run directory (the launch script owns the lock and the
// sandbox ledger).

import { execFileSync } from "node:child_process";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createBudget, PROJECT, REGION } from "./harness.mjs";
import {
  PRIVATE_ROOT,
  PROJECT_IDENTITY_FILE,
  PROJECT_IDENTITY_SHA,
  assertTargetAbsent,
  cleanupTarget,
  createControl,
  deployTarget,
  ownerAdc,
  preflightCliSideEffects,
  readDeployedTarget,
  readPrivateProjectIdentity,
  requiredSourceDigests,
  storageSend,
  withUploadClosure,
} from "./production.mjs";
import { openSourceUploads, redactUploadSecrets } from "../src/shared/gen2-source-uploads.mjs";

const TARGET = "http";
const PROBE_ID = "upload-probe/http";
// The number every committed fixture uses in place of a project number, whatever its real length.
const MASK = "123456789012";

/** The probe's own request caps (the packet's request list); they can only lower the global ones. */
export const PROBE_LIMITS = Object.freeze({
  invocation: 0,
  auth: 0,
  control: 12,
  cleanup: 30,
  upload: 15,
  token: 12,
  cliDeploy: 1,
  cliDelete: 1,
});

const sha256 = (bytes) =>
  execFileSync("shasum", ["-a", "256"], { input: bytes, encoding: "utf8" }).split(" ")[0];

/** A recorded line with the project number masked and every signed URL removed. */
export function maskProbeLine(line, projectNumber) {
  return redactUploadSecrets(line.replaceAll(projectNumber, MASK)).replace(
    /"uploadUrl":"[^"]*"/gu,
    '"uploadUrl":"[REDACTED UPLOAD URL]"',
  );
}

/** Collects what the deploy's upload events show: booleans, codes and lengths, plus masked lines. */
export function createFormsCollector(projectNumber) {
  const masked = [];
  const summary = {
    receiptLineSeen: false,
    putStatusLineSeen: false,
    putStatusCodes: [],
    receiptLineBytes: 0,
    putStatusLineBytes: 0,
  };
  return {
    observe(event, line) {
      if (event?.type === "receipt") {
        summary.receiptLineSeen = true;
        summary.receiptLineBytes = Buffer.byteLength(line);
      } else if (event?.type === "put-status") {
        summary.putStatusLineSeen = true;
        summary.putStatusCodes.push(event.status);
        summary.putStatusLineBytes = Buffer.byteLength(line);
      } else return;
      masked.push(maskProbeLine(line, projectNumber));
    },
    summary: () => ({ ...summary, putStatusCodes: [...summary.putStatusCodes] }),
    maskedLines: () => [...masked],
  };
}

/**
 * Without a receipt line the helper owns nothing, so the run stops: nothing in the uploads bucket
 * is deleted (the helper refuses on its own), while the deploy's function, service and image are
 * still removed by exact name. A missing PUT line is only a finding.
 */
export function decideAfterDeploy(forms) {
  if (!forms.receiptLineSeen) return { decision: "stop", finding: "no-receipt-line" };
  if (!forms.putStatusLineSeen) {
    return { decision: "continue", finding: "put-status-line-missing" };
  }
  return { decision: "continue", finding: "both-forms" };
}

export function assertProbeApproval(content, gitSha, packetSha256) {
  const lines = content.replaceAll("\r\n", "\n").split("\n");
  if (
    lines[0] !== "Decision: APPROVE" ||
    lines[1] !== `gitSha: ${gitSha}` ||
    lines[2] !== `packetSha256: ${packetSha256}` ||
    lines.slice(3).some((line) => /(?:^|[\s#>])(?:Decision|gitSha|packetSha256)\s*:/u.test(line))
  ) {
    throw new Error("upload probe pre-send APPROVE must bind a single decision, commit and packet");
  }
}

/** Read-only: whether Cloud Logging is enabled (stage 2 reads frames from it). Never enables it. */
export async function loggingApiState(control) {
  try {
    const reply = await control(
      "GET",
      `https://serviceusage.googleapis.com/v1/projects/${PROJECT}/services/logging.googleapis.com`,
      undefined,
      "control",
      [200, 403, 404],
    );
    return reply.status === 200 && typeof reply.value?.state === "string"
      ? reply.value.state
      : "UNKNOWN";
  } catch {
    return "UNKNOWN";
  }
}

/** Runs the probe against `control`; returns counts and booleans only (no names, no URLs). */
export async function runUploadProbe({
  control,
  adcPath,
  budget,
  runDir,
  projectNumber,
  run,
  send = storageSend(control),
}) {
  const journal = join(runDir, "journal.jsonl");
  const log = (action, detail) =>
    appendFile(journal, `${JSON.stringify({ ts: new Date().toISOString(), action, detail })}\n`, {
      mode: 0o600,
    });
  const uploads = openSourceUploads({
    ledgerPath: join(runDir, "owned-uploads.jsonl"),
    runId: basename(runDir),
    projectNumber,
    region: REGION,
    send,
    requestsLeft: () => PROBE_LIMITS.upload - budget.snapshot().upload,
  });
  const forms = createFormsCollector(projectNumber);
  const state = { started: false, cleaned: false };
  let error;
  const loggingState = await loggingApiState(control);
  try {
    await preflightCliSideEffects(control);
    await assertTargetAbsent(control, TARGET);
    await deployTarget(
      TARGET,
      PROBE_ID,
      state,
      uploads,
      adcPath,
      budget,
      runDir,
      run,
      forms.observe,
    );
    await log("function-deployed", "Firebase CLI completed");
    await readDeployedTarget(control, TARGET, state);
  } catch (caught) {
    error = caught;
  }
  const { decision, finding } = decideAfterDeploy(forms.summary());
  await cleanupTarget(control, TARGET, adcPath, budget, runDir, state, { run, log });
  const residual = Boolean(error?.indeterminate) || (state.started && !state.cleaned);
  const outcome = withUploadClosure(uploads.report(), {
    outcome: error || residual ? "stopped-needs-review" : "recorded",
    reason: error?.message ?? state.cleanupError,
    residual,
  });
  const report = uploads.report();
  uploads.close();
  const requests = budget.snapshot();
  return {
    outcome: outcome.outcome,
    residual: outcome.residual,
    decision,
    finding,
    forms: forms.summary(),
    uploadsClosureReady: report.closureReady,
    a2Required: report.a2Required,
    loggingApiState: loggingState,
    requests,
    estimatedUsd: Number((0.01 + requests.cliDeploy * 0.55).toFixed(2)),
    maskedLines: forms.maskedLines(),
  };
}

/** The command-line entry: admission by approval file, pins, ADC, then the probe. */
export async function recordUploadProbe() {
  const reviewPath = process.env.FIREEMU_UPLOAD_PROBE_REVIEW;
  const packetPath = process.env.FIREEMU_UPLOAD_PROBE_PACKET;
  if (
    !reviewPath ||
    !packetPath ||
    !reviewPath.startsWith(`${PRIVATE_ROOT}/`) ||
    !packetPath.startsWith(`${PRIVATE_ROOT}/`)
  ) {
    throw new Error("private review and packet paths are required");
  }
  const root = fileURLToPath(new URL("../..", import.meta.url));
  const gitSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const dirty = execFileSync(
    "git",
    ["status", "--porcelain", "--", "conformance/functions-http", "conformance/src/shared"],
    { cwd: root, encoding: "utf8" },
  );
  if (dirty) throw new Error("upload probe needs a clean reviewed commit");
  assertProbeApproval(
    await readFile(reviewPath, "utf8"),
    gitSha,
    sha256(await readFile(packetPath)),
  );
  await requiredSourceDigests();
  const adc = await ownerAdc();
  const projectNumber = await readPrivateProjectIdentity(
    PROJECT_IDENTITY_FILE,
    PROJECT_IDENTITY_SHA,
  );
  const runDir = join(
    PRIVATE_ROOT,
    "runs",
    `upload-probe-${new Date().toISOString().replaceAll(":", "")}`,
  );
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const budget = createBudget(PROBE_LIMITS);
  const control = createControl(adc.file, budget);
  const result = await runUploadProbe({
    control,
    adcPath: adc.path,
    budget,
    runDir,
    projectNumber,
  });
  const { maskedLines, ...summary } = result;
  await writeFile(join(runDir, "forms.json"), `${JSON.stringify(summary, null, 2)}\n`, {
    mode: 0o600,
  });
  await writeFile(join(runDir, "lines-masked.txt"), `${maskedLines.join("\n")}\n`, { mode: 0o600 });
  console.log(JSON.stringify({ outcome: summary.outcome, decision: summary.decision, runDir }));
  if (summary.residual) process.exitCode = 3;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  recordUploadProbe().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
