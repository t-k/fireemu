// One production recording of AUTH-FS-CROSS stage 2, end to end: admission, the owner's
// approval, the project locks, the baseline read, the compile probe, the listen window, the
// final readback and the ledger lines. A run records once; the packet approves two runs in
// order (decision D2). Every request, clock and recording is injected, so the lock and
// recovery rules are tested without a network.

import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { PRODUCTION } from "../fs-rules/harness.mjs";
import { readBaseline } from "./production.mjs";
import { admissionProblems, scrub } from "./sandbox.mjs";
import {
  acquireProjectLocks,
  closingLines,
  DECLARED_PROJECTS,
  keyRestrictionProblems,
  restrictedKeys,
  stoppedLine,
  packetApproval,
  recordingProblems,
  releaseProjectLock,
  SANDBOX_PROJECT,
  STAGE,
  startedLine,
  TASK_ID,
} from "./stage2-sandbox.mjs";
import { RULESET_IDS, rulesetSource } from "./stage2-rulesets.mjs";

const RULES = `${PRODUCTION.rules}/v1/projects/${SANDBOX_PROJECT}`;
const KEYS = `https://apikeys.googleapis.com/v2/projects/${SANDBOX_PROJECT}/locations/global/keys?pageSize=300`;

/** One read of the project's API keys (restrictions only, never a key string). */
export async function readKeyRestrictions(fetchJson) {
  const answer = await fetchJson("GET", KEYS, undefined, SANDBOX_PROJECT);
  return {
    requests: 1,
    problems: keyRestrictionProblems(answer),
    restricted: answer.status === 200 ? restrictedKeys(answer.json) : [],
  };
}
const line = (row) => `${JSON.stringify(row)}\n`;

/**
 * Compiles each stage-2 ruleset in production (created and deleted, never released) and reads
 * back that no ruleset is left. Throws on a transport failure: something may have been created.
 */
export async function compileProbe(fetchJson) {
  let requests = 0;
  const compiled = {};
  let clean = true;
  for (const id of RULESET_IDS) {
    requests += 1;
    const created = await fetchJson(
      "POST",
      `${RULES}/rulesets`,
      { source: { files: [{ name: "firestore.rules", content: rulesetSource(id) }] } },
      SANDBOX_PROJECT,
    );
    compiled[id] = created.status;
    if (created.status === 200) {
      requests += 1;
      const deleted = await fetchJson(
        "DELETE",
        `${PRODUCTION.rules}/v1/${created.json.name}`,
        undefined,
        SANDBOX_PROJECT,
      );
      if (deleted.status !== 200) clean = false;
    }
  }
  requests += 1;
  const left = await fetchJson("GET", `${RULES}/rulesets?pageSize=100`, undefined, SANDBOX_PROJECT);
  if (left.status !== 200 || (left.json?.rulesets ?? []).length) clean = false;
  return { requests, compiled, clean };
}

/**
 * One recording. `deps` provides: `ledger`, `lockDir`, `legacyLock`, `ownerDecisions` (path),
 * `privateRoot`, `packetSha256`, `recording` (1 or 2), `runner` ({project, maxRequests,
 * reserveUsd}), `secrets` ([value, placeholder] pairs), and the functions `admission()` (→
 * {problems, sha, harness, programDigest}), `target()`, `fetchJson(target, method, url, body,
 * quotaProject)`, `clockOffset()`, `browserKeyProbe()` (→ {ok, code, requests}: a browser
 * client's read with the web key, before anything is written), `compileProbe(fetchJson)`,
 * `recordWindow(target)`, `now()`, `recentAbort(ledgerText)`, `stopRequested()` and `log()`.
 */
export async function runStage2Production(deps) {
  if (JSON.stringify(DECLARED_PROJECTS) !== JSON.stringify([deps.runner.project]))
    throw new Error(`the runner's project ${deps.runner.project} is not the declared one`);
  const admission = await deps.admission();
  if (admission.problems.length) throw new Error(`admission: ${admission.problems.join("; ")}`);
  const { approval, problems } = packetApproval(await readFile(deps.ownerDecisions, "utf8"), {
    packetSha256: deps.packetSha256,
    sourceCommit: admission.sha,
    harnessDigest: admission.harness,
    runner: deps.runner,
  });
  if (!approval) throw new Error(`approval: ${problems.join("; ")}`);
  const clean = (text) => scrub(text, deps.secrets);
  const locks = await acquireProjectLocks({
    lockDir: deps.lockDir,
    legacyLock: deps.legacyLock,
    projects: DECLARED_PROJECTS,
    body: {
      taskId: TASK_ID,
      packetId: deps.packetSha256,
      sourceCommit: admission.sha,
      pid: process.pid,
      acquiredAt: deps.now().toISOString(),
    },
  });
  let keepLocks = false;
  try {
    // The ledger is judged, and the started line written, while the locks are held.
    const ledgerText = await readFile(deps.ledger, "utf8");
    const open = [
      ...admissionProblems(ledgerText, SANDBOX_PROJECT, deps.now().getTime()),
      ...(deps.recentAbort(ledgerText) ? ["this task's last run aborted within the hour"] : []),
      ...recordingProblems(ledgerText, deps.packetSha256, deps.recording),
    ];
    if (open.length) throw new Error(`admission under the lock: ${open.join("; ")}`);
    const target = await deps.target();
    const fetchJson = (method, url, body, quota) =>
      deps.fetchJson(target, method, url, body, quota);
    // Reads only: a failure here leaves nothing behind.
    const start = await readBaseline(fetchJson);
    const keys = await readKeyRestrictions(fetchJson);
    const startProblems = [...start.mismatches, ...keys.problems];
    // Nothing is written yet. A key that may refuse the browser is left for the owner to decide
    // on, so the stop is written down with the keys it names; other differences stop silently.
    const stop = async (reason, detail, requests) => {
      await appendFile(
        deps.ledger,
        line(
          stoppedLine({
            ts: deps.now().toISOString(),
            sha: admission.sha,
            packetSha256: deps.packetSha256,
            recording: deps.recording,
            programDigest: admission.programDigest,
            reason,
            detail,
            requests,
          }),
        ),
      );
    };
    if (keys.restricted.length)
      await stop("api-key-application-restriction", { keys: keys.restricted }, start.requests + 1);
    if (startProblems.length) throw new Error(`preflight: ${startProblems.join("; ")}`);
    const clockOffsetSeconds = await deps.clockOffset();
    // The browser's first request with the web key is a read: a refusal ends the run here,
    // before anything is written, and the locks are released.
    const keyProbe = await deps.browserKeyProbe();
    if (!keyProbe.ok) {
      await stop(
        "browser-key-probe-refused",
        { code: clean(String(keyProbe.code)) },
        start.requests + 1 + keyProbe.requests,
      );
      throw new Error(`browser key probe refused: ${clean(String(keyProbe.code))}`);
    }
    // A stop requested before the first write ends the run here, with nothing written.
    if (deps.stopRequested?.()) throw new Error("stopped by a signal before any write");
    // The compile probe writes: from its first request only a clean readback releases the locks.
    keepLocks = true;
    let probe;
    try {
      probe = await deps.compileProbe(fetchJson);
    } catch (error) {
      probe = { clean: false, error: String(error.message ?? error), compiled: {}, requests: 0 };
    }
    if (!probe.clean || Object.values(probe.compiled).some((status) => status !== 200)) {
      if (!probe.clean)
        await appendFile(
          deps.ledger,
          line({
            ts: deps.now().toISOString(),
            event: "needs-recovery",
            taskId: TASK_ID,
            project: SANDBOX_PROJECT,
            stage: STAGE,
            recording: deps.recording,
            packetSha256: deps.packetSha256,
            reason: "compile-probe",
            sandboxAtBaseline: false,
            ...(probe.error ? { error: clean(probe.error) } : {}),
          }),
        );
      else keepLocks = false;
      throw new Error(`compile probe: ${clean(probe.error ?? JSON.stringify(probe.compiled))}`);
    }
    const startedAt = deps.now().toISOString();
    const runDir = join(
      deps.privateRoot,
      `auth-fs-cross-stage2-recording-${deps.recording}-${startedAt.replaceAll(":", "")}`,
    );
    await mkdir(runDir, { recursive: true, mode: 0o700 });
    // From here on the sandbox changes: only a clean, verified end releases the locks.
    await appendFile(
      deps.ledger,
      line(
        startedLine({
          ts: startedAt,
          sha: admission.sha,
          packetSha256: deps.packetSha256,
          recording: deps.recording,
          programDigest: admission.programDigest,
          locks,
          approval,
          reserveUsd: deps.runner.reserveUsd,
        }),
      ),
    );
    let recording;
    let outcome = "recorded";
    let error;
    try {
      if (deps.stopRequested?.())
        throw Object.assign(new Error("stopped by a signal"), { fatal: true });
      recording = await deps.recordWindow(target);
    } catch (caught) {
      outcome = caught.fatal ? "aborted-fatal" : "aborted";
      error = String(caught.message ?? caught);
      recording = caught.partial;
    }
    if (recording)
      await writeFile(
        join(runDir, outcome === "recorded" ? "recording.json" : "recording-partial.json"),
        clean(JSON.stringify(recording)),
        { mode: 0o600 },
      );
    const cleanupErrors = recording?.cleanupErrors ?? [];
    if (cleanupErrors.length) outcome = "aborted-cleanup-incomplete";
    // Whatever happened above, the project is read back against the baseline; the owner token
    // may have aged over the window.
    let final;
    try {
      await target.refresh?.();
      final = await readBaseline(fetchJson);
    } catch (caught) {
      final = { requests: 0, mismatches: [`readback failed: ${caught.message ?? caught}`] };
    }
    const atBaseline = final.mismatches.length === 0 && cleanupErrors.length === 0;
    const wire = Object.values(recording?.wire ?? {}).reduce((n, count) => n + count, 0);
    const requests =
      start.requests +
      keys.requests +
      keyProbe.requests +
      probe.requests +
      (recording?.harnessRequests ?? 0) +
      (recording?.requests ?? 0) +
      wire +
      final.requests;
    const problem = [error, ...final.mismatches, ...cleanupErrors].filter(Boolean).join("; ");
    for (const row of closingLines({
      ts: deps.now().toISOString(),
      sha: admission.sha,
      packetSha256: deps.packetSha256,
      recording: deps.recording,
      programDigest: admission.programDigest,
      outcome,
      atBaseline,
      error: problem ? clean(problem) : undefined,
      counts: {
        database: "(default)",
        requests,
        sdkRequests: wire,
        // Firestore reads, writes, listens and Rules evaluations at list price; Auth MAU for a
        // few accounts.
        estimatedUsd: Number((requests * 0.0000006 + 0.1).toFixed(4)),
        configurationChanges: recording?.changes ?? [],
        publications: (recording?.publications ?? []).length,
        finalReadback: final.mismatches.map(clean),
      },
    }))
      await appendFile(deps.ledger, line(row));
    await writeFile(
      join(runDir, "meta.json"),
      clean(
        JSON.stringify(
          {
            sha: admission.sha,
            harness: admission.harness,
            programDigest: admission.programDigest,
            packetSha256: deps.packetSha256,
            recording: deps.recording,
            approval: { kind: approval.kind, envelopeId: approval.envelopeId ?? null },
            startedAt,
            clockOffsetSeconds,
            outcome,
            error,
            requests,
            finalReadback: final,
          },
          null,
          2,
        ),
      ),
      { mode: 0o600 },
    );
    deps.log({ outcome, atBaseline, requests, runDir });
    if (atBaseline) keepLocks = false;
    if (error) throw new Error(clean(error));
    return { outcome, atBaseline, requests, runDir };
  } finally {
    if (!keepLocks) for (const lock of locks.toReversed()) await releaseProjectLock(lock);
  }
}
