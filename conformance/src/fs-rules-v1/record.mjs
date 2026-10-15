// The production recording of FS-3, with every effect behind `deps` so a test can run the whole
// sequence against fakes: the refusals before anything is created, the ledger lines, the stop
// signal, the two recordings, the fixture and the outcome.
//
// The order is the safety argument: every refusal (dirty tree, a recent abort, no operator
// confirmation, a sandbox not in the state the lanes leave it) comes before the first write to
// production; the `started` ledger line comes before the first recording; the final ledger line is
// written whatever happens; and a fixture is written only for a clean, complete recording.

import { join } from "node:path";

import { SANDBOX_PROJECT } from "../fs-rules/harness.mjs";
import { corpusDigest, programDigest, validateCorpus } from "./corpus.mjs";
import {
  confirmedNoAuthRecording,
  estimatedUsd,
  fixtureText,
  recentAbort,
  selectPrograms,
  taskIdFor,
} from "./judge.mjs";

/**
 * @param {object} deps every effect: `now`, `readLedger(path)`, `appendLedger(path, text)`,
 *   `assertCleanTree()`, `gitSha()`, `harnessDigest()`, `assertIgnored(dir)`, `makeRunDir(dir)`,
 *   `writeRunFile(dir, name, text)`, `clockOffset()`, `sandboxWebConfig()`, `productionTarget(web)`,
 *   `preflight(target, ledgerText)`, `recordOnce(programs, web, { shouldStop })`,
 *   `readFixture()`, `writeFixture(text)`, `scanFixture(text, secrets)`, `installSignals(handler)`,
 *   `log(text)`, `warn(text)`.
 * @returns {Promise<{ outcome: string, exitCode: number, error?: string }>}
 */
export async function recordProduction(env, deps) {
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = env.FIREEMU_FS3_PRIVATE_DIR;
  if (!ledger || !privateRoot)
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_FS3_PRIVATE_DIR are required");
  await deps.assertCleanTree();
  const ledgerText = await deps.readLedger(ledger);
  const programs = selectPrograms(undefined, env);
  const taskId = taskIdFor(programs);
  const aborted = recentAbort(ledgerText, deps.now(), taskId);
  if (aborted)
    throw new Error(`the last run ended ${aborted.outcome} at ${aborted.ts}; wait an hour`);
  const corpusRequests = validateCorpus(programs);
  const operatorConfirmation = confirmedNoAuthRecording(env, deps.now());
  const web = await deps.sandboxWebConfig();
  const target = await deps.productionTarget(web);
  const { report, problems } = await deps.preflight(target, ledgerText, taskId);
  if (problems.length) throw new Error(`preflight: ${problems.join("; ")}`);
  const meta = {
    sha: await deps.gitSha(),
    harness: deps.harnessDigest(),
    startedAt: new Date(deps.now()).toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
    preflight: report,
    operatorConfirmation,
    clockOffsetSeconds: await deps.clockOffset(),
  };
  await deps.assertIgnored(privateRoot);
  const runDir = join(privateRoot, `fs-rules-v1-${meta.startedAt.replaceAll(":", "")}`);
  await deps.makeRunDir(runDir);
  await deps.appendLedger(
    ledger,
    `${JSON.stringify({ ts: meta.startedAt, event: "started", taskId, project: SANDBOX_PROJECT, gitSha: meta.sha, programs: programs.length, operatorConfirmation })}\n`,
  );

  const state = { stop: false };
  await deps.installSignals((signal) => {
    if (state.stop) {
      deps.warn(
        `${signal} again: cleanup is running and is not interrupted. A kill -9 now leaves a release, rulesets and an anonymous account for hand cleanup (see the private run directory).`,
      );
      return;
    }
    state.stop = true;
    deps.warn(`${signal}: stopping at the next step or wait; cleanup follows`);
  });

  const recordings = [];
  let outcome = "recorded";
  let error;
  try {
    for (const n of [1, 2]) {
      if (state.stop) throw Object.assign(new Error("stopped by a signal"), { fatal: true });
      const recording = await deps.recordOnce(programs, web, { shouldStop: () => state.stop });
      recordings.push(recording);
      await deps.writeRunFile(runDir, `recording-${n}.json`, JSON.stringify(recording));
    }
  } catch (caught) {
    outcome = caught.fatal ? "aborted-fatal" : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) {
      recordings.push(caught.partial);
      await deps.writeRunFile(
        runDir,
        `recording-${recordings.length}-partial.json`,
        JSON.stringify(caught.partial),
      );
    }
  }
  await deps.writeRunFile(
    runDir,
    "meta.json",
    JSON.stringify({ ...meta, outcome, error }, null, 2),
  );
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const failures = recordings.flatMap((r) => r.failures ?? []);
  const cleanupErrors = recordings.flatMap((r) => r.cleanupErrors ?? []);
  const unknowns = recordings.flatMap((r) => r.unknowns ?? []);
  // Something the run could not remove, or an answer it could not read, is what anyone must see first.
  if (cleanupErrors.length || unknowns.length) {
    outcome = "needs-recovery";
    deps.warn(
      `NOT CLOSURE-READY on ${SANDBOX_PROJECT}:\n  ${[...cleanupErrors, ...unknowns.map((u) => `unknown answer to ${u.call}: ${u.answer}`)].join("\n  ")}`,
    );
  }
  try {
    if (!error && outcome === "recorded") {
      const text = fixtureText({
        programs,
        recordings,
        meta,
        existing: JSON.parse((await deps.readFixture()) ?? "null") ?? undefined,
      });
      await deps.scanFixture(text, [web.apiKey, SANDBOX_PROJECT, web.projectNumber]);
      await deps.writeFixture(text);
      if (failures.length) outcome = "recorded-with-program-failures";
      deps.log(
        JSON.stringify({ programs: programs.length, corpusRequests, requests, failures }, null, 2),
      );
    }
  } catch (caught) {
    outcome = "not-written";
    error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
  } finally {
    await deps.appendLedger(
      ledger,
      `${JSON.stringify({
        ts: new Date(deps.now()).toISOString(),
        project: SANDBOX_PROJECT,
        database: "(default)",
        gitSha: meta.sha,
        corpusDigest: corpusDigest(programs),
        requests,
        estimatedUsd: estimatedUsd(requests),
        outcome,
        taskId,
        programs: meta.programs,
        publications: recordings.flatMap((r) => r.publications ?? []).length,
        closureReady: recordings.length > 0 && recordings.every((r) => r.closureReady === true),
        ...(unknowns.length ? { unknowns } : {}),
        ...(cleanupErrors.length ? { cleanupErrors } : {}),
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  return {
    outcome,
    exitCode: outcome === "recorded" ? 0 : 1,
    ...(error ? { error } : {}),
  };
}
