// The production recording of the Secure Token body corpus, with every effect behind `deps` so a
// test can run the whole sequence against fakes.
//
// The order is the safety argument: every refusal (dirty tree, a recent abort, a sandbox not in the
// state the lanes leave it) comes before the first write to production; the `started` ledger line
// comes before the first recording; the final ledger line is written whatever happens; and the
// fixture is written only for two clean, complete recordings. Nothing that was resolved at send
// time (a token, the key, the owner credential) is written to any file: the recordings are
// stripped of it before they are written, and the text is scanned for it before it is kept.

import { join } from "node:path";

import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { ROWS, corpusDigest, validateCorpus } from "./corpus.mjs";
import { TASK_ID, estimatedUsd, recentAbort } from "./judge.mjs";

const RECORDINGS = 2;

/** The fixture text for two complete recordings of the corpus. */
export function fixtureText({ recordings, meta }) {
  return `${JSON.stringify(
    {
      version: 1,
      recordedAgainst: {
        target:
          "production Identity Toolkit and Secure Token REST, Identity Platform sandbox; multi-tenancy switched on for each recording and restored",
        task: TASK_ID,
        note: "Tokens, the API key, the project id and its number never appear. A refresh answer is its normalized body; a token is recorded as its presence and length. user_id is the run's own account (a, b or t).",
      },
      gitSha: meta.sha,
      corpusDigest: meta.corpusDigest,
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      recordings: recordings.map(({ run: _run, rows }) => ({ rows })),
    },
    null,
    2,
  )}\n`;
}

/** What may be written to a file: a recording without the secrets the session held. */
export const publicRecording = ({ secrets: _secrets, ...rest }) => rest;

/**
 * @param {object} deps every effect: `now`, `readLedger(path)`, `appendLedger(path, text)`,
 *   `assertCleanTree()`, `gitSha()`, `harnessDigest()`, `assertIgnored(dir)`, `makeRunDir(dir)`,
 *   `writeRunFile(dir, name, text)`, `clockOffset()`, `sandboxWebConfig()`, `productionTarget(web)`,
 *   `preflight(target, ledgerText)`, `recordOnce(n, web, { runDir, shouldStop })`,
 *   `readFixture()`, `writeFixture(text)`, `scanFixture(text, secrets)`, `installSignals(handler)`,
 *   `log(text)`, `warn(text)`.
 * @returns {Promise<{ outcome: string, exitCode: number, error?: string }>}
 */
export async function recordProduction(env, deps) {
  const ledger = env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = env.FIREEMU_SECURETOKEN_PRIVATE_DIR;
  if (!ledger || !privateRoot)
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_SECURETOKEN_PRIVATE_DIR are required");
  await deps.assertCleanTree();
  const ledgerText = await deps.readLedger(ledger);
  const aborted = recentAbort(ledgerText, deps.now());
  if (aborted)
    throw new Error(`the last run ended ${aborted.outcome} at ${aborted.ts}; wait an hour`);
  const corpusRows = validateCorpus(ROWS);
  const web = await deps.sandboxWebConfig();
  const target = await deps.productionTarget(web);
  const { report, problems } = await deps.preflight(target, ledgerText);
  if (problems.length) throw new Error(`preflight: ${problems.join("; ")}`);
  const meta = {
    sha: await deps.gitSha(),
    harness: await deps.harnessDigest(),
    corpusDigest: corpusDigest(),
    startedAt: new Date(deps.now()).toISOString(),
    preflight: report,
    clockOffsetSeconds: await deps.clockOffset(),
  };
  await deps.assertIgnored(privateRoot);
  const runDir = join(privateRoot, `securetoken-body-${meta.startedAt.replaceAll(":", "")}`);
  await deps.makeRunDir(runDir);
  await deps.appendLedger(
    ledger,
    `${JSON.stringify({ ts: meta.startedAt, event: "started", taskId: TASK_ID, project: SANDBOX_PROJECT, gitSha: meta.sha, rows: corpusRows })}\n`,
  );

  const state = { stop: false };
  await deps.installSignals((signal) => {
    if (state.stop) {
      deps.warn(
        `${signal} again: cleanup is running and is not interrupted. A kill -9 now leaves accounts, a tenant and the multi-tenancy switch for hand cleanup (see the private run directory).`,
      );
      return;
    }
    state.stop = true;
    deps.warn(`${signal}: stopping at the next step; cleanup follows`);
  });

  const recordings = [];
  let outcome = "recorded";
  let error;
  const secrets = [web.apiKey, web.projectNumber, SANDBOX_PROJECT];
  try {
    for (let n = 1; n <= RECORDINGS; n += 1) {
      if (state.stop) throw Object.assign(new Error("stopped by a signal"), { fatal: true });
      const recording = await deps.recordOnce(n, web, { runDir, shouldStop: () => state.stop });
      secrets.push(...(recording.secrets ?? []));
      const text = JSON.stringify(publicRecording(recording));
      await deps.scanFixture(text, secrets);
      recordings.push(publicRecording(recording));
      await deps.writeRunFile(runDir, `recording-${n}.json`, text);
      if (recording.failure) {
        outcome = recording.fatal ? "aborted-fatal" : "aborted";
        error = recording.failure;
        break;
      }
      // A recording that left a name open or tenancy on is the last: the next one would take what is left
      // as its starting state, and the preflight has not re-read the sandbox.
      if (recording.closureReady !== true) {
        error = `recording ${n} is not closure-ready; recording ${n + 1} is not started`;
        break;
      }
    }
  } catch (caught) {
    outcome = caught.fatal ? "aborted-fatal" : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) recordings.push(publicRecording(caught.partial));
  }
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const cleanupErrors = recordings.flatMap((r) => r.cleanupErrors ?? []);
  const unknowns = recordings.flatMap((r) => r.unknowns ?? []);
  // Anything left open, or an answer that was ever unknown, is for recovery first: it outranks an abort.
  if (cleanupErrors.length || unknowns.length || recordings.some((r) => r.closureReady !== true)) {
    outcome = "needs-recovery";
    deps.warn(
      `NOT CLOSURE-READY on ${SANDBOX_PROJECT}:\n  ${[...cleanupErrors, ...unknowns.map((u) => `unknown answer to ${u.call}: ${u.answer}`)].join("\n  ")}`,
    );
  }
  await deps.writeRunFile(
    runDir,
    "meta.json",
    JSON.stringify({ ...meta, outcome, error }, null, 2),
  );
  try {
    if (!error && outcome === "recorded") {
      const text = fixtureText({ recordings, meta });
      await deps.scanFixture(text, secrets);
      await deps.writeFixture(text);
      deps.log(JSON.stringify({ rows: corpusRows, requests }, null, 2));
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
        gitSha: meta.sha,
        corpusDigest: meta.corpusDigest,
        requests,
        estimatedUsd: estimatedUsd(requests),
        outcome,
        taskId: TASK_ID,
        rows: corpusRows,
        recordings: recordings.length,
        closureReady:
          recordings.length === RECORDINGS && recordings.every((r) => r.closureReady === true),
        ...(unknowns.length ? { unknowns } : {}),
        ...(cleanupErrors.length ? { cleanupErrors } : {}),
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  return { outcome, exitCode: outcome === "recorded" ? 0 : 1, ...(error ? { error } : {}) };
}
