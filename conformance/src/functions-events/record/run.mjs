// The recorder: preflight, create the run's data resources, one deploy, readiness, two passes of the
// source script with the capture running underneath, the cleanup. It records; it does not judge. The
// only things that stop it are a failed preflight (nothing was written), a deploy that did not become
// ready, a signal, the request ceiling, and a guard refusal. After any of them, if something was
// created, the cleanup still runs.

import { LISTS, PROPAGATION_WAIT_SECONDS, waitReady } from "./deploy.mjs";
import { runCleanup } from "./cleanup.mjs";
import { listRequest, parseEntries } from "./logs.mjs";
import { runPreflight } from "./preflight.mjs";
import { resolveText } from "./rest.mjs";
import { STEP_GAP_SECONDS, buildPass, runSetupRequests } from "./script.mjs";

export const NORMAL_CEILING = 480;
export const CLEANUP_CEILING = 520;
export const CAPTURE_EVERY_SECONDS = 30;
export const FINAL_WINDOW_SECONDS = 120;
export const MAX_PAGES = 5;

const micro = (ms) => new Date(ms).toISOString().replace("Z", "000Z");

function createCapture({ transport, now, startedAt }) {
  const seen = new Set();
  const frames = [];
  const ignored = {};
  let polls = 0;
  let incomplete = 0;
  let lastEnd = startedAt;
  async function poll() {
    const start = Math.max(startedAt, lastEnd - 30_000);
    const end = now();
    let pageToken;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      polls += 1;
      const answer = await transport.request(listRequest({ start: micro(start), end: micro(end), pageToken }));
      if (answer.kind !== "success") {
        incomplete += 1;
        return;
      }
      const parsed = parseEntries(answer.json, { readAt: new Date(now()).toISOString(), seen });
      frames.push(...parsed.frames);
      for (const [key, count] of Object.entries(parsed.ignored)) ignored[key] = (ignored[key] ?? 0) + count;
      pageToken = parsed.nextPageToken;
      if (!pageToken) {
        lastEnd = end;
        return;
      }
    }
    incomplete += 1;
  }
  return { poll, frames, stats: () => ({ polls, incompletePolls: incomplete, ignored }) };
}

const iso = (now) => new Date(now()).toISOString();

/**
 * `record({ transport, cli, sleep, now, newId, corpusDigest, signal })`. `cli(action)` runs the one
 * deploy or delete; `sleep(seconds)` waits (a test advances a virtual clock); `now()` is epoch ms.
 */
export async function record({ transport, cli, sleep, now, newId, corpusDigest, signal = { aborted: false }, log = () => {} }) {
  const startedAt = now();
  const run = { schemaVersion: 1, kind: "functions-events-production-run", project: "fireemu-oracle-events", corpusDigest, recordedAt: new Date(startedAt).toISOString(), passes: [], frames: [], preflight: null, deploy: { cli: null, readiness: null }, cleanup: null, capture: null, stops: [] };
  const ran = { created: false, deployStarted: false };
  transport.setCeiling(NORMAL_CEILING);
  const capture = createCapture({ transport, now, startedAt });

  async function waitAndCapture(seconds) {
    let left = seconds;
    while (left > 0) {
      const chunk = Math.min(CAPTURE_EVERY_SECONDS, left);
      await sleep(chunk);
      left -= chunk;
      await capture.poll();
    }
  }

  async function runPass(pass) {
    const record_ = { pass, startedAt: iso(now), endedAt: null, operations: [] };
    run.passes.push(record_);
    for (const step of buildPass({ pass, newId }).steps) {
      if (signal.aborted) {
        run.stops.push(`a stop signal arrived before ${step.scenarioId} of pass ${pass}`);
        return false;
      }
      transport.state.vars = {};
      const op = { scenarioId: step.scenarioId, role: step.role, sourceResult: null, startedAt: null, endedAt: null, matchKey: null, readback: [], windowSeconds: step.settleSeconds, requests: [] };
      record_.operations.push(op);
      let subject;
      let windowDone = false;
      let previous = null;
      for (const request of step.requests) {
        if (request.role === "subject" && step.seedWaitSeconds > 0 && previous?.role === "setup") await waitAndCapture(step.seedWaitSeconds);
        if (request.role === "cleanup" && !windowDone) {
          await waitAndCapture(step.settleSeconds);
          windowDone = true;
        }
        const isSubject = step.subject.includes(request.id);
        if (isSubject) op.startedAt = iso(now);
        const answer = await transport.request(request);
        if (isSubject) {
          op.endedAt = iso(now);
          subject = answer;
        }
        op.requests.push({ id: request.id, role: request.role, status: answer.status ?? null, kind: answer.kind ?? null, skipped: answer.skipped ?? false, expected: answer.expected ?? null });
        if (request.role === "readback" && !answer.skipped) op.readback.push({ id: request.id, status: answer.status ?? null });
        previous = request;
      }
      if (!windowDone) await waitAndCapture(step.settleSeconds);
      op.sourceResult = subject?.kind === "success" ? "typed-success" : subject?.kind === "refusal" ? "typed-refusal" : "unknown";
      const vars = transport.state.vars;
      const resolve = (text) => {
        try {
          return resolveText(text, vars);
        } catch {
          return null;
        }
      };
      op.matchKey = { ...step.matchKey, value: resolve(step.matchKey.value), ...(step.matchKey.values ? { values: step.matchKey.values } : {}) };
      await waitAndCapture(STEP_GAP_SECONDS);
    }
    record_.endedAt = iso(now);
    return true;
  }

  let passesComplete = false;
  try {
    const pre = await runPreflight((spec, vars) => transport.request(spec, vars));
    run.preflight = { problems: pre.problems };
    if (pre.problems.length) {
      run.stops.push("the preflight found problems; nothing was written");
      run.cleanup = null;
      return finish("stopped-clean");
    }
    ran.created = true;
    for (const request of runSetupRequests()) await transport.request(request);
    log("deploy");
    ran.deployStarted = true;
    run.deploy.cli = await cli("deploy");
    run.deploy.readiness = await waitReady({ transport, sleep });
    if (!run.deploy.readiness.ready) {
      run.stops.push("the 22 handlers did not become active; the passes were skipped");
    } else {
      await waitAndCapture(PROPAGATION_WAIT_SECONDS);
      passesComplete = (await runPass(1)) && (await runPass(2));
      if (passesComplete) await waitAndCapture(FINAL_WINDOW_SECONDS);
    }
  } catch (error) {
    run.stops.push(`${error.constructor.name}: ${error.message}`);
  }

  // The cleanup runs after any stop once something was created.
  transport.setCeiling(CLEANUP_CEILING);
  try {
    run.cleanup = await runCleanup({ transport, cli, sleep, ran });
  } catch (error) {
    run.cleanup = { verified: false, problems: [`cleanup: ${error.message}`], steps: {} };
  }
  await capture.poll().catch(() => {});
  const outcome = run.cleanup.verified ? (passesComplete && run.stops.length === 0 ? "recorded" : "incomplete-clean") : "needs-recovery";
  return finish(outcome);

  function finish(outcome) {
    run.frames = capture.frames;
    run.capture = capture.stats();
    run.requestsSent = transport.state.sent;
    run.endedAt = iso(now);
    return { outcome, run };
  }
}
