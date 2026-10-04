// The recorder: preflight, create the run's data resources, one deploy, readiness, two passes of the
// source script with the capture running underneath, the cleanup. It records; it does not judge. The
// only things that stop it are a failed preflight (nothing was written), a deploy that did not become
// ready, a signal, the request ceiling, and a guard refusal. After any of them, if something was
// created, the cleanup still runs.

import { PROPAGATION_WAIT_SECONDS, cliFailed as failed, waitReady } from "./deploy.mjs";
import { runCleanup } from "./cleanup.mjs";
import { listRequest, parseEntries } from "./logs.mjs";
import { iamPairs, runPreflight } from "./preflight.mjs";
import { BudgetExhausted, GuardRefused, TokenFailure, resolveText } from "./rest.mjs";
import { STEP_GAP_SECONDS, buildPass, runSetupRequests } from "./script.mjs";

export const NORMAL_CEILING = 480;
export const CLEANUP_CEILING = 520;
// The log entries persist, so the capture only needs to read often enough that no entry waits long: a poll covers everything since the last one.
export const CAPTURE_EVERY_SECONDS = 120;
export const SLEEP_CHUNK_SECONDS = 60;
export const FINAL_WINDOW_SECONDS = 120;
export const MAX_PAGES = 5;
export const FULL_READ_PAGES = 20;

const micro = (ms) => new Date(ms).toISOString().replace("Z", "000Z");

function createCapture({ transport, now, startedAt }) {
  const seen = new Set();
  const frames = [];
  const ignored = {};
  let polls = 0;
  let incomplete = 0;
  let lastEnd = startedAt;
  let lastPollAt = startedAt;
  async function readWindow(from, pages) {
    const end = now();
    let pageToken;
    for (let page = 0; page < pages; page += 1) {
      polls += 1;
      const answer = await transport.request(
        listRequest({ start: micro(from), end: micro(end), pageToken }),
      );
      if (answer.kind !== "success") {
        incomplete += 1;
        return false;
      }
      const parsed = parseEntries(answer.json, { readAt: new Date(now()).toISOString(), seen });
      frames.push(...parsed.frames);
      for (const [key, count] of Object.entries(parsed.ignored))
        ignored[key] = (ignored[key] ?? 0) + count;
      pageToken = parsed.nextPageToken;
      if (!pageToken) return end;
    }
    incomplete += 1;
    return false;
  }
  async function poll() {
    lastPollAt = now();
    const end = await readWindow(Math.max(startedAt, lastEnd - 30_000), MAX_PAGES);
    if (end) lastEnd = end;
  }
  // The last read covers the whole run, so the negative cases and the per-handler checks rest on one
  // complete read, whatever the earlier polls missed (a page that did not read, a late-ingested entry).
  async function pollRun() {
    lastPollAt = now();
    return readWindow(startedAt, FULL_READ_PAGES);
  }
  return {
    poll,
    pollRun,
    frames,
    sincePoll: () => now() - lastPollAt,
    stats: () => ({ polls, incompletePolls: incomplete, ignored }),
  };
}

const iso = (now) => new Date(now()).toISOString();

/**
 * `record({ transport, cli, sleep, now, newId, corpusDigest, signal })`. `cli(action)` runs the one
 * deploy or delete; `sleep(seconds)` waits (a test advances a virtual clock); `now()` is epoch ms.
 */
export async function record({
  transport,
  cli,
  sleep,
  now,
  newId,
  corpusDigest,
  signal = { aborted: false },
  log = () => {},
}) {
  const startedAt = now();
  const run = {
    schemaVersion: 1,
    kind: "functions-events-production-run",
    project: "fireemu-oracle-events",
    corpusDigest,
    recordedAt: new Date(startedAt).toISOString(),
    passes: [],
    frames: [],
    preflight: null,
    deploy: { dryRun: null, cli: null, readiness: null },
    cleanup: null,
    capture: null,
    stops: [],
  };
  const ran = { created: false, deployStarted: false };
  transport.setCeiling(NORMAL_CEILING);
  const capture = createCapture({ transport, now, startedAt });

  async function waitAndCapture(seconds) {
    let left = seconds;
    while (left > 0 && !signal.aborted) {
      const chunk = Math.min(SLEEP_CHUNK_SECONDS, left);
      await sleep(chunk);
      left -= chunk;
      if (capture.sincePoll() >= CAPTURE_EVERY_SECONDS * 1000) await capture.poll();
    }
  }

  // What the run may have made in Auth: uids and emails (a sign-up whose answer was lost may still have made a user).
  const owned = { uids: new Set(), emails: new Set() };
  transport.observe(({ method, url, body }) => {
    const { hostname, pathname } = new URL(url);
    if (hostname !== "identitytoolkit.googleapis.com" || method !== "POST") return;
    if (!pathname.endsWith("/accounts") && !pathname.endsWith("/accounts:signUp")) return;
    if (typeof body?.email === "string") owned.emails.add(body.email);
    if (typeof body?.localId === "string") owned.uids.add(body.localId);
  });

  async function runStep(step, record_) {
    transport.state.vars = {};
    const op = {
      scenarioId: step.scenarioId,
      role: step.role,
      sourceResult: null,
      startedAt: null,
      endedAt: null,
      matchKey: null,
      readback: [],
      windowSeconds: step.settleSeconds,
      requests: [],
    };
    record_.operations.push(op);
    let subject;
    try {
      let windowDone = false;
      let previous = null;
      for (const request of step.requests) {
        if (request.role === "subject" && step.seedWaitSeconds > 0 && previous?.role === "setup")
          await waitAndCapture(step.seedWaitSeconds);
        if (request.role === "cleanup" && !windowDone) {
          await waitAndCapture(step.settleSeconds);
          windowDone = true;
        }
        const isSubject = step.subject.includes(request.id);
        if (isSubject) op.startedAt = iso(now);
        const answer = await transport.request(request);
        if (transport.state.vars.uid) owned.uids.add(String(transport.state.vars.uid));
        if (isSubject) {
          op.endedAt = iso(now);
          subject = answer;
        }
        op.requests.push({
          id: request.id,
          role: request.role,
          status: answer.status ?? null,
          kind: answer.kind ?? null,
          skipped: answer.skipped ?? false,
          expected: answer.expected ?? null,
        });
        if (request.role === "readback" && !answer.skipped)
          op.readback.push({ id: request.id, status: answer.status ?? null });
        previous = request;
      }
      if (!windowDone) await waitAndCapture(step.settleSeconds);
    } catch (error) {
      // The guard, the ceiling and the credential end the passes; any other error is this step's: it is
      // recorded as unknown, and the final sweep removes whatever the step made.
      if (
        error instanceof GuardRefused ||
        error instanceof BudgetExhausted ||
        error instanceof TokenFailure
      )
        throw error;
      op.error = `${error.constructor.name}: ${error.message}`;
      run.stops.push(`${step.scenarioId} (${step.role}) of pass ${record_.pass}: ${op.error}`);
    }
    op.sourceResult =
      subject?.kind === "success"
        ? "typed-success"
        : subject?.kind === "refusal"
          ? "typed-refusal"
          : "unknown";
    const vars = transport.state.vars;
    const resolve = (text) => {
      try {
        return resolveText(text, vars);
      } catch {
        return null;
      }
    };
    op.matchKey = {
      ...step.matchKey,
      value: resolve(step.matchKey.value),
      ...(step.matchKey.values ? { values: step.matchKey.values } : {}),
    };
  }

  async function runPass(pass) {
    const record_ = { pass, startedAt: iso(now), endedAt: null, operations: [] };
    run.passes.push(record_);
    for (const step of buildPass({ pass, newId }).steps) {
      if (signal.aborted) {
        run.stops.push(`a stop signal arrived before ${step.scenarioId} of pass ${pass}`);
        return false;
      }
      await runStep(step, record_);
      await waitAndCapture(STEP_GAP_SECONDS);
    }
    record_.endedAt = iso(now);
    return true;
  }

  let passesComplete = false;
  let iamBefore = null;
  let servicesBefore = null;
  let notificationsBefore = null;
  try {
    const pre = await runPreflight((spec, vars) => transport.request(spec, vars));
    iamBefore = pre.iamBefore;
    servicesBefore = pre.servicesBefore;
    notificationsBefore = pre.notificationsBefore;
    run.preflight = {
      problems: pre.problems,
      iamBefore: iamPairs(pre.iamBefore),
      notificationConfigs: pre.notificationsBefore?.map((config) => config.id) ?? null,
    };
    if (pre.problems.length) {
      run.stops.push("the preflight found problems; nothing was written");
      run.cleanup = null;
      return finish("stopped-clean");
    }
    if (signal.aborted) {
      run.stops.push("a stop signal arrived before anything was created");
      return finish("stopped-clean");
    }
    // One CLI dry run of the exact deploy command, before anything is created: a refusal of the CLI itself
    // (a prompt it cannot answer, a build or validation error) stops the run with nothing written.
    log("dry run");
    run.deploy.dryRun = await cli("dry-run");
    if (failed(run.deploy.dryRun)) {
      run.stops.push("the CLI dry run failed; nothing was created or deployed");
      return finish("stopped-clean");
    }
    if (signal.aborted) {
      run.stops.push("a stop signal arrived after the dry run; nothing was created");
      return finish("stopped-clean");
    }
    ran.created = true;
    const setup = [];
    for (const request of runSetupRequests()) setup.push(await transport.request(request));
    run.setup = setup.map(({ id, status, kind }) => ({
      id,
      status: status ?? null,
      kind: kind ?? null,
    }));
    if (setup.some((answer) => answer.kind !== "success")) {
      run.stops.push("a resource of the run could not be created; the deploy was not started");
    } else if (signal.aborted) {
      run.stops.push("a stop signal arrived before the deploy; nothing was deployed");
    } else {
      log("deploy");
      ran.deployStarted = true;
      run.deploy.cli = await cli("deploy");
      const cliFailed = failed(run.deploy.cli);
      run.deploy.readiness = await waitReady({
        transport,
        sleep,
        polls: cliFailed ? 2 : undefined,
        shouldStop: () => signal.aborted,
      });
    }
    if (run.stops.length > 0) {
      // nothing more is sent before the cleanup
    } else if (signal.aborted) {
      run.stops.push("a stop signal arrived while the deploy settled; the passes were skipped");
    } else if (!run.deploy.readiness.ready) {
      run.stops.push("the 22 handlers did not become active; the passes were skipped");
    } else {
      await waitAndCapture(PROPAGATION_WAIT_SECONDS);
      passesComplete = (await runPass(1)) && (await runPass(2));
      if (passesComplete) await waitAndCapture(FINAL_WINDOW_SECONDS);
    }
  } catch (error) {
    run.stops.push(`${error.constructor.name}: ${error.message}`);
  }

  // Nothing was created: there is nothing of the run's to clean up, and a delete must never touch a resource the run did not make.
  if (!ran.created) return finish("stopped-clean");

  // The cleanup runs after any stop once something was created.
  transport.setCeiling(CLEANUP_CEILING);
  try {
    run.cleanup = await runCleanup({
      transport,
      cli,
      sleep,
      ran,
      iamBefore,
      servicesBefore,
      notificationsBefore,
      owned,
    });
  } catch (error) {
    run.cleanup = { verified: false, problems: [`cleanup: ${error.message}`], steps: {} };
  }
  // One last read of the whole run window, after the cleanup (late entries included).
  await capture.pollRun().catch(() => {});
  const outcome = run.cleanup.verified
    ? passesComplete && run.stops.length === 0
      ? "recorded"
      : "incomplete-clean"
    : "needs-recovery";
  return finish(outcome);

  function finish(finalOutcome) {
    run.frames = capture.frames;
    run.capture = capture.stats();
    run.requestsSent = transport.state.sent;
    run.owned = { uids: owned.uids.size, emails: owned.emails.size };
    run.endedAt = iso(now);
    return { outcome: finalOutcome, run };
  }
}
