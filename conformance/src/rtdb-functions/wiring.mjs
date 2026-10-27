// The glue between the CV14 flow and the reviewed parts it runs on: a fetch that adds the token, the log
// reader, the collector of the debug-line forms, the target operations bound to one run, the preflight,
// and the request ceilings. Nothing here decides anything the flow or the reviewed parts decide.

import { createBudget, resolveTarget } from "../../functions-http/harness.mjs";
import {
  assertNoNameCollisions,
  assertTargetAbsent,
  cleanupTarget,
  deployTarget,
  preflightCliSideEffects,
  readDeployedTarget,
  readServiceAgentGrants,
  targetResources,
} from "../../functions-http/production.mjs";
import { loggingApiState, maskProbeLine } from "../../functions-http/upload-probe.mjs";
import { assertGen1Absent, cleanupGen1, deployGen1, readDeployedGen1 } from "./gen1.mjs";
import { INVENTORY_HOSTS } from "./inventory.mjs";
import { LOGGING_HOST, listRequest, parseEntries } from "./logs.mjs";

/** The request ceilings of one run, counted from the code (see wiring.test.mjs and the integration test). */
export const STAGE2_LIMITS = Object.freeze({
  invocation: 0,
  auth: 0,
  cliDelete: 0,
  cliDeploy: 8,
  upload: 120,
  token: 12,
  control: 120,
  cleanup: 200,
});
export const STAGE2_KINDS = Object.freeze({ logs: 250, inventory: 100 });
export const STAGE2_HOSTS = Object.freeze([LOGGING_HOST, ...INVENTORY_HOSTS]);

export const createStage2Budget = () => createBudget({ ...STAGE2_LIMITS }, { ...STAGE2_KINDS });

/** A fetch that adds the bearer token (a fresh one each time, from `getToken`) and the quota project. */
export function bearerFetch(getToken, project, base = fetch) {
  return async (url, init = {}) =>
    base(url, {
      ...init,
      headers: {
        ...init.headers,
        authorization: `Bearer ${await getToken()}`,
        "x-goog-user-project": project,
      },
    });
}

const LOG_PAGES = 3;

/** Reads the frames of a window, page by page (at most three), each insert id once across reads. */
export function createLogReader({ control, now }) {
  const seen = new Set();
  return {
    async read({ start, end }) {
      const total = { frames: [], entries: 0, ignored: {}, complete: true };
      let pageToken;
      try {
        for (let page = 0; page < LOG_PAGES; page += 1) {
          const request = listRequest({ start, end, pageToken });
          const reply = await control(request.method, request.url, request.body, "logs");
          const parsed = parseEntries(reply.value, { readAt: now(), seen });
          total.frames.push(...parsed.frames);
          total.entries += parsed.entries;
          for (const [key, count] of Object.entries(parsed.ignored)) {
            total.ignored[key] = (total.ignored[key] ?? 0) + count;
          }
          pageToken = parsed.nextPageToken ?? undefined;
          if (pageToken === undefined) return total;
        }
        total.complete = false;
      } catch {
        return { frames: [], entries: 0, ignored: {}, complete: false };
      }
      return total;
    },
  };
}

/**
 * Collects, for each target, what its deploy's debug lines showed: a receipt (2nd gen), an external
 * upload (1st gen) and the PUT statuses, with the lines masked (the project number, and the number in
 * the name of a bucket outside the project, are replaced; signed URLs are removed).
 */
export function createFormsCollector(projectNumber) {
  const perTarget = {};
  const lines = [];
  return {
    observe(event, line, key) {
      if (!["receipt", "external-upload", "put-status"].includes(event?.type)) return;
      const entry = (perTarget[key] ??= {
        receipt: false,
        externalUpload: false,
        putStatusCodes: [],
      });
      if (event.type === "receipt") entry.receipt = true;
      else if (event.type === "external-upload") entry.externalUpload = true;
      else entry.putStatusCodes.push(event.status);
      lines.push(
        maskProbeLine(line, projectNumber).replace(/uploads-\d+\./gu, "uploads-123456789012."),
      );
    },
    summary: () => structuredClone(perTarget),
    maskedLines: () => [...lines],
  };
}

const twinOf = ({ functionName, region, codebase, runtime, entryPoint }) =>
  resolveTarget({ functionName, region, codebase, runtime, entryPoint, generation: "gcfv2" });

/** The four operations of each generation, bound to one run's control, budget, directory and ledger. */
export function bindOps({
  control,
  adcPath,
  budget,
  runDir,
  uploads,
  runCli,
  programId,
  log,
  sleep,
  forms,
  impl = {
    assertTargetAbsent,
    deployTarget,
    readDeployedTarget,
    cleanupTarget,
    assertGen1Absent,
    assertNoNameCollisions,
    deployGen1,
    readDeployedGen1,
    cleanupGen1,
  },
}) {
  const tap = (spec) => (event, line) => forms.observe(event, line, spec.key);
  return {
    gcfv1: {
      async assertAbsent(spec) {
        await impl.assertGen1Absent(control, spec);
        // the v2 list covers both generations; the name and codebase rules are the 2nd gen ones
        await impl.assertNoNameCollisions(control, twinOf(spec));
      },
      deploy: (spec, state) =>
        impl.deployGen1(
          spec,
          programId,
          state,
          uploads,
          adcPath,
          budget,
          runDir,
          runCli,
          tap(spec),
        ),
      read: (spec, state) => impl.readDeployedGen1(control, spec, state),
      cleanup: (spec, state) => impl.cleanupGen1(control, spec, state, { log, sleep }),
    },
    gcfv2: {
      assertAbsent: (spec) => impl.assertTargetAbsent(control, spec),
      deploy: (spec, state) =>
        impl.deployTarget(
          spec,
          programId,
          state,
          uploads,
          adcPath,
          budget,
          runDir,
          runCli,
          tap(spec),
        ),
      async read(spec, state) {
        await impl.readDeployedTarget(control, spec, state);
        // the record names the Eventarc trigger and topic the cleanup may have to remove
        state.record = (
          await control("GET", targetResources(spec).functionUrl, undefined, "control")
        ).value;
      },
      cleanup: (spec, state) =>
        impl.cleanupTarget(control, spec, adcPath, budget, runDir, state, {
          run: runCli,
          log,
          sleep,
        }),
    },
  };
}

/** Read-only checks before anything is changed; returns the service-agent grants as they were. */
export async function preflightStage2({
  control,
  projectNumber,
  impl = { loggingApiState, preflightCliSideEffects, readServiceAgentGrants },
}) {
  if ((await impl.loggingApiState(control)) !== "ENABLED") {
    throw new Error(
      "Cloud Logging is not enabled on the sandbox project, so the frames cannot be read back",
    );
  }
  await impl.preflightCliSideEffects(control);
  return impl.readServiceAgentGrants(control, projectNumber);
}
