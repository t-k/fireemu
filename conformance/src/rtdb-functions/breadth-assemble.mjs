// Puts one breadth run together from its environment: the REST control, the Firebase CLI, the fetch of the
// RTDB admin client and of the unauthenticated writes, the clock and the private run directory. The
// recorder entry builds the environment from real things (ADC, the CLI, the network); the integration
// test builds it from fakes. Everything between is this module, so the entry cannot differ from what the
// test ran.

import { writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { basename, join } from "node:path";

import { LOCATION } from "./breadth-frames.mjs";
import {
  serviceAgentGrantChanges,
  readServiceAgentGrants,
  storageSend,
} from "../../functions-http/production.mjs";
import { openSourceUploads } from "../shared/gen2-source-uploads.mjs";
import { BREADTH_WINDOWS } from "./breadth-flow.mjs";
import { diffPairs, readProjectIam } from "./iam.mjs";
import { ownedEventarcNames, removeLeftovers, takeInventory } from "./inventory.mjs";
import { createRtdb } from "./breadth-rtdb.mjs";
import { resolveTarget } from "../../functions-http/harness.mjs";
import { resolveGen1Target } from "./gen1.mjs";
import { buildSteps } from "./breadth-sequence.mjs";
import { CODEBASE, TARGETS } from "./breadth-targets.mjs";
import {
  BREADTH_LIMITS,
  bindOps,
  createFormsCollector,
  createLogReader,
  preflightStage2,
} from "./breadth-wiring.mjs";

export function assembleBreadth({
  control,
  runCli,
  adminFetch,
  anonymousFetch,
  auth,
  sdk,
  packet,
  budget,
  runDir,
  adcPath,
  projectNumber,
  clock,
  abort,
  log,
  secrets = [],
  stop = {},
  programId = "breadth",
  nonce = randomBytes(8).toString("hex"),
}) {
  if (!auth || !sdk) throw new Error("breadth auth and SDK are required");
  const specs = new Map(
    TARGETS.map((target) => {
      const { functionName, region, codebase, generation, project, runtime, entryPoint } = target;
      return [
        target,
        (generation === "gcfv1" ? resolveGen1Target : resolveTarget)({
          functionName,
          region,
          codebase,
          generation,
          project,
          runtime,
          entryPoint,
        }),
      ];
    }),
  );
  const records = {};
  const send = control;
  control = async (...args) => {
    const reply = await send(...args);
    const spec = TARGETS.find(
      (target) =>
        args[1] ===
        `https://cloudfunctions.googleapis.com/${target.generation === "gcfv1" ? "v1" : "v2"}/projects/${target.project}/locations/${target.region}/functions/${target.functionName}`,
    );
    if (args[0] === "GET" && reply.status === 200 && spec) {
      records[spec.key] = reply.value;
      await writeFile(join(runDir, "records.json"), JSON.stringify(records), { mode: 0o600 });
    }
    return reply;
  };
  const uploads = openSourceUploads({
    ledgerPath: join(runDir, "owned-uploads.jsonl"),
    runId: basename(runDir),
    projectNumber,
    region: LOCATION,
    send: storageSend(control),
    requestsLeft: () => BREADTH_LIMITS.upload - budget.snapshot().upload,
  });
  const forms = createFormsCollector(projectNumber);
  const ops = bindOps({
    control,
    adcPath,
    budget,
    runDir,
    uploads,
    runCli,
    programId,
    log,
    sleep: clock.sleep,
    forms,
  });
  for (const actions of Object.values(ops)) {
    for (const [name, action] of Object.entries(actions)) {
      actions[name] = async (target, ...args) => {
        if (!specs.has(target)) throw Error("unreviewed breadth target");
        return action(specs.get(target), ...args);
      };
    }
  }
  const rtdb = createRtdb({
    fetchImpl: anonymousFetch,
    adminFetch,
    packet,
    log,
    secrets,
    stop,
    sleep: clock.sleep,
    now: clock.now,
    nonce,
    runDir,
    userToken: () => auth.idToken,
  });
  const grants = {
    before: null,
    after: null,
    changes: [],
    iam: { before: null, after: null, added: [], removed: [] },
  };
  const deps = {
    records,
    runDir,
    budget,
    targets: TARGETS,
    steps: buildSteps(nonce),
    nonce,
    ops,
    // only a 2nd gen record names an Eventarc trigger and topic
    ownedNames: (record, spec) =>
      spec.generation === "gcfv2" ? ownedEventarcNames(record, specs.get(spec)) : null,
    preflight: async () => {
      grants.before = await preflightStage2({ control, projectNumber });
      grants.iam.before = await readProjectIam(control, projectNumber);
    },
    inventory: {
      take: () =>
        takeInventory(async (...args) => {
          if (args[1].includes("/functions?"))
            args[1] = args[1].replace(`/locations/${LOCATION}/`, "/locations/-/");
          const reply = await control(...args);
          if (
            args[1].includes("/functions?") &&
            reply.value?.functions?.some(
              (entry) => entry.labels?.["firebase-functions-codebase"] === CODEBASE,
            )
          )
            throw Error("breadth codebase already has a function");
          return reply;
        }, "inventory"),
      removeLeftovers: (before, owned) =>
        removeLeftovers(control, before, owned, { sleep: clock.sleep }),
    },
    rtdb,
    auth,
    sdk,
    logs: createLogReader({ control, now: () => new Date(clock.now()).toISOString() }),
    uploads,
    log,
    abort,
    clock,
    windows: BREADTH_WINDOWS,
    programId,
  };
  return {
    deps,
    forms,
    uploads,
    rtdb,
    grants,
    /** The project's service-agent grants after the run, and what changed (the deploy can add some). */
    async readGrantsAfter() {
      grants.after = await readServiceAgentGrants(control, projectNumber);
      grants.changes = serviceAgentGrantChanges(grants.before, grants.after);
      grants.iam.after = await readProjectIam(control, projectNumber);
      Object.assign(grants.iam, diffPairs(grants.iam.before, grants.iam.after));
      return grants;
    },
  };
}
