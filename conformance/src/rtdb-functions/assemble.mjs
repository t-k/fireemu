// Puts one CV14 run together from its environment: the REST control, the Firebase CLI, the fetch of the
// RTDB admin client and of the unauthenticated writes, the clock and the private run directory. The
// recorder entry builds the environment from real things (ADC, the CLI, the network); the integration
// test builds it from fakes. Everything between is this module, so the entry cannot differ from what the
// test ran.

import { basename, join } from "node:path";

import { LOCATION } from "./frames.mjs";
import {
  serviceAgentGrantChanges,
  readServiceAgentGrants,
  storageSend,
} from "../../functions-http/production.mjs";
import { openSourceUploads } from "../shared/gen2-source-uploads.mjs";
import { STAGE2_WINDOWS } from "./flow.mjs";
import { ownedEventarcNames, removeLeftovers, takeInventory } from "./inventory.mjs";
import { createRtdb } from "./rtdb.mjs";
import { TARGETS } from "./targets.mjs";
import {
  STAGE2_LIMITS,
  bindOps,
  createFormsCollector,
  createLogReader,
  preflightStage2,
} from "./wiring.mjs";

export function assembleStage2({
  control,
  runCli,
  adminFetch,
  anonymousFetch,
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
  programId = "cv14",
}) {
  const uploads = openSourceUploads({
    ledgerPath: join(runDir, "owned-uploads.jsonl"),
    runId: basename(runDir),
    projectNumber,
    region: LOCATION,
    send: storageSend(control),
    requestsLeft: () => STAGE2_LIMITS.upload - budget.snapshot().upload,
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
  const rtdb = createRtdb({
    fetchImpl: anonymousFetch,
    adminFetch,
    packet,
    log,
    secrets,
    stop,
    sleep: clock.sleep,
    now: clock.now,
  });
  const grants = { before: null, after: null, changes: [] };
  const deps = {
    targets: TARGETS,
    ops,
    // only a 2nd gen record names an Eventarc trigger and topic
    ownedNames: (record, spec) =>
      spec.generation === "gcfv2" ? ownedEventarcNames(record, spec) : null,
    preflight: async () => {
      grants.before = await preflightStage2({ control, projectNumber });
    },
    inventory: {
      take: () => takeInventory(control, "inventory"),
      removeLeftovers: (before, owned) =>
        removeLeftovers(control, before, owned, { sleep: clock.sleep }),
    },
    rtdb,
    logs: createLogReader({ control, now: () => new Date(clock.now()).toISOString() }),
    uploads,
    log,
    abort,
    clock,
    windows: STAGE2_WINDOWS,
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
      return grants;
    },
  };
}
