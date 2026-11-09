export const BREADTH_LIMITS = Object.freeze({
  cliDeploy: 3,
  upload: 45,
  token: 12,
  control: 38,
  cleanup: 89,
  logs: 40,
  inventory: 100,
  userClient: 6,
  browserHttp: 40,
  browserWs: 4,
});

import { createBudget } from "../../functions-http/harness.mjs";
import { CODEBASE, TARGETS } from "./breadth-targets.mjs";
import { INVENTORY_HOSTS } from "./inventory.mjs";
import { LOGGING_HOST, listRequest, parseEntries } from "./breadth-logs.mjs";
export { bearerFetch, bindOps, createFormsCollector, preflightStage2 } from "./wiring.mjs";
export const BREADTH_HOSTS = Object.freeze([LOGGING_HOST, ...INVENTORY_HOSTS]);
export const NORMAL_CEILING = 130;
export const CLEANUP_CEILING = 212;
export const createBreadthBudget = ({
  limits = BREADTH_LIMITS,
  ceilings = { normal: NORMAL_CEILING, cleanup: CLEANUP_CEILING },
} = {}) => {
  const { userClient, browserHttp, browserWs, ...caps } = limits;
  const budget = createBudget(caps, {
    logs: caps.logs,
    inventory: caps.inventory,
    userClient,
    browserHttp,
    browserWs,
    rtdbAdmin: 200,
    breadthAuth: 200,
  });
  let total = 0;
  let cleanup = false;
  let exhausted = false;
  let cleanupExhausted = false;
  return {
    take(kind) {
      const limit = cleanup ? ceilings.cleanup : ceilings.normal;
      if (total >= limit) {
        exhausted = true;
        if (cleanup) cleanupExhausted = true;
        throw new Error(`total request ceiling ${limit} reached`);
      }
      const count = budget.take(kind);
      total++;
      return count;
    },
    startCleanup() {
      cleanup = true;
    },
    get exhausted() {
      return exhausted;
    },
    get cleanupExhausted() {
      return cleanupExhausted;
    },
    snapshot: () => ({ ...budget.snapshot(), total }),
  };
};

export function breadthCli(
  run,
  { targets = TARGETS, codebase = CODEBASE, config = "firebase-breadth.json" } = {},
) {
  return async (args, ...rest) => {
    const only = args.indexOf("--only");
    if (
      args[0] !== "deploy" ||
      only < 0 ||
      !targets.some(
        (target) => args[only + 1] === `functions:${codebase}:${target.functionName}`,
      ) ||
      args.filter((arg) => arg === "--only").length !== 1 ||
      args.includes("--config")
    ) {
      throw new Error("invalid breadth deploy");
    }
    return run([...args, "--config", config, "--force"], ...rest);
  };
}

const LOG_PAGES = 3;

/** Reads the frames of a window, page by page (at most three), each insert id once across reads. */
export function createLogReader({ control, now, handlers }) {
  const seen = new Set();
  return {
    async read({ start, end }) {
      const total = { frames: [], entries: 0, ignored: {}, complete: true };
      let pageToken;
      try {
        for (let page = 0; page < LOG_PAGES; page += 1) {
          const request = listRequest({ start, end, pageToken }, handlers);
          const reply = await control(request.method, request.url, request.body, "logs");
          const parsed = parseEntries(reply.value, { readAt: now(), seen, handlers });
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
        // the frames of the pages read so far are already marked seen: they are returned, not lost
        return { ...total, complete: false };
      }
      return total;
    },
  };
}
