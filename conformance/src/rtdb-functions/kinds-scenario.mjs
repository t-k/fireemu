// The kinds recording as a scenario of the breadth recorder: which targets, steps, rules, limits and
// judgement it plugs into the shared flow, assembly and entry. Nothing here sends anything.

import { fileURLToPath } from "node:url";
import { CODEBASE, FIXTURE_HANDLERS, PREFIX } from "./kinds-frames.mjs";
import { judgeRun } from "./kinds-judge.mjs";
import { buildSteps, observe } from "./kinds-sequence.mjs";
import { TARGETS } from "./kinds-targets.mjs";

/**
 * Request categories for eight functions, scaled from the three-function breadth figures: per function a
 * deploy, 15 uploads, 6 control requests and 16 cleanup requests; the rest is the breadth fixed part, with
 * more log reads (the run is longer), more browser requests (long polling is one request per poll) and
 * the same user client.
 */
export const KINDS_LIMITS = Object.freeze({
  cliDeploy: 8,
  upload: 120,
  token: 12,
  control: 68,
  cleanup: 168,
  logs: 60,
  inventory: 100,
  userClient: 6,
  browserHttp: 80,
  browserWs: 4,
});
/** Total request ceilings: before the cleanup phase, and including it. */
export const KINDS_CEILINGS = Object.freeze({ normal: 250, cleanup: 380 });
/**
 * Windows of the flow. The tail is 210 s: the last write registers an onDisconnect on a long-polling
 * connection and goes offline, and production runs it after about 100 s to 105 s (the recorded idle
 * drop of RTDB/longPollingIdleClose), then the log lags.
 */
export const KINDS_WINDOWS = Object.freeze({
  propagationMs: 300000,
  writeMs: 6000,
  pollMs: 15000,
  quietMs: 30000,
  tailMs: 210000,
});

/** The user claims the run sets on its own user (names start with the fixture's `k9` allow-list prefix). */
export const KINDS_CLAIMS = Object.freeze({ k9role: "claims", k9n: 3 });

/**
 * Rules for the run: only the claims group (REST user writes) and the SDK group (long-polling user
 * writes) are writable, by a signed-in user, on a leaf that carries the run's nonce.
 */
export function rulesFor(prefix, nonce) {
  if (!/^[A-Za-z0-9_-]+$/.test(nonce)) throw new Error("invalid nonce");
  const validate = `newData.child('run').val() === '${nonce}'`;
  const guarded = { items: { $id: { ".write": "auth != null", ".validate": validate } } };
  return {
    rules: {
      ".read": false,
      ".write": false,
      [prefix]: { gc: guarded, gs: guarded },
    },
  };
}

/**
 * Complete when every deployed handler has delivered every transition it is expected for on a step that is
 * not observation-only. Observation-only steps are never waited for: their absence is an answer.
 */
export function complete({ report, deployed, result }) {
  const names = new Set(deployed.map((target) => target.functionName));
  const seenAll = (entries) =>
    entries.every((entry) =>
      Object.entries(entry.handlers).every(
        ([name, seen]) => !names.has(name) || seen.expected === 0 || seen.frames > 0,
      ),
    );
  return (
    !result.logs.incomplete &&
    report.steps.every(
      (step) => step.observeOnly || (seenAll(step.leaves ?? []) && seenAll(step.groups ?? [])),
    )
  );
}

/**
 * The reviewed sources the deploy uploads and the run reads (relative to this directory). The recorder
 * refuses to start when one of them differs; kinds-record.test.mjs checks these against the files.
 */
export const KINDS_PINS = Object.freeze({
  "firebase-kinds.json": "f250225c7fa799b1c041e925b910b7fa05bfb613ea21931eea9464e720fc2ef8",
  "fixtures-kinds/index.js": "a123b78fd592a920bedb74e4c8052ea3d4f0b64e88c594db8ea5af187146b09d",
  "fixtures-kinds/frames.js": "d7774ca01875c6805b9cc132ab158c460b8597fdbfe1d54390ccbb4d29d32bbf",
  "fixtures-kinds/package.json": "7da22ccd9851e3119b81462c2c1e071fc0d72f0196415c52acd69e1b12ebdd1e",
  "fixtures-kinds/package-lock.json":
    "c492afe0fa1e5336d78be6f1fa76e594d357e0412cacfd9d963d2569389b7dea",
});

export const KINDS_SCENARIO = Object.freeze({
  id: "kinds",
  codebase: CODEBASE,
  config: "firebase-kinds.json",
  fixtureDir: "fixtures-kinds",
  pins: KINDS_PINS,
  runDirPrefix: "kinds",
  prefix: PREFIX,
  handlers: FIXTURE_HANDLERS,
  targets: TARGETS,
  limits: KINDS_LIMITS,
  ceilings: KINDS_CEILINGS,
  windows: KINDS_WINDOWS,
  buildSteps,
  observe,
  judge: judgeRun,
  complete,
  rulesFor,
  claims: KINDS_CLAIMS,
  sdk: Object.freeze({
    pageFile: fileURLToPath(new URL("./kinds-sdk-page.js", import.meta.url)),
    ids: Object.freeze(["k18", "k19", "k20", "k21"]),
  }),
});
