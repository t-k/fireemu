// Resource names of a production recording. Every resource the recorder creates carries the run's
// prefix, so that it can be found and removed by prefix, and so that nothing outside the prefix can
// be changed. The few names that are refused on purpose (too short, a digit first, `goog...`) cannot
// carry the prefix; they are registered as probes before they are sent, so that one that is accepted
// by mistake is still known and removed.

import { randomBytes } from "node:crypto";

const RUN_ID = /^[0-9a-f]{12}$/;
const KINDS = ["topics", "subscriptions", "snapshots"];

export function newRunId(random = randomBytes) {
  return random(6).toString("hex");
}

export function isRunId(value) {
  return typeof value === "string" && RUN_ID.test(value);
}

/** The prefix of the run: a letter first (resource ids start with one), then the run ID. */
export function prefixOf(runId) {
  if (!isRunId(runId)) throw new Error("the run ID must be 12 hex digits");
  return `fe${runId}-`;
}

const escaped = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The names a run may change: `projects/<project>/<kind>/<prefix>...` for topics, subscriptions and
 * snapshots, and the probe names registered before they are sent.
 */
export function createOwnership({ project, runId }) {
  if (typeof project !== "string" || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project))
    throw new Error("the project is not a project ID");
  const prefix = prefixOf(runId);
  const pattern = new RegExp(
    `^projects/${escaped(project)}/(${KINDS.join("|")})/${escaped(prefix)}[A-Za-z0-9._~+%-]*$`,
  );
  const probes = new Set();
  const probePattern = new RegExp(`^projects/${escaped(project)}/(${KINDS.join("|")})/[^/]+$`);
  const isOwned = (name) => typeof name === "string" && (pattern.test(name) || probes.has(name));
  return Object.freeze({
    project,
    runId,
    prefix,
    resource: (kind, key) => {
      if (!KINDS.includes(kind)) throw new Error(`unknown resource kind ${kind}`);
      const id = `${prefix}${key}`;
      if (id.length > 255) throw new Error("a resource ID is at most 255 characters");
      return `projects/${project}/${kind}/${id}`;
    },
    /** Names the recorder sends on purpose although they cannot carry the prefix. */
    registerProbe: (name) => {
      if (typeof name !== "string" || !probePattern.test(name))
        throw new Error("a probe must name one topic, subscription or snapshot of the project");
      probes.add(name);
      return name;
    },
    probes: () => [...probes],
    isOwned,
    assertOwned: (name) => {
      if (!isOwned(name))
        throw new Error(`refusing to change ${String(name)}: it is not a resource of this run`);
      return name;
    },
    prefixPattern: pattern,
  });
}
