// The rulesets an FS-RULES recording publishes. `main` is the concatenation of every area's rules
// fragment; `alt` is the same with the publication area's variant flipped; `named` governs the
// run's named database. Each carries a marker rule, `fsr-marker/<label>`, whose label names the
// ruleset and its source digest: an unauthenticated get of the marker is allowed (a 404 for a
// missing document) exactly while that ruleset is in force.

import { createHash } from "node:crypto";

import { FRAGMENTS } from "./programs/index.mjs";

const digest = (text) => createHash("sha256").update(text).digest("hex").slice(0, 12);

function body(rulesetId) {
  if (rulesetId === "named") {
    return ["    match /fsr-named-only/{d} {", "      allow get: if true;", "    }"].join("\n");
  }
  if (rulesetId !== "main" && rulesetId !== "alt") throw new Error(`unknown ruleset ${rulesetId}`);
  return FRAGMENTS.map((fragment) =>
    typeof fragment === "function" ? fragment(rulesetId) : fragment,
  )
    .map((text) => text.trimEnd())
    .join("\n\n");
}

function compose(rulesetId, label) {
  return [
    "rules_version = '2';",
    "service cloud.firestore {",
    "  match /databases/{database}/documents {",
    "    match /fsr-marker/{label} {",
    `      allow get: if label == '${label}';`,
    "    }",
    "",
    body(rulesetId),
    "  }",
    "}",
    "",
  ].join("\n");
}

/** The marker label of a ruleset: its id and the digest of its unlabelled source. */
export function markerOf(rulesetId) {
  return `${rulesetId}-${digest(compose(rulesetId, "LABEL"))}`;
}

/** The source of a ruleset as published. */
export function rulesetSource(rulesetId) {
  return compose(rulesetId, markerOf(rulesetId));
}

export const RULESET_IDS = ["main", "alt", "named"];
