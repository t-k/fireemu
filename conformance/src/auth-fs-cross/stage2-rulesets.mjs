// The Security Rules AUTH-FS-CROSS stage 2 runs under. Kept apart from stage 1's rulesets, whose
// text every stage-1 program digest covers: a change here must not make stage-1 rows stale.

import { createHash } from "node:crypto";

const digest = (text) => createHash("sha256").update(text).digest("hex").slice(0, 12);

const BODY = [
  // One principal's document: listened to by that principal, written only by the harness.
  "    match /afc2-owned/{doc} {",
  "      allow read: if request.auth != null && request.auth.uid == resource.data.owner;",
  "    }",
  // Readable while the caller's token carries the custom claim `c`.
  "    match /afc2-claim/{doc} {",
  "      allow read: if request.auth != null && request.auth.token.get('c', false) == true;",
  "    }",
  // One tenant principal's document: the uid and the tenant claim must both match.
  "    match /afc2-tenant/{doc} {",
  "      allow read: if request.auth != null",
  "        && request.auth.uid == resource.data.owner",
  "        && request.auth.token.firebase.get('tenant', null) == resource.data.tenant;",
  "    }",
  // Any signed-in principal: the documents a switched-to principal may still read, and the
  // witness's view of the same commits.
  "    match /afc2-open/{doc} {",
  "      allow read: if request.auth != null;",
  "    }",
  // A write left pending by one principal: created only by the uid it names.
  "    match /afc2-pending/{doc} {",
  "      allow read: if request.auth != null;",
  "      allow create: if request.auth != null && request.auth.uid == request.resource.data.owner;",
  "    }",
  // A transaction's target: the committing principal must be the one the write names, so the
  // outcome shows whose token the commit carried.
  "    match /afc2-tx/{doc} {",
  "      allow read: if request.auth != null;",
  "      allow write: if request.auth != null && request.auth.uid == request.resource.data.by;",
  "    }",
];

function compose(rulesetId, label) {
  return [
    "rules_version = '2';",
    "service cloud.firestore {",
    "  match /databases/{database}/documents {",
    "    match /fsr-marker/{label} {",
    `      allow get: if label == '${label}';`,
    "    }",
    "",
    ...BODY,
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
  if (!RULESET_IDS.includes(rulesetId)) throw new Error(`unknown ruleset ${rulesetId}`);
  return compose(rulesetId, markerOf(rulesetId));
}

export const RULESET_IDS = ["cross2"];
