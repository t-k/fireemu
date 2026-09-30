// The Security Rules the AUTH-FS-CROSS corpus runs under. Kept apart from FS-RULES' rulesets,
// whose text every FS-RULES program digest covers: a change here must not make FS-RULES rows
// stale, and a change there must not make these rows stale.

import { createHash } from "node:crypto";

const digest = (text) => createHash("sha256").update(text).digest("hex").slice(0, 12);

const BODY = [
  // A document of one principal in one namespace: the uid alone does not tell the same uid in
  // two tenants (or a tenant and the project) apart, the tenant claim does.
  "    match /afc-same/{doc} {",
  "      allow read: if request.auth != null",
  "        && request.auth.uid == resource.data.owner",
  "        && request.auth.token.firebase.get('tenant', null) == resource.data.tenant;",
  "    }",
  // Owner-only documents for the read-only transaction and the foreign-project token.
  "    match /afc-owned/{doc} {",
  "      allow read: if request.auth != null && request.auth.uid == resource.data.owner;",
  "    }",
  "    match /afc-open/{doc} {",
  "      allow read: if true;",
  "    }",
  "    match /afc-signed-in/{doc} {",
  "      allow read: if request.auth != null;",
  "    }",
  "    match /afc-created/{doc} {",
  "      allow create: if request.auth != null && request.auth.uid == request.resource.data.owner;",
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

export const RULESET_IDS = ["cross"];
