// Who answers each condition a manifest row carries, so no token is left to chance. `object-ledger` and `run-ledger`
// answer it before the request from recorded state; `post-check` answers it from the response of the row itself;
// `admission` is settled once before the run from the approved private inputs; `delegate` is settled by the credential
// module; `refs` by the reference store; `schedule` and `settle` by construction; `policy` by the acceptance schema.
const table = {
  "object-ledger": ["owned-namespace-and-absence", "confirmed-write-history-and-current-version", "object-not-absent-per-latest-readback"],
  // Answered by the object ledger for objects and by the run ledger for every other resource kind.
  shared: ["delete-not-attempted", "resource-started-and-provenance-matches"],
  "run-ledger": [
    "acknowledged-ruleset-create", "all-final-control-readbacks-complete", "all-four-controls-confirmed-and-retained", "all-owned-resources-and-sessions-cleaned",
    "both-releases-absent", "cancel-not-attempted", "canonical-program-state-and-fresh-credential", "compiled-source-and-entry-baseline", "confirmed-active-session",
    "confirmed-document-write-history-and-current-version", "durable-verified-start-url-and-target", "entry-baseline-unchanged", "exact-owned-current-release-and-absent-entry-baseline",
    "exact-release-source-and-effective-settle", "owned-control-confirmed-present", "owned-control-retained-through-final-readback", "owned-control-still-present-and-version-matches",
    "owned-ruleset-and-source-readback", "owned-ruleset-and-unreferenced-after-restore", "restore-controls-retained-until-owner-readbacks", "restore-without-unowned-release-change",
    "two-complete-all-denied-restore-cycles", "document-not-absent-per-latest-readback", "session-active-per-latest-query",
  ],
  // Answered by the run ledger before a write that depends on it and again as a check on the read that produced the state.
  both: ["exact-previous-release-or-entry-absence"],
  "post-check": [
    "all-explicit-bucket-permissions-present", "all-explicit-permissions-present-does-not-authorize-send", "bucket-release-absent", "bucketless-release-absent",
    "approved-ruleset-count-and-cleanup-baseline", "empty-items-and-no-next-page-token", "entry-page-has-no-next-token", "release-name-and-created-ruleset-match", "literal-source-digest-match",
  ],
  admission: [
    "approved-bucket-policy-baseline-match", "approved-cross-service-grant-and-policy-baseline-match", "approved-private-input-provenance",
    "bucket-name-project-number-and-baseline-match", "default-database-project-and-baseline-match", "key-name-uid-not-deleted-and-approved-restrictions-match",
    "private-key-string-matches-key-metadata-and-cached-secret", "project-id-number-active-match", "verified-email-and-subject-match-packet-owner",
  ],
  delegate: ["confirmed-owned-account", "credential-session-exact-state-and-project", "explicit-counted-refresh-and-durable-cache-proof"],
  refs: ["previous-page-token-verified"],
  structure: ["at-most-ten-pages-or-stop", "finite-distinct-cycle-and-fresh-user-token"],
  policy: ["unknown-terminal-shape-remains-needs-recovery"],
};
export const ENFORCEMENT = Object.freeze(Object.fromEntries(Object.entries(table).map(([enforcer, tokens]) => [enforcer, Object.freeze([...tokens])])));
export const enforcerOf = (token) => Object.keys(ENFORCEMENT).find((enforcer) => ENFORCEMENT[enforcer].includes(token));
