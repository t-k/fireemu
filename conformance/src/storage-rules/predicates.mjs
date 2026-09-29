// Closed vocabulary of the free-text conditions a declared row carries. Each token names a category, the ledger or input
// facts it reads and what a failure means. This module only names and validates the vocabulary; the resource ledger,
// the acceptance kinds and the admission step decide each condition.
const entry = (category, needs, onFalse = "stop") => Object.freeze({ category, needs: Object.freeze([...needs]), onFalse });

export const PREDICATE_CATEGORIES = Object.freeze(["guard", "proof", "input", "check", "budget", "policy"]);
export const PREDICATE_FACTS = Object.freeze([
  "run.state", "credential.fresh", "credential.session-state", "credential.cache-proof",
  "input.provenance", "input.bucket-policy-baseline", "input.project-policy-baseline", "input.ruleset-baseline",
  "input.identity-match", "input.project-match", "input.bucket-match", "input.database-match", "input.key-match",
  "response.permissions", "response.page-complete", "response.release-state", "response.source-digest",
  "resource.absent", "resource.started", "resource.provenance", "resource.all-cleaned", "namespace.owned",
  "object.write-history", "object.generation", "document.write-history", "document.update-time",
  "witness.four-confirmed", "witness.retained", "control.final-readbacks",
  "session.active", "session.start-url-durable", "session.all-terminal", "session.terminal-shape",
  "mutation.delete", "mutation.cancel",
  "account.owned", "ruleset.created-ack", "ruleset.owned", "ruleset.source-readback", "ruleset.unreferenced",
  "source.compiled", "entry.baseline",
  "release.absent", "release.previous", "release.owned-current", "settle.effective", "restore.cycles",
  "page.count", "page.token", "cycle.count",
  "object.present-per-readback", "document.present-per-readback", "session.active-per-query",
]);

export const REQUIRES_REGISTRY = Object.freeze({
  "acknowledged-ruleset-create": entry("proof", ["ruleset.created-ack"]),
  "all-explicit-bucket-permissions-present": entry("check", ["response.permissions"]),
  "all-explicit-permissions-present-does-not-authorize-send": entry("check", ["response.permissions"]),
  "all-final-control-readbacks-complete": entry("guard", ["control.final-readbacks"]),
  "all-four-controls-confirmed-and-retained": entry("guard", ["witness.four-confirmed", "witness.retained"]),
  "all-owned-resources-and-sessions-cleaned": entry("guard", ["resource.all-cleaned", "session.all-terminal"]),
  "approved-bucket-policy-baseline-match": entry("input", ["input.bucket-policy-baseline"]),
  "approved-cross-service-grant-and-policy-baseline-match": entry("input", ["input.project-policy-baseline"]),
  "approved-private-input-provenance": entry("input", ["input.provenance"]),
  "approved-ruleset-count-and-cleanup-baseline": entry("input", ["input.ruleset-baseline"]),
  "at-most-ten-pages-or-stop": entry("budget", ["page.count"]),
  "both-releases-absent": entry("guard", ["release.absent"]),
  "bucket-name-project-number-and-baseline-match": entry("input", ["input.bucket-match"]),
  "bucket-release-absent": entry("check", ["release.absent"]),
  "bucketless-release-absent": entry("check", ["release.absent"]),
  "cancel-not-attempted": entry("guard", ["mutation.cancel"]),
  "canonical-program-state-and-fresh-credential": entry("guard", ["run.state", "credential.fresh"]),
  "compiled-source-and-entry-baseline": entry("guard", ["source.compiled", "entry.baseline"]),
  "confirmed-active-session": entry("guard", ["session.active"]),
  "confirmed-document-write-history-and-current-version": entry("guard", ["document.write-history", "document.update-time"]),
  "confirmed-owned-account": entry("guard", ["account.owned"]),
  "confirmed-write-history-and-current-version": entry("guard", ["object.write-history", "object.generation"]),
  "credential-session-exact-state-and-project": entry("guard", ["credential.session-state"]),
  "default-database-project-and-baseline-match": entry("input", ["input.database-match"]),
  "delete-not-attempted": entry("guard", ["mutation.delete"]),
  "durable-verified-start-url-and-target": entry("proof", ["session.start-url-durable"]),
  "empty-items-and-no-next-page-token": entry("check", ["response.page-complete"]),
  "entry-baseline-unchanged": entry("guard", ["entry.baseline"]),
  "entry-page-has-no-next-token": entry("check", ["response.page-complete"]),
  "exact-owned-current-release-and-absent-entry-baseline": entry("guard", ["release.owned-current", "entry.baseline"]),
  "exact-previous-release-or-entry-absence": entry("check", ["release.previous"]),
  "exact-release-source-and-effective-settle": entry("guard", ["release.owned-current", "settle.effective"]),
  "explicit-counted-refresh-and-durable-cache-proof": entry("proof", ["credential.cache-proof"]),
  "finite-distinct-cycle-and-fresh-user-token": entry("budget", ["cycle.count", "credential.fresh"]),
  "key-name-uid-not-deleted-and-approved-restrictions-match": entry("input", ["input.key-match"]),
  "literal-source-digest-match": entry("check", ["response.source-digest"]),
  "owned-control-confirmed-present": entry("guard", ["witness.retained"]),
  "owned-namespace-and-absence": entry("guard", ["resource.absent", "namespace.owned"]),
  "owned-control-retained-through-final-readback": entry("guard", ["witness.retained"]),
  "owned-control-still-present-and-version-matches": entry("guard", ["witness.retained", "object.generation"]),
  "owned-ruleset-and-source-readback": entry("guard", ["ruleset.owned", "ruleset.source-readback"]),
  "owned-ruleset-and-unreferenced-after-restore": entry("guard", ["ruleset.owned", "ruleset.unreferenced"]),
  "previous-page-token-verified": entry("guard", ["page.token"]),
  "private-key-string-matches-key-metadata-and-cached-secret": entry("input", ["input.key-match"]),
  "project-id-number-active-match": entry("input", ["input.project-match"]),
  "release-name-and-created-ruleset-match": entry("check", ["response.release-state"]),
  "resource-started-and-provenance-matches": entry("guard", ["resource.started", "resource.provenance"], "skip"),
  "restore-controls-retained-until-owner-readbacks": entry("guard", ["witness.retained"]),
  "restore-without-unowned-release-change": entry("guard", ["release.owned-current"]),
  "two-complete-all-denied-restore-cycles": entry("guard", ["restore.cycles"]),
  "unknown-terminal-shape-remains-needs-recovery": entry("policy", ["session.terminal-shape"]),
  "verified-email-and-subject-match-packet-owner": entry("input", ["input.identity-match"]),
  // Conditional cleanup that used to be implicit: the write is skipped, at no request cost, when the latest readback
  // already shows nothing to remove (or, for a session, nothing active to cancel).
  "object-not-absent-per-latest-readback": entry("guard", ["object.present-per-readback"], "skip"),
  "document-not-absent-per-latest-readback": entry("guard", ["document.present-per-readback"], "skip"),
  "session-active-per-latest-query": entry("guard", ["session.active-per-query"], "skip"),
});

export const REQUIRED_STATES = Object.freeze(["absent", "present-allowed-true", "object-state-readback", "object-byte-readback", "present-allowed-false", "owned-or-absent", "present"]);
export const WHEN_CONDITIONS = Object.freeze(["owned-generation-matches-receipt", "owned-update-time-matches-run-write"]);

/** Refuse a manifest whose rows use a token, required state or condition outside the closed vocabulary. */
export function assertManifestPredicates(manifest) {
  const fail = () => { throw new Error("invalid manifest predicate"); };
  if (!manifest || !Array.isArray(manifest.rows)) fail();
  for (const row of manifest.rows) {
    if (!row || !Array.isArray(row.requires) || new Set(row.requires).size !== row.requires.length) fail();
    for (const token of row.requires) if (typeof token !== "string" || !Object.hasOwn(REQUIRES_REGISTRY, token)) fail();
    // A row without a state or condition may carry an explicit null; nothing else outside the closed sets is allowed.
    if (Object.hasOwn(row, "requiredState") && row.requiredState !== null && !REQUIRED_STATES.includes(row.requiredState)) fail();
    if (Object.hasOwn(row, "when") && row.when !== null && !WHEN_CONDITIONS.includes(row.when)) fail();
  }
}
