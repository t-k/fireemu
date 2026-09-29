// The reviewed execution order of one recording. The manifest lists rows as an inventory grouped by family; this module
// fixes the order in which they may run and proves that every non-recovery row is covered once. Settle waits, the final
// Ruleset list pages and the credential work of other modules are steps of their own. It sends nothing.
const bad = () => { throw new Error("invalid schedule manifest"); };
const PREFLIGHT_ORDER = [
  "preflight/auth/owner-token", "preflight/auth/signing-keys", "preflight/owner/identity",
  "preflight/query/project", "preflight/query/key-metadata", "preflight/query/key-string", "preflight/query/permissions",
  "preflight/idp/project", "preflight/idp/key-metadata", "preflight/idp/key-string", "preflight/idp/permissions",
  "preflight/bucket/metadata", "preflight/bucket/iam", "preflight/bucket/permissions",
  "preflight/query/database", "preflight/query/iam",
  "preflight/rulesets-list/entry/1", "preflight/release/entry/bucket", "preflight/release/entry/bucketless",
];
const WITNESS_CONTROLS = [0, 1, 3, 4];
const SEED_STAGES = ["baseline-metadata", "baseline-media", "seed", "seed-metadata", "seed-media"];
const CLEANUP_AUTH_STEPS = new Set(["delete", "absence"]);

export function buildSchedule(manifest) {
  try { return build(manifest); } catch { return bad(); }
}

function build(manifest) {
  if (!manifest || manifest.sendAuthorized !== false || !Array.isArray(manifest.rows) || !Array.isArray(manifest.preflightIds) || !manifest.publication || !manifest.restoration) bad();
  if (JSON.stringify([...manifest.preflightIds].sort()) !== JSON.stringify([...PREFLIGHT_ORDER].sort())) bad();
  // The manifest states how many rows it declares; a manifest that lost rows cannot be scheduled by what is left.
  const recoveryCount = manifest.rows.filter((r) => r.phase === "recovery").length;
  if (manifest.counts?.total !== manifest.rows.length || manifest.counts?.recovery !== recoveryCount || manifest.counts?.normal !== manifest.rows.length - recoveryCount) bad();
  const byId = new Map(manifest.rows.map((row) => [row.id, row]));
  const rowsOf = (predicate) => manifest.rows.filter(predicate);
  const need = (id) => { if (!byId.has(id)) bad(); return id; };
  const steps = [];
  const row = (id) => steps.push({ type: "row", id: need(id) });
  const rows = (ids) => ids.forEach(row);
  const delegate = (op, rowIds) => steps.push({ type: "delegate", op, rowIds: rowIds.map(need) });

  const authRows = rowsOf((r) => r.family === "auth" && r.phase === "normal");
  const foreign = authRows.filter((r) => r.programId === "foreign-project-token");
  const foreignSignup = foreign.filter((r) => !CLEANUP_AUTH_STEPS.has(r.stage)).map((r) => r.id);
  const foreignCleanup = foreign.filter((r) => CLEANUP_AUTH_STEPS.has(r.stage)).map((r) => r.id);
  const prepare = authRows.filter((r) => r.programId !== "foreign-project-token" && !CLEANUP_AUTH_STEPS.has(r.stage)).map((r) => r.id);
  const cleanup = authRows.filter((r) => r.programId !== "foreign-project-token" && CLEANUP_AUTH_STEPS.has(r.stage)).map((r) => r.id);

  delegate("credential-cache", rowsOf((r) => r.family === "credential-cache" && r.phase === "normal").map((r) => r.id));
  // The four witnesses are seeded and read back first, then the two other controls.
  for (const index of [...WITNESS_CONTROLS, 2, 5]) rows(SEED_STAGES.map((stage) => `management/control-${index}/${stage}`));
  delegate("prepare-query", prepare);
  rows(["management/no-release/entry/subject", "management/no-release/entry/after-metadata", "management/no-release/entry/after-media", "release/no-release-entry-after/bucket", "release/no-release-entry-after/bucketless"]);
  const tests = rowsOf((r) => r.family === "compile" && r.stage === "test").map((r) => r.id);
  rows(["compile/release/before", ...tests, "compile/release/after-invalid"]);
  for (const name of ["v1", "v2", "A", "B"]) rows([`ruleset/${name}/create`, `ruleset/${name}/read-source`]);

  const settleBlock = (name, kind, phase, witnesses) => {
    const settleRows = rowsOf((r) => r.family === "settle" && r.phase === phase && r.programId === name);
    steps.push({
      type: "settle", name, rowIds: settleRows.map((r) => r.id), intervalMs: manifest.restoration.intervalMs,
      config: { kind, name, phase, maxCycles: kind === "publication" ? 30 : manifest.restoration.maxCycles, requiredConsecutive: kind === "publication" ? 2 : manifest.restoration.consecutiveCompleteCycles, witnesses },
    });
  };
  const publicationWitnesses = (name) => {
    const first = byId.get(`settle/${name}/1/0`);
    const second = byId.get(`settle/${name}/1/1`);
    if (!first || !second) bad();
    return [{ objectName: first.request.objectName, expect: "allowed" }, { objectName: second.request.objectName, expect: "denied" }];
  };
  const publish = (name) => { rows([`release/${name}/before`, `release/${name}/publish`, `release/${name}/after`]); settleBlock(name, "publication", "normal", publicationWitnesses(name)); };
  const runCases = (ids) => {
    for (const id of ids) {
      for (const declared of rowsOf((r) => r.family === "declared" && r.programId === id)) {
        if (declared.request.credential === "foreign-project-token") {
          delegate("foreign-signup", foreignSignup);
          row(declared.id);
          delegate("foreign-cleanup", foreignCleanup);
        } else row(declared.id);
        // The cancel's answer alone proves nothing, so the session is asked once more right after it.
        if (declared.request.headers?.["x-goog-upload-command"] === "cancel") row(`session-verify/${id}`);
      }
    }
  };
  publish("v1"); runCases(manifest.publication.v1);
  publish("v2"); runCases(manifest.publication.v2);
  for (const name of ["A", "B"]) {
    publish(name);
    for (const index of [3, 4]) rows(["before-metadata", "before-media", "subject", "after-metadata", "after-media"].map((stage) => `management/${name}/control-${index}/${stage}`));
  }

  rows(["release/restore/owner-before-delete", "release/restore/delete", "release/restore/bucket-absence", "release/restore/bucketless-absence"]);
  const witnesses = rowsOf((r) => r.family === "settle" && r.phase === "normal" && r.programId === "restore" && r.id.startsWith("settle/restore/1/")).map((r) => ({ objectName: r.request.objectName, expect: "denied" }));
  settleBlock("restore", "restoration", "normal", witnesses);
  rows([0, 1, 2, 3].map((index) => `management/restore-owner-media/${index}`));
  rows(["management/no-release/final/before-metadata", "management/no-release/final/before-media", "management/no-release/final/subject", "management/no-release/final/after-metadata", "management/no-release/final/after-media", "release/final/bucket", "release/final/bucketless"]);

  const controls = [0, 1, 2, 3, 4, 5];
  rows(controls.map((index) => `management/control-${index}/cleanup-metadata`));
  rows(controls.map((index) => `management/control-${index}/delete`));
  for (const index of controls) rows([`management/control-${index}/absence-metadata`, `management/control-${index}/absence-media`]);
  for (const name of ["v1", "v2", "A", "B"]) rows([`ruleset/${name}/delete`, `ruleset/${name}/absence`]);
  steps.push({ type: "pages", rowIds: Array.from({ length: 10 }, (_, index) => need(`rulesets-list/final/${index + 1}`)), stopWhen: "no-next-page-token" });
  row("management/prefix-empty");
  delegate("cleanup-query", cleanup);

  // Every non-recovery row must be covered exactly once.
  const covered = new Set(PREFLIGHT_ORDER);
  if (covered.size !== PREFLIGHT_ORDER.length) bad();
  for (const step of steps) for (const id of step.type === "row" ? [step.id] : step.rowIds) { if (covered.has(id)) bad(); covered.add(id); }
  const expected = manifest.rows.filter((r) => r.phase !== "recovery").map((r) => r.id);
  if (covered.size !== expected.length || expected.some((id) => !covered.has(id))) bad();
  return Object.freeze({ preflight: Object.freeze([...PREFLIGHT_ORDER]), steps: Object.freeze(steps.map((step) => Object.freeze(step))) });
}

export function buildRecoverySchedule(manifest) {
  try { return buildRecovery(manifest); } catch { return bad(); }
}

// The reviewed recovery order (design review section B): each step is enabled at run time only by ledger facts, and a
// resource keeps its own steps together. Auth accounts and their shared token are one delegated group.
function buildRecovery(manifest) {
  if (!manifest || manifest.sendAuthorized !== false || !Array.isArray(manifest.rows) || !manifest.restoration) bad();
  const recovery = manifest.rows.filter((r) => r.phase === "recovery");
  if (manifest.counts?.recovery !== recovery.length) bad();
  const byId = new Map(recovery.map((row) => [row.id, row]));
  const steps = [];
  const row = (id, enabledBy) => { if (!byId.has(id)) bad(); steps.push(enabledBy === undefined ? { type: "row", id } : { type: "row", id, enabledBy }); };
  const family = (name) => recovery.filter((r) => r.family === name);
  // Rows of one resource in the manifest's order, grouped by the resource segment of the ID (recovery/<kind>/<resource>/<stage>).
  const grouped = (name, stages, resourceOf, enabledByOf) => {
    const groups = new Map();
    for (const r of family(name)) {
      const key = resourceOf(r);
      if (!groups.has(key)) groups.set(key, new Map());
      if (groups.get(key).has(r.stage)) bad();
      groups.get(key).set(r.stage, r.id);
    }
    for (const [key, stageMap] of groups) {
      if (stageMap.size !== stages.length || !stages.every((stage) => stageMap.has(stage))) bad();
      stages.forEach((stage) => row(stageMap.get(stage), enabledByOf?.(key, stage)));
    }
  };
  const segment = (index) => (r) => r.id.split("/")[index];

  // The release goes only when a release write was attempted; its readback and delete only while it is not deleted yet.
  ["owner-before-delete", "delete"].forEach((stage) => row(`recovery/release/restore/${stage}`, "release-written-not-deleted"));
  ["bucket-absence", "bucketless-absence"].forEach((stage) => row(`recovery/release/restore/${stage}`, "release-written"));
  const settleRows = family("settle").filter((r) => r.programId === "restore");
  const witnesses = settleRows.filter((r) => r.id.startsWith("recovery/settle/restore/1/")).map((r) => ({ objectName: r.request.objectName, expect: "denied" }));
  if (witnesses.length !== 4 || settleRows.length !== 60) bad();
  steps.push({
    type: "settle", name: "restore", enabledBy: "restore-needed", rowIds: settleRows.map((r) => r.id), intervalMs: manifest.restoration.intervalMs,
    config: { kind: "restoration", name: "restore", phase: "recovery", maxCycles: manifest.restoration.maxCycles, requiredConsecutive: manifest.restoration.consecutiveCompleteCycles, witnesses },
  });
  [0, 1, 2, 3].forEach((index) => row(`recovery/management/restore-owner-media/${index}`, "restore-needed"));
  grouped("recovery-session", ["current", "cancel", "terminal"], segment(2), (key) => `session-started:${key}`);
  grouped("recovery-object", ["metadata", "delete", "absence-metadata", "absence-media"], segment(1));
  grouped("recovery-document", ["current", "delete", "absence"], segment(1));
  steps.push({ type: "delegate", op: "recover-accounts", rowIds: recovery.filter((r) => r.family === "auth" || r.family === "credential-cache").map((r) => r.id) });
  for (const name of ["v1", "v2", "A", "B"]) {
    ["current", "delete"].forEach((stage) => row(`recovery/ruleset/${name}/${stage}`, `ruleset-created-not-deleted:${name}`));
    row(`recovery/ruleset/${name}/absence`, `ruleset-attempted:${name}`);
  }
  steps.push({ type: "pages", rowIds: Array.from({ length: 10 }, (_, index) => { const id = `recovery/rulesets-list/final/${index + 1}`; if (!byId.has(id)) bad(); return id; }), stopWhen: "no-next-page-token" });
  row("recovery/management/prefix-empty");

  const seen = new Set();
  for (const step of steps) for (const id of step.type === "row" ? [step.id] : step.rowIds) { if (seen.has(id)) bad(); seen.add(id); }
  if (seen.size !== recovery.length || recovery.some((r) => !seen.has(r.id))) bad();
  return Object.freeze({ steps: Object.freeze(steps.map((step) => Object.freeze(step))) });
}
