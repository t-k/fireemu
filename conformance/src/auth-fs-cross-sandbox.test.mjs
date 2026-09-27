import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  acquireLock,
  admissionProblems,
  ATB_AUTHORIZED_DOMAINS,
  ATB_TEST_PHONES,
  closingLines,
  finalMismatches,
  FOREIGN_PROJECT,
  releaseLock,
  SANDBOX_PROJECT,
  startedLines,
  TASK_ID,
} from "./auth-fs-cross/sandbox.mjs";

const NOW = Date.parse("2026-09-27T20:00:00Z");
const ago = (minutes) => new Date(NOW - minutes * 60_000).toISOString();
const ledger = (...rows) => rows.map((row) => JSON.stringify(row)).join("\n");

test("admission refuses another lane's recent line or open run on either project", () => {
  assert.deepEqual(admissionProblems("", SANDBOX_PROJECT, NOW), []);
  const recent = ledger({
    ts: ago(10),
    taskId: "AUTH-TENANT-SANDBOX",
    project: SANDBOX_PROJECT,
    event: "note",
  });
  assert.match(
    admissionProblems(recent, SANDBOX_PROJECT, NOW).join(),
    /AUTH-TENANT-SANDBOX wrote a line/,
  );
  assert.deepEqual(admissionProblems(recent, FOREIGN_PROJECT, NOW), []);
  const old = ledger({
    ts: ago(31),
    taskId: "STORAGE-OBJECT",
    project: FOREIGN_PROJECT,
    event: "note",
  });
  assert.deepEqual(admissionProblems(old, FOREIGN_PROJECT, NOW), []);
  const open = ledger({
    ts: ago(300),
    taskId: "FUNCTIONS-HTTP",
    project: FOREIGN_PROJECT,
    event: "started",
  });
  assert.match(
    admissionProblems(open, FOREIGN_PROJECT, NOW).join(),
    /FUNCTIONS-HTTP on .* is open/,
  );
  const recovery = ledger({
    ts: ago(300),
    taskId: "X",
    project: SANDBOX_PROJECT,
    event: "needs-recovery",
  });
  assert.match(admissionProblems(recovery, SANDBOX_PROJECT, NOW).join(), /X on .* needs recovery/);
});

test("another lane's run is open until any later line of it, for six hours", () => {
  const started = (hours) => ({
    ts: ago(hours * 60),
    taskId: "OTHER",
    project: SANDBOX_PROJECT,
    event: "started",
  });
  assert.match(
    admissionProblems(ledger(started(2)), SANDBOX_PROJECT, NOW).join(),
    /OTHER on .* is open/,
  );
  assert.deepEqual(admissionProblems(ledger(started(7)), SANDBOX_PROJECT, NOW), []);
  const ended = ledger(started(2), {
    ts: ago(60),
    taskId: "OTHER",
    project: SANDBOX_PROJECT,
    outcome: "exploration-recorded",
  });
  assert.deepEqual(admissionProblems(ended, SANDBOX_PROJECT, NOW), []);
  // A line without a task id names no run.
  const anonymous = ledger({ ts: ago(60), project: SANDBOX_PROJECT, event: "started" });
  assert.deepEqual(admissionProblems(anonymous, SANDBOX_PROJECT, NOW), []);
});

test("another lane's needs-recovery stays open until a line ends its run", () => {
  const recovery = {
    ts: ago(3000),
    taskId: "OTHER",
    project: SANDBOX_PROJECT,
    event: "needs-recovery",
  };
  assert.match(admissionProblems(ledger(recovery), SANDBOX_PROJECT, NOW).join(), /needs recovery/);
  const note = { ts: ago(2000), taskId: "OTHER", project: SANDBOX_PROJECT, event: "note" };
  assert.match(
    admissionProblems(ledger(recovery, note), SANDBOX_PROJECT, NOW).join(),
    /needs recovery/,
  );
  for (const end of [
    { event: "finished", outcome: "recovered-no-observation" },
    { event: "cleanup-verified" },
  ]) {
    const closed = ledger(recovery, {
      ts: ago(2000),
      taskId: "OTHER",
      project: SANDBOX_PROJECT,
      ...end,
    });
    assert.deepEqual(admissionProblems(closed, SANDBOX_PROJECT, NOW), [], JSON.stringify(end));
  }
});

test("this task's own unclean end blocks its next run", () => {
  const text = ledger(
    { ts: ago(120), taskId: TASK_ID, project: FOREIGN_PROJECT, event: "started" },
    { ts: ago(100), taskId: TASK_ID, project: FOREIGN_PROJECT, event: "needs-recovery" },
  );
  assert.match(
    admissionProblems(text, FOREIGN_PROJECT, NOW).join(),
    /this task's run .* did not end cleanly/,
  );
});

test("the lock is exclusive and released only while it is this run's", async () => {
  const dir = mkdtempSync(join(tmpdir(), "afc-lock-"));
  try {
    const path = join(dir, "ledger.jsonl");
    const lock = await acquireLock(path, "a".repeat(40), new Date(NOW));
    assert.deepEqual(JSON.parse(readFileSync(lock.path, "utf8")), {
      taskId: TASK_ID,
      sourceCommit: "a".repeat(40),
      acquiredAt: new Date(NOW).toISOString(),
    });
    await assert.rejects(acquireLock(path, "b".repeat(40)), /is held; not starting/);
    writeFileSync(lock.path, "{}");
    await assert.rejects(releaseLock(lock), /rewritten; left in place/);
    rmSync(lock.path);
    writeFileSync(lock.path, JSON.stringify({ taskId: "OTHER" }));
    await assert.rejects(releaseLock(lock), /replaced; left in place/);
    rmSync(lock.path);
    const own = await acquireLock(path, "c".repeat(40));
    await releaseLock(own);
    assert.throws(() => readFileSync(own.path), /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const baseline = () => ({
  config: {
    multiTenant: { allowTenants: false },
    emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
    client: { permissions: {} },
    signIn: {
      email: { enabled: true, passwordRequired: true },
      anonymous: { enabled: true },
      phoneNumber: { enabled: true, testPhoneNumbers: { ...ATB_TEST_PHONES } },
    },
    mfa: { state: "DISABLED" },
    authorizedDomains: [...ATB_AUTHORIZED_DOMAINS].toReversed(),
  },
  tenantsUnlistable: true,
  tenants: [],
  projectAccounts: 0,
  bindings: [{ role: "roles/iam.serviceAccountTokenCreator" }],
  releases: [],
  rulesets: [],
  databases: ["(default)"],
  defaultHasDocuments: false,
});

test("the final readback names every difference from the baseline", () => {
  assert.deepEqual(finalMismatches(baseline()), []);
  const cases = {
    "atb-1 tenants": (r) =>
      Object.assign(r, { tenantsUnlistable: false, tenants: [{ name: "t" }] }),
    "atb-2 allowTenants": (r) => (r.config.multiTenant.allowTenants = true),
    "atb-2 improvedEmailPrivacy": (r) => (r.config.emailPrivacyConfig = {}),
    "atb-2 disabledUserSignup": (r) => (r.config.client.permissions.disabledUserSignup = true),
    "atb-2 disabledUserDeletion": (r) => (r.config.client.permissions.disabledUserDeletion = true),
    "atb-2 allowDuplicateEmails": (r) => (r.config.signIn.allowDuplicateEmails = true),
    "atb-2 mfa": (r) => (r.config.mfa.state = "ENABLED"),
    "atb-3 email": (r) => (r.config.signIn.email.passwordRequired = false),
    "atb-3 anonymous": (r) => (r.config.signIn.anonymous.enabled = false),
    "atb-3 phone": (r) => (r.config.signIn.phoneNumber.enabled = false),
    "atb-3 testPhoneNumbers": (r) =>
      (r.config.signIn.phoneNumber.testPhoneNumbers["+16505550101"] = "654321"),
    "atb-4 authorizedDomains": (r) => r.config.authorizedDomains.push("localhost"),
    "atb-5 project accounts": (r) => (r.projectAccounts = 1),
    "atb-6 signer bindings": (r) =>
      r.bindings.push({ role: `projects/${SANDBOX_PROJECT}/roles/fireemuCustomTokenSigner` }),
    releases: (r) => r.releases.push({ name: "x" }),
    rulesets: (r) => r.rulesets.push({ name: "x" }),
    databases: (r) => r.databases.push("named"),
    "default documents": (r) => (r.defaultHasDocuments = true),
  };
  for (const [name, change] of Object.entries(cases)) {
    const reads = baseline();
    change(reads);
    assert.ok(finalMismatches(reads).includes(name), name);
  }
  // An unlistable tenant list counts as empty only while multi-tenancy is off.
  const on = baseline();
  on.config.multiTenant.allowTenants = true;
  assert.deepEqual(finalMismatches(on), ["atb-1 tenants", "atb-2 allowTenants"]);
});

test("both projects get a started line and the same kind of closing line", () => {
  const lock = { sha256: "l".repeat(64) };
  const started = startedLines({ ts: "t", sha: "s", programs: 4, operatorConfirmation: "c", lock });
  assert.deepEqual(
    started.map(({ project, event }) => [project, event]),
    [
      [SANDBOX_PROJECT, "started"],
      [FOREIGN_PROJECT, "started"],
    ],
  );
  assert.ok(started.every((line) => line.lockSha256 === lock.sha256 && line.taskId === TASK_ID));
  const args = {
    ts: "t",
    sha: "s",
    corpusDigest: "d",
    outcome: "recorded",
    idp: { requests: 5 },
    query: { requests: 2 },
  };
  const clean = closingLines({ ...args, atBaseline: true });
  assert.deepEqual(
    clean.map(({ event, sandboxAtBaseline, requests }) => [event, sandboxAtBaseline, requests]),
    [
      ["finished", true, 5],
      ["finished", true, 2],
    ],
  );
  const failures = closingLines({
    ...args,
    outcome: "recorded-with-program-failures",
    atBaseline: true,
  });
  assert.deepEqual(
    failures.map(({ event, project }) => [event, project]),
    [
      ["finished", SANDBOX_PROJECT],
      ["finished", FOREIGN_PROJECT],
      ["cleanup-verified", SANDBOX_PROJECT],
      ["cleanup-verified", FOREIGN_PROJECT],
    ],
  );
  assert.ok(failures.slice(2).every((line) => line.outcome === undefined));
  const unclean = closingLines({ ...args, atBaseline: false, error: "readback failed" });
  assert.deepEqual(
    unclean.map(({ event, outcome }) => [event, outcome]),
    [
      ["needs-recovery", undefined],
      ["needs-recovery", undefined],
    ],
  );
  assert.ok(unclean.every(({ error }) => error === "readback failed"));
});
