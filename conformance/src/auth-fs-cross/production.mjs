// A production recording of AUTH-FS-CROSS stage 1, end to end: admission, the shared lock, the
// baseline read, the compile probe, the recordings, the final readback and the ledger lines of
// both projects. Every request, clock and recording is injected, so the lock and recovery rules
// are tested without a network.

import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { PRODUCTION } from "../fs-rules/harness.mjs";
import { RULESET_IDS, rulesetSource } from "./rulesets.mjs";
import {
  acquireLock,
  admissionProblems,
  approvalUsed,
  closingLines,
  finalMismatches,
  FOREIGN_PROJECT,
  releaseLock,
  SANDBOX_PROJECT,
  scrub,
  startedLines,
  TASK_ID,
} from "./sandbox.mjs";

const RULES = `${PRODUCTION.rules}/v1/projects/${SANDBOX_PROJECT}`;
const ITK = PRODUCTION.itk;
const DATABASES = `${PRODUCTION.firestore}/v1/projects/${SANDBOX_PROJECT}/databases`;
const SERVICE_ACCOUNT = `firebase-adminsdk-fbsvc@${SANDBOX_PROJECT}.iam.gserviceaccount.com`;

/** The baseline of the sandbox, read at the start and at the end (8 reads, all on idp). */
export async function readBaseline(fetchJson) {
  const read = (method, url, body) => fetchJson(method, url, body, SANDBOX_PROJECT);
  const answers = {
    config: await read("GET", `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}/config`),
    tenants: await read("GET", `${ITK}/v2/projects/${SANDBOX_PROJECT}/tenants?pageSize=100`),
    accounts: await read("POST", `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:query`, {
      returnUserInfo: false,
    }),
    policy: await read(
      "POST",
      `https://iam.googleapis.com/v1/projects/${SANDBOX_PROJECT}/serviceAccounts/${SERVICE_ACCOUNT}:getIamPolicy?options.requestedPolicyVersion=3`,
    ),
    releases: await read("GET", `${RULES}/releases?pageSize=100`),
    rulesets: await read("GET", `${RULES}/rulesets?pageSize=100`),
    databases: await read("GET", DATABASES),
    documents: await read("POST", `${DATABASES}/(default)/documents:runQuery`, {
      structuredQuery: { from: [{ allDescendants: true }], limit: 1 },
    }),
  };
  const unlistable =
    answers.tenants.status === 400 && answers.tenants.json?.error?.message === "INVALID_PROJECT_ID";
  const failed = Object.entries(answers)
    .filter(([name, { status }]) => status !== 200 && !(name === "tenants" && unlistable))
    .map(([name, { status }]) => `readback failed: ${name} (HTTP ${status})`);
  const reads = {
    config: answers.config.json,
    tenantsUnlistable: unlistable,
    // An empty list is answered as `{}`; a failed read is reported above, not read as empty.
    tenants: unlistable ? [] : (answers.tenants.json?.tenants ?? []),
    projectAccounts: Number(answers.accounts.json?.recordsCount ?? -1),
    bindings: answers.policy.json?.bindings ?? [],
    releases: answers.releases.json?.releases ?? [],
    rulesets: answers.rulesets.json?.rulesets ?? [],
    databases: (answers.databases.json?.databases ?? []).map(({ name }) => name.split("/").at(-1)),
    defaultHasDocuments: (answers.documents.json ?? []).some((entry) => entry.document),
  };
  return {
    requests: Object.keys(answers).length,
    mismatches: [...failed, ...finalMismatches(reads)],
  };
}

/**
 * The other project: whether it offers email/password sign-up, and whether any account this run
 * named there is left (every email is the run's own: `afc-<run>-foreign@example.com`).
 */
export async function readForeign(fetchJson, emails = []) {
  const read = (method, url, body) => fetchJson(method, url, body, FOREIGN_PROJECT);
  const problems = [];
  const config = await read("GET", `${ITK}/admin/v2/projects/${FOREIGN_PROJECT}/config`);
  if (config.status !== 200) problems.push(`foreign config read failed (HTTP ${config.status})`);
  else if (config.json?.signIn?.email?.enabled !== true)
    problems.push(`${FOREIGN_PROJECT} does not offer email/password sign-up`);
  for (const email of emails) {
    const found = await read("POST", `${ITK}/v1/projects/${FOREIGN_PROJECT}/accounts:lookup`, {
      email: [email],
    });
    if (found.status !== 200) problems.push(`foreign account lookup failed (HTTP ${found.status})`);
    else if ((found.json?.users ?? []).length)
      problems.push(`a foreign account of the run remains`);
  }
  return { requests: 1 + emails.length, problems };
}

/**
 * Compiles each ruleset in production (created and deleted, never released) and reads back that
 * no ruleset is left. Throws on a transport failure: something may have been created.
 */
export async function compileProbe(fetchJson) {
  let requests = 0;
  const compiled = {};
  let clean = true;
  for (const id of RULESET_IDS) {
    requests += 1;
    const created = await fetchJson(
      "POST",
      `${RULES}/rulesets`,
      {
        source: { files: [{ name: "firestore.rules", content: rulesetSource(id) }] },
      },
      SANDBOX_PROJECT,
    );
    compiled[id] = created.status;
    if (created.status === 200) {
      requests += 1;
      const deleted = await fetchJson(
        "DELETE",
        `${PRODUCTION.rules}/v1/${created.json.name}`,
        undefined,
        SANDBOX_PROJECT,
      );
      if (deleted.status !== 200) clean = false;
    }
  }
  requests += 1;
  const left = await fetchJson("GET", `${RULES}/rulesets?pageSize=100`, undefined, SANDBOX_PROJECT);
  if (left.status !== 200 || (left.json?.rulesets ?? []).length) clean = false;
  return { requests, compiled, clean };
}

const line = (row) => `${JSON.stringify(row)}\n`;

/**
 * One production recording campaign. `deps` provides: `ledger`, `privateRoot`, `packetSha256`,
 * `programs`, `operatorConfirmation`, `secrets` ([value, placeholder] pairs), and the functions
 * `admission()`, `target()`, `fetchJson(target, method, url, body, quotaProject)`,
 * `clockOffset()`, `recordOnce(target, n)`, `writeFixture(recordings, meta)`, `now()`, `log()`.
 */
export async function runProduction(deps) {
  const admission = await deps.admission();
  if (admission.problems.length) throw new Error(`admission: ${admission.problems.join("; ")}`);
  const clean = (text) => scrub(text, deps.secrets);
  // The lock comes first: the ledger is judged, and the started lines written, while it is held.
  const lock = await acquireLock(deps.ledger, admission.sha, deps.now());
  let keepLock = false;
  try {
    const ledgerText = await readFile(deps.ledger, "utf8");
    const open = [
      ...admissionProblems(ledgerText, SANDBOX_PROJECT, deps.now().getTime()),
      ...admissionProblems(ledgerText, FOREIGN_PROJECT, deps.now().getTime()),
      ...(deps.recentAbort(ledgerText) ? ["this task's last run aborted within the hour"] : []),
      ...(approvalUsed(ledgerText, deps.packetSha256)
        ? ["this packet's approval was already used"]
        : []),
    ];
    if (open.length) throw new Error(`admission under the lock: ${open.join("; ")}`);
    const target = await deps.target();
    const fetchJson = (method, url, body, quota) =>
      deps.fetchJson(target, method, url, body, quota);
    // Reads only: a failure here leaves nothing behind.
    const start = await readBaseline(fetchJson);
    const foreignStart = await readForeign(fetchJson);
    const startProblems = [...start.mismatches, ...foreignStart.problems];
    if (startProblems.length) throw new Error(`preflight: ${startProblems.join("; ")}`);
    // The compile probe writes: from its first request only a clean readback releases the lock.
    keepLock = true;
    let probe;
    try {
      probe = await deps.compileProbe(fetchJson);
    } catch (error) {
      probe = { clean: false, error: String(error.message ?? error), compiled: {}, requests: 0 };
    }
    if (!probe.clean || Object.values(probe.compiled).some((status) => status !== 200)) {
      if (!probe.clean)
        await appendFile(
          deps.ledger,
          line({
            ts: deps.now().toISOString(),
            event: "needs-recovery",
            taskId: TASK_ID,
            project: SANDBOX_PROJECT,
            stage: 1,
            reason: "compile-probe",
            sandboxAtBaseline: false,
            ...(probe.error ? { error: clean(probe.error) } : {}),
          }),
        );
      else keepLock = false;
      throw new Error(`compile probe: ${clean(probe.error ?? JSON.stringify(probe.compiled))}`);
    }
    keepLock = false;
    const meta = {
      sha: admission.sha,
      harness: admission.harness,
      packetSha256: deps.packetSha256,
      startedAt: deps.now().toISOString(),
      programs: deps.programs.map((p) => p.id),
      corpusDigests: admission.corpusDigests,
      operatorConfirmation: deps.operatorConfirmation,
      clockOffsetSeconds: await deps.clockOffset(),
      lock: { path: lock.path, sha256: lock.sha256 },
    };
    const runDir = join(
      deps.privateRoot,
      `auth-fs-cross-production-${meta.startedAt.replaceAll(":", "")}`,
    );
    await mkdir(runDir, { recursive: true, mode: 0o700 });
    // From here on the sandbox changes: only a clean, verified end releases the lock.
    keepLock = true;
    for (const row of startedLines({
      ts: meta.startedAt,
      sha: meta.sha,
      programs: deps.programs.length,
      operatorConfirmation: deps.operatorConfirmation,
      lock,
      packetSha256: deps.packetSha256,
    }))
      await appendFile(deps.ledger, line(row));
    const recordings = [];
    let outcome = "recorded";
    let error;
    try {
      for (const n of [1, 2]) {
        if (deps.stopRequested?.())
          throw Object.assign(new Error("stopped by a signal"), { fatal: true });
        const recording = await deps.recordOnce(target, n);
        recordings.push(recording);
        await writeFile(join(runDir, `recording-${n}.json`), JSON.stringify(recording), {
          mode: 0o600,
        });
      }
    } catch (caught) {
      outcome = caught.fatal ? "aborted-fatal" : "aborted";
      error = String(caught.message ?? caught);
      if (caught.partial) {
        recordings.push(caught.partial);
        await writeFile(
          join(runDir, `recording-${recordings.length}-partial.json`),
          JSON.stringify(caught.partial),
          { mode: 0o600 },
        );
      }
    }
    const failures = recordings.flatMap((r) => r.failures ?? []);
    const cleanupErrors = recordings.flatMap((r) => r.cleanupErrors ?? []);
    if (cleanupErrors.length) outcome = "aborted-cleanup-incomplete";
    if (!error) {
      try {
        const nondeterministic = await deps.writeFixture(recordings, meta);
        if (failures.length) outcome = "recorded-with-program-failures";
        deps.log({ programs: deps.programs.length, nondeterministic, failures });
      } catch (caught) {
        outcome = "not-written";
        error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
      }
    }
    // Whatever happened above, both projects are read back against the baseline; the owner
    // token may have aged over the run.
    const emails = recordings.flatMap((r) => (r.foreignAccounts ?? []).map(({ email }) => email));
    let final;
    try {
      await target.refresh?.();
      const idp = await readBaseline(fetchJson);
      const foreign = await readForeign(fetchJson, emails);
      final = {
        requests: { idp: idp.requests, query: foreign.requests },
        mismatches: [...idp.mismatches, ...foreign.problems],
      };
    } catch (caught) {
      final = {
        requests: { idp: 0, query: 0 },
        mismatches: [`readback failed: ${caught.message ?? caught}`],
      };
    }
    const atBaseline = final.mismatches.length === 0 && cleanupErrors.length === 0;
    const foreignRequests = recordings.reduce((n, r) => n + (r.foreignRequests ?? 0), 0);
    const allRequests = recordings.reduce(
      (n, r) => n + (r.requests ?? 0) + (r.harnessRequests ?? 0),
      0,
    );
    const idpRequests =
      allRequests - foreignRequests + start.requests + probe.requests + final.requests.idp;
    const queryRequests = foreignRequests + foreignStart.requests + final.requests.query;
    const problem = [error, ...final.mismatches, ...cleanupErrors].filter(Boolean).join("; ");
    for (const row of closingLines({
      ts: deps.now().toISOString(),
      sha: meta.sha,
      corpusDigest: admission.corpusDigest,
      outcome,
      atBaseline,
      error: problem ? clean(problem) : undefined,
      idp: {
        database: "(default)",
        requests: idpRequests,
        // Firestore reads, writes and Rules evaluations at list price; Auth MAU for a few accounts.
        estimatedUsd: Number((idpRequests * 0.0000006 + 0.1).toFixed(4)),
        programs: meta.programs,
        configurationChanges: recordings.flatMap((r) => r.changes ?? []),
        publications: recordings.flatMap((r) => r.publications ?? []).length,
        finalReadback: final.mismatches.map(clean),
      },
      query: { requests: queryRequests, estimatedUsd: 0 },
    }))
      await appendFile(deps.ledger, line(row));
    await writeFile(
      join(runDir, "meta.json"),
      clean(
        JSON.stringify(
          {
            ...meta,
            outcome,
            error,
            finalReadback: final,
            timings: recordings.flatMap((r) => r.timings ?? []),
          },
          null,
          2,
        ),
      ),
      { mode: 0o600 },
    );
    if (atBaseline) keepLock = false;
    if (error) throw new Error(clean(error));
    return { outcome, atBaseline, failures };
  } finally {
    if (!keepLock) await releaseLock(lock);
  }
}
