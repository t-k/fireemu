// AUTH-CREDENTIAL sandbox runner.
//
//   node src/auth-credential/run.mjs record-production   record the corpus twice against the
//                                                        Identity Platform sandbox and update
//                                                        auth-credential-production.json
//   node src/auth-credential/run.mjs check               run the corpus against fireemu and
//                                                        compare with the saved production rows
//   node src/auth-credential/run.mjs export-comparison <out.json>
//
// `record-production` needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON,
// kept outside the repository), owner ADC (`gcloud auth application-default`) with
// `signJwt` on both signer service accounts, FIREEMU_SANDBOX_LEDGER and
// FIREEMU_AUTH_CREDENTIAL_PRIVATE_DIR. AUTH_CREDENTIAL_PROGRAMS selects programs by id prefix
// (AUTH_CREDENTIAL_PROGRAMS_EXACT=1: by exact id). A recording takes a little over an hour,
// because the expiry program waits for an ID token to expire.
//
// `check` uses FIREEMU_BIN (or the workspace build). Custom tokens are signed with keys made
// for the run; fireemu is configured to trust their public halves as the two signer service
// accounts, so the same corpus reaches the same verification decisions on both sides.

import { execFile, spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { BASELINE_CONFIG, CONFIG_DEFAULTS } from "../auth-account/corpus.mjs";
import { scanFixture } from "../auth-account/fixture-scan.mjs";
import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  createContext,
  diffRecordings,
  isTransient,
  sameRecording,
} from "../auth-account/harness.mjs";
import { configMatches, createSession as createAccountSession } from "../auth-account/session.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { SIGNER_ACCOUNTS, validateCredentialCorpus } from "./harness.mjs";
import { runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-credential-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-credential");
const LOCAL_PORT = 32297;
/** The synthetic project number fireemu is configured with. */
const LOCAL_PROJECT_NUMBER = "123456789012";
const TASK_ID = "AUTH-CREDENTIAL-SANDBOX";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

function selectedPrograms() {
  const prefixes = (process.env.AUTH_CREDENTIAL_PROGRAMS ?? "").split(",").filter(Boolean);
  const exact = process.env.AUTH_CREDENTIAL_PROGRAMS_EXACT === "1";
  const programs = prefixes.length
    ? PROGRAMS.filter((p) =>
        prefixes.some((prefix) => (exact ? p.id === prefix : p.id.startsWith(prefix))),
      )
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches AUTH_CREDENTIAL_PROGRAMS");
  return programs;
}

const programDigest = (program) => sha256(JSON.stringify(program));

/** Normalization and request semantics a saved row depends on; a change makes it stale. */
async function harnessDigest() {
  const sources = await Promise.all(
    [
      "auth-credential/harness.mjs",
      "auth-credential/session.mjs",
      "auth-credential/tokens.mjs",
      "auth-account/harness.mjs",
    ].map((file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8")),
  );
  return sha256(`${sources.join("\n")}\n${JSON.stringify(BASELINE_CONFIG)}`);
}

/** Per recording: every step once; the harness gets its own budget for wipes, signing and waits. */
const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.length, 0),
  maxHarnessRequests: programs.reduce(
    (total, p) =>
      total +
      12 +
      Object.keys(p.tokens ?? {}).length +
      p.steps.filter((s) => s.waitSeconds || s.waitUntil).length,
    20,
  ),
});

async function assertIgnored(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  try {
    await execFileAsync("git", ["-C", path, "rev-parse", "--show-toplevel"]);
  } catch {
    return;
  }
  try {
    await execFileAsync("git", ["-C", path, "check-ignore", "-q", path]);
  } catch {
    throw new Error(`${path} is not ignored by git; private recordings must not be committable`);
  }
}

async function assertCleanTree() {
  const { stdout } = await execFileAsync(
    "git",
    [
      "status",
      "--porcelain",
      "--",
      "src/auth-credential",
      "src/auth-account",
      "auth-credential-production.json",
    ],
    { cwd: CONFORMANCE_DIR },
  );
  if (stdout.trim()) throw new Error(`record-production needs a clean tree:\n${stdout}`);
}

async function gitSha() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: CONFORMANCE_DIR });
  return stdout.trim();
}

async function adminToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

async function sandboxWebConfig() {
  const configPath = process.env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG;
  if (!configPath) throw new Error("FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required");
  const web = JSON.parse(await readFile(configPath, "utf8"));
  if (web.projectId !== SANDBOX_PROJECT) throw new Error("web config is not the sandbox project");
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId) {
    throw new Error("web config has no consistent project number");
  }
  return web;
}

/** The sign-in baseline and the account-behaviour defaults, read (production) or applied (local). */
async function prepareProject(ctx, { apply }) {
  const account = createAccountSession(ctx, { maxHarnessRequests: 80 });
  const baselineMask = Object.keys(BASELINE_CONFIG);
  if (apply) await account.writeConfig(baselineMask, BASELINE_CONFIG);
  else {
    const current = await account.readConfig(baselineMask);
    const drift = baselineMask.filter(
      (path) => !configMatches(current[path], BASELINE_CONFIG[path]),
    );
    if (drift.length) throw new Error(`sandbox baseline differs at ${drift.join(", ")}`);
  }
  const defaultsMask = Object.keys(CONFIG_DEFAULTS);
  const now = await account.readConfig(defaultsMask);
  const drift = defaultsMask.filter((path) => !configMatches(now[path], CONFIG_DEFAULTS[path]));
  if (drift.length && ctx.target.kind === "production")
    throw new Error(`sandbox config is not at its defaults: ${drift.join(", ")}`);
  // The legacy program offers a token to MFA enrollment: with a second factor enabled an
  // honoured request would answer with an enrollment secret, so the sandbox must have none.
  const { mfa } = await account.readConfig(["mfa"]);
  if (ctx.target.kind === "production" && !mfaDisabled(mfa)) {
    throw new Error(`sandbox MFA is not disabled: ${JSON.stringify(mfa)}`);
  }
  return account.counts().harnessRequests;
}

/** Whether a project's `mfa` config enables no second factor. */
export function mfaDisabled(mfa) {
  if (mfa === undefined || mfa === null) return true;
  const enabled = (state) => state === "ENABLED" || state === "MANDATORY";
  return (
    !enabled(mfa.state) && !(mfa.providerConfigs ?? []).some((provider) => enabled(provider?.state))
  );
}

/**
 * The boundary rows need this machine's clock within 100 ms of Google's: a run starts only
 * after `sntp` against time.google.com reports such an offset.
 */
async function assertClockSynchronized() {
  const { stdout } = await execFileAsync("sntp", ["-t", "2", "time.google.com"]);
  const offset = Number(/^([+-]\d+\.\d+)/m.exec(stdout)?.[1]);
  if (!Number.isFinite(offset) || Math.abs(offset) > 0.1) {
    throw new Error(`clock offset to time.google.com is ${offset} s; synchronize before recording`);
  }
  return offset;
}

async function recordOnce(programs, run, web) {
  let token = await adminToken();
  let fetchedAt = Date.now();
  const target = {
    kind: "production",
    apiKey: web.apiKey,
    adminToken: token,
    quotaProject: SANDBOX_PROJECT,
    projectNumber: web.projectNumber,
    async refresh() {
      if (Date.now() - fetchedAt < 30 * 60_000) return;
      token = await adminToken();
      fetchedAt = Date.now();
      target.adminToken = token;
    },
  };
  const ctx = createContext({ run, project: SANDBOX_PROJECT, target });
  const preparation = await prepareProject(ctx, { apply: false });
  const out = await runCorpus(programs, ctx, {
    ...ceilings(programs),
    signers: {
      project: { serviceAccount: SIGNER_ACCOUNTS.project },
      other: { serviceAccount: SIGNER_ACCOUNTS.other },
    },
    log: (line) => console.log(line),
  });
  return { ...out, harnessRequests: out.harnessRequests + preparation, secrets: [token] };
}

async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Identity Toolkit and Secure Token REST, Identity Platform sandbox; custom tokens signed through IAM signJwt",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. Tokens are recorded as their decoded header shape and claims, with times relative to the token's own iat; key ids and signatures are recorded as present or absent only. Refresh tokens, generated ids, run-window times, the project id, its number and the API key are placeholders. `second` holds the other recording of rows that differed.",
    baselineConfig: BASELINE_CONFIG,
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => !sameRecording(rec, one.steps[id])),
    );
    fixture.programs[program.id] = {
      corpusDigest: programDigest(program),
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      gitSha: meta.sha,
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  scanFixture(text, [...secrets, ...Object.values(SIGNER_ACCOUNTS)]);
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

/**
 * The per-IP account-creation limit is about 100 per hour, so a run is refused within an hour of
 * this task's last aborted run.
 */
export function recentAbort(ledgerText, now = Date.now()) {
  const entries = ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return undefined;
      }
    })
    .filter((entry) => entry?.taskId === TASK_ID);
  const last = entries.at(-1);
  if (!last || !String(last.outcome).startsWith("aborted")) return undefined;
  const age = now - Date.parse(last.ts);
  return age < 3_600_000 ? last : undefined;
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_AUTH_CREDENTIAL_PRIVATE_DIR;
  if (!ledger || !privateRoot) {
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_CREDENTIAL_PRIVATE_DIR are required");
  }
  await assertCleanTree();
  const aborted = existsSync(ledger) ? recentAbort(await readFile(ledger, "utf8")) : undefined;
  if (aborted)
    throw new Error(`the last run aborted at ${aborted.ts}; wait an hour before retrying`);
  const programs = selectedPrograms();
  const corpusRequests = validateCredentialCorpus(programs);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  const web = await sandboxWebConfig();
  meta.clockOffsetSeconds = await assertClockSynchronized();
  await assertIgnored(privateRoot);
  const runDir = join(
    privateRoot,
    `auth-credential-production-${meta.startedAt.replaceAll(":", "")}`,
  );
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const recordings = [];
  const secrets = [];
  let outcome = "recorded";
  let error;
  try {
    for (const offset of [0, 1]) {
      const { secrets: used, ...recording } = await recordOnce(
        programs,
        String(Date.now() + offset),
        web,
      );
      secrets.push(...used);
      recordings.push(recording);
      await writeFile(join(runDir, `recording-${offset + 1}.json`), JSON.stringify(recording), {
        mode: 0o600,
      });
    }
  } catch (caught) {
    outcome = caught.fatal ? "aborted-fatal" : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) recordings.push(caught.partial);
  }
  await writeFile(join(runDir, "meta.json"), JSON.stringify({ ...meta, outcome, error }, null, 2), {
    mode: 0o600,
  });
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const failures = recordings.flatMap((r) => r.failures);
  try {
    if (!error) {
      const nondeterministic = await writeFixture({
        programs,
        recordings,
        meta,
        secrets: [web.apiKey, ...secrets, SANDBOX_PROJECT, web.projectNumber],
      });
      if (failures.length) outcome = "recorded-with-program-failures";
      console.log(
        JSON.stringify(
          { programs: programs.length, corpusRequests, requests, nondeterministic, failures },
          null,
          2,
        ),
      );
    }
  } catch (caught) {
    outcome = "not-written";
    error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
  } finally {
    await appendFile(
      ledger,
      `${JSON.stringify({
        ts: new Date().toISOString(),
        project: SANDBOX_PROJECT,
        database: null,
        gitSha: meta.sha,
        corpusDigest: sha256(JSON.stringify(programs)),
        requests,
        estimatedUsd: 0,
        outcome,
        taskId: TASK_ID,
        programs: meta.programs,
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

/** Retries the fixture from a saved run directory; sends nothing to production. */
async function rebuildFixture(runDir) {
  const meta = JSON.parse(await readFile(join(runDir, "meta.json"), "utf8"));
  if (meta.harness !== (await harnessDigest()))
    throw new Error("harness changed since the recording");
  const recordings = await Promise.all(
    [1, 2].map(async (n) =>
      JSON.parse(await readFile(join(runDir, `recording-${n}.json`), "utf8")),
    ),
  );
  const programs = PROGRAMS.filter((p) => meta.programs.includes(p.id));
  const changed = programs.filter((p) => meta.corpusDigests?.[p.id] !== programDigest(p));
  if (changed.length || programs.length !== meta.programs.length) {
    throw new Error(`corpus changed since the recording: ${changed.map((p) => p.id).join(", ")}`);
  }
  const web = await sandboxWebConfig();
  const nondeterministic = await writeFixture({
    programs,
    recordings,
    meta,
    secrets: [web.apiKey, SANDBOX_PROJECT, web.projectNumber],
  });
  console.log(JSON.stringify({ programs: programs.length, nondeterministic }, null, 2));
}

/** A run-local RSA key standing in for one signer service account. */
function localSigner(serviceAccount) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = randomBytes(20).toString("hex");
  return {
    serviceAccount,
    kid,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    jwks: { keys: [{ ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" }] },
  };
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.AUTH_CREDENTIAL_IN, "utf8"));
  const signers = JSON.parse(await readFile(process.env.AUTH_CREDENTIAL_SIGNERS, "utf8"));
  const ctx = createContext({
    run: process.env.AUTH_CREDENTIAL_RUN,
    project: SANDBOX_PROJECT,
    target: {
      kind: "local",
      origin: process.env.AUTH_CREDENTIAL_ORIGIN,
      projectNumber: LOCAL_PROJECT_NUMBER,
      control: { url: process.env.FIREEMU_CONTROL_URL, token: process.env.FIREEMU_CONTROL_TOKEN },
    },
  });
  const preparation = await prepareProject(ctx, { apply: true });
  const out = await runCorpus(programs, ctx, { ...ceilings(programs), signers });
  await writeFile(
    process.env.AUTH_CREDENTIAL_OUT,
    JSON.stringify({ ...out, harnessRequests: out.harnessRequests + preparation }),
  );
}

async function runLocal(programs) {
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const inPath = join(RUN_DIR, "programs.json");
  const outPath = join(RUN_DIR, "fireemu.json");
  const signersPath = join(RUN_DIR, "signers.json");
  const configPath = join(RUN_DIR, "fireemu.config.json");
  const signers = Object.fromEntries(
    Object.entries(SIGNER_ACCOUNTS).map(([name, account]) => [name, localSigner(account)]),
  );
  const trust = Object.fromEntries(
    Object.values(signers).map(({ serviceAccount, jwks }) => [serviceAccount, jwks]),
  );
  await writeFile(signersPath, JSON.stringify(signers), { mode: 0o600 });
  await writeFile(
    configPath,
    JSON.stringify({
      schemaVersion: 1,
      profile: "strict",
      daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER } },
      auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"], customTokenSigners: trust },
    }),
  );
  await writeFile(inPath, JSON.stringify(programs));
  const binary = resolveFireemuBinary();
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      configPath,
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "auth",
      "--http-port",
      String(LOCAL_PORT),
      "--firestore-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      process.execPath,
      "src/auth-credential/run.mjs",
      "session-local",
    ],
    {
      cwd: CONFORMANCE_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        AUTH_CREDENTIAL_IN: inPath,
        AUTH_CREDENTIAL_OUT: outPath,
        AUTH_CREDENTIAL_SIGNERS: signersPath,
        AUTH_CREDENTIAL_RUN: String(Date.now()),
        AUTH_CREDENTIAL_ORIGIN: `http://127.0.0.1:${LOCAL_PORT}`,
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

export function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  const repeatedServerError = production.status >= 500 && alternative === undefined;
  const transient = (recorded) =>
    isTransient(recorded) && !(repeatedServerError && recorded?.status >= 500);
  if ([production, alternative, fireemu].some(transient)) return "INDETERMINATE";
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const selected = selectedPrograms();
  validateCredentialCorpus(selected);
  const harness = await harnessDigest();
  const local = await runLocal(selected);
  const rows = [];
  for (const program of selected) {
    const saved = fixture.programs[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) || saved.harnessDigest !== harness);
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      rows.push({
        row: `${program.id}#${step.id}`,
        status: classify({ stale, production, alternative, fireemu }),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  const known = new Set(PROGRAMS.map((p) => p.id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC"]);
  for (const row of rows.filter((r) => !passing.has(r.status))) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${String(JSON.stringify(row.production)).slice(0, 600)}`);
    console.log(`  fireemu    ${String(JSON.stringify(row.fireemu)).slice(0, 600)}`);
  }
  console.log(JSON.stringify({ summary, orphans, failures: local.failures }, null, 2));
  if (!rows.every((r) => passing.has(r.status)) || orphans.length || local.failures.length) {
    process.exitCode = 1;
  }
}

function differenceSummary(production, fireemu) {
  const differences = [];
  const walk = (a, b, path) => {
    if (JSON.stringify(a) === JSON.stringify(b)) return;
    if (
      a &&
      b &&
      typeof a === "object" &&
      typeof b === "object" &&
      Array.isArray(a) === Array.isArray(b)
    ) {
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
        walk(a[key], b[key], `${path}.${key}`);
      return;
    }
    differences.push(path.slice(1));
  };
  walk(production, fireemu, "");
  const code = (recorded) => String(recorded?.body?.error?.message ?? "").split(" : ")[0];
  return {
    differences,
    sameErrorCode: code(production) !== "" && code(production) === code(fireemu),
  };
}

async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const fixtureSha256 = sha256(await readFile(FIXTURE, "utf8"));
  const evidence = {
    kind: "auth-credential-comparison-v1",
    artifactSha256: comparison.artifactSha256,
    fixtureSha256,
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status, production, fireemu }) =>
      status === "MISMATCH"
        ? Object.assign({ row, status }, differenceSummary(production, fireemu))
        : { row, status },
    ),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ out, summary: evidence.summary, fixtureSha256 }, null, 2));
}

const mode = process.argv[2];
if (mode === "record-production") await recordProduction();
else if (mode === "rebuild-fixture") await rebuildFixture(process.argv[3]);
else if (mode === "check") await check();
else if (mode === "export-comparison") await exportComparison(process.argv[3]);
else if (mode === "session-local") await sessionLocal();
else if (mode === "local") {
  const local = await runLocal(selectedPrograms());
  await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
  console.log(JSON.stringify({ requests: local.requests, failures: local.failures }, null, 2));
} else if (mode !== undefined) {
  console.error("usage: run.mjs record-production|check|export-comparison|local");
  process.exitCode = 2;
}
