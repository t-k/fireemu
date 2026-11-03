// Signed XML PUT observer (owner ledger 2215).
//
//   node run.mjs record-production --out <new dir>   coordinator only; ADC, project lock, sends
//   node run.mjs record-local --out <new dir>        under `fireemu exec --only storage -- ...`
//   node run.mjs readback --run-dir <dir>            the A2 read-back (production, reads only)
//   node run.mjs compare --production <dir> --local <dir> --out <new dir>
//
// The recorder never writes a ledger row; it prints the run report for the coordinator.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { createLocalDeps, createProductionDeps, fetchNet, installEgressGuard } from "./deps.mjs";
import { validateSigner } from "./guard.mjs";
import { compareTargets } from "./judge.mjs";
import { observe, readbackAbsent } from "./observe.mjs";
import { BUCKET, ESTIMATED_USD, PROJECT, SIGNER, newRunId, runPrefix } from "./plan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULES = ["plan.mjs", "guard.mjs", "judge.mjs", "observe.mjs", "deps.mjs", "run.mjs"];
const FORBIDDEN_ENV = [/^GOOGLE_APPLICATION_CREDENTIALS$/, /^FIREBASE_TOKEN$/, /^CLOUDSDK_/];

function argValue(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

function required(name) {
  const value = argValue(name);
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function newOutDir(path) {
  mkdirSync(path, { recursive: false, mode: 0o700 });
  return {
    journal: (entry) =>
      appendFileSync(
        join(path, "journal.jsonl"),
        `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`,
        { mode: 0o600 },
      ),
    save: (name, data) =>
      writeFileSync(join(path, name), `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 }),
    path,
  };
}

function pins() {
  const digest = (file) =>
    createHash("sha256")
      .update(readFileSync(join(HERE, file)))
      .digest("hex");
  const version = (name) =>
    JSON.parse(readFileSync(join(HERE, "../..", "node_modules", name, "package.json"), "utf8"))
      .version;
  return {
    gitSha: execFileSync("git", ["-C", HERE, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
    dirty:
      execFileSync("git", ["-C", HERE, "status", "--porcelain", "--", "."], {
        encoding: "utf8",
      }).trim() !== "",
    modules: Object.fromEntries(MODULES.map((file) => [file, digest(file)])),
    node: process.version,
    firebaseAdmin: version("firebase-admin"),
    cloudStorage: version("@google-cloud/storage"),
    googleAuthLibrary: version("google-auth-library"),
  };
}

function finish(out, report, extra) {
  const full = {
    ...report,
    ...extra,
    estimatedUsd: ESTIMATED_USD,
    finishedAt: new Date().toISOString(),
  };
  out.save("run-report.json", full);
  console.log(JSON.stringify(full));
  return full;
}

async function recordProduction() {
  for (const name of Object.keys(process.env)) {
    if (FORBIDDEN_ENV.some((pattern) => pattern.test(name)))
      throw new Error(`refusing to start with ${name} set`);
  }
  const runId = newRunId();
  const signer = validateSigner(argValue("signer") ?? SIGNER, PROJECT);
  const pin = pins();
  if (pin.dirty) throw new Error("the recorder's checkout has uncommitted or untracked files");
  const out = newOutDir(required("out"));
  const startedAt = new Date().toISOString();
  installEgressGuard([
    "storage.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
  ]);
  let accessToken;
  try {
    accessToken = execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
      encoding: "utf8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    throw new Error("ADC token acquisition failed");
  }
  const target = { name: "production", bucket: BUCKET, project: PROJECT, signer };
  out.save("run-header.json", {
    runId,
    prefix: runPrefix(runId),
    startedAt,
    ...pin,
    target: { ...target },
  });
  let final;
  await withProjectLocks(
    {
      projects: [PROJECT],
      taskId: "STORAGE-SIGNED-PUT",
      packetId: runId,
      sourceCommit: pin.gitSha,
      pid: process.pid,
      acquiredAt: startedAt.replace(/\.\d{3}Z$/, "Z"),
      lockDir: argValue("lock-dir") ?? "docs.local/runs/sandbox-locks",
      legacyLockPath: argValue("legacy-lock") ?? "docs.local/runs/sandbox-ledger.jsonl.lock",
    },
    async (lease) => {
      const deps = createProductionDeps({ accessToken, lease, signer });
      try {
        const { report } = await observe({ target, runId, deps, out });
        final = finish(out, report, { startedAt, ...pin });
        if (report.closureReady) lease.confirmClosed();
      } finally {
        await deps.close();
      }
    },
  );
  return final;
}

async function recordLocal() {
  const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
  if (!host)
    throw new Error("run under `fireemu exec --only storage -- node run.mjs record-local`");
  const out = newOutDir(required("out"));
  const runId = newRunId();
  const pin = pins();
  const startedAt = new Date().toISOString();
  const origin = `http://${host}`;
  const target = { name: "local", bucket: "demo-signed-put.appspot.com", origin };
  const deps = createLocalDeps({ origin, bucket: target.bucket, project: "demo-signed-put" });
  try {
    const { report } = await observe({ target, runId, deps, out });
    return finish(out, report, { startedAt, ...pin });
  } finally {
    await deps.close();
  }
}

async function readback() {
  const dir = required("run-dir");
  const header = JSON.parse(readFileSync(join(dir, "run-header.json"), "utf8"));
  const accessToken = execFileSync(
    "gcloud",
    ["auth", "application-default", "print-access-token"],
    {
      encoding: "utf8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    },
  ).trim();
  const target = { name: "production", bucket: BUCKET, project: PROJECT, signer };
  const out = {
    journal: (entry) =>
      appendFileSync(
        join(dir, "a2-journal.jsonl"),
        `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`,
        { mode: 0o600 },
      ),
    save: (name, data) =>
      writeFileSync(join(dir, name), `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 }),
  };
  const deps = {
    adminHeaders: () => ({
      authorization: `Bearer ${accessToken}`,
      "x-goog-user-project": PROJECT,
    }),
    net: fetchNet,
  };
  const report = await readbackAbsent({ target, runId: header.runId, deps, out });
  console.log(JSON.stringify(report));
  return report;
}

function compare() {
  const load = (dir) => JSON.parse(readFileSync(join(dir, "results.json"), "utf8")).rows;
  const rows = compareTargets(load(required("production")), load(required("local")));
  const out = newOutDir(required("out"));
  out.save("comparison.json", {
    rows,
    matching: rows.filter((r) => r.match).length,
    differing: rows.filter((r) => !r.match).length,
  });
  console.log(JSON.stringify(rows.map((r) => [r.id, r.match ? "match" : r.fields.join("+")])));
  return rows;
}

const commands = {
  "record-production": recordProduction,
  "record-local": recordLocal,
  readback,
  compare,
};
const command = process.argv[2];
if (import.meta.url === `file://${process.argv[1]}`) {
  if (!commands[command]) throw new Error(`usage: run.mjs ${Object.keys(commands).join(" | ")}`);
  await commands[command]();
}
