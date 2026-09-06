// Evidence identity and recording helpers shared by the production probes.
//
// A production comparison is only a compatibility claim when the live fireemu observation,
// the input corpus and the execution configuration can be identified independently. This
// module keeps the identity comparison pure so its refusal behavior is testable without a
// network request or a production credential.

import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { promisify } from "node:util";
import { basename, dirname, join, relative, resolve } from "node:path";

import { CONFORMANCE_DIR, REPO_ROOT } from "./config.mjs";

const execFile = promisify(execFileCallback);
const gitShaPattern = /^[0-9a-f]{7,64}$/;
const IDENTITY_FIELDS = Object.freeze([
  "sourceSha",
  "packageVersion",
  "packageManifestDigest",
  "packageIntegrity",
  "artifactSha256",
  "artifactPlatform",
  "profile",
  "configDigest",
  "rulesDigest",
  "sdkLockDigest",
  "corpusDigest",
  "indexDigest",
  "databaseDigest",
]);

const stable = (value) => {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, stable(value[key])]),
    );
  }
  return value;
};

/** SHA-256 digest for a JSON identity value. */
export const digestJson = (value) =>
  "sha256-" +
  createHash("sha256")
    .update(JSON.stringify(stable(value)))
    .digest("hex");

/** SHA-256 digest for a file. */
export async function digestFile(path) {
  return (
    "sha256-" +
    createHash("sha256")
      .update(await readFile(path))
      .digest("hex")
  );
}

/** Returns the binary selected by the conformance run, or throws a useful error. */
export function resolveFireemuBinary() {
  const candidates = process.env.FIREEMU_BIN
    ? [resolve(REPO_ROOT, process.env.FIREEMU_BIN)]
    : [join(REPO_ROOT, "target/release/fireemu"), join(REPO_ROOT, "target/debug/fireemu")];
  const binary = candidates.find((path) => existsSync(path));
  if (!binary) throw new Error("fireemu is not built: run cargo build -p fireemu");
  return binary;
}

const git = async (args) => {
  const result = await execFile("git", args, { cwd: REPO_ROOT, encoding: "utf8" });
  return result.stdout.trim();
};

const cargoVersion = async () => {
  const cargo = await readFile(join(REPO_ROOT, "Cargo.toml"), "utf8");
  return cargo.match(/^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m)?.[1] ?? null;
};

const fileRecord = async (path, label) => {
  if (!path) return null;
  const absolute = resolve(path);
  const [metadata, sha256] = await Promise.all([stat(absolute), digestFile(absolute)]);
  return { file: label ?? basename(absolute), bytes: metadata.size, sha256 };
};

const repoFile = (path) => relative(REPO_ROOT, path).replaceAll("\\", "/");

const findPackageManifest = async (artifactPath) => {
  const candidates = [];
  if (artifactPath) {
    let current = dirname(resolve(artifactPath));
    while (true) {
      candidates.push(join(current, "package.json"));
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  candidates.push(join(REPO_ROOT, "npm/fireemu/package.json"));
  for (const path of new Set(candidates)) {
    try {
      const manifest = JSON.parse(await readFile(path, "utf8"));
      if (manifest.name === "fireemu" || manifest.name?.startsWith("@fireemu/")) {
        const record = await fileRecord(path, manifest.name + "/package.json");
        return { ...record, name: manifest.name, version: manifest.version ?? null };
      }
    } catch {
      // A direct cargo build has no adjacent npm package; use the source package below.
    }
  }
  return null;
};

const packageIntegrity = async () => {
  if (process.env.FIREEMU_PACKAGE_INTEGRITY) return process.env.FIREEMU_PACKAGE_INTEGRITY;
  const tarball = process.env.FIREEMU_PACKAGE_TARBALL;
  if (!tarball) return null;
  try {
    return (
      "sha512-" +
      createHash("sha512")
        .update(await readFile(resolve(REPO_ROOT, tarball)))
        .digest("base64")
    );
  } catch {
    return null;
  }
};

/**
 * Returns a flattened identity used to decide whether two observations can be joined.
 * null is retained so a missing identity cannot compare equal by omission.
 */
export function evidenceIdentity(evidence) {
  return {
    sourceSha: evidence?.source?.gitSha ?? null,
    packageVersion: evidence?.package?.version ?? null,
    packageManifestDigest: evidence?.package?.manifestDigest ?? null,
    packageIntegrity: evidence?.package?.integrity ?? evidence?.artifact?.packageIntegrity ?? null,
    artifactSha256: evidence?.artifact?.sha256 ?? null,
    artifactPlatform: evidence?.artifact?.platform ?? null,
    profile: evidence?.runtime?.profile ?? null,
    configDigest: evidence?.runtime?.configDigest ?? null,
    rulesDigest: evidence?.runtime?.rulesDigest ?? null,
    sdkLockDigest: evidence?.inputs?.sdkLockDigest ?? null,
    corpusDigest: evidence?.inputs?.corpusDigest ?? null,
    indexDigest: evidence?.inputs?.indexDigest ?? null,
    databaseDigest: evidence?.observation?.database
      ? digestJson(evidence.observation.database)
      : null,
  };
}

/**
 * Compares all identity components and refuses a verified join on missing or mismatched data.
 * The returned field names are stable enough to use in a report and in mutation tests.
 */
export function validateEvidenceJoin(expected, actual, fields = IDENTITY_FIELDS) {
  const left = evidenceIdentity(expected);
  const right = evidenceIdentity(actual);
  const mismatches = [];
  for (const field of fields) {
    if (left[field] === null || right[field] === null) {
      mismatches.push(field + ": missing identity");
    } else if (left[field] !== right[field]) {
      mismatches.push(field + ": " + left[field] + " != " + right[field]);
    }
  }
  return { verified: mismatches.length === 0, mismatches };
}

/** Validates that a live fireemu observation carries every identity needed for a claim. */
export function validateLiveEvidence(
  evidence,
  { requireIndex = false, requirePackageIntegrity = true } = {},
) {
  const required = IDENTITY_FIELDS.filter(
    (field) =>
      field !== "indexDigest" &&
      field !== "rulesDigest" &&
      (requirePackageIntegrity || field !== "packageIntegrity"),
  );
  if (requireIndex) required.push("indexDigest");
  const identity = evidenceIdentity(evidence);
  const missing = required.filter((field) => identity[field] === null);
  const errors = [];
  if (evidence?.observation?.mode !== "live") {
    errors.push("observation: live observation required");
  }
  if (!gitShaPattern.test(identity.sourceSha ?? "")) errors.push("sourceSha: invalid git SHA");
  if (evidence?.source?.trackedTreeClean !== true) {
    errors.push("source: tracked working tree is dirty");
  }
  errors.push(...missing.map((field) => field + ": missing identity"));
  return { verified: errors.length === 0, errors };
}

/** Validates the stored corpus identity against a new actual observation. */
export function validateRecordedExpectation(recorded, actual, { requireIndex = false } = {}) {
  const fields = ["sourceSha", "corpusDigest", "sdkLockDigest"];
  if (requireIndex) fields.push("indexDigest");
  const expected = recorded?.identity ?? recorded ?? {};
  const identity = evidenceIdentity(actual);
  const mismatches = [];
  for (const field of fields) {
    const left = expected[field] ?? null;
    const right = identity[field] ?? null;
    if (left === null || right === null) mismatches.push(field + ": missing identity");
    else if (left !== right) mismatches.push(field + ": " + left + " != " + right);
  }
  return { verified: mismatches.length === 0, mismatches };
}

/**
 * Classifies one production row. Rows without a validated live identity cannot become a
 * compatibility match; local-only and index-required rows stay explicit exclusions.
 */
export function classifyProductionCase({
  production,
  emulator,
  fireemu,
  evidenceValid = true,
  localOnly = false,
  needsIndex = false,
}) {
  if (localOnly) return "excluded-local-only";
  if (needsIndex) return "production-needs-index";
  if (!evidenceValid) return "unverified";
  const same = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));
  if (same(production, emulator) && same(production, fireemu)) return "parity";
  if (same(production, fireemu)) return "fireemu-matches-production";
  if (same(production, emulator)) return "fireemu-divergence";
  if (same(emulator, fireemu)) return "emulators-diverge-from-production";
  return "three-way-difference";
}

/** Counts row statuses without presenting a global compatibility percentage. */
export function summarizeStatuses(statuses) {
  return statuses.reduce((counts, status) => {
    counts[status] = (counts[status] ?? 0) + 1;
    return counts;
  }, {});
}

/**
 * Collects the identity manifest for one observation. Private identifiers are represented only
 * by the caller-supplied sanitized database metadata and by file basenames/relative paths.
 */
export async function collectEvidence({
  side,
  mode = "live",
  profile = null,
  configPath = null,
  rulesPath = null,
  corpusPath = null,
  indexPaths = [],
  database = null,
  startedAt = new Date().toISOString(),
  finishedAt = new Date().toISOString(),
  artifactPath = null,
}) {
  const [
    sha,
    trackedStatus,
    sourceVersion,
    sourceManifest,
    sdkLock,
    config,
    rules,
    corpus,
    indexFiles,
    packageManifest,
    integrity,
  ] = await Promise.all([
    git(["rev-parse", "HEAD"]),
    git(["status", "--porcelain", "--untracked-files=no"]),
    cargoVersion(),
    fileRecord(join(REPO_ROOT, "crates/fireemu/Cargo.toml"), "crates/fireemu/Cargo.toml"),
    fileRecord(join(CONFORMANCE_DIR, "pnpm-lock.yaml"), "conformance/pnpm-lock.yaml"),
    fileRecord(configPath, configPath ? repoFile(resolve(configPath)) : null),
    fileRecord(rulesPath, rulesPath ? repoFile(resolve(rulesPath)) : null),
    fileRecord(corpusPath, corpusPath ? repoFile(resolve(corpusPath)) : null),
    Promise.all(indexPaths.map((path) => fileRecord(path, repoFile(resolve(path))))),
    findPackageManifest(artifactPath),
    packageIntegrity(),
  ]);
  const artifact = await fileRecord(
    artifactPath,
    artifactPath ? basename(resolve(artifactPath)) : null,
  );
  const indexDigest = indexFiles.length > 0 ? digestJson(indexFiles) : null;
  return {
    schemaVersion: 1,
    observation: {
      side,
      mode,
      startedAt,
      finishedAt,
      database,
    },
    source: {
      gitSha: sha,
      trackedTreeClean: trackedStatus === "",
    },
    package: {
      name: "fireemu",
      version: process.env.FIREEMU_PACKAGE_VERSION ?? packageManifest?.version ?? sourceVersion,
      manifest: packageManifest?.file ?? "crates/fireemu/Cargo.toml",
      manifestDigest: packageManifest?.sha256 ?? sourceManifest?.sha256 ?? null,
      integrity,
    },
    artifact: artifact
      ? {
          file: artifact.file,
          bytes: artifact.bytes,
          sha256: artifact.sha256,
          platform: process.env.FIREEMU_PACKAGE_PLATFORM ?? process.platform + "-" + process.arch,
          packageIntegrity: integrity,
        }
      : null,
    runtime: {
      profile,
      config: config?.file ?? null,
      configDigest: config?.sha256 ?? null,
      rules: rules?.file ?? null,
      rulesDigest: rules?.sha256 ?? null,
    },
    inputs: {
      sdkLock: sdkLock?.file ?? null,
      sdkLockDigest: sdkLock?.sha256 ?? null,
      corpus: corpus?.file ?? null,
      corpusDigest: corpus?.sha256 ?? null,
      indexFiles: indexFiles.map(({ file, bytes, sha256 }) => ({ file, bytes, sha256 })),
      indexDigest,
    },
  };
}
