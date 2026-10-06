// The v2 default path verifies actual loaded source/runtime and coordinator proof files before ADC.
import { createHash } from "node:crypto";
import {
  readFileSync,
  readdirSync,
  statSync,
  realpathSync,
  openSync,
  closeSync,
  writeFileSync,
  fsyncSync,
  mkdirSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const require = createRequire(import.meta.url);
export const SOURCE_FILES = Object.freeze([
  "conformance/package.json",
  "conformance/pnpm-lock.yaml",
  "conformance/src/pubsub-production/fixtures/recorded-v2-iam.json",
  ...readdirSync(resolve(sourceRoot, "conformance/src/pubsub-production"))
    .filter((name) => name.endsWith(".mjs"))
    .sort()
    .map((name) => `conformance/src/pubsub-production/${name}`),
  ...readdirSync(resolve(sourceRoot, "conformance/src/pubsub-production/cases"))
    .filter((name) => name.endsWith(".mjs"))
    .sort()
    .map((name) => `conformance/src/pubsub-production/cases/${name}`),
]);
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const readJson = (path) => {
  const bytes = readFileSync(path);
  if (bytes.length > 1_048_576) throw new Error("admission proof byte limit");
  return { value: JSON.parse(bytes), digest: sha256(bytes) };
};
const packageJson = (name, from = require) => {
  let root;
  try {
    root = dirname(from.resolve(`${name}/package.json`));
  } catch {
    root = dirname(from.resolve(name));
  }
  for (let i = 0; i < 8; i += 1) {
    try {
      const value = JSON.parse(readFileSync(resolve(root, "package.json")));
      if (value.name === name) return { value, root };
    } catch {
      /* Resolve only public package metadata. */
    }
    root = dirname(root);
  }
  throw new Error("cannot pin loaded SDK package");
};
function installedDependencies() {
  const seen = new Set();
  const pins = [];
  let files = 0;
  let bytes = 0;
  const visit = (name, from) => {
    const pkg = packageJson(name, from);
    const root = realpathSync(pkg.root);
    if (seen.has(root)) return;
    seen.add(root);
    if (seen.size > 256) throw new Error("runtime package bound exceeded");
    const leaves = [];
    const walk = (directory, prefix = "") => {
      for (const leaf of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
        a.name.localeCompare(b.name, "en"),
      )) {
        if (["node_modules", ".git"].includes(leaf.name)) continue;
        const path = resolve(directory, leaf.name);
        const relative = `${prefix}${leaf.name}`;
        if (leaf.isDirectory()) walk(path, `${relative}/`);
        else if (leaf.isFile()) {
          const size = statSync(path).size;
          files += 1;
          bytes += size;
          if (files > 16_384 || bytes > 536_870_912)
            throw new Error("runtime file/byte bound exceeded");
          leaves.push(`${relative}\0${sha256(readFileSync(path))}\n`);
        } else throw new Error("unreviewed symlink in runtime package");
      }
    };
    walk(root);
    pins.push({
      name: pkg.value.name,
      version: pkg.value.version,
      treeSha256: sha256(Buffer.from(leaves.join(""))),
    });
    const next = createRequire(resolve(root, "package.json"));
    for (const dependency of Object.keys(pkg.value.dependencies ?? {}).sort())
      visit(dependency, next);
    for (const dependency of Object.keys(pkg.value.optionalDependencies ?? {}).sort()) {
      try {
        packageJson(dependency, next);
      } catch {
        pins.push({
          name: dependency,
          optionalAbsent: true,
          treeSha256: sha256(Buffer.from("optional-absent")),
        });
        continue;
      }
      visit(dependency, next);
    }
  };
  visit("@google-cloud/pubsub", require);
  visit("@grpc/grpc-js", require);
  pins.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), "en"));
  return pins;
}
export function runtimeIdentity() {
  if (process.execArgv.length || process.env.NODE_OPTIONS || process.env.NODE_PATH)
    throw new Error("unreviewed runtime flags/preload");
  const sdk = packageJson("@google-cloud/pubsub");
  const gax = packageJson("google-gax", createRequire(resolve(sdk.root, "package.json")));
  const grpc = packageJson("@grpc/grpc-js");
  return {
    dependencies: installedDependencies(),
    executionFlags: [],
    node: process.version,
    nodeExecutableSha256: sha256(readFileSync(process.execPath)),
    pubsub: sdk.value.version,
    gax: gax.value.version,
    grpc: grpc.value.version,
    sdkProtoSha256: sha256(readFileSync(resolve(sdk.root, "build/protos/protos.js"))),
    sdkEntrySha256: sha256(readFileSync(require.resolve("@google-cloud/pubsub"))),
    grpcEntrySha256: sha256(readFileSync(require.resolve("@grpc/grpc-js"))),
    gaxEntrySha256: sha256(
      readFileSync(createRequire(resolve(sdk.root, "package.json")).resolve("google-gax")),
    ),
  };
}
export function describeSource() {
  return {
    schema: 1,
    suite: "stream-dlq-v2",
    head: execFileSync("git", ["-C", sourceRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
    runtime: runtimeIdentity(),
    sources: SOURCE_FILES.map((path) => ({
      path,
      sha256: sha256(readFileSync(resolve(sourceRoot, path))),
    })),
  };
}
export function descriptorMatches(descriptor, actual) {
  return (
    descriptor?.schema === 1 &&
    descriptor.suite === "stream-dlq-v2" &&
    descriptor.head === actual.head &&
    JSON.stringify(descriptor.runtime) === JSON.stringify(actual.runtime) &&
    JSON.stringify(descriptor.sources) === JSON.stringify(actual.sources)
  );
}
export function verifyDescriptor(descriptor) {
  const actual = describeSource();
  if (!descriptorMatches(descriptor, actual)) throw new Error("descriptor source/runtime mismatch");
  execFileSync("git", ["-C", sourceRoot, "verify-commit", descriptor.head], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  for (const pin of descriptor.sources) {
    const committed = execFileSync(
      "git",
      ["-C", sourceRoot, "show", `${descriptor.head}:${pin.path}`],
      { maxBuffer: 4_194_304 },
    );
    if (sha256(committed) !== pin.sha256)
      throw new Error("descriptor is not bound to signed commit source bytes");
  }
  return actual;
}

// The coordinator creates the canonical file with O_EXCL immediately before launch.
// It retains the file for recovery and releases it only after matching-envelope PID absence.
const pidAlive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
};
export function verifyLiveLock(
  { path, expectedPath, cleanupOnly = false, pidAlive: alive = pidAlive },
  binding,
) {
  if (typeof path !== "string" || resolve(path) !== expectedPath)
    throw new Error("canonical sandbox lock required");
  const bytes = readFileSync(path);
  if (bytes.length > 1_048_576) throw new Error("oversized sandbox lock");
  const lock = JSON.parse(bytes);
  if (
    lock === null ||
    typeof lock !== "object" ||
    Array.isArray(lock) ||
    !Number.isSafeInteger(lock.pid) ||
    lock.pid <= 0 ||
    (lock.pid !== process.pid && (!cleanupOnly || alive(lock.pid))) ||
    lock.envelopeId !== binding.envelopeId ||
    lock.sourceCommit !== binding.sourceCommit ||
    typeof lock.acquiredAt !== "string" ||
    !Number.isFinite(Date.parse(lock.acquiredAt))
  )
    throw new Error("actual sandbox lock does not match recorder source authority");
  // acquiredAt is descriptive. The coordinator contract deliberately has no lock expiry.
  return lock;
}

export function verifyRunOutput(authority, options) {
  const allowed = options.cleanupOnly
    ? authority.cleanupRecovery?.out
    : authority.runOutputs?.[options.runId];
  if (
    typeof allowed !== "string" ||
    resolve(allowed) !== allowed ||
    resolve(options.out ?? "") !== allowed
  )
    throw new Error("v2 source-bound output mismatch");
  if (
    options.cleanupOnly &&
    resolve(options.fromCapture ?? "") !==
      resolve(authority.runOutputs[options.runId], `capture-${options.runId}.jsonl`)
  )
    throw new Error("v2 recovery original input directory mismatch");
}
export function claimSourceRun({ out, runId }) {
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const fd = openSync(resolve(out, `source-started-${runId}.json`), "wx", 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify({ runId, startedAt: new Date().toISOString() })}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

const proofScopeFields = [
  "kind",
  "state",
  "taskId",
  "envelopeId",
  "sourceHead",
  "descriptorSha256",
  "packetSha256",
  "project",
  "runIds",
  "runOutputs",
  "expiresAt",
  "maxRequestsPerAttempt",
  "cleanupRequests",
  "a2Requests",
  "cleanupRecovery",
  "bInheritedGrants",
];
export const proofScopeDigest = (row) =>
  sha256(JSON.stringify(Object.fromEntries(proofScopeFields.map((key) => [key, row[key]]))));
export function verifyLedgerProof(row, ledgerPath) {
  if (
    !Number.isSafeInteger(row.ledgerLine) ||
    row.ledgerLine <= 0 ||
    !/^[a-f0-9]{64}$/.test(row.ledgerLineSha256 ?? "")
  )
    throw new Error("ledger line binding required");
  const line = readFileSync(ledgerPath, "utf8").split("\n")[row.ledgerLine - 1];
  if (
    typeof line !== "string" ||
    sha256(line) !== row.ledgerLineSha256 ||
    !line.includes(`| PUBSUB-STREAM-DLQ ${row.kind} |`) ||
    !line.includes("decision=APPROVE;") ||
    !line.includes(`envelopeId=${row.envelopeId};`) ||
    !line.includes(`scopeSha256=${proofScopeDigest(row)} `)
  )
    throw new Error("ledger line does not approve the exported scope");
}

export function verifyAuthority(
  authority,
  descriptor,
  descriptorDigest,
  options,
  now = Date.now(),
) {
  if (
    authority.schema !== 1 ||
    authority.taskId !== "PUBSUB-STREAM-DLQ" ||
    authority.suite !== "stream-dlq-v2" ||
    typeof authority.envelopeId !== "string" ||
    !/^[A-Z][A-Z0-9-]{3,95}$/.test(authority.envelopeId) ||
    authority.sourceHead !== descriptor.head ||
    authority.descriptorSha256 !== descriptorDigest ||
    !/^[a-f0-9]{64}$/.test(authority.packetSha256 ?? "") ||
    authority.project !== options.project ||
    !Array.isArray(authority.runIds) ||
    authority.runIds.length !== 2 ||
    new Set(authority.runIds).size !== 2 ||
    authority.runIds.some((run) => !/^[a-f0-9]{12}$/.test(run)) ||
    !authority.runIds.includes(options.runId) ||
    !Number.isFinite(Date.parse(authority.expiresAt)) ||
    Date.parse(authority.expiresAt) <= now ||
    authority.iamWaitAfterGrantMs !== 900_000 ||
    authority.iamPhaseMs !== 1_800_000 ||
    authority.iamConvergenceClaim !== false ||
    authority.maxRequestsPerAttempt !== 228 ||
    authority.cleanupRequests !== 600 ||
    authority.a2Requests !== 600 ||
    !/^serviceAccount:service-\d{1,20}@gcp-sa-pubsub\.iam\.gserviceaccount\.com$/.test(
      authority.serviceAgent ?? "",
    ) ||
    authority.serviceAgent !== options.serviceAgent ||
    authority.bInheritedGrants !== "UNAUDITED"
  )
    throw new Error("source-bound coordinator authority missing or mismatched");
  if (
    !authority.runOutputs ||
    JSON.stringify(Object.keys(authority.runOutputs).sort()) !==
      JSON.stringify([...authority.runIds].sort()) ||
    new Set(Object.values(authority.runOutputs)).size !== 2
  )
    throw new Error("v2 source-bound output identities missing");
  verifyRunOutput(authority, options);
  const packet = readJson(authority.packetPath);
  if (packet.digest !== authority.packetSha256) throw new Error("packet digest mismatch");
  const commonGit = execFileSync(
    "git",
    ["-C", sourceRoot, "rev-parse", "--path-format=absolute", "--git-common-dir"],
    { encoding: "utf8" },
  ).trim();
  for (const kind of ["E", "V"]) {
    const proof = readJson(authority[kind]?.path);
    const row = proof.value;
    if (
      proof.digest !== authority[kind]?.sha256 ||
      row.kind !== kind ||
      row.state !== "APPROVED" ||
      row.taskId !== authority.taskId ||
      row.envelopeId !== authority.envelopeId ||
      row.sourceHead !== descriptor.head ||
      row.descriptorSha256 !== descriptorDigest ||
      row.packetSha256 !== authority.packetSha256 ||
      row.project !== options.project ||
      JSON.stringify(row.runIds) !== JSON.stringify(authority.runIds) ||
      row.expiresAt !== authority.expiresAt ||
      row.maxRequestsPerAttempt !== 228 ||
      row.cleanupRequests !== 600 ||
      row.a2Requests !== 600 ||
      JSON.stringify(row.runOutputs) !== JSON.stringify(authority.runOutputs) ||
      row.bInheritedGrants !== authority.bInheritedGrants ||
      JSON.stringify(row.cleanupRecovery) !== JSON.stringify(authority.cleanupRecovery)
    )
      throw new Error(`${kind} authority proof mismatch`);
    verifyLedgerProof(
      row,
      resolve(dirname(commonGit), "docs.local/instructions/owner-decisions.md"),
    );
  }
  const canonical = resolve(
    dirname(commonGit),
    "docs.local/runs/sandbox-locks",
    `${options.project}.lock`,
  );
  verifyLiveLock(
    {
      path: authority.lockPath,
      expectedPath: canonical,
      cleanupOnly: options.cleanupOnly === true,
    },
    { envelopeId: authority.envelopeId, sourceCommit: descriptor.head },
  );
  if (authority.runIds[1] === options.runId) {
    const prior = readJson(authority.previousAttempt?.path);
    if (
      prior.digest !== authority.previousAttempt?.sha256 ||
      prior.value.runId !== authority.runIds[0] ||
      prior.value.closureReady !== true ||
      prior.value.project !== options.project ||
      prior.value.sourceHead !== descriptor.head ||
      prior.value.envelopeId !== authority.envelopeId
    )
      throw new Error("fresh attempt2 requires closed attempt1");
  }
  return authority;
}
export function admitV2(options, now = Date.now()) {
  if (!options.descriptor || !options.authority)
    throw new Error("v2 production needs --descriptor and --authority");
  const descriptor = readJson(options.descriptor);
  verifyDescriptor(descriptor.value);
  const authority = readJson(options.authority);
  return verifyAuthority(authority.value, descriptor.value, descriptor.digest, options, now);
}
