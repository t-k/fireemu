import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import {
  SOURCE_FILES as inheritedSources,
  runtimeIdentity,
  sha256,
  verifyLiveLock,
} from "../pubsub-production/admission.mjs";
import { SUITE, TASK, PROJECT, makePlan, validatePlan } from "./plan.mjs";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
export const SOURCE_FILES = Object.freeze([
  ...inheritedSources,
  ...[
    "admission",
    "credentials",
    "journal",
    "metadata",
    "meter",
    "payload",
    "plan",
    "record",
    "scenarios",
    "stream",
    "wire",
  ].map((name) => `conformance/src/pubsub-observation/${name}.mjs`),
  "conformance/src/pubsub-production-observation-a.test.mjs",
  "conformance/src/pubsub-observation/fixtures/recorded-resources.json",
]);
const git = (...args) =>
  execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 4194304 }).trim();
export function describeSource() {
  return {
    schema: 1,
    suite: SUITE,
    head: git("rev-parse", "HEAD"),
    runtime: runtimeIdentity(),
    sources: SOURCE_FILES.map((path) => ({
      path,
      sha256: sha256(readFileSync(resolve(root, path))),
    })),
  };
}
export function verifyDescriptor(descriptor) {
  const actual = describeSource();
  if (JSON.stringify(descriptor) !== JSON.stringify(actual))
    throw new Error("descriptor source/runtime mismatch");
  git("verify-commit", descriptor.head);
  for (const pin of descriptor.sources)
    if (
      sha256(
        execFileSync("git", ["-C", root, "show", `${descriptor.head}:${pin.path}`], {
          maxBuffer: 4194304,
        }),
      ) !== pin.sha256
    )
      throw new Error("descriptor lacks signed source bytes");
  return actual;
}
const fields = [
  "taskId",
  "suite",
  "envelopeId",
  "sourceHead",
  "descriptorSha256",
  "packetSha256",
  "project",
  "runIds",
  "runOutputs",
  "recoveryOutputs",
  "expiresAt",
  "plan",
  "recoveryBindings",
  "previousAttempt",
];
const projectScope = (value) => Object.fromEntries(fields.map((key) => [key, value[key]]));
export const scopeDigest = (value) =>
  sha256(JSON.stringify({ kind: value.kind, ...projectScope(value) }));
export function verifyScope(scope, descriptor, digest, options, now = Date.now()) {
  validatePlan(scope.plan);
  if (
    scope.taskId !== TASK ||
    scope.suite !== SUITE ||
    scope.project !== PROJECT ||
    !/^[A-Z][A-Z0-9-]{3,95}$/.test(scope.envelopeId ?? "") ||
    scope.sourceHead !== descriptor.head ||
    scope.descriptorSha256 !== digest ||
    !/^[a-f0-9]{64}$/.test(scope.packetSha256 ?? "") ||
    !Array.isArray(scope.runIds) ||
    scope.runIds.length !== 2 ||
    new Set(scope.runIds).size !== 2 ||
    scope.runIds.some((id) => !/^[a-f0-9]{12}$/.test(id)) ||
    !scope.runIds.includes(options.runId) ||
    !Number.isFinite(Date.parse(scope.expiresAt)) ||
    Date.parse(scope.expiresAt) <= now
  )
    throw new Error("source-bound scope mismatch");
  for (const key of ["runOutputs", "recoveryOutputs"])
    if (
      !scope[key] ||
      JSON.stringify(Object.keys(scope[key]).sort()) !== JSON.stringify([...scope.runIds].sort()) ||
      Object.values(scope[key]).some((path) => typeof path !== "string" || resolve(path) !== path)
    )
      throw new Error("absolute output scope required");
  const all = [...Object.values(scope.runOutputs), ...Object.values(scope.recoveryOutputs)];
  if (
    new Set(all).size !== 4 ||
    all.some((a, index) => all.some((b, j) => index !== j && b.startsWith(`${a}/`)))
  )
    throw new Error("distinct output scope required");
  if (
    resolve(options.out ?? "") !==
    (options.a2 ? scope.recoveryOutputs : scope.runOutputs)[options.runId]
  )
    throw new Error("output scope mismatch");
  return scope;
}
export function verifyProof(row, line, scope, kind) {
  if (
    row.kind !== kind ||
    row.state !== "APPROVED" ||
    JSON.stringify(projectScope(row)) !== JSON.stringify(projectScope(scope))
  )
    throw new Error("proof scope mismatch");
  const label = kind === "E" ? `${TASK} envelope` : TASK;
  if (
    typeof line !== "string" ||
    !line.includes(`| ${label} |`) ||
    !line.includes("decision=APPROVE;") ||
    !line.includes(`envelopeId=${scope.envelopeId};`) ||
    !line.includes(`scopeSha256=${scopeDigest(row)} `)
  )
    throw new Error("ledger does not approve exact scope");
}
export function readJson(path) {
  const bytes = readFileSync(path);
  if (bytes.length > 4194304) throw new Error("admission file byte cap");
  return { value: JSON.parse(bytes), sha256: sha256(bytes) };
}
export function admit(options, now = Date.now()) {
  const descriptorFile = readJson(options.descriptor),
    descriptor = descriptorFile.value;
  verifyDescriptor(descriptor);
  const scope = readJson(options.authority).value;
  verifyScope(scope, descriptor, descriptorFile.sha256, options, now);
  const packet = readJson(options.packet);
  if (
    packet.sha256 !== scope.packetSha256 ||
    packet.value.schema !== 1 ||
    packet.value.taskId !== TASK ||
    packet.value.version !== "v1" ||
    packet.value.sourceHead !== descriptor.head ||
    packet.value.descriptorSha256 !== descriptorFile.sha256 ||
    JSON.stringify(packet.value.runIds) !== JSON.stringify(scope.runIds) ||
    JSON.stringify(packet.value.runOutputs) !== JSON.stringify(scope.runOutputs) ||
    JSON.stringify(packet.value.recoveryOutputs) !== JSON.stringify(scope.recoveryOutputs)
  )
    throw new Error("packet identity mismatch");
  validatePlan(packet.value.plan);
  const main = dirname(git("rev-parse", "--path-format=absolute", "--git-common-dir"));
  const ledgerPath = resolve(main, "docs.local/instructions/owner-decisions.md");
  for (const kind of ["E", "V"]) {
    const file = readJson(options[kind]);
    const row = file.value;
    if (
      scope[kind]?.sha256 !== file.sha256 ||
      !Number.isSafeInteger(row.ledgerLine) ||
      row.ledgerLine < 1 ||
      !/^[a-f0-9]{64}$/.test(row.ledgerLineSha256 ?? "")
    )
      throw new Error("approved ledger export required");
    const line = readFileSync(ledgerPath, "utf8").split("\n")[row.ledgerLine - 1];
    if (typeof line !== "string" || sha256(line) !== row.ledgerLineSha256)
      throw new Error("actual ledger line mismatch");
    verifyProof(row, line, scope, kind);
  }
  const canonical = resolve(main, "docs.local/runs/sandbox-locks", `${PROJECT}.lock`);
  const check = () => {
    if (Date.now() >= Date.parse(scope.expiresAt) || git("rev-parse", "HEAD") !== descriptor.head)
      throw new Error("authority expired or source HEAD changed");
    for (const pin of descriptor.sources)
      if (sha256(readFileSync(resolve(root, pin.path))) !== pin.sha256)
        throw new Error("loaded source pin changed");
    verifyLiveLock(
      { path: options.lock, expectedPath: canonical, cleanupOnly: options.a2 },
      { envelopeId: scope.envelopeId, sourceCommit: descriptor.head },
    );
  };
  check();
  if (!options.a2 && options.runId === scope.runIds[1]) {
    if (
      scope.previousAttempt?.path !==
      resolve(scope.runOutputs[scope.runIds[0]], `summary-${scope.runIds[0]}.json`)
    )
      throw new Error("run2 prior summary path mismatch");
    const previous = readJson(scope.previousAttempt?.path);
    if (
      previous.sha256 !== scope.previousAttempt?.sha256 ||
      previous.value.runId !== scope.runIds[0] ||
      previous.value.sourceHead !== descriptor.head ||
      previous.value.envelopeId !== scope.envelopeId ||
      previous.value.packetSha256 !== scope.packetSha256 ||
      previous.value.resourcesClosed !== true ||
      previous.value.recordingComplete !== true
    )
      throw new Error("run2 requires complete closed run1");
  }
  return { scope, descriptor, descriptorSha256: descriptorFile.sha256, check, plan: makePlan() };
}
