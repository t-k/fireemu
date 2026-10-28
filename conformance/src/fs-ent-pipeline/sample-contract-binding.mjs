import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";
import { createContext, normalizeStep, resolveValue, sameRecording } from "./harness.mjs";
import { evaluateSample } from "./sample-contract.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fixed = {
  fixture: "8312d30849afcd19f06125ee5fdb2b05afa96a185efbc2982c982b44a663a27b",
  requests: "8e0591940bd2fb6f879ef02609dff2ab2285ef3f27729fec7092a0b1b4917a17",
  production1: "6a5559c471d4778fe1416bcf330e9ca018ea6515c91dd659b8b070e8bf5d1166",
  production2: "7e5f89169e19e618a4df14ed42e1bb11fb96e5a4a0d4eeca757db1c5768c6516",
  policy: "f69d6502fff4ae4b9f9c57a84d6a3672bb59d9d875d412197987fe8c6b2e2a33",
  predicate: "cca84cef6a651b18aee56972f9e62b47e4f9bd92397706aeaa56cb1783451a7f",
  harness: "0f665a00e57ffd09fed301ac6d47cdf93b1d8633536c909eaf5ee06c24aa32d3",
  runtimeSource: "3f119d74906c7d56be90edbe7e1f287bc9d0d87183c12755781e0c898b888e92",
  runtimeTests: "1b9896f018a0a179c6160c0d0613ef63dd31dac8228b26e88c64db33b0f2591f",
  runtimeIndex: "a3f6be6c9f1341a48aedec8d738ceac5afdd6f4fbb6b4f9ac0bb384d28eecaf9",
  runtimeLog: "05e50c4b9823e09d6d2c30ef6f234460e69e32d4efee3b5fc538a559b8ba0cc4",
};
const source = "8220a36ad88c136592551ebb94f358d6abe4d909";
const parse = (bytes) => JSON.parse(bytes.toString("utf8"));
function requireThat(value, message) {
  if (!value) throw Error(message);
}
export function checkIdentity(rows, ids, summary) {
  if (
    !Array.isArray(rows) ||
    !Array.isArray(ids) ||
    rows.length !== ids.length ||
    new Set(ids).size !== ids.length
  )
    return false;
  const seen = new Set(),
    counts = {};
  for (const row of rows) {
    if (seen.has(row.row) || !ids.includes(row.row)) return false;
    seen.add(row.row);
    counts[row.status] = (counts[row.status] ?? 0) + 1;
  }
  return isDeepStrictEqual(counts, summary);
}
export function checkConfig(config) {
  return (
    config?.profile === "strict" &&
    config.productionExact === true &&
    config.firestore?.edition === "enterprise" &&
    config.firestore?.apiMode === "native"
  );
}
export function checkBuild(index, receipt, binary, expectedBinary, checklog) {
  return (
    index?.sourceCommit === source &&
    receipt?.sourceCommit === source &&
    index.binarySha256 === expectedBinary &&
    receipt.binarySha256 === expectedBinary &&
    sha(binary) === expectedBinary &&
    checklog.includes("profile: strict")
  );
}
export function rawResponse(raw) {
  if (
    raw?.transport !== "rest" ||
    typeof raw.response?.text !== "string" ||
    raw.response.status !== 200 ||
    raw.response.transportError !== undefined
  )
    throw Error("raw REST response");
  const body = JSON.parse(raw.response.text);
  return { status: raw.response.status, body };
}
function context(recording, kind) {
  return createContext({
    run: recording.context.run,
    startedMs: recording.context.startedMs,
    database: "entpipe1",
    target:
      kind === "production"
        ? { kind: "production", token: "offline", quotaProject: "fireemu-oracle-query" }
        : { kind: "local", origin: "http://127.0.0.1:1", grpcHost: "127.0.0.1", grpcPort: 1 },
  });
}
export function normalizeProgram(recording, program, kind) {
  const ctx = context(recording, kind),
    saved = recording.results[program.id],
    anchors = new Map(),
    output = {};
  requireThat(saved, "missing program");
  for (const step of program.steps) {
    const raw = saved.raw?.[step.id];
    if (!raw) continue;
    const normalized = normalizeStep(raw, ctx, anchors);
    requireThat(sameRecording(normalized, saved.steps[step.id]), "normalization mapping");
    output[step.id] = { raw, normalized };
  }
  return { ctx, rows: output };
}
export function checkCandidate(bytes, candidate) {
  requireThat(
    candidate?.profile === "strict" &&
      candidate.sourceCommit === source &&
      /^[a-f0-9]{64}$/.test(candidate.indexSha256 ?? ""),
    "candidate identity",
  );
  requireThat(bytes.index && sha(bytes.index) === candidate.indexSha256, "index hash");
  for (const [name, digest] of Object.entries(fixed))
    requireThat(bytes[name] && sha(bytes[name]) === digest, `fixed hash ${name}`);
  for (const [name, path] of [
    ["policy", "./finitepolicy.json"],
    ["predicate", "./sample-contract.mjs"],
    ["harness", "./harness.mjs"],
  ])
    requireThat(
      sha(readFileSync(new URL(path, import.meta.url))) === fixed[name],
      `loaded ${name}`,
    );
  const index = parse(bytes.index);
  requireThat(
    index.sourceCommit === source && index.binarySha256 === candidate.binarySha256,
    "index source/binary",
  );
  const names = [
    "receipt",
    "binary",
    "compact",
    "detail",
    "local",
    "programs",
    "config",
    "checklog",
    "launch",
    "native",
    "sessionReceipt",
  ];
  requireThat(
    Array.isArray(index.artifacts) &&
      new Set(index.artifacts.map((a) => a.path)).size === index.artifacts.length,
    "index artifacts",
  );
  for (const name of names) {
    const pin = candidate.files?.[name];
    requireThat(pin && bytes[name] && sha(bytes[name]) === pin.sha256, `candidate hash ${name}`);
    if (name !== "config") {
      const item = index.artifacts.find((a) => a.path === pin.indexKey);
      requireThat(
        item && item.sha256 === pin.sha256 && item.bytes === bytes[name].length,
        `custody ${name}`,
      );
    }
  }
  const recordedPrograms = parse(bytes.programs);
  const launch = parse(bytes.launch),
    sessionReceipt = parse(bytes.sessionReceipt);
  const receipt = parse(bytes.receipt),
    compact = parse(bytes.compact),
    detail = parse(bytes.detail),
    local = parse(bytes.local),
    requests = parse(bytes.requests),
    fixture = parse(bytes.fixture),
    policy = parse(bytes.policy),
    production1 = parse(bytes.production1),
    production2 = parse(bytes.production2),
    runtimeIndex = parse(bytes.runtimeIndex);
  requireThat(
    checkBuild(
      index,
      receipt,
      bytes.binary,
      candidate.binarySha256,
      bytes.checklog.toString("utf8"),
    ) && checkConfig(parse(bytes.config)),
    "actual source/profile",
  );
  requireThat(
    launch.source === source &&
      launch.binarySha256 === candidate.binarySha256 &&
      launch.configSha256 === sha(bytes.config) &&
      launch.environment?.FIREEMU_SANDBOX_LANE === "fs-ent-pipeline" &&
      typeof launch.environment?.FIREEMU_BIN === "string" &&
      bytes.native.toString("utf8").includes(launch.environment.FIREEMU_BIN) &&
      sessionReceipt.binarySha256 === candidate.binarySha256 &&
      sessionReceipt.rows === 1951 &&
      sessionReceipt.exit === 1,
    "launch custody",
  );
  for (const name of ["compact", "detail", "local", "programs", "launch", "native", "checklog"]) {
    const pin = candidate.files[name];
    requireThat(
      sessionReceipt.outputs[pin.indexKey.split("/").at(-1)] === pin.sha256,
      `session custody ${name}`,
    );
  }
  requireThat(
    runtimeIndex.source === "5840105f1cd113568c683d6504b7cfde80e8d491" &&
      runtimeIndex.artifacts.some((a) => a.sha256 === fixed.runtimeLog),
    "runtime evidence",
  );
  const ids = compact.rows.map((x) => x.row);
  requireThat(
    ids.length === 1951 &&
      checkIdentity(compact.rows, ids, compact.summary) &&
      checkIdentity(detail.rows, ids, compact.summary) &&
      isDeepStrictEqual(detail.summary, compact.summary) &&
      isDeepStrictEqual(index.firestore?.strict, compact.summary) &&
      isDeepStrictEqual(sessionReceipt.summary, compact.summary),
    "identity/counts",
  );
  const statuses = new Map(compact.rows.map((x) => [x.row, x.status]));
  requireThat(
    detail.rows.every((x) => statuses.get(x.row) === x.status) &&
      compact.artifactSha256 === candidate.binarySha256 &&
      detail.artifactSha256 === candidate.binarySha256 &&
      detail.failures.length === 0 &&
      detail.orphans.length === 0,
    "comparison provenance",
  );
  const id = "fs-ent-pipeline/o8d/stages-main",
    program = requests.programs.find((p) => p.id === id);
  requireThat(
    program &&
      Array.isArray(recordedPrograms) &&
      recordedPrograms.filter((p) => p.id === id).length === 1 &&
      isDeepStrictEqual(
        recordedPrograms.find((p) => p.id === id),
        program,
      ),
    "program binding",
  );
  requireThat(
    program && policy.recipes.length === 8 && new Set(policy.recipes.map((p) => p.id)).size === 8,
    "recipe identity",
  );
  const companionRequest = program.steps.find((s) => s.id === "sample-percent-100"),
    companion = fixture.programs[id].steps[companionRequest.id];
  // Force raw LIVE checks for every selected request before invoking the shared normalizer.
  for (const [recording, kind] of [
    [production1, "production"],
    [production2, "production"],
    [local, "local"],
  ]) {
    const saved = recording.results[id],
      ctx = context(recording, kind);
    requireThat(saved, "missing raw program");
    for (const p of policy.recipes) {
      const sid = p.id.split("#")[1],
        request = program.steps.find((s) => s.id === sid),
        raw = saved.raw?.[sid];
      requireThat(
        raw && isDeepStrictEqual(raw.request, resolveValue(request.body, ctx, new Map())),
        "raw request binding",
      );
      requireThat(
        evaluateSample({
          id: p.id,
          profile: "strict",
          request,
          seed: program.seed,
          companionRequest,
          companion,
          role: "live",
          response: rawResponse(raw),
        }),
        "raw live sample",
      );
    }
  }
  const rec = [
    normalizeProgram(production1, program, "production"),
    normalizeProgram(production2, program, "production"),
    normalizeProgram(local, program, "local"),
  ];
  const results = [];
  for (const p of policy.recipes) {
    const stepId = p.id.split("#")[1],
      request = program.steps.find((s) => s.id === stepId),
      row = detail.rows.find((x) => x.row === p.id),
      fixtureRow = fixture.programs[id].steps[stepId],
      alternate = fixture.programs[id].second?.[stepId];
    requireThat(
      row &&
        request &&
        rec.every((x) => x.rows[stepId]) &&
        rec.every((x) =>
          isDeepStrictEqual(
            x.rows[stepId].raw.request,
            resolveValue(request.body, x.ctx, new Map()),
          ),
        ),
      "raw request binding",
    );
    const [r1, r2, actual] = rec.map((x) => x.rows[stepId]);
    requireThat(
      sameRecording(r1.normalized, fixtureRow) &&
        sameRecording(r2.normalized, alternate ?? fixtureRow) &&
        sameRecording(row.production, r1.normalized) &&
        sameRecording(row.fireemu, actual.normalized),
      "normalized mapping",
    );
    const input = {
      id: p.id,
      profile: "strict",
      request,
      seed: program.seed,
      companionRequest,
      companion,
      role: "live",
    };
    const proofs = [r1, r2, actual].map((x) =>
      evaluateSample({ ...input, response: rawResponse(x.raw) }),
    );
    requireThat(proofs.every(Boolean), "live sample contract");
    const localCompanion = rec[2].rows["sample-percent-100"];
    requireThat(
      localCompanion &&
        evaluateSample({
          ...input,
          id: policy.recipes.find((x) => x.id.endsWith("#sample-percent-100")).id,
          request: companionRequest,
          response: rawResponse(localCompanion.raw),
        }),
      "local companion order",
    );
    results.push({
      id: p.id,
      rawStatus: row.status,
      proofClassification: "FINITE_SAMPLE_CONTRACT",
      productionAvailableAlternate: Boolean(alternate),
      outputCount: proofs[2].outputCount,
    });
  }
  return {
    kind: "sample-contract-candidate-v1",
    binding: "PENDING_REVIEW",
    sourceCommit: source,
    binarySha256: candidate.binarySha256,
    indexSha256: candidate.indexSha256,
    profile: "strict",
    proofs: results,
    rawSummary: compact.summary,
    hashes: Object.fromEntries(Object.entries(bytes).map(([k, v]) => [k, sha(v)])),
    runtimeEvidence: {
      source: fixed.runtimeSource,
      tests: fixed.runtimeTests,
      index: fixed.runtimeIndex,
      log: fixed.runtimeLog,
      scope: "reviewed source properties; no inference from one sample",
    },
    scope:
      "raw timestamp and frame guards precede normalized mapping; no distribution or raw-byte equality claim",
  };
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const options = parse(readFileSync(process.argv[2]));
  const bytes = Object.fromEntries(
    Object.entries(options.paths).map(([k, p]) => [k, readFileSync(p)]),
  );
  process.stdout.write(JSON.stringify(checkCandidate(bytes, options.candidate), null, 2) + "\n");
}
