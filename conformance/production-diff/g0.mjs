import { execFileSync } from "node:child_process";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { digestJson, requireThat, sha256 } from "./core.mjs";
import { gitState, readSource } from "./io.mjs";
import { compileFrozenG0Plan } from "./g0-plan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const G0_PRODUCTION_SHA256 =
  "47672f4e3162b4a0ddfb7baaab622007602aeed6c1fa3d6e5e84034bcbb87772";

const adapterFiles = ["g0-plan.mjs", "g0-session.mjs", "g0.mjs", "pilot.mjs", "registry.mjs"];

async function sourceDigests() {
  const output = {};
  for (const name of adapterFiles) output[name] = sha256(await readSource(HERE, name));
  return output;
}

export function validateBuildBinding(repo, artifact) {
  const manifest = process.env.G0_BUILD_MANIFEST;
  const profile = process.env.G0_ARTIFACT_PROFILE;
  requireThat(typeof artifact === "string" && artifact.startsWith("/"), "g0-build-provenance-unavailable");
  requireThat(typeof manifest === "string" && manifest.startsWith("/"), "g0-build-provenance-unavailable");
  requireThat(typeof profile === "string" && /^[a-z0-9][a-z0-9-]{1,80}$/.test(profile), "g0-build-provenance-unavailable");
  const script = [
    "import json,sys",
    "from pathlib import Path",
    "sys.path.insert(0, sys.argv[1])",
    "from owned_transform_runner import validate_current_g0_artifact",
    "result=validate_current_g0_artifact(Path(sys.argv[2]),Path(sys.argv[3]),profile=sys.argv[4],repo=Path(sys.argv[5]))",
    "print(json.dumps({k:result[k] for k in ('artifactSha256','runtimeSourceCommit','currentSourceCommit','sourceInputsDigest','currentInputsDigest','retainedManifestSha256','artifactProfile')}))",
  ].join("; ");
  try {
    const output = execFileSync(
      "uv",
      ["run", "python", "-c", script, `${repo}/tools/compat-broad/fs-commit-transform-limits`, artifact, manifest, profile, repo],
      { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    return JSON.parse(output);
  } catch {
    throw new Error("g0-build-provenance-refused");
  }
}

export async function prepareG0(repo, entry, artifact = null, requireBuild = false) {
  const state = gitState(repo);
  const productionPath = process.env[entry.productionResultPath];
  requireThat(typeof productionPath === "string" && productionPath.startsWith("/"), "g0-production-input-unavailable");
  const bytes = await readSource(dirname(productionPath), basename(productionPath), 4 * 1024 * 1024).catch(() => null);
  requireThat(bytes && sha256(bytes) === G0_PRODUCTION_SHA256, "g0-production-input-unavailable");
  const program = compileFrozenG0Plan(repo, entry.nonce);
  requireThat(
    Object.values(program.jobs).reduce((total, job) => total + job.observation.length, 0) === 12,
    "g0-observation-shape",
  );
  const retainedArtifact = artifact ?? process.env.G0_RETAINED_ARTIFACT ?? null;
  if (requireBuild) requireThat(retainedArtifact, "g0-build-provenance-unavailable");
  return {
    entry,
    state,
    program,
    production: {
      kind: "pinned-normalized-g0-reference",
      sha256: G0_PRODUCTION_SHA256,
      path: entry.productionResultPath,
    },
    provenance: {
      repository: state,
      oracle: {
        path: entry.productionResultPath,
        sha256: G0_PRODUCTION_SHA256,
        historicalRawAvailable: true,
        normalization: "shared-g0-batchwrite-status-resource-v1",
        byteExact: false,
      },
      implementation: {
        adapterSha256: await sourceDigests(),
        comparator: "tools/compat-broad/shared_production_pair.py:compare_g0_current_runtime_recompare",
        frozenRecipe: "tools/compat-broad/shared_production_pair.py:frozen_g0_manifest",
        build: retainedArtifact ? validateBuildBinding(repo, retainedArtifact) : null,
      },
    },
  };
}

function invokeComparator(repo, productionPath, local, runtime) {
  const script = [
    "import json,sys",
    "sys.path.insert(0, sys.argv[1])",
    "from shared_production_pair import compare_g0_current_runtime_recompare",
    "local=json.loads(sys.stdin.buffer.read())",
    "result=compare_g0_current_runtime_recompare(sys.argv[2],local,sys.argv[3],json.loads(sys.argv[4]))",
    "print(json.dumps({'compatibility':result['compatibility'],'rows':[{'job':r['job'],'index':r['index'],'verdict':r['verdict']} for r in result['rows']],'reason':result.get('reason')}))",
  ].join("; ");
  let output;
  try {
    output = execFileSync(
      "uv",
      ["run", "python", "-c", script, `${repo}/tools/compat-broad`, productionPath, repo, JSON.stringify(runtime)],
      { cwd: repo, input: JSON.stringify(local), encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
    );
  } catch {
    throw new Error("g0-comparator-refused");
  }
  try {
    return JSON.parse(output);
  } catch {
    throw new Error("g0-comparator-invalid-result");
  }
}

export function compareG0({ repo, entry, actual, execution, build }) {
  requireThat(actual && typeof actual === "object", "g0-local-record-shape");
  requireThat(build?.artifactSha256 === execution?.artifact?.sha256, "g0-artifact-receipt-mismatch");
  const result = invokeComparator(
    repo,
    process.env[entry.productionResultPath],
    actual,
    { artifactSha256: execution?.artifact?.sha256 },
  );
  const rows = result.rows.map((row) => ({
    stepId: `${row.job}:${row.index}`,
    comparison: row.verdict.toUpperCase(),
    production: { redacted: true },
    local: { redacted: true },
  }));
  const counts = { match: 0, mismatch: 0, indeterminate: 0 };
  for (const row of rows) counts[row.comparison.toLowerCase()]++;
  return {
    verdict: result.compatibility === "match" ? "MATCH" : "MISMATCH",
    counts,
    rows,
    issues: result.reason ? [result.reason] : [],
    legacySummary: null,
    legacyMismatchesIncludesIndeterminate: false,
  };
}

export function g0ProgramDigest(program) {
  return digestJson(program);
}

export async function g0SourceUnchanged(repo, before, adapterBefore) {
  try {
    const after = gitState(repo);
    return after.head === before.head && !after.dirty && digestJson(await sourceDigests()) === digestJson(adapterBefore);
  } catch {
    return false;
  }
}
