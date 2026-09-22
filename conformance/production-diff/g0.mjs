import { execFileSync } from "node:child_process";
import { closeSync, openSync, readSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { digestJson, object, requireThat, sha256 } from "./core.mjs";
import { gitState, readSource } from "./io.mjs";
import { compileFrozenG0Plan } from "./g0-plan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const G0_PRODUCTION_SHA256 =
  "47672f4e3162b4a0ddfb7baaab622007602aeed6c1fa3d6e5e84034bcbb87772";

export function validateG0Origins(env) {
  const values = {
    firestore: env?.FIRESTORE_EMULATOR_HOST,
    auth: env?.FIREBASE_AUTH_EMULATOR_HOST,
  };
  for (const value of Object.values(values))
    requireThat(/^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(value ?? ""), "g0-owned-origin-required");
  return values;
}

export function canonicalG0Origins(env) {
  return Object.fromEntries(Object.entries(validateG0Origins(env)).map(([service, host]) => [service, `http://${host}`]));
}

// Local probe limits, not OS/Firebase limits. G0 launches far fewer arguments.
const PROCESS_ARGV_MAX_BYTES = 128 * 1024;
const PROCESS_ARGV_MAX_COUNT = 4096;

/** Decode observed arguments without dropping empty strings or inventing argv[0]. */
export function decodeProcessArgv(raw, platform) {
  requireThat(
    Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= PROCESS_ARGV_MAX_BYTES,
    "g0-process-argv-invalid",
  );
  // A literal UTF-8 BOM belongs to an argument; never strip it or replace bad bytes.
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  if (platform === "linux") {
    requireThat(raw.at(-1) === 0, "g0-process-argv-invalid");
    const args = decoder.decode(raw.subarray(0, -1)).split("\0");
    requireThat(args.length <= PROCESS_ARGV_MAX_COUNT, "g0-process-argv-invalid");
    return args;
  }
  requireThat(platform === "darwin" && raw.length >= 4, "g0-process-argv-invalid");
  const argc = raw.readInt32LE(0); // Supported macOS targets: native arm64/x64.
  requireThat(argc > 0 && argc <= PROCESS_ARGV_MAX_COUNT, "g0-process-argv-invalid");
  const execEnd = raw.indexOf(0, 4);
  requireThat(execEnd > 4, "g0-process-argv-invalid");
  // XNU exec_extract_strings pads (executable_path= + path + NUL) to the
  // target pointer width. KERN_PROCARGS2 strips the 16-byte prefix and prepends
  // argc. For 64-bit targets the argv area starts at this aligned offset.
  // Do not skip arbitrary NULs: those may be leading empty arguments.
  const pathBytes = execEnd - 4 + 1;
  let offset = 4 + Math.ceil(pathBytes / 8) * 8;
  requireThat(offset < raw.length, "g0-process-argv-invalid");
  requireThat(raw.subarray(execEnd + 1, offset).every((b) => b === 0), "g0-process-argv-invalid");
  const args = [];
  for (let i = 0; i < argc; i++) {
    const end = raw.indexOf(0, offset);
    requireThat(end >= offset, "g0-process-argv-invalid");
    args.push(decoder.decode(raw.subarray(offset, end)));
    offset = end + 1;
  }
  // Bytes after argc strings may contain environment variables: never return them.
  return args;
}

function readProcCmdline(pid) {
  const fd = openSync(`/proc/${pid}/cmdline`, "r");
  try {
    const data = Buffer.alloc(PROCESS_ARGV_MAX_BYTES + 1);
    let used = 0;
    while (used < data.length) {
      const count = readSync(fd, data, used, data.length - used, null);
      if (count === 0) break;
      used += count;
    }
    return data.subarray(0, used);
  } finally {
    closeSync(fd);
  }
}

export function readOwnedProcessArgv(pid) {
  if (!Number.isInteger(pid) || pid <= 0 || pid > 2147483647) return null;
  try {
    if (process.platform === "linux") return decodeProcessArgv(readProcCmdline(pid), "linux");
    if (process.platform === "darwin" && ["arm64", "x64"].includes(process.arch)) {
      const source = [
        "import ctypes,sys",
        "pid=int(sys.argv[1]); libc=ctypes.CDLL(None); mib=(ctypes.c_int*3)(1,49,pid); size=ctypes.c_size_t(0)",
        "libc.sysctl.argtypes=[ctypes.POINTER(ctypes.c_int),ctypes.c_uint,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]",
        "libc.sysctl.restype=ctypes.c_int",
        "if libc.sysctl(mib,3,None,ctypes.byref(size),None,0)!=0: raise OSError()",
        `if not 4 < size.value <= ${PROCESS_ARGV_MAX_BYTES}: raise ValueError()`,
        "capacity=size.value; buffer=ctypes.create_string_buffer(capacity)",
        "if libc.sysctl(mib,3,buffer,ctypes.byref(size),None,0)!=0: raise OSError()",
        "if not 4 < size.value <= capacity: raise ValueError()",
        "sys.stdout.buffer.write(buffer.raw[:size.value])",
      ].join("\n");
      // Isolated Python; no shell, no stderr/body logging, bounded helper lifetime.
      const raw = execFileSync("python3", ["-I", "-c", source, String(pid)], {
        timeout: 5000, killSignal: "SIGKILL", maxBuffer: PROCESS_ARGV_MAX_BYTES,
        stdio: ["ignore", "pipe", "ignore"],
      });
      return decodeProcessArgv(raw, "darwin");
    }
  } catch {}
  return null;
}

export function resolveLockedUvCommand() {
  const command = execFileSync("which", ["uv"], { encoding: "utf8" }).trim();
  requireThat(command.startsWith("/"), "g0-uv-command-unavailable");
  return command;
}

export function g0SessionPythonSource() {
  return [
    "import json, os, pathlib, subprocess, sys",
    "root=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])",
    "sys.path.insert(0, str(root/'tools/compat-broad'))",
    "from broad_contract import digest, local_origin",
    "from batch_adapter import observer_digest",
    "from g0_local_recovery import execute",
    "from shared_gate import create",
    "firestore=os.environ.get('FIRESTORE_EMULATOR_HOST'); auth=os.environ.get('FIREBASE_AUTH_EMULATOR_HOST')",
    "if not firestore or not auth: raise ValueError('g0-owned-origins-missing')",
    "origins={'firestore': local_origin('http://' + firestore), 'auth': local_origin('http://' + auth)}",
    "plan=json.loads((out/'program.json').read_bytes()); canonical_program_digest=digest(plan); plan['observerSha256']=observer_digest(); plan['localOrigins']=origins; plan['transport']='local-only'",
    "create(out/'gate', plan)",
    "if not execute(out, origins): raise SystemExit(3)",
  ].join("\n");
}

const adapterFiles = ["g0-plan.mjs", "g0-session.mjs", "g0.mjs", "pilot.mjs", "registry.mjs"];

async function sourceDigests() {
  const output = {};
  for (const name of adapterFiles) output[name] = sha256(await readSource(HERE, name));
  output["tools/compat-broad/g0_local_recovery.py"] = sha256(
    await readSource(resolve(HERE, "../../tools/compat-broad"), "g0_local_recovery.py"),
  );
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

/** The prepared frozen recipe, not the reply, defines the complete row identity set. */
function expectedG0Rows(program) {
  requireThat(object(program?.jobs), "g0-comparison-program-shape");
  const rows = [];
  for (const [job, recipe] of Object.entries(program.jobs)) {
    requireThat(object(recipe) && Array.isArray(recipe.observation), "g0-comparison-program-shape");
    requireThat(recipe.observation.length <= 12 - rows.length, "g0-observation-shape");
    for (let index = 0; index < recipe.observation.length; index++) rows.push({ job, index });
  }
  requireThat(rows.length === 12, "g0-observation-shape");
  return rows;
}

export function compareG0({ repo, entry, program, actual, execution, build }) {
  requireThat(actual && typeof actual === "object", "g0-local-record-shape");
  requireThat(build?.artifactSha256 === execution?.artifact?.sha256, "g0-artifact-receipt-mismatch");
  const expected = expectedG0Rows(program);
  const result = invokeComparator(
    repo,
    process.env[entry.productionResultPath],
    actual,
    { artifactSha256: execution?.artifact?.sha256 },
  );
  requireThat(
    object(result) &&
      ["match", "mismatch", "indeterminate"].includes(result.compatibility) &&
      Array.isArray(result.rows) &&
      result.rows.length <= expected.length &&
      (result.reason === undefined || result.reason === null || typeof result.reason === "string"),
    "g0-comparator-result-shape",
  );
  const key = (row) => JSON.stringify([row.job, row.index]);
  const expectedKeys = new Set(expected.map(key));
  const received = new Map();
  for (const row of result.rows) {
    requireThat(
      object(row) &&
        typeof row.job === "string" &&
        Number.isSafeInteger(row.index) &&
        expectedKeys.has(key(row)) &&
        !received.has(key(row)) &&
        ["match", "mismatch", "indeterminate"].includes(row.verdict),
      "g0-comparator-row-shape",
    );
    received.set(key(row), row);
  }
  const indeterminate = result.compatibility === "indeterminate";
  if (!indeterminate) {
    requireThat(
      received.size === expected.length &&
        result.rows.every((row) => row.verdict !== "indeterminate") &&
        result.compatibility === (result.rows.some((row) => row.verdict === "mismatch") ? "mismatch" : "match") &&
        !result.reason,
      "g0-comparator-result-contradiction",
    );
  }
  // An upstream admission failure is not a completed mismatch. Materialize unknown
  // rows from the frozen recipe so resultEnvelope cannot mistake empty counts for
  // complete evidence. Preserve any provisional verdicts as diagnostics only.
  const rows = expected.map((identity) => {
    const row = received.get(key(identity));
    return {
      stepId: `${identity.job}:${identity.index}`,
      comparison: indeterminate ? "INDETERMINATE" : row.verdict.toUpperCase(),
      ...(indeterminate ? {
        comparisonReported: row !== undefined,
        ...(row ? { reportedComparison: row.verdict.toUpperCase() } : {}),
      } : {}),
      production: { redacted: true },
      local: { redacted: true },
    };
  });
  const counts = { match: 0, mismatch: 0, indeterminate: 0 };
  for (const row of rows) counts[row.comparison.toLowerCase()]++;
  return {
    verdict: result.compatibility.toUpperCase(),
    expectedRowCount: expected.length,
    reportedRowCount: received.size,
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
