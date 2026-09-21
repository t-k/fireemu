import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { digestJson, requireThat } from "./core.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

export function compileFrozenG0Plan(repo = ROOT, nonce) {
  requireThat(/^[0-9a-f]{32}$/.test(nonce), "g0-nonce");
  const script = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from shared_production_pair import frozen_g0_manifest",
    "print(json.dumps(frozen_g0_manifest(sys.argv[2]), separators=(',', ':')))",
  ].join("; ");
  let output;
  try {
    output = execFileSync("uv", ["run", "python", "-c", script, `${repo}/tools/compat-broad`, nonce], {
      cwd: repo,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    throw new Error("g0-frozen-plan-unavailable");
  }
  try {
    return JSON.parse(output);
  } catch {
    throw new Error("g0-frozen-plan-invalid");
  }
}

export function g0ProgramDigest(plan) {
  return digestJson(plan);
}
