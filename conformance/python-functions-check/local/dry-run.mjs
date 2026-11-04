// The local dry run: the fixture under `fireemu exec`, the same source operations, and the judge on what was delivered.
//
//   node dry-run.mjs --fireemu <binary> --venv <python venv> --out <dir> [--profile strict|emulator]
//
// Nothing here reaches Google: the fixture runs on this machine against fireemu's own emulators.
import { spawn } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { parseFramesFromText } from "../record/logs.mjs";

const here = dirname(fileURLToPath(import.meta.url));

export function parseArgs(argv) {
  const values = { profile: "strict" };
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith("--") || argv[i + 1] === undefined) throw new Error("bad arguments");
    values[argv[i].slice(2)] = argv[i + 1];
  }
  return values;
}

export async function dryRun({
  fireemu,
  venv,
  out,
  profile = "strict",
  runId = randomBytes(8).toString("hex"),
}) {
  const root = mkdtempSync(join(tmpdir(), "pycheck-dry-"));
  const source = join(root, "source");
  cpSync(join(here, "..", "fixture"), source, { recursive: true });
  symlinkSync(venv, join(source, "venv"));
  const project = "demo-pycheck";
  writeFileSync(
    join(root, "firebase.json"),
    JSON.stringify({ functions: [{ source, codebase: "pycheck", runtime: "python312" }] }),
  );
  writeFileSync(join(root, "fireemu.json"), JSON.stringify({ schemaVersion: 1, profile }));
  mkdirSync(out, { recursive: true });
  const args = [
    "exec",
    "--firestore-port",
    "0",
    "--http-port",
    "0",
    "--storage-port",
    "0",
    "--functions-port",
    "0",
    "--eventarc-port",
    "0",
    "--tasks-port",
    "0",
    "--logging-port",
    "0",
    "--ui-port",
    "0",
    "--hub-port",
    "0",
    "--pubsub-port",
    "0",
    "--project",
    project,
    "--config",
    join(root, "fireemu.json"),
    "--firebase-json",
    join(root, "firebase.json"),
    "--",
    process.execPath,
    join(here, "drive.mjs"),
    runId,
    project,
  ];
  const child = spawn(fireemu, args, { stdio: ["ignore", "pipe", "pipe"] });
  let text = "";
  child.stdout.on("data", (chunk) => (text += chunk));
  child.stderr.on("data", (chunk) => (text += chunk));
  const code = await new Promise((resolve) => child.on("exit", resolve));
  writeFileSync(join(out, "exec-output.txt"), text, { mode: 0o600 });
  return { runId, profile, code, ...parseFramesFromText(text), text };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const values = parseArgs(process.argv.slice(2));
  const result = await dryRun({
    fireemu: values.fireemu,
    venv: values.venv,
    out: values.out,
    profile: values.profile,
  });
  console.log(
    JSON.stringify(
      { runId: result.runId, code: result.code, frames: result.frames.length },
      null,
      2,
    ),
  );
}
