import { constants, readFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { withPrepReads } from "./prep-reads.mjs";

// The one command that runs the stage 2a reads: `node record.mjs <local inputs file> <approval file> <run ID>`. It calls only
// `withPrepReads` (never `bindPrepEntry`), which reads, writes the stage 3 private inputs file into the run directory and releases
// the locks itself on a clean end. The approval file is a private JSON file of this user, `{ "packet": {...}, "review": {...} }`.
// It prints one JSON line without secrets (the run ID, the status, the request count and the path of the inputs file); a stop
// leaves both project locks for the coordinator and exits 3.
const CLOSURE_SPEC = "spec/compatibility/closure/STORAGE-RULES.json";
const MAX_APPROVAL_BYTES = 64 * 1024;
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;

async function readApproval(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid() || stat.nlink !== 1 || stat.size > MAX_APPROVAL_BYTES) throw new Error();
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile()));
    if (!plain(value) || Reflect.ownKeys(value).length !== 2 || !plain(value.packet) || !plain(value.review) || !/^[a-f0-9]{40}$/.test(value.packet.sourceCommit ?? "")) throw new Error();
    return value;
  } catch { throw new Error("approval file refused"); } finally { await handle?.close(); }
}

/** The command with its collaborators injected; returns the exit code (0 clean, 1 refused before any read, 2 usage, 3 not clean). */
export async function runPrepCommand({ args, codeRoot, entry = withPrepReads, out, err }) {
  const [localPath, approvalPath, runId, ...extra] = args;
  if (typeof localPath !== "string" || typeof approvalPath !== "string" || typeof runId !== "string" || extra.length > 0 || !RUN_ID.test(runId)) { err("usage: node record.mjs <local inputs file> <approval file> <run ID>\n"); return 2; }
  let approval;
  let closure;
  try {
    approval = await readApproval(approvalPath);
    closure = JSON.parse(readFileSync(resolve(codeRoot, CLOSURE_SPEC), "utf8"));
  } catch (error) { err(`${error?.message ?? "refused"}\n`); return 1; }
  try {
    const result = await entry({ localPath, closure, runId, sourceCommit: approval.packet.sourceCommit, packet: approval.packet, review: approval.review });
    out(`${JSON.stringify({ runId, status: result.status, requests: result.requests, inputsPath: result.inputsPath })}\n`);
    return 0;
  } catch (error) {
    err(`${error?.message ?? "failed"}\n`);
    out(`${JSON.stringify({ runId, status: "not-clean", locksReleased: false })}\n`);
    return 3;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  process.exitCode = await runPrepCommand({ args: process.argv.slice(2), codeRoot, out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
