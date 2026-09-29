import { constants, readFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { withStorageRulesRecording } from "./entry.mjs";
import { CLOSURE_SPEC } from "./pins.mjs";

// The one command that records: `node record.mjs <private inputs file> <approval file> <run ID>`. It calls only the entry point
// (`withStorageRulesRecording`, never `bindStorageRulesEntry`), runs the recording, runs the one recovery only when the run says it
// needs one, and confirms the close, which releases the project locks, only for the controller's own clean result. Anything else
// (a stop that needs recovery, a stop that sent nothing, a failed recovery) leaves both locks where they are for the coordinator.
// The approval file is a private JSON file of this user, `{ "packet": {...}, "review": {...} }`, the objects the approval check reads.
// It prints one JSON line with no secret: the run ID, the statuses, the reasons, the request counts and whether the locks were released.
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

const short = (result) => (result === undefined ? undefined : {
  status: result.status, ...(typeof result.reason === "string" ? { reason: result.reason } : {}), ...(typeof result.needsRecovery === "boolean" ? { needsRecovery: result.needsRecovery } : {}),
  ...(Number.isSafeInteger(result.requests) ? { requests: result.requests } : {}), ...(typeof result.detail?.rowId === "string" && /^[A-Za-z0-9._/-]{1,160}$/.test(result.detail.rowId) ? { rowId: result.detail.rowId } : {}),
});

/**
 * The command with its collaborators injected. `entry` is the real `withStorageRulesRecording` unless a test passes another;
 * the command line below never does. Returns the exit code: 0 clean and released, 1 refused before a run, 2 usage, 3 not clean.
 */
export async function runRecordCommand({ args, codeRoot, entry = withStorageRulesRecording, out, err }) {
  const [inputsPath, approvalPath, runId, ...extra] = args;
  if (typeof inputsPath !== "string" || typeof approvalPath !== "string" || typeof runId !== "string" || extra.length > 0 || !RUN_ID.test(runId)) { err("usage: node record.mjs <private inputs file> <approval file> <run ID>\n"); return 2; }
  let approval;
  let closure;
  try {
    approval = await readApproval(approvalPath);
    closure = JSON.parse(readFileSync(resolve(codeRoot, CLOSURE_SPEC), "utf8"));
  } catch (error) { err(`${error?.message ?? "refused"}\n`); return 1; }
  const seen = { runId, locksReleased: false };
  let failure = null;
  try {
    await entry({ inputsPath, closure, runId, sourceCommit: approval.packet.sourceCommit, packet: approval.packet, review: approval.review }, async (recording) => {
      const first = await recording.run();
      seen.run = short(first);
      let final = first;
      // One recovery, and only when the run itself says it needs one.
      if (first.needsRecovery === true) { final = await recording.recover(); seen.recovery = short(final); }
      if (final.status === "finished" || final.status === "recovered") {
        try { recording.confirmCleanClose(final); seen.locksReleased = true; } catch { seen.closeRefused = true; }
      }
    });
  } catch (error) {
    failure = error;
    seen.locksReleased = false;
    err(`${error?.message ?? "failed"}\n`);
  }
  out(`${JSON.stringify(seen)}\n`);
  if (failure === null && seen.locksReleased === true) return 0;
  return seen.run === undefined ? 1 : 3;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  process.exitCode = await runRecordCommand({ args: process.argv.slice(2), codeRoot, out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
