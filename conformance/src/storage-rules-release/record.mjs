import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { MODES } from "./plan.mjs";
import { withReleaseRun } from "./release-entry.mjs";

// The one command that runs a stage 2c release run: `node record.mjs <pre|post> <local inputs file> <approval file> <run ID>`. It calls
// only `withReleaseRun` (never `bindReleaseEntry`). `pre` saves the bucket release of the query project and deletes it; `post` publishes
// the saved release again. It releases the query project's lock itself on a clean end. The approval file is a private JSON file of this
// user, `{ "packet": {...}, "review": {...} }`. It prints one JSON line without secrets. Exit codes: 0 finished, 1 approval file refused,
// 2 usage, 3 not finished (a recovery ended the run, or the entry failed: read the journal; the lock is released only after a recovery
// that proved the release state).
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

/** The command with its collaborators injected; returns the exit code. */
export async function runReleaseCommand({ args, entry = withReleaseRun, out, err }) {
  const [mode, localPath, approvalPath, runId, ...extra] = args;
  if (!MODES.includes(mode) || typeof localPath !== "string" || typeof approvalPath !== "string" || typeof runId !== "string" || extra.length > 0 || !RUN_ID.test(runId)) { err("usage: node record.mjs <pre|post> <local inputs file> <approval file> <run ID>\n"); return 2; }
  let approval;
  try { approval = await readApproval(approvalPath); } catch (error) { err(`${error?.message ?? "refused"}\n`); return 1; }
  try {
    const result = await entry({ mode, localPath, runId, sourceCommit: approval.packet.sourceCommit, packet: approval.packet, review: approval.review });
    out(`${JSON.stringify({ runId, mode, status: result.status, changed: result.changed, requests: result.requests, locksReleased: result.released === true, ...(result.savedSha256 === undefined ? {} : { savedSha256: result.savedSha256 }) })}\n`);
    return result.status === "finished" ? 0 : 3;
  } catch (error) {
    err(`${error?.message ?? "failed"}\n`);
    out(`${JSON.stringify({ runId, mode, status: "not-finished", locksReleased: false })}\n`);
    return 3;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = await runReleaseCommand({ args: process.argv.slice(2), out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
