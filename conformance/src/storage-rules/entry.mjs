import { constants, lstatSync } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { withAssembledRun } from "./assemble-run.mjs";
import { createSingleAttemptHttpsTransport } from "./http-transport.mjs";
import { plain } from "./shape.mjs";

// The one entry point a recording is started from. The ledger it trusts, the lock directory it takes, the usage ledger it
// marks and the run directory it writes are constants resolved from the MAIN repository checkout (never the working
// directory or a linked worktree), and the caller cannot name others: the options are a closed record without any path
// of those four kinds, without a transport and without a clock. The only network capability is the single-attempt HTTPS
// transport built here, which reaches the wire only through the dispatch gate `withAssembledRun` wires around it.
const OPTION_KEYS = ["inputsPath", "closure", "runId", "sourceCommit", "packet", "review"];
const ROOT_KEYS = ["root", "requestImpl", "clock"];
const MAX_LEDGER_BYTES = 8 * 1024 * 1024;
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const closed = (value, keys) => plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const refuse = (message) => { throw new Error(message); };

/** The paths a recording uses, all under the main repository checkout `root`. */
export function pinnedPaths(root) {
  const runs = join(root, "docs.local", "runs");
  return Object.freeze({
    ownerLedger: join(root, "docs.local", "instructions", "owner-decisions.md"),
    lockDir: join(runs, "sandbox-locks"),
    legacyLockPath: join(runs, "sandbox-ledger.jsonl.lock"),
    usagePath: join(runs, "storage-rules-recording-usage.jsonl"),
    runsDir: runs,
    runDirectory: (runId) => join(runs, `storage-rules-${runId}`),
  });
}

/**
 * The main checkout above `start`: the nearest ancestor whose `.git` is a directory. A linked worktree has a `.git` file, so
 * the walk continues past it to the checkout that owns it.
 */
export function mainRepositoryRoot(start) {
  let current = resolve(start);
  for (;;) {
    let stat = null;
    try { stat = lstatSync(join(current, ".git")); } catch (error) { if (error?.code !== "ENOENT") throw error; }
    if (stat?.isDirectory()) return current;
    const parent = dirname(current);
    if (parent === current) refuse("main repository root not found");
    current = parent;
  }
}

/** The owner ledger, read fresh on every call: a regular file of this user that nobody else can write, read without following a link. */
async function readOwnerLedger(path) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { refuse("owner ledger refused"); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0 || stat.size > MAX_LEDGER_BYTES) refuse("owner ledger refused");
    return new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile());
  } catch { refuse("owner ledger refused"); } finally { await handle.close(); }
}

export const systemClock = Object.freeze({
  nowSeconds: () => Math.floor(Date.now() / 1000),
  waitUntilSeconds: (target) => new Promise((done) => setTimeout(done, Math.max(0, target * 1000 - Date.now()))),
  sleep: (ms) => new Promise((done) => setTimeout(done, ms)),
});

/**
 * Bind the entry to a checkout. `root` must be a main checkout (its `.git` is a directory) that already has `docs.local/runs`.
 * The exported `withStorageRulesRecording` is this function applied to the checkout this file lives in, with the real HTTPS
 * request and the system clock; the parameters exist so a test can point it at a scratch checkout and a stub wire.
 */
export function bindStorageRulesEntry(options) {
  if (!closed(options, ROOT_KEYS)) refuse("invalid entry binding");
  const { root, requestImpl, clock } = options;
  if (typeof root !== "string" || typeof requestImpl !== "function" || !closed(clock, ["nowSeconds", "waitUntilSeconds", "sleep"])) refuse("invalid entry binding");
  if (mainRepositoryRoot(root) !== root) refuse("entry root is not a main checkout");
  const paths = pinnedPaths(root);
  const transport = createSingleAttemptHttpsTransport({ requestImpl });

  return async function withStorageRulesRecording(callerOptions, use) {
    if (!closed(callerOptions, OPTION_KEYS) || typeof use !== "function") refuse("invalid storage rules recording options");
    const { inputsPath, closure, runId, sourceCommit, packet, review } = callerOptions;
    if (typeof runId !== "string" || !RUN_ID.test(runId)) refuse("invalid storage rules recording options");
    for (const [path, name] of [[paths.runsDir, "runs directory"], [paths.lockDir, "lock directory"]]) {
      const stat = await lstat(path).catch(() => refuse(`${name} missing`));
      if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) refuse(`${name} refused`);
    }
    // A private, fresh directory for this run's journals: it must not exist yet.
    const directory = paths.runDirectory(runId);
    await mkdir(directory, { mode: 0o700 }).catch((error) => refuse(error?.code === "EEXIST" ? "run directory exists" : "run directory refused"));
    return withAssembledRun({
      inputsPath, closure, runId, sourceCommit, packet, review,
      readLedger: () => readOwnerLedger(paths.ownerLedger),
      locks: { lockDir: paths.lockDir, legacyLockPath: paths.legacyLockPath, pid: process.pid, acquiredAt: new Date().toISOString() },
      usagePath: paths.usagePath, directory, transport, clock,
    }, use);
  };
}

/** The main checkout this file belongs to, resolved from the file's own location and never from the working directory. */
export const entryRoot = mainRepositoryRoot(dirname(fileURLToPath(import.meta.url)));
/** What the real entry is bound to: that checkout, the real HTTPS request function and the system clock. */
export const realBinding = Object.freeze({ root: entryRoot, requestImpl: httpsRequest, clock: systemClock });
/** Start a recording. */
export const withStorageRulesRecording = bindStorageRulesEntry(realBinding);
