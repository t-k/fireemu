import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createCaptureJournal } from "../storage-rules/capture-journal.mjs";
import { createCountedCredentialCache } from "../storage-rules/credential-cache.mjs";
import { createDispatchGate } from "../storage-rules/dispatch-gate.mjs";
import { mainRepositoryRoot, pinnedPaths, systemClock } from "../storage-rules/entry.mjs";
import { leaseTransport } from "../storage-rules/locked-run.mjs";
import { checkoutMatches, gitOutput } from "../storage-rules/pins.mjs";
import { generateRunSecrets, readAdcFile } from "../storage-rules/private-inputs.mjs";
import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { createRecordingUsage } from "../storage-rules/recording-usage.mjs";
import { createReservationJournal } from "../storage-rules/reservation-journal.mjs";
import { createReleaseAdmission } from "./admission.mjs";
import { ALL_IDS, MODES, PREFLIGHT_IDS, releaseCorpus } from "./plan.mjs";
import { releaseCodeDigests } from "./pins.mjs";
import { isBucket, isRulesetName, parseBaseline, PROJECT_ID, parseSaved, savedSha256 } from "./release.mjs";
import { runReleasePost, runReleasePre } from "./run.mjs";
import { createReleaseTargets } from "./targets.mjs";
import { createReleaseHttpsTransport } from "./transport.mjs";

// The entry point of the stage 2c release runs (`pre` deletes the bucket release after saving it, `post` publishes it again). Like the
// stage 3 entry, the ledger, lock, usage and run-directory paths are constants of the main checkout, the options are a closed record,
// the approval's pins are recomputed from the code and the corpus before anything is created, and the only network capability is the
// single-attempt HTTPS transport built here. It writes no file but the journals and, for `pre`, the saved record in its own run
// directory. It takes the query project's lock alone, for the run only: the time between `pre` and `post` is held by the ledger.
const OPTION_KEYS = ["mode", "localPath", "runId", "sourceCommit", "packet", "review"];
const BIND_KEYS = ["root", "codeRoot", "requestImpl", "clock", "git"];
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const RELEASE_DIR = "conformance/src/storage-rules-release";
const MAX_LOCAL_BYTES = 64 * 1024;
export const SAVED_FILE = "saved-release.json";
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const closed = (value, keys) => plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const refuse = (message) => { throw new Error(message); };

/** The paths of a stage 2c run: the stage 3 paths, a usage ledger and run directory of its own. */
export function releasePaths(root) {
  const base = pinnedPaths(root);
  return Object.freeze({ ...base, usagePath: join(base.runsDir, "storage-object-reclaim-usage.jsonl"), runDirectory: (runId) => join(base.runsDir, `storage-object-reclaim-${runId}`) });
}

async function readOwnerLedger(path) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch { refuse("owner ledger refused"); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o022) !== 0 || stat.size > 8 * 1024 * 1024) refuse("owner ledger refused");
    return new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile());
  } catch { refuse("owner ledger refused"); } finally { await handle.close(); }
}

async function readPrivateJson(path, limit) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid() || stat.nlink !== 1 || stat.size > limit) throw new Error();
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile()));
  } finally { await handle.close(); }
}

/**
 * The operator's own values: a private, closed JSON file of this user. `pre`: the ADC path, the digest of the owner's address, the bucket
 * and the ruleset the bucket release must point at, and the baseline (times and digests) of that release and ruleset, which the run
 * confirms before it writes. `post`: the ADC path, the digest of the owner's address and the path of the saved record
 * a `pre` run wrote.
 */
export async function readLocalInputs(path, mode) {
  try {
    if (!MODES.includes(mode)) throw new Error();
    const value = await readPrivateJson(path, MAX_LOCAL_BYTES);
    const keys = mode === "pre" ? ["schemaVersion", "adcPath", "ownerEmailSha256", "bucket", "expectedRulesetName", "expectedBaseline"] : ["schemaVersion", "adcPath", "ownerEmailSha256", "savedPath"];
    if (!closed(value, keys) || value.schemaVersion !== 1) throw new Error();
    const ok = (text, pattern) => typeof text === "string" && pattern.test(text);
    if (!ok(value.adcPath, /^\/[^\0\r\n]{1,1023}$/) || !ok(value.ownerEmailSha256, HEX64)) throw new Error();
    if (mode === "pre") {
      if (!isBucket(value.bucket) || !isRulesetName(value.expectedRulesetName)) throw new Error();
      return Object.freeze({ mode, adcPath: value.adcPath, ownerEmailSha256: value.ownerEmailSha256, bucket: value.bucket, expectedRulesetName: value.expectedRulesetName, baseline: parseBaseline(value.expectedBaseline) });
    }
    if (!ok(value.savedPath, /^\/[^\0\r\n]{1,1023}$/)) throw new Error();
    const saved = parseSaved(await readPrivateJson(value.savedPath, 16 * 1024));
    return Object.freeze({ mode, adcPath: value.adcPath, ownerEmailSha256: value.ownerEmailSha256, bucket: saved.bucket, saved, savedSha256: savedSha256(saved) });
  } catch { throw new Error("local inputs file refused"); }
}

/** The corpus of a run, from its local inputs. */
export function corpusOf(local) {
  return local.mode === "pre"
    ? releaseCorpus({ mode: "pre", bucket: local.bucket, rulesetName: local.expectedRulesetName, ownerEmailSha256: local.ownerEmailSha256, baseline: local.baseline })
    : releaseCorpus({ mode: "post", bucket: local.bucket, rulesetName: local.saved.rulesetName, ownerEmailSha256: local.ownerEmailSha256, savedSha256: local.savedSha256 });
}

/** The saved record, written once into the run directory with mode 600 and flushed before the deletion it protects. */
async function writeSavedFile(directory, saved) {
  const handle = await open(join(directory, SAVED_FILE), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(saved, null, 2)}\n`);
    await handle.sync();
  } finally { await handle.close(); }
}

export function bindReleaseEntry(options) {
  if (!closed(options, BIND_KEYS)) refuse("invalid entry binding");
  const { root, codeRoot, requestImpl, clock, git } = options;
  if (typeof root !== "string" || typeof codeRoot !== "string" || typeof git !== "function" || typeof requestImpl !== "function" || !closed(clock, ["nowSeconds", "waitUntilSeconds", "sleep"])) refuse("invalid entry binding");
  if (mainRepositoryRoot(root) !== root) refuse("entry root is not a main checkout");
  const paths = releasePaths(root);
  const transport = createReleaseHttpsTransport({ requestImpl });

  return async function withReleaseRun(callerOptions) {
    if (!closed(callerOptions, OPTION_KEYS)) refuse("invalid release options");
    const { mode, localPath, runId, sourceCommit, packet, review } = callerOptions;
    if (!MODES.includes(mode) || typeof localPath !== "string" || typeof runId !== "string" || !RUN_ID.test(runId) || typeof sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(sourceCommit) || !plain(packet) || packet.sourceCommit !== sourceCommit || !plain(review)) refuse("invalid release options");
    if (!["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].every((key) => HEX64.test(packet[key]))) refuse("invalid release options");
    for (const [path, name] of [[paths.runsDir, "runs directory"], [paths.lockDir, "lock directory"]]) {
      const stat = await lstat(path).catch(() => refuse(`${name} missing`));
      if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) refuse(`${name} refused`);
    }
    const local = await readLocalInputs(localPath, mode);
    // The approval's pins must be what this code, this checkout and this corpus reproduce, before anything is created.
    const digests = await releaseCodeDigests(codeRoot).catch(() => refuse("pin source refused"));
    if (digests.runnerSha256 !== packet.runnerSha256) refuse("pin mismatch: runnerSha256");
    if (digests.fixtureSchemaSha256 !== packet.fixtureSchemaSha256) refuse("pin mismatch: fixtureSchemaSha256");
    const corpus = corpusOf(local);
    if (corpus.sha256 !== packet.manifestSha256) refuse("pin mismatch: manifestSha256");
    const checkout = await checkoutMatches({ root: codeRoot, sourceCommit, git }).catch(() => ({ ok: false, reason: "source commit unreadable" }));
    if (!checkout.ok) refuse(checkout.reason);
    // The runner pin also hashes the stage 2c directory, so nothing untracked or ignored may sit there either.
    const extra = await git(codeRoot, ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", RELEASE_DIR]).catch(() => refuse("source commit unreadable"));
    if (extra.trim() !== "") refuse("untracked or ignored runner files");
    const adc = await readAdcFile({ path: local.adcPath });
    const directory = paths.runDirectory(runId);
    await mkdir(directory, { mode: 0o700 }).catch((error) => refuse(error?.code === "EEXIST" ? "run directory exists" : "run directory refused"));
    const usage = createRecordingUsage({ path: paths.usagePath, packetSha256: packet.packetSha256 });
    const secrets = generateRunSecrets();
    const ids = ALL_IDS[mode];

    return withProjectLocks({ lockDir: paths.lockDir, legacyLockPath: paths.legacyLockPath, projects: [...packet.projects], taskId: packet.taskId, packetId: packet.packetName, sourceCommit, pid: process.pid, acquiredAt: new Date().toISOString() }, async (lease) => {
      const admission = createReleaseAdmission({ readLedger: () => readOwnerLedger(paths.ownerLedger), packet, review, locks: { verify: () => lease.verifyHeld() }, runId, usage, mode });
      const reservations = await createReservationJournal({ directory, runId, sourceCommit, manifestDigest: corpus.sha256, requestIds: [...ids], preflightIds: [...PREFLIGHT_IDS], io: { open, lstat } });
      let capture;
      try { capture = await createCaptureJournal({ directory, runId, sourceCommit, manifestDigest: corpus.sha256, digestSalt: secrets.digestSalt, requestIds: [...ids], io: { open, lstat, mkdir } }); } catch (error) { await reservations.close().catch(() => {}); throw error; }
      try {
        const targets = createReleaseTargets({ bucket: local.bucket, digestSalt: secrets.digestSalt });
        let cache;
        const gate = createDispatchGate({
          reservations: { onStarted: reservations.onStarted, onReserve: reservations.onReserve, onTerminal: reservations.onTerminal },
          capture, transport: leaseTransport(lease, transport), targets,
          credentials: { headersFor: (credential, context) => {
            if (credential !== "admin" || context?.project !== PROJECT_ID) refuse("no credential for this request");
            // The gate says whether this route carries the quota project header (userinfo does not); only an explicit yes adds it.
            return { authorization: `Bearer ${cache.ownerCredential().accessToken}`, ...(context.quotaProject === true ? { "x-goog-user-project": context.project } : {}) };
          } },
          preflightIds: [...PREFLIGHT_IDS], admission,
        });
        cache = createCountedCredentialCache({ adc, counter: gate.delegated.counter, digestSalt: secrets.digestSalt, nowSeconds: clock.nowSeconds, sendHttp: gate.delegated.http, writeProof: (proof) => capture.writeCredentialProof(proof) });
        const result = mode === "pre"
          ? await runReleasePre({ gate, cache, targets, local, capture, runId, saveSaved: (saved) => writeSavedFile(directory, saved) })
          : await runReleasePost({ gate, cache, targets, local, capture, runId, saved: local.saved });
        // The run ended cleanly (finished, or recovered with the release proven in a known state): the lock may go.
        lease.confirmClosed();
        const { saved, ...rest } = result;
        return Object.freeze({ ...rest, mode, released: true, ...(saved === undefined ? {} : { savedSha256: savedSha256(saved) }) });
      } finally { await capture.close().catch(() => {}); await reservations.close().catch(() => {}); }
    });
  };
}

const here = dirname(fileURLToPath(import.meta.url));
export const releaseEntryRoot = mainRepositoryRoot(here);
export const releaseRealBinding = Object.freeze({ root: releaseEntryRoot, codeRoot: resolve(here, "..", "..", ".."), requestImpl: httpsRequest, clock: systemClock, git: gitOutput });
/** Run a stage 2c release run. */
export const withReleaseRun = bindReleaseEntry(releaseRealBinding);
