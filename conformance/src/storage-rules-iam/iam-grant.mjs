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
import { createIamAdmission } from "./admission.mjs";
import { ALL_IDS, iamCorpus, PREFLIGHT_IDS, PROJECT_ID } from "./plan.mjs";
import { iamCodeDigests } from "./pins.mjs";
import { runIamGrant } from "./run.mjs";
import { createIamTargets } from "./targets.mjs";
import { createIamHttpsTransport } from "./transport.mjs";

// The entry point of the stage 2b IAM grant. Like the stage 3 entry, the ledger, lock, usage and run-directory paths are constants of the
// main checkout, the options are a closed record, the approval's pins are recomputed from the code and the corpus before anything is
// created, and the only network capability is the single-attempt HTTPS transport built here. The only IAM policy it writes is the one
// `runIamGrant` builds. It writes no file but the journals. It takes the query project's lock alone.
const OPTION_KEYS = ["localPath", "runId", "sourceCommit", "packet", "review"];
const BIND_KEYS = ["root", "codeRoot", "requestImpl", "clock", "git"];
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const IAM_DIR = "conformance/src/storage-rules-iam";
const MAX_LOCAL_BYTES = 64 * 1024;
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const closed = (value, keys) => plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const refuse = (message) => { throw new Error(message); };

/** The paths of a stage 2b run: the stage 3 paths, a usage ledger and run directory of its own. */
export function iamPaths(root) {
  const base = pinnedPaths(root);
  return Object.freeze({ ...base, usagePath: join(base.runsDir, "storage-rules-iam-usage.jsonl"), runDirectory: (runId) => join(base.runsDir, `storage-rules-iam-${runId}`) });
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

/** The operator's own values: a private, closed JSON file of this user (the ADC path, the query project's number, the digest of the owner's address). */
export async function readLocalInputs(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid() || stat.nlink !== 1 || stat.size > MAX_LOCAL_BYTES) throw new Error();
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile()));
    if (!closed(value, ["schemaVersion", "adcPath", "projectNumber", "ownerEmailSha256"]) || value.schemaVersion !== 1) throw new Error();
    const ok = (text, pattern) => typeof text === "string" && pattern.test(text);
    if (!ok(value.adcPath, /^\/[^\0\r\n]{1,1023}$/) || !ok(value.projectNumber, /^[1-9]\d{0,19}$/) || !ok(value.ownerEmailSha256, HEX64)) throw new Error();
    return Object.freeze({ adcPath: value.adcPath, projectNumber: value.projectNumber, ownerEmailSha256: value.ownerEmailSha256 });
  } catch { throw new Error("local inputs file refused"); } finally { await handle?.close(); }
}

export function bindIamEntry(options) {
  if (!closed(options, BIND_KEYS)) refuse("invalid entry binding");
  const { root, codeRoot, requestImpl, clock, git } = options;
  if (typeof root !== "string" || typeof codeRoot !== "string" || typeof git !== "function" || typeof requestImpl !== "function" || !closed(clock, ["nowSeconds", "waitUntilSeconds", "sleep"])) refuse("invalid entry binding");
  if (mainRepositoryRoot(root) !== root) refuse("entry root is not a main checkout");
  const paths = iamPaths(root);
  const transport = createIamHttpsTransport({ requestImpl });

  return async function withIamGrant(callerOptions) {
    if (!closed(callerOptions, OPTION_KEYS)) refuse("invalid iam options");
    const { localPath, runId, sourceCommit, packet, review } = callerOptions;
    if (typeof localPath !== "string" || typeof runId !== "string" || !RUN_ID.test(runId) || typeof sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(sourceCommit) || !plain(packet) || packet.sourceCommit !== sourceCommit || !plain(review)) refuse("invalid iam options");
    if (!["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].every((key) => HEX64.test(packet[key]))) refuse("invalid iam options");
    for (const [path, name] of [[paths.runsDir, "runs directory"], [paths.lockDir, "lock directory"]]) {
      const stat = await lstat(path).catch(() => refuse(`${name} missing`));
      if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) refuse(`${name} refused`);
    }
    const local = await readLocalInputs(localPath);
    // The approval's pins must be what this code, this checkout and this corpus reproduce, before anything is created.
    const digests = await iamCodeDigests(codeRoot).catch(() => refuse("pin source refused"));
    if (digests.runnerSha256 !== packet.runnerSha256) refuse("pin mismatch: runnerSha256");
    if (digests.fixtureSchemaSha256 !== packet.fixtureSchemaSha256) refuse("pin mismatch: fixtureSchemaSha256");
    const corpus = iamCorpus({ projectNumber: local.projectNumber, ownerEmailSha256: local.ownerEmailSha256 });
    if (corpus.sha256 !== packet.manifestSha256) refuse("pin mismatch: manifestSha256");
    const checkout = await checkoutMatches({ root: codeRoot, sourceCommit, git }).catch(() => ({ ok: false, reason: "source commit unreadable" }));
    if (!checkout.ok) refuse(checkout.reason);
    // The runner pin also hashes the stage 2b directory, so nothing untracked or ignored may sit there either.
    const extra = await git(codeRoot, ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", IAM_DIR]).catch(() => refuse("source commit unreadable"));
    if (extra.trim() !== "") refuse("untracked or ignored runner files");
    const adc = await readAdcFile({ path: local.adcPath });
    const directory = paths.runDirectory(runId);
    await mkdir(directory, { mode: 0o700 }).catch((error) => refuse(error?.code === "EEXIST" ? "run directory exists" : "run directory refused"));
    const usage = createRecordingUsage({ path: paths.usagePath, packetSha256: packet.packetSha256 });
    const secrets = generateRunSecrets();

    return withProjectLocks({ lockDir: paths.lockDir, legacyLockPath: paths.legacyLockPath, projects: [...packet.projects], taskId: packet.taskId, packetId: packet.packetName, sourceCommit, pid: process.pid, acquiredAt: new Date().toISOString() }, async (lease) => {
      const admission = createIamAdmission({ readLedger: () => readOwnerLedger(paths.ownerLedger), packet, review, locks: { verify: () => lease.verifyHeld() }, runId, usage });
      const reservations = await createReservationJournal({ directory, runId, sourceCommit, manifestDigest: corpus.sha256, requestIds: [...ALL_IDS], preflightIds: [...PREFLIGHT_IDS], io: { open, lstat } });
      let capture;
      try { capture = await createCaptureJournal({ directory, runId, sourceCommit, manifestDigest: corpus.sha256, digestSalt: secrets.digestSalt, requestIds: [...ALL_IDS], io: { open, lstat, mkdir } }); } catch (error) { await reservations.close().catch(() => {}); throw error; }
      try {
        const targets = createIamTargets({ projectNumber: local.projectNumber, digestSalt: secrets.digestSalt });
        let cache;
        const gate = createDispatchGate({
          reservations: { onStarted: reservations.onStarted, onReserve: reservations.onReserve, onTerminal: reservations.onTerminal },
          capture, transport: leaseTransport(lease, transport), targets,
          credentials: { headersFor: (credential, context) => {
            if (credential !== "admin" || context?.project !== PROJECT_ID) refuse("no credential for this request");
            return { authorization: `Bearer ${cache.ownerCredential().accessToken}`, "x-goog-user-project": context.project };
          } },
          preflightIds: [...PREFLIGHT_IDS], admission,
        });
        cache = createCountedCredentialCache({ adc, counter: gate.delegated.counter, digestSalt: secrets.digestSalt, nowSeconds: clock.nowSeconds, sendHttp: gate.delegated.http, writeProof: (proof) => capture.writeCredentialProof(proof) });
        const result = await runIamGrant({ gate, cache, targets, local, capture, runId });
        // The run ended cleanly (finished, or recovered with the grant proven absent again): the lock may go.
        lease.confirmClosed();
        return Object.freeze({ ...result, released: true });
      } finally { await capture.close().catch(() => {}); await reservations.close().catch(() => {}); }
    });
  };
}

const here = dirname(fileURLToPath(import.meta.url));
export const iamEntryRoot = mainRepositoryRoot(here);
export const iamRealBinding = Object.freeze({ root: iamEntryRoot, codeRoot: resolve(here, "..", "..", ".."), requestImpl: httpsRequest, clock: systemClock, git: gitOutput });
/** Run the stage 2b grant. */
export const withIamGrant = bindIamEntry(iamRealBinding);
