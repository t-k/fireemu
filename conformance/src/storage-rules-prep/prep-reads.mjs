import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createCaptureJournal } from "../storage-rules/capture-journal.mjs";
import { createCountedCredentialCache } from "../storage-rules/credential-cache.mjs";
import { createDispatchGate } from "../storage-rules/dispatch-gate.mjs";
import { mainRepositoryRoot, pinnedPaths, systemClock } from "../storage-rules/entry.mjs";
import { createPrepHttpsTransport } from "./transport.mjs";
import { leaseTransport } from "../storage-rules/locked-run.mjs";
import { checkoutMatches, gitOutput } from "../storage-rules/pins.mjs";
import { generateRunSecrets, readAdcFile } from "../storage-rules/private-inputs.mjs";
import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { createRecordingUsage } from "../storage-rules/recording-usage.mjs";
import { createReservationJournal } from "../storage-rules/reservation-journal.mjs";
import { createPrepAdmission } from "./admission.mjs";
import { prepCorpus, PREP_IDS } from "./plan.mjs";
import { prepCodeDigests } from "./pins.mjs";
import { runPrepReads } from "./run.mjs";
import { createPrepTargets } from "./targets.mjs";

// The entry point of the stage 2a reads. Like the stage 3 entry, the ledger, lock, usage and run-directory paths are constants of
// the main checkout, the options are a closed record, the approval's pins are recomputed from the code and the corpus before
// anything is created, and the only network capability is the single-attempt HTTPS transport built here. It writes the private
// inputs file for stage 3 (mode 600) into the run directory and nothing else outside the journals.
const OPTION_KEYS = ["localPath", "closure", "runId", "sourceCommit", "packet", "review"];
const BIND_KEYS = ["root", "codeRoot", "requestImpl", "clock", "git"];
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const PREP_DIR = "conformance/src/storage-rules-prep";
const MAX_LOCAL_BYTES = 64 * 1024;
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const closed = (value, keys) => plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const refuse = (message) => { throw new Error(message); };

/** The paths of a stage 2a run: the stage 3 paths, a usage ledger and run directory of its own. */
export function prepPaths(root) {
  const base = pinnedPaths(root);
  return Object.freeze({ ...base, usagePath: join(base.runsDir, "storage-rules-prep-usage.jsonl"), runDirectory: (runId) => join(base.runsDir, `storage-rules-prep-${runId}`) });
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

/** The operator's own values for the reads: a private, closed JSON file of this user. */
export async function readLocalInputs(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid() || stat.nlink !== 1 || stat.size > MAX_LOCAL_BYTES) throw new Error();
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile()));
    if (!closed(value, ["schemaVersion", "adcPath", "projects", "bucket"]) || value.schemaVersion !== 1 || !closed(value.projects, ["query", "idp"]) || !closed(value.projects.query, ["projectNumber", "apiKey"]) || !closed(value.projects.idp, ["projectNumber", "apiKey"]) || !closed(value.bucket, ["name"])) throw new Error();
    const ok = (name, pattern) => typeof name === "string" && pattern.test(name);
    if (!ok(value.adcPath, /^\/[^\0\r\n]{1,1023}$/) || !ok(value.projects.query.projectNumber, /^[1-9]\d{0,19}$/) || !ok(value.projects.idp.projectNumber, /^[1-9]\d{0,19}$/) || value.projects.query.projectNumber === value.projects.idp.projectNumber ||
      !ok(value.projects.query.apiKey, /^[A-Za-z0-9_-]{20,128}$/) || !ok(value.projects.idp.apiKey, /^[A-Za-z0-9_-]{20,128}$/) || value.projects.query.apiKey === value.projects.idp.apiKey || !ok(value.bucket.name, /^[a-z0-9][a-z0-9._-]{2,221}$/)) throw new Error();
    return Object.freeze({ adcPath: value.adcPath, numbers: Object.freeze({ query: value.projects.query.projectNumber, idp: value.projects.idp.projectNumber }), keys: Object.freeze({ query: value.projects.query.apiKey, idp: value.projects.idp.apiKey }), bucket: value.bucket.name });
  } catch { throw new Error("local inputs file refused"); } finally { await handle?.close(); }
}

export function bindPrepEntry(options) {
  if (!closed(options, BIND_KEYS)) refuse("invalid entry binding");
  const { root, codeRoot, requestImpl, clock, git } = options;
  if (typeof root !== "string" || typeof codeRoot !== "string" || typeof git !== "function" || typeof requestImpl !== "function" || !closed(clock, ["nowSeconds", "waitUntilSeconds", "sleep"])) refuse("invalid entry binding");
  if (mainRepositoryRoot(root) !== root) refuse("entry root is not a main checkout");
  const paths = prepPaths(root);
  const transport = createPrepHttpsTransport({ requestImpl });

  return async function withPrepReads(callerOptions) {
    if (!closed(callerOptions, OPTION_KEYS)) refuse("invalid prep options");
    const { localPath, closure, runId, sourceCommit, packet, review } = callerOptions;
    if (typeof localPath !== "string" || typeof runId !== "string" || !RUN_ID.test(runId) || typeof sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(sourceCommit) || !plain(packet) || packet.sourceCommit !== sourceCommit || !plain(review) || !plain(closure)) refuse("invalid prep options");
    if (!["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].every((key) => HEX64.test(packet[key]))) refuse("invalid prep options");
    for (const [path, name] of [[paths.runsDir, "runs directory"], [paths.lockDir, "lock directory"]]) {
      const stat = await lstat(path).catch(() => refuse(`${name} missing`));
      if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) refuse(`${name} refused`);
    }
    const local = await readLocalInputs(localPath);
    // The approval's pins must be what this code, this checkout and this corpus reproduce, before anything is created.
    const digests = await prepCodeDigests(codeRoot).catch(() => refuse("pin source refused"));
    if (digests.runnerSha256 !== packet.runnerSha256) refuse("pin mismatch: runnerSha256");
    if (digests.fixtureSchemaSha256 !== packet.fixtureSchemaSha256) refuse("pin mismatch: fixtureSchemaSha256");
    const params = { bucket: local.bucket, queryProjectNumber: local.numbers.query, idpProjectNumber: local.numbers.idp, sourceCommit };
    const corpus = prepCorpus(closure, params);
    if (corpus.sha256 !== packet.manifestSha256) refuse("pin mismatch: manifestSha256");
    const checkout = await checkoutMatches({ root: codeRoot, sourceCommit, git }).catch(() => ({ ok: false, reason: "source commit unreadable" }));
    if (!checkout.ok) refuse(checkout.reason);
    // The runner pin also hashes the stage 2a directory, so nothing untracked or ignored may sit there either.
    const extra = await git(codeRoot, ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", PREP_DIR]).catch(() => refuse("source commit unreadable"));
    if (extra.trim() !== "") refuse("untracked or ignored runner files");
    const adc = await readAdcFile({ path: local.adcPath });
    const directory = paths.runDirectory(runId);
    await mkdir(directory, { mode: 0o700 }).catch((error) => refuse(error?.code === "EEXIST" ? "run directory exists" : "run directory refused"));
    const usage = createRecordingUsage({ path: paths.usagePath, packetSha256: packet.packetSha256 });
    const secrets = generateRunSecrets();

    return withProjectLocks({ lockDir: paths.lockDir, legacyLockPath: paths.legacyLockPath, projects: [...packet.projects], taskId: packet.taskId, packetId: packet.packetName, sourceCommit, pid: process.pid, acquiredAt: new Date().toISOString() }, async (lease) => {
      const admission = createPrepAdmission({ readLedger: () => readOwnerLedger(paths.ownerLedger), packet, review, locks: { verify: () => lease.verifyHeld() }, runId, usage });
      const reservations = await createReservationJournal({ directory, runId, sourceCommit, manifestDigest: corpus.sha256, requestIds: [...PREP_IDS], preflightIds: [...PREP_IDS], io: { open, lstat } });
      let capture;
      try { capture = await createCaptureJournal({ directory, runId, sourceCommit, manifestDigest: corpus.sha256, digestSalt: secrets.digestSalt, requestIds: [...PREP_IDS], io: { open, lstat, mkdir } }); } catch (error) { await reservations.close().catch(() => {}); throw error; }
      try {
        const targets = createPrepTargets({ closure, params, digestSalt: secrets.digestSalt });
        let cache;
        const gate = createDispatchGate({
          reservations: { onStarted: reservations.onStarted, onReserve: reservations.onReserve, onTerminal: reservations.onTerminal },
          capture, transport: leaseTransport(lease, transport), targets,
          credentials: { headersFor: (credential, context) => {
            if (credential !== "admin" || !["fireemu-oracle-idp", "fireemu-oracle-query"].includes(context?.project)) refuse("no credential for this request");
            return { authorization: `Bearer ${cache.ownerCredential().accessToken}`, "x-goog-user-project": context.project };
          } },
          preflightIds: [...PREP_IDS], admission,
        });
        cache = createCountedCredentialCache({ adc, counter: gate.delegated.counter, digestSalt: secrets.digestSalt, nowSeconds: clock.nowSeconds, sendHttp: gate.delegated.http, writeProof: (proof) => capture.writeCredentialProof(proof) });
        const inputs = await runPrepReads({ gate, cache, targets, local, bucket: local.bucket, capture, runId });
        const inputsPath = join(directory, "private-inputs.json");
        const handle = await open(inputsPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try { await handle.writeFile(`${JSON.stringify(inputs, null, 2)}\n`); await handle.sync(); } finally { await handle.close(); }
        // This entry has no caller callback: it closes only after every read passed and the inputs file was written.
        lease.confirmClosed();
        return Object.freeze({ status: "finished", requests: gate.snapshot().requests, inputsPath });
      } finally { await capture.close().catch(() => {}); await reservations.close().catch(() => {}); }
    });
  };
}

const here = dirname(fileURLToPath(import.meta.url));
export const prepEntryRoot = mainRepositoryRoot(here);
export const prepRealBinding = Object.freeze({ root: prepEntryRoot, codeRoot: resolve(here, "..", "..", ".."), requestImpl: httpsRequest, clock: systemClock, git: gitOutput });
/** Run the stage 2a reads. */
export const withPrepReads = bindPrepEntry(prepRealBinding);
