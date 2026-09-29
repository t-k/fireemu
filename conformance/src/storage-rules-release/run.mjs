import { createHash } from "node:crypto";
import { STOP_CODES, stopCodeOf, tagged } from "../storage-rules/stop-codes.mjs";
import { BUCKETLESS_RELEASE_NAME, classifyRelease, classifyRuleset, isEmptyOk, makeSaved, parseSaved } from "./release.mjs";
import { IDS } from "./plan.mjs";

// The two release runs, through the dispatch gate (each request admitted, journalled before it is sent and counted).
//
// `pre`: the owner's token and identity, then three reads that must all say what the packet says: the bucket release points at the
// expected ruleset, the bucketless release is absent, the ruleset exists. The release is saved (durably, before anything is deleted),
// deleted, and both releases are read back as absent. If the deletion's result is wrong or unknown, the recovery reads the bucket release:
// unchanged means nothing to undo, absent means it is published again from the saved record and read back, anything else is left alone.
//
// `post`: the same three reads against the saved record (the ruleset exists and its source digest is the saved one; the bucket release is
// absent, or already the saved one, which makes the run a no-op; the bucketless release is absent), then the release is published from
// the saved record and read back. If the publication's result is wrong or unknown, one read decides: the saved release is there, or it is not.
const sha = (value) => createHash("sha256").update(value).digest("hex");
const stop = (message) => { throw tagged(STOP_CODES.preflightFailed, message); };
const same = (release, saved) => release.name === saved.name && release.rulesetName === saved.rulesetName;

async function preflight({ gate, cache, targets, local, capture, ids, rulesetName, judgeRuleset, judgeBucket }) {
  const found = {};
  await cache.refreshOwner(ids.token);
  // The owner is who the packet says: verified, and the digest of the address matches.
  await gate.send(targets.prepareIdentity(ids.identity), { phase: "preflight", mutationKey: null, accept: (raw) => {
    let body;
    try { body = raw.status === 200 ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes)) : undefined; } catch { body = undefined; }
    return body !== null && typeof body === "object" && body.verified_email === true && typeof body.email === "string" && sha(body.email) === local.ownerEmailSha256;
  } });
  await gate.send(targets.prepareRulesetRead(ids.ruleset, rulesetName), { phase: "preflight", mutationKey: null, accept: (raw) => {
    const read = classifyRuleset(raw, rulesetName);
    found.ruleset = read.state === "present" ? read.ruleset : null;
    return found.ruleset !== null && judgeRuleset(found.ruleset);
  } });
  await gate.send(targets.prepareBucketRead(ids.bucket), { phase: "preflight", mutationKey: null, accept: (raw) => {
    found.bucket = classifyRelease(raw, targets.releaseName);
    return judgeBucket(found.bucket);
  } });
  await gate.send(targets.prepareBucketlessRead(ids.bucketless), { phase: "preflight", mutationKey: null, accept: (raw) => {
    found.bucketless = classifyRelease(raw, BUCKETLESS_RELEASE_NAME);
    return found.bucketless.state === "absent";
  } });
  if (!found.ruleset || !found.bucket || found.bucketless?.state !== "absent") stop("the release state is not the one the packet describes");
  await capture.writeFacts({ operationId: ids.ruleset, kind: "rules-ruleset-read", verdict: "present", facts: { status: 200, rulesetName, createTime: found.ruleset.createTime, sourceSha256: found.ruleset.sourceSha256 } });
  return found;
}

const releaseFacts = (operationId, capture, kind, verdict, release) => capture.writeFacts({ operationId, kind, verdict, facts: release === null ? { status: 404 } : { status: 200, releaseName: release.name, rulesetName: release.rulesetName, createTime: release.createTime, updateTime: release.updateTime, bodySha256: release.bodySha256 } });

const finished = (gate, changed) => Object.freeze({ status: "finished", changed, requests: gate.snapshot().requests });
const recoveredResult = (gate, changed) => Object.freeze({ status: "recovered", changed, requests: gate.snapshot().requests });

async function afterAttempt({ error, gate, recover }) {
  const code = stopCodeOf(error);
  // A refused admission or a failed journal leaves the gate unable to send anything: nothing more can be done through it.
  if (code === STOP_CODES.admissionRefused || code === STOP_CODES.captureFailed) {
    if (gate.snapshot().mode !== "closed") await gate.finish("needs-recovery").catch(() => {});
    throw error;
  }
  try { return await recover(); } catch (failure) {
    // Whatever went wrong in the recovery, the run ends as needs-recovery (the locks stay), unless the gate itself can no longer write.
    if (gate.snapshot().mode !== "closed") await gate.finish("needs-recovery").catch(() => {});
    throw failure;
  }
}

/** Stage 2c `pre`: save the bucket release, delete it, read both releases back as absent. */
export async function runReleasePre({ gate, cache, targets, local, capture, runId, saveSaved }) {
  const ids = IDS.pre;
  await gate.start({ runId });
  const found = await preflight({ gate, cache, targets, local, capture, ids, rulesetName: local.expectedRulesetName,
    judgeRuleset: () => true, judgeBucket: (read) => read.state === "present" && read.release.rulesetName === local.expectedRulesetName });
  await releaseFacts(ids.bucket, capture, "rules-release-read", "present", found.bucket.release);
  await releaseFacts(ids.bucketless, capture, "rules-release-read", "absent", null);
  const saved = makeSaved({ bucket: local.bucket, release: found.bucket.release, ruleset: found.ruleset });
  gate.admit();

  let attempted = false;
  try {
    // The record that lets the second run publish the same release is durable before anything is deleted.
    await saveSaved(saved);
    const remove = targets.prepareDelete(ids.remove, saved);
    attempted = true;
    const answer = await gate.send(remove, { phase: "normal", mutationKey: "release-delete", accept: null });
    if (!isEmptyOk(answer.raw)) throw new Error("the deletion was not accepted");
    const bucket = classifyRelease((await gate.send(targets.prepareBucketRead(ids.absence), { phase: "normal", mutationKey: null, accept: null })).raw, targets.releaseName);
    if (bucket.state !== "absent") throw new Error("the bucket release is still there after its deletion");
    await releaseFacts(ids.absence, capture, "rules-release-read", "absent", null);
    const bucketless = classifyRelease((await gate.send(targets.prepareBucketlessRead(ids.absenceBucketless), { phase: "normal", mutationKey: null, accept: null })).raw, BUCKETLESS_RELEASE_NAME);
    if (bucketless.state !== "absent") throw new Error("a bucketless release appeared");
    await releaseFacts(ids.absenceBucketless, capture, "rules-release-read", "absent", null);
    await gate.finish("finished");
    return { ...finished(gate, true), saved };
  } catch (error) {
    if (!attempted) { await gate.finish("stopped-no-mutation"); throw error; }
    const result = await afterAttempt({ error, gate, recover: () => recoverPre({ gate, targets, saved, capture }) });
    return { ...result, saved };
  }
}

async function recoverPre({ gate, targets, saved, capture }) {
  const ids = IDS.pre;
  if (gate.snapshot().mode === "normal") gate.enterRecovery();
  const meta = { phase: "recovery", mutationKey: null, accept: null };
  const current = classifyRelease((await gate.send(targets.prepareBucketRead(ids.current), meta)).raw, targets.releaseName);
  if (current.state === "present" && same(current.release, saved)) { await releaseFacts(ids.current, capture, "rules-release-read", "present", current.release); await gate.finish("recovered"); return recoveredResult(gate, false); }
  if (current.state !== "absent") throw tagged(STOP_CODES.outcomeUncertain, "the bucket release is neither the saved one nor absent");
  await releaseFacts(ids.current, capture, "rules-release-read", "absent", null);
  const answer = await gate.send(targets.preparePublish(ids.restore, saved), { phase: "recovery", mutationKey: "release-restore", accept: null });
  if (classifyRelease(answer.raw, saved.name).state !== "present") throw tagged(STOP_CODES.outcomeUncertain, "the release could not be published again");
  const after = classifyRelease((await gate.send(targets.prepareBucketRead(ids.restored), meta)).raw, targets.releaseName);
  if (after.state !== "present" || !same(after.release, saved)) throw tagged(STOP_CODES.outcomeUncertain, "the published release is not the saved one");
  await releaseFacts(ids.restored, capture, "rules-release-read", "present", after.release);
  await gate.finish("recovered");
  return recoveredResult(gate, false);
}

/** Stage 2c `post`: publish the saved release again, or find it there already. */
export async function runReleasePost({ gate, cache, targets, local, capture, runId, saved: savedInput }) {
  const ids = IDS.post;
  const saved = parseSaved(savedInput);
  await gate.start({ runId });
  const found = await preflight({ gate, cache, targets, local, capture, ids, rulesetName: saved.rulesetName,
    judgeRuleset: (ruleset) => ruleset.sourceSha256 === saved.rulesetSourceSha256,
    judgeBucket: (read) => read.state === "absent" || (read.state === "present" && same(read.release, saved)) });
  await releaseFacts(ids.bucket, capture, "rules-release-read", found.bucket.state, found.bucket.state === "present" ? found.bucket.release : null);
  await releaseFacts(ids.bucketless, capture, "rules-release-read", "absent", null);
  gate.admit();
  if (found.bucket.state === "present") { await gate.finish("finished"); return finished(gate, false); }

  let attempted = false;
  try {
    const create = targets.preparePublish(ids.create, saved);
    attempted = true;
    const answer = await gate.send(create, { phase: "normal", mutationKey: "release-create", accept: null });
    const made = classifyRelease(answer.raw, saved.name);
    if (made.state !== "present" || !same(made.release, saved)) throw new Error("the publication was not accepted as the saved release");
    const after = classifyRelease((await gate.send(targets.prepareBucketRead(ids.after), { phase: "normal", mutationKey: null, accept: null })).raw, targets.releaseName);
    if (after.state !== "present" || !same(after.release, saved)) throw new Error("the release read back is not the saved one");
    await releaseFacts(ids.after, capture, "rules-release-read", "present", after.release);
    await gate.finish("finished");
    return finished(gate, true);
  } catch (error) {
    if (!attempted) { await gate.finish("stopped-no-mutation"); throw error; }
    return afterAttempt({ error, gate, recover: () => recoverPost({ gate, targets, saved, capture }) });
  }
}

async function recoverPost({ gate, targets, saved, capture }) {
  const ids = IDS.post;
  if (gate.snapshot().mode === "normal") gate.enterRecovery();
  const current = classifyRelease((await gate.send(targets.prepareBucketRead(ids.current), { phase: "recovery", mutationKey: null, accept: null })).raw, targets.releaseName);
  if (current.state === "present" && same(current.release, saved)) { await releaseFacts(ids.current, capture, "rules-release-read", "present", current.release); await gate.finish("recovered"); return recoveredResult(gate, true); }
  throw tagged(STOP_CODES.outcomeUncertain, "the saved release is not there");
}
