import { createHash } from "node:crypto";
import { STOP_CODES, stopCodeOf, tagged } from "../storage-rules/stop-codes.mjs";
import { assess, bindingsDigest, parsePolicy, sameBindings, withGrant, withoutGrant } from "./policy.mjs";
import { IDS } from "./plan.mjs";

// The IAM grant, through the dispatch gate (each request admitted, journalled before it is sent and counted). Normal path: the owner's
// token, the owner's identity (the digest of the address must be the expected one), the policy before, the grant only if it is
// absent, the policy after (it must be the policy before with the grant added, and nothing else changed). Anything wrong after the
// grant was attempted goes to the recovery: read the policy now, and if it is the policy before there is nothing to undo; if it is
// the policy before with our grant, remove exactly that grant and read it back; if anything else changed, touch nothing and stop.
const sha = (value) => createHash("sha256").update(value).digest("hex");
const stop = (message) => { throw tagged(STOP_CODES.preflightFailed, message); };
const parse = (raw) => {
  try { return raw.status === 200 ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes)) : undefined; } catch { return undefined; }
};
const policyOf = (raw) => { try { return parsePolicy(parse(raw)); } catch { return null; } };

export async function runIamGrant({ gate, cache, targets, local, capture, runId }) {
  const member = targets.member;
  const facts = (operationId, policy, extra = {}) => capture.writeFacts({ operationId, kind: "iam-policy", verdict: "accepted", facts: { status: 200, bindings: policy.bindings.length, grant: assess(policy, member).state, policySha256: bindingsDigest(policy), ...extra } });

  await gate.start({ runId });
  await cache.refreshOwner(IDS.token);
  // The owner is who the packet says: verified, and the digest of the address matches.
  await gate.send(targets.prepareIdentity(IDS.identity), { phase: "preflight", mutationKey: null, accept: (raw) => {
    const body = parse(raw);
    return body !== null && typeof body === "object" && body.verified_email === true && typeof body.email === "string" && sha(body.email) === local.ownerEmailSha256;
  } });
  let before = null;
  await gate.send(targets.prepareRead(IDS.before), { phase: "preflight", mutationKey: null, accept: (raw) => {
    before = policyOf(raw);
    return before !== null && assess(before, member).state !== "ambiguous";
  } });
  if (before === null) stop("the policy before was not read");
  await facts(IDS.before, before);
  gate.admit();
  if (assess(before, member).state === "present") { await gate.finish("finished"); return Object.freeze({ status: "finished", changed: false, requests: gate.snapshot().requests }); }

  let attempted = false;
  try {
    const grant = targets.prepareGrant(IDS.grant, before);
    attempted = true;
    const answer = await gate.send(grant, { phase: "normal", mutationKey: "iam-grant", accept: null });
    if (answer.raw.status !== 200) throw new Error("the grant was not accepted");
    const read = await gate.send(targets.prepareRead(IDS.after), { phase: "normal", mutationKey: null, accept: null });
    const after = policyOf(read.raw);
    if (after === null || assess(after, member).state !== "present" || !sameBindings(after, withGrant(before, member))) throw new Error("the policy after is not the policy before with the grant");
    await facts(IDS.after, after);
    await gate.finish("finished");
    return Object.freeze({ status: "finished", changed: true, requests: gate.snapshot().requests });
  } catch (error) {
    if (!attempted) { await gate.finish("stopped-no-mutation"); throw error; }
    const code = stopCodeOf(error);
    // A refused admission or a failed journal leaves the gate unable to send anything: nothing more can be done through it.
    if (code === STOP_CODES.admissionRefused || code === STOP_CODES.captureFailed) throw error;
    return recover({ gate, targets, member, before, facts });
  }
}

async function recover(context) {
  try { return await recoverOnce(context); } catch (error) {
    // Whatever went wrong in the recovery, the run ends as needs-recovery (the locks stay), unless the gate itself can no longer write.
    if (context.gate.snapshot().mode !== "closed") await context.gate.finish("needs-recovery").catch(() => {});
    throw error;
  }
}

async function recoverOnce({ gate, targets, member, before, facts }) {
  if (gate.snapshot().mode === "normal") gate.enterRecovery();
  const meta = { phase: "recovery", mutationKey: null, accept: null };
  const current = policyOf((await gate.send(targets.prepareRead(IDS.current), meta)).raw);
  if (current === null) { await gate.finish("needs-recovery"); throw tagged(STOP_CODES.outcomeUncertain, "the policy could not be read back"); }
  await facts(IDS.current, current);
  if (sameBindings(current, before)) { await gate.finish("recovered"); return Object.freeze({ status: "recovered", changed: false, requests: gate.snapshot().requests }); }
  if (assess(current, member).state === "present" && sameBindings(withoutGrant(current, member), before)) {
    const answer = await gate.send(targets.prepareRevoke(IDS.revoke, current), { phase: "recovery", mutationKey: "iam-revoke", accept: null });
    const read = answer.raw.status === 200 ? policyOf((await gate.send(targets.prepareRead(IDS.absent), meta)).raw) : null;
    if (read !== null && sameBindings(read, before)) { await facts(IDS.absent, read); await gate.finish("recovered"); return Object.freeze({ status: "recovered", changed: false, requests: gate.snapshot().requests }); }
  }
  await gate.finish("needs-recovery");
  throw tagged(STOP_CODES.outcomeUncertain, "the policy is neither the one before nor the one before with the grant, or the grant could not be removed");
}
