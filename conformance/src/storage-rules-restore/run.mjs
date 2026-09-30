import { createHash } from "node:crypto";
import { judgeAnswer } from "./judge.mjs";
import { IDENTITY_ID, restoreRequests, TOKEN_ID } from "./plan.mjs";

// The cleanup, through the dispatch gate (each request admitted, journalled before it is sent and counted). The owner's token and identity are checked as in the
// other stages; then every fact the cleanup relies on is read and must be exactly the expected state (a wrong answer stops the run before anything is deleted,
// as a preflight failure with nothing changed). Only then are the objects, the accounts and the rulesets deleted, once each and in that order, and every
// answer must be the one the plan expects; the verification reads that follow must show the state clean. Any surprise after the first deletion ends the run
// as needs-recovery (the locks stay), and nothing is retried: the reads of a later run decide what is left.
const sha = (value) => createHash("sha256").update(value).digest("hex");
const WRITES = new Set(["object-delete", "account-delete", "ruleset-delete"]);

export async function runRestore({ gate, cache, targets, state, local, capture, runId }) {
  const requests = restoreRequests(state);
  await gate.start({ runId });
  await cache.refreshOwner(TOKEN_ID);
  await gate.send(targets.prepareIdentity(IDENTITY_ID), { phase: "preflight", mutationKey: null, accept: (raw) => {
    let body;
    try { body = raw.status === 200 ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes)) : undefined; } catch { body = undefined; }
    return body !== null && typeof body === "object" && body.verified_email === true && typeof body.email === "string" && sha(body.email) === local.ownerEmailSha256;
  } });
  const record = (request, answer, ok) => capture.writeFacts({ operationId: request.id, kind: "restore-answer", verdict: "recorded", facts: { status: answer.raw.status, bodyBytes: answer.raw.bytes.length, bodySha256: sha(answer.raw.bytes), expected: ok } });
  for (const request of requests.filter((entry) => entry.phase === "preflight")) {
    const answer = await gate.send(targets.prepare(request.id), { phase: "preflight", mutationKey: null, accept: (raw) => judgeAnswer(request.kind, raw, { state, request }) });
    await record(request, answer, true);
  }
  gate.admit();
  let wrote = false;
  try {
    for (const request of requests.filter((entry) => entry.phase === "normal")) {
      const write = WRITES.has(request.kind);
      if (write) wrote = true;
      const answer = await gate.send(targets.prepare(request.id), { phase: "normal", mutationKey: write ? `restore:${request.id}` : null, accept: null });
      const ok = judgeAnswer(request.kind, answer.raw, { state, request });
      await record(request, answer, ok);
      if (!ok) throw new Error(`unexpected answer at ${request.id}`);
    }
    await gate.finish("finished");
    return Object.freeze({ status: "finished", changed: true, requests: gate.snapshot().requests });
  } catch (error) {
    if (gate.snapshot().mode !== "closed") await gate.finish(wrote ? "needs-recovery" : "stopped-no-mutation").catch(() => {});
    throw error;
  }
}
