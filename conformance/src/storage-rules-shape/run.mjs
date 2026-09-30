import { createHash } from "node:crypto";
import { judgeAnswer, proofOf } from "./judge.mjs";
import { CREATE_IDS, IDENTITY_ID, TOKEN_ID, WRITE_IDS, staticRequests } from "./plan.mjs";

// The probe, through the dispatch gate (each request admitted, journalled before it is sent and counted). The owner's token and identity are checked as in the other
// stages; the three environment reads must be exactly what the probe expects (a wrong answer stops the run before anything is created, as a preflight failure).
// Then the shape steps run: each answer is recorded (status, size, digest, content type; the raw bytes are in the capture journal) and none is judged, except the three
// create answers, which must prove ownership of what was created (or the run stops: nothing more is sent and the residue is not known). A step whose answer is not the
// one expected goes on, so that everything created is deleted; three reads at the end prove the deletion, and a read that does not prove it ends the run as needs-recovery.
const sha = (value) => createHash("sha256").update(value).digest("hex");
const contentTypeOf = (headers) => {
  for (let index = 0; index + 1 < headers.length; index += 2) {
    if (headers[index].toLowerCase() === "content-type") return /^[\x20-\x7e]{1,100}$/.test(headers[index + 1]) && !/[<>]/.test(headers[index + 1]) ? headers[index + 1] : null;
  }
  return null;
};

export async function runShape({ gate, cache, targets, bucket, local, capture, runId }) {
  const statics = new Map(staticRequests(bucket).map((entry) => [entry.id, entry]));
  await gate.start({ runId });
  await cache.refreshOwner(TOKEN_ID);
  await gate.send(targets.prepareIdentity(IDENTITY_ID), { phase: "preflight", mutationKey: null, accept: (raw) => {
    let body;
    try { body = raw.status === 200 ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes)) : undefined; } catch { body = undefined; }
    return body !== null && typeof body === "object" && body.verified_email === true && typeof body.email === "string" && sha(body.email) === local.ownerEmailSha256;
  } });
  const record = (id, answer) => capture.writeFacts({ operationId: id, kind: "shape-answer", verdict: "recorded", facts: { status: answer.raw.status, bodyBytes: answer.raw.bytes.length, bodySha256: sha(answer.raw.bytes), contentType: contentTypeOf(answer.raw.rawHeaders) } });
  const context = { bucket };
  for (const id of ["preflight/rulesets/list", "preflight/objects/list", "preflight/document/absent"]) {
    const entry = statics.get(id);
    const answer = await gate.send(targets.prepare(id), { phase: "preflight", mutationKey: null, accept: (raw) => judgeAnswer(entry.kind, raw, context) });
    await record(id, answer);
  }
  gate.admit();
  try {
    const send = async (prepared, id) => {
      const answer = await gate.send(prepared, { phase: "normal", mutationKey: WRITE_IDS.includes(id) ? `shape:${id}` : null, accept: null });
      await record(id, answer);
      return answer;
    };
    const step = (id) => send(targets.prepare(id), id);
    const dependent = (id, proofs) => send(targets.prepareDependent(id, proofs), id);
    const owned = (id, kind) => async () => {
      const answer = await step(id);
      const proof = proofOf(kind, answer.raw, context);
      if (proof === null) throw new Error(`ownership not proven at ${id}`);
      return proof;
    };
    await step("shape/ruleset/never");
    const ruleset = await owned(CREATE_IDS.ruleset, "own-ruleset")();
    for (const id of ["shape/ruleset/read", "shape/ruleset/delete", "shape/ruleset/read-deleted"]) await dependent(id, { ruleset });
    const generation = await owned(CREATE_IDS.object, "own-object")();
    await step("shape/object/list");
    await dependent("shape/object/delete", { generation });
    const updateTime = await owned(CREATE_IDS.document, "own-document")();
    await step("shape/document/read");
    await dependent("shape/document/delete", { updateTime });
    let proven = true;
    for (const id of ["verify/rulesets/list", "verify/objects/list", "verify/document/absent"]) {
      const answer = await step(id);
      if (!judgeAnswer(statics.get(id).kind, answer.raw, context)) proven = false;
    }
    if (!proven) throw new Error("deletion not proven");
    await gate.finish("finished");
    return Object.freeze({ status: "finished", changed: true, requests: gate.snapshot().requests });
  } catch (error) {
    if (gate.snapshot().mode !== "closed") await gate.finish("needs-recovery").catch(() => {});
    throw error;
  }
}
