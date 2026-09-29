import { createHash } from "node:crypto";
import { PROBE_IDS, IDS } from "./plan.mjs";

// The probe, through the dispatch gate (each request admitted, journalled before it is sent and counted). The owner's token and identity are checked as in
// the other stages (the identity digest must be the expected one); then the six read requests are sent once each and every answer is recorded, whatever
// its status: the gate captures the raw response into the private journal, and a fact per request notes its status, size and digest. The probe judges
// nothing about a body (that is what it is for) and writes nothing to production. A request that cannot be sent or answered ends the run as stopped.
const sha = (value) => createHash("sha256").update(value).digest("hex");
/** The value of the first header of that name in a raw header list (name, value, name, value, ...), or null. */
export function headerValue(rawHeaders, name) {
  for (let index = 0; index + 1 < rawHeaders.length; index += 2) if (rawHeaders[index].toLowerCase() === name) return rawHeaders[index + 1];
  return null;
}

export async function runProbe({ gate, cache, targets, local, capture, runId }) {
  await gate.start({ runId });
  await cache.refreshOwner(IDS.token);
  await gate.send(targets.prepareIdentity(IDS.identity), { phase: "preflight", mutationKey: null, accept: (raw) => {
    let body;
    try { body = raw.status === 200 ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes)) : undefined; } catch { body = undefined; }
    return body !== null && typeof body === "object" && body.verified_email === true && typeof body.email === "string" && sha(body.email) === local.ownerEmailSha256;
  } });
  gate.admit();
  try {
    for (const id of PROBE_IDS) {
      const answer = await gate.send(targets.prepare(id), { phase: "normal", mutationKey: null, accept: null });
      const type = headerValue(answer.raw.rawHeaders, "content-type");
      await capture.writeFacts({ operationId: id, kind: "probe-answer", verdict: "recorded", facts: { status: answer.raw.status, bodyBytes: answer.raw.bytes.length, bodySha256: sha(answer.raw.bytes), contentType: typeof type === "string" && /^[\x20-\x7e]{1,100}$/.test(type) && !/[<>]/.test(type) ? type : null } });
    }
    await gate.finish("finished");
    return Object.freeze({ status: "finished", changed: false, requests: gate.snapshot().requests });
  } catch (error) {
    if (gate.snapshot().mode !== "closed") await gate.finish("stopped-no-mutation").catch(() => {});
    throw error;
  }
}
