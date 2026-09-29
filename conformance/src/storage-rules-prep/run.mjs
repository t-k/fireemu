import { classifyResponse } from "../storage-rules/acceptance.mjs";
import { STOP_CODES, tagged } from "../storage-rules/stop-codes.mjs";
import { assembleInputs, keyFacts, keyStringMatches, KEY_LIST_IDS, OWNER_TOKEN_ID, PREP_IDS, selectKey } from "./plan.mjs";

// The thirteen reads, in order, through the dispatch gate (so each is admitted, journalled before it is sent and counted).
// A request whose answer is not the expected shape, or whose facts do not fit, ends the run at that request: the gate's
// preflight acceptance turns the refusal into the counter's `preflight-failed` terminal row. Nothing here writes to production.
const stop = (message) => { throw tagged(STOP_CODES.preflightFailed, message); };
const parse = (raw) => {
  try { return raw.status === 200 ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes)) : undefined; } catch { return undefined; }
};

/**
 * Run the reads. `cache` is the counted credential cache (the token read), `targets` the prep targets, `local` the operator's
 * own values (`adcPath`, project `numbers`, API `keys`), `bucket` the expected bucket name. Returns the private inputs object.
 */
export async function runPrepReads({ gate, cache, targets, local, bucket, capture, runId }) {
  const meta = (accept) => ({ phase: "preflight", mutationKey: null, accept });
  const outcomes = new Map();

  const sendRow = async (prepared, row, judge = () => true) => {
    let outcome = null;
    const accept = (raw) => {
      try { outcome = classifyResponse(row, raw); return outcome.verdict === "accepted" && judge(outcome) === true; } catch { return false; }
    };
    const result = await gate.send(prepared, meta(accept));
    outcome ??= classifyResponse(row, result.raw);
    await capture.writeFacts({ operationId: row.id, kind: outcome.kind, verdict: outcome.verdict, facts: outcome.facts });
    outcomes.set(row.id, outcome);
    return outcome;
  };
  const standard = (id, judge) => sendRow(targets.prepareStandard(id), targets.row(id), judge);
  const permissions = (outcome) => outcome.facts.missing.length === 0 && outcome.facts.granted === outcome.facts.requested;

  await gate.start({ runId });
  await cache.refreshOwner(OWNER_TOKEN_ID);
  const identity = await standard("preflight/owner/identity", (outcome) => outcome.facts.verifiedEmail === true && typeof outcome.secretFacts?.email === "string" && typeof outcome.secretFacts?.subject === "string");

  // The key lists: exactly one live key each, which the stage 3 preflight classifier then reads as key metadata.
  const keys = {};
  for (const project of ["query", "idp"]) {
    const prepared = targets.prepareList(project);
    let chosen = null;
    let facts = null;
    const accept = (raw) => {
      try {
        const body = parse(raw);
        if (body === undefined) return false;
        chosen = selectKey(body, local.numbers[project], local.keyIds[project]);
        const metaRow = targets.manifestRow(`preflight/${project}/key-metadata`);
        const row = { ...metaRow, request: { ...metaRow.request, path: `/v2/${chosen.item.name}` } };
        const seen = classifyResponse(row, { status: 200, rawHeaders: ["content-type", "application/json"], bytes: Buffer.from(JSON.stringify(chosen.item)) });
        if (seen.verdict !== "accepted") return false;
        facts = keyFacts(seen.facts);
        return true;
      } catch { return false; }
    };
    const result = await gate.send(prepared, meta(accept));
    if (chosen === null || facts === null) stop("key list not judged");
    await capture.writeFacts({ operationId: KEY_LIST_IDS[project], kind: "preflight-key-list", verdict: "accepted", facts: { status: 200, otherLiveKeys: chosen.otherLiveKeys, apiTargets: facts.apiTargets.length } });
    keys[project] = { keyId: chosen.keyId, facts, attempt: result.attempt };
  }
  if (keys.query.keyId === keys.idp.keyId) stop("the two projects report the same key ID");
  const keyIds = { query: keys.query.keyId, idp: keys.idp.keyId };
  const strings = {};
  for (const project of ["query", "idp"]) {
    const id = `preflight/${project}/key-string`;
    // The classifier reads the key string from the body; the row only names the kind.
    const outcome = await sendRow(targets.prepareKeyString(project, keyIds), targets.manifestRow(id), (seen) => keyStringMatches(seen.secretFacts?.keyString, local.keys[project]));
    strings[project] = outcome.secretFacts.keyString;
  }
  const bucketMeta = await standard("preflight/bucket/metadata", (outcome) => outcome.facts.projectNumber === local.numbers.query);
  const bucketIam = await standard("preflight/bucket/iam");
  const database = await standard("preflight/query/database");
  const queryIam = await standard("preflight/query/iam");
  await standard("preflight/query/permissions", permissions);
  await standard("preflight/idp/permissions", permissions);
  await standard("preflight/bucket/permissions", permissions);
  if (outcomes.size !== PREP_IDS.length - 3) stop("a read is missing");

  const inputs = assembleInputs({
    adcPath: local.adcPath, local: { numbers: local.numbers, keys: local.keys },
    identity: { email: identity.secretFacts.email, subject: identity.secretFacts.subject },
    query: { keyId: keys.query.keyId, facts: keys.query.facts, keyString: strings.query },
    idp: { keyId: keys.idp.keyId, facts: keys.idp.facts, keyString: strings.idp },
    bucket: { name: bucket, facts: bucketMeta.facts, iamSha256: bucketIam.facts.policySha256 },
    database: database.facts, queryIamSha256: queryIam.facts.policySha256,
  });
  gate.admit();
  await gate.finish("finished");
  return inputs;
}

