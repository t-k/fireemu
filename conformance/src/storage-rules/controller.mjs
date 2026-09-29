import { createHash } from "node:crypto";
import { classifyResponse } from "./acceptance.mjs";
import { ENFORCEMENT } from "./enforcement.mjs";
import { applyVerdict, createSettleState, nextRead } from "./settle.mjs";
import { STOP_CODES, stopCodeOf } from "./stop-codes.mjs";

// Runs the reviewed schedule of one recording. Each row goes through the same steps: guards from the ledgers, the
// run-time references it needs, its exact target, the ledgers' record of the intent, one send through the gate, the
// classification of the response, the durable facts, the ledgers' record of the outcome, the post-response checks, the
// expected verdict and the references the response produced. Anything unexpected stops the run at once; the controller
// never resends, never recovers by itself and never widens what a row may do. It sends only through the gate.
class RunStop extends Error {
  constructor(reason, detail = {}) { super(`run stopped: ${reason}`); this.reason = reason; this.detail = detail; }
}
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const callable = (value) => typeof value === "function";
const DEFER = new Set(["admission", "delegate", "refs", "structure", "policy", "post-check"]);

export function createController(options) {
  const fail = () => { throw new Error("invalid controller options"); };
  const keys = ["manifest", "schedule", "recoverySchedule", "gate", "targets", "refs", "tables", "objects", "run", "capture", "delegates", "wait", "credentials", "judgePreflight"];
  if (!plain(options) || Reflect.ownKeys(options).length !== keys.length || !keys.every((key) => Object.hasOwn(options, key))) fail();
  const { manifest, schedule, recoverySchedule, gate, targets, refs, tables, objects, run, capture, delegates, wait, credentials, judgePreflight } = options;
  if (!manifest || manifest.sendAuthorized !== false || !schedule?.steps || !recoverySchedule?.steps || typeof run?.recoveryEnabled !== "function" || ![gate?.send, gate?.start, gate?.admit, gate?.finish, targets?.prepare, refs?.bind, refs?.resolve, objects?.evaluate, run?.evaluate, capture?.writeFacts, capture?.writeNote, wait, credentials?.fresh, judgePreflight].every(callable) || !plain(delegates)) fail();
  const rowById = new Map(manifest.rows.map((row) => [row.id, row]));
  const skipped = [];
  const seedDigest = new Map();
  for (const row of manifest.rows) {
    if (row.request.operation === "upload" && row.request.credential === "admin" && typeof row.request.body?.base64 === "string" && manifest.resources.controls.includes(row.request.objectName)) {
      seedDigest.set(row.request.objectName, createHash("sha256").update(Buffer.from(row.request.body.base64, "base64")).digest("hex"));
    }
  }
  const invalidCompile = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").at(-1)?.id;
  let executed = 0;

  const mustBeAbsent = (row) => ["baseline", "baseline-metadata", "baseline-media", "absence-metadata", "absence-media"].includes(row.stage) || (row.stage === "cleanup" && /absence/.test(row.id));
  function verdictOk(row, outcome) {
    const { kind, verdict } = outcome;
    if (kind === "gcs-metadata-read" || kind === "gcs-media-read") return mustBeAbsent(row) ? verdict === "absent" : verdict === "present" || verdict === "absent";
    if (kind === "subject-observed") return verdict === "observed";
    if (kind === "rules-test") return row.id === invalidCompile ? verdict === "rejected" : verdict === "accepted";
    if (kind === "rules-ruleset-read") return row.stage === "absence" || /\/absence$/.test(row.id) ? verdict === "absent" : verdict === "present";
    if (kind === "rules-release-read") {
      if (/no-release-entry-after|\/final\/|-absence$|^compile\/release\/|^preflight\/release\//.test(row.id)) return verdict === "absent";
      if (/owner-before-delete$|\/after$/.test(row.id)) return verdict === "present";
      return verdict === "present" || verdict === "absent";
    }
    if (kind === "firestore-read") return verdict === "present" || verdict === "absent";
    // A query right after a cancel (the verify rows and recovery's terminal query) must find the session finished; only the first look may find it active.
    if (kind === "session-command") return row.request.headers["x-goog-upload-command"] === "cancel" ? verdict === "acknowledged" : row.family === "session-verify" || /\/terminal$/.test(row.id) ? verdict === "final" : verdict === "active" || verdict === "final";
    // A settle read either shows the witness readable or shows it denied; any other answer (a quota error, a lost witness, wrong bytes) is a surprise, not a cycle that has not settled yet.
    if (kind === "settle-read") return verdict === "allowed" || verdict === "denied";
    return verdict === "accepted";
  }

  const mutationKeyOf = (row) => {
    const { method, operation } = row.request;
    if (!["POST", "PATCH", "PUT", "DELETE"].includes(method)) return null;
    const resource = row.request.objectName ?? row.request.documentName ?? row.programId;
    return `${row.family}:${resource}:${operation ?? method}:${row.id}`;
  };

  function decide(row) {
    const first = objects.evaluate(row);
    const second = run.evaluate(row, first.unresolved);
    const failed = [...first.failed, ...second.failed];
    for (const token of second.unresolved) if (!DEFER.has(Object.keys(ENFORCEMENT).find((enforcer) => ENFORCEMENT[enforcer].includes(token)))) throw new RunStop("unhandled guard", { rowId: row.id, token });
    const decision = failed.some((entry) => entry.outcome === "skip") ? "skip" : failed.some((entry) => entry.outcome === "stop") ? "stop" : "go";
    return { decision, failed };
  }

  const bindable = (type, key, operationId, verdict) => (tables.producers[type]?.[key] ?? []).some((entry) => entry.operationId === operationId && entry.verdict === verdict);
  async function bindReferences(row, outcome, attempt) {
    const { kind, verdict, facts } = outcome;
    const provenance = (deletable) => ({ operationId: row.id, attempt, verdict, deletable });
    const ref = (type, key) => ({ kind: "runtime-reference", type, key, resolveOnlyAfterDurableProof: true });
    const bind = async (type, key, value, deletable = false) => { if (typeof value === "string" && bindable(type, key, row.id, verdict)) await refs.bind({ ref: ref(type, key), value, provenance: provenance(deletable) }); };
    const name = row.request.objectName;
    if (kind === "gcs-seed-upload" || kind === "gcs-patch" || (kind === "gcs-metadata-read" && verdict === "present")) {
      const deletable = objects.object(name).deletable;
      await bind("generation", name, facts.generation, deletable);
      await bind("metageneration", name, facts.metageneration, false);
    } else if (kind === "rules-ruleset-create") await bind("ruleset-name", row.programId, facts.rulesetName);
    else if (kind === "firestore-read" && verdict === "present") await bind("update-time", row.request.documentName, facts.updateTime, run.document(row.request.documentName).deletable);
    else if (kind === "firestore-write" && verdict === "accepted" && row.request.method !== "DELETE") await bind("update-time", row.request.documentName, facts.updateTime, run.document(row.request.documentName).deletable);
    else if (kind === "rules-list-page" && facts.hasNextPage) {
      const match = /^rulesets-list\/final\/(\d+)$/.exec(row.id);
      if (match) await bind("page-token", `normal/final/${match[1]}`, facts.nextPageToken);
    }
  }
  async function bindSecrets(row, outcome, attempt) {
    if (!outcome.secretFacts) return;
    const provenance = { operationId: row.id, attempt, verdict: outcome.verdict, deletable: false };
    const ref = (type, key) => ({ kind: "runtime-reference", type, key, resolveOnlyAfterDurableProof: true });
    if (outcome.kind === "session-start") await refs.bind({ ref: ref("session-url", row.request.objectName), value: outcome.secretFacts.sessionUrl, provenance });
    else if (outcome.kind === "firebase-create-token") {
      const token = outcome.secretFacts.downloadTokens;
      if (token.includes(",")) throw new RunStop("more than one download token", { rowId: row.id });
      await refs.bind({ ref: ref("download-token", row.request.objectName), value: token, provenance });
    }
  }

  async function execute(row, phase, { ctx, accept = null } = {}) {
    // A credential provider may refresh what the row needs (through the gate's seam) before its freshness is judged.
    if (callable(credentials.ensure)) {
      try { await credentials.ensure(row); } catch {
        throw new RunStop(gate.snapshot().admissionRefused === true ? "admission refused" : "credential refresh failed", { rowId: row.id });
      }
    }
    run.setFlag("credentialFresh", credentials.fresh(row) === true);
    const decision = decide(row);
    if (decision.decision === "skip") { skipped.push(row.id); await capture.writeNote({ operationId: null, text: `skipped ${row.id}: ${decision.failed.map((f) => f.token).join(", ")}` }); return null; }
    if (decision.decision === "stop") throw new RunStop("guard failed", { rowId: row.id, tokens: decision.failed.map((f) => f.token) });
    let prepared;
    let unavailable = "target refused";
    try { prepared = targets.prepare(row, (reference, rowId) => { try { return refs.resolve(reference, rowId); } catch (error) { unavailable = error.message; throw error; } }); } catch { throw new RunStop("target unavailable", { rowId: row.id, cause: unavailable }); }
    objects.recordIntent(row); run.recordIntent(row);
    let result;
    try { result = await gate.send(prepared, { phase, mutationKey: mutationKeyOf(row), accept }); } catch (error) {
      const code = stopCodeOf(error);
      if (code === STOP_CODES.admissionRefused) throw new RunStop("admission refused", { rowId: row.id });
      if (code === STOP_CODES.preflightFailed) throw new RunStop("preflight refused", { rowId: row.id });
      if (code === STOP_CODES.outcomeUncertain) { executed++; objects.recordOutcome(row, { uncertain: true }); run.recordOutcome(row, { uncertain: true }); throw new RunStop("outcome uncertain", { rowId: row.id }); }
      throw new RunStop(code === STOP_CODES.captureFailed ? "capture failed" : "not sent", { rowId: row.id, message: error.message });
    }
    executed++;
    let outcome;
    try { outcome = classifyResponse(row, result.raw, ctx); } catch { throw new RunStop("unclassifiable response", { rowId: row.id }); }
    await capture.writeFacts({ operationId: row.id, kind: outcome.kind, verdict: outcome.verdict, facts: outcome.facts });
    // The ledgers read the classification only; a secret carried by the result never reaches them.
    const shown = { kind: outcome.kind, verdict: outcome.verdict, facts: outcome.facts };
    objects.recordOutcome(row, shown); run.recordOutcome(row, shown);
    const checked = run.check(row, shown);
    if (!checked.ok) throw new RunStop("check failed", { rowId: row.id, tokens: [...checked.failed] });
    if (!verdictOk(row, outcome)) throw new RunStop("unexpected verdict", { rowId: row.id, kind: outcome.kind, verdict: outcome.verdict });
    await bindReferences(row, outcome, result.attempt);
    await bindSecrets(row, outcome, result.attempt);
    return outcome;
  }

  async function settleStep(step) {
    let state = createSettleState(step.config);
    for (let read = nextRead(state); read !== null; read = nextRead(state)) {
      const row = rowById.get(read.rowId);
      const digest = seedDigest.get(read.witness.objectName);
      const outcome = await execute(row, step.config.phase, { ctx: { expectedSha256: digest ?? "0".repeat(64) } });
      if (outcome === null) throw new RunStop("settle read skipped", { rowId: row.id });
      state = applyVerdict(state, outcome.verdict);
      if (state.status === "running" && read.index === step.config.witnesses.length - 1) await wait(step.intervalMs);
    }
    run.recordSettle(step.name, state.status);
    if (state.status !== "settled") throw new RunStop("settle exhausted", { name: step.name });
  }

  // A delegate carries its own requests through the gate's seam. Whatever it throws becomes a stop: a refused admission keeps
  // its reason, anything else is a failed delegate; the run never continues after a delegate that did not finish.
  async function runDelegate(op, argument) {
    if (!callable(delegates[op])) throw new RunStop("delegate missing", { op });
    try { await delegates[op](argument); } catch {
      if (gate.snapshot().admissionRefused === true) throw new RunStop("admission refused", { op });
      throw new RunStop("delegate failed", { op });
    }
  }

  async function pagesStep(step, phase) {
    for (let index = 0; index < step.rowIds.length; index++) {
      const outcome = await execute(rowById.get(step.rowIds[index]), phase);
      if (outcome !== null && !outcome.facts.hasNextPage) return;
    }
    throw new RunStop("more than ten Ruleset pages");
  }

  async function runAll() {
    try { await gate.start({ runId: manifest.binding.runId }); } catch (error) {
      if (stopCodeOf(error) === STOP_CODES.admissionRefused) throw new RunStop("admission refused", {});
      throw error;
    }
    for (const id of schedule.preflight) {
      const row = rowById.get(id);
      if (row.family === "credential-cache") { await runDelegate("preflight-cache", row); continue; }
      // The counter closes the run itself when the answer is not the admitted one, so the judgement is made as the response arrives.
      const accept = (raw) => { try { const seen = classifyResponse(row, raw); return verdictOk(row, seen) && judgePreflight(row, seen) === true; } catch { return false; } };
      const outcome = await execute(row, "preflight", { accept });
      if (outcome === null) throw new RunStop("preflight refused", { rowId: id });
    }
    gate.admit();
    for (const step of schedule.steps) {
      if (step.type === "row") await execute(rowById.get(step.id), "normal");
      else if (step.type === "settle") await settleStep(step);
      else if (step.type === "pages") await pagesStep(step, "normal");
      else if (step.type === "delegate") {
        await runDelegate(step.op, step);
      } else throw new RunStop("unknown step", { type: step.type });
    }
  }

  // Recovery: the declared recovery rows in the reviewed order. Each row is enabled by the ledgers' facts (a skip costs nothing,
  // a failed guard stops), the same gate, ledgers and checks apply, and recovery never resends or widens what a row may do.
  // It closes as `recovered` only when the last row, the owned-prefix check behind every cleanup guard, was sent and accepted.
  let recoveryAttempted = false;
  async function recoverAll() {
    for (const step of recoverySchedule.steps) {
      if (step.enabledBy !== undefined && !run.recoveryEnabled(step.enabledBy)) {
        const ids = step.type === "row" ? [step.id] : step.rowIds;
        skipped.push(...ids);
        await capture.writeNote({ operationId: null, text: `skipped ${ids.length} recovery row(s), ${step.enabledBy} is not true: ${ids[0]}` });
        continue;
      }
      if (step.type === "row") await execute(rowById.get(step.id), "recovery");
      else if (step.type === "settle") await settleStep(step);
      else if (step.type === "pages") await pagesStep(step, "recovery");
      else if (step.type === "delegate") {
        await runDelegate(step.op, step);
      } else throw new RunStop("unknown step", { type: step.type });
    }
  }

  return Object.freeze({
    async recover() {
      const mode = gate.snapshot().mode;
      if (recoveryAttempted || !["normal", "recovery"].includes(mode)) return Object.freeze({ status: "refused", reason: recoveryAttempted ? "recovery already attempted" : "the counter is not open" });
      recoveryAttempted = true;
      const start = executed;
      const startSkipped = skipped.length;
      const finalRow = recoverySchedule.steps.at(-1)?.id;
      let proven = false;
      try {
        if (mode === "normal") gate.enterRecovery();
        await recoverAll();
        proven = !skipped.slice(startSkipped).includes(finalRow);
      } catch (error) {
        if (!(error instanceof RunStop)) throw error;
        await gate.finish("needs-recovery");
        return Object.freeze({ status: "stopped", reason: error.reason, detail: Object.freeze({ ...error.detail }), requests: executed - start, skipped: Object.freeze(skipped.slice(startSkipped)), needsRecovery: true });
      }
      await gate.finish(proven ? "recovered" : "needs-recovery");
      return Object.freeze({ status: proven ? "recovered" : "stopped", ...(proven ? {} : { reason: "owned-prefix check skipped", detail: Object.freeze({}), needsRecovery: true }), requests: executed - start, skipped: Object.freeze(skipped.slice(startSkipped)) });
    },
    async run() {
      try {
        await runAll();
        await gate.finish("finished");
        return Object.freeze({ status: "finished", requests: executed, skipped: Object.freeze([...skipped]) });
      } catch (error) {
        if (!(error instanceof RunStop)) throw error;
        const untouched = objects.snapshot().mutations === 0 && run.snapshot().mutations === 0;
        let closed = false;
        if (untouched && gate.snapshot().mode === "normal") { await gate.finish("stopped-no-mutation"); closed = true; }
        // Untouched and closed needs no recovery; anything still open (a counter that flipped to recovery after an uncertain read) is reported as open.
        const open = ["normal", "recovery"].includes(gate.snapshot().mode);
        return Object.freeze({ status: "stopped", reason: error.reason, detail: Object.freeze({ ...error.detail }), requests: executed, skipped: Object.freeze([...skipped]), needsRecovery: !closed && (!untouched || open) });
      }
    },
  });
}
