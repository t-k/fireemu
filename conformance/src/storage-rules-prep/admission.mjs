import { PREP_RECORDINGS_PER_APPROVAL, validatePrepApproval } from "./approval.mjs";
import { STOP_CODES, tagged } from "../storage-rules/stop-codes.mjs";

// The stage 2a copy of the stage 3 admission (one recording, the 2a approval). The live proof that a run may go on: the owner ledger, read again at every check, still holds this version's
// approval (envelope, version pins, decision) with no revocation in any spelling, and the project locks are still
// this run's. Any failure refuses, and a refusal is permanent, so a ledger that looks valid again later cannot resume the run.
// This module decides nothing about a request; the dispatch gate asks before it starts and before it sends.
const isFunction = (value) => typeof value === "function";
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const KEYS = ["readLedger", "packet", "review", "locks", "runId", "usage"];

function deepFreezeCopy(value) {
  const copy = structuredClone(value);
  const freeze = (item) => { if (item !== null && typeof item === "object") { Object.values(item).forEach(freeze); Object.freeze(item); } return item; };
  return freeze(copy);
}

export function createPrepAdmission(options) {
  const fail = () => { throw new Error("invalid admission options"); };
  if (!plain(options) || Reflect.ownKeys(options).length !== KEYS.length || !KEYS.every((key) => Object.hasOwn(options, key))) fail();
  if (!isFunction(options.readLedger) || !isFunction(options.locks?.verify) || !plain(options.packet) || !plain(options.review) || typeof options.runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(options.runId) || !isFunction(options.usage?.startedRunIds) || !isFunction(options.usage?.markStarted)) fail();
  const { readLedger, locks, runId, usage } = options;
  let packet;
  let review;
  try { packet = deepFreezeCopy(options.packet); review = deepFreezeCopy(options.review); } catch { fail(); }
  let refused = false;
  let checks = 0;
  let begun = false;

  const refuse = (reason) => { refused = true; throw tagged(STOP_CODES.admissionRefused, `admission refused: ${reason}`); };

  async function verify() {
    if (refused) throw tagged(STOP_CODES.admissionRefused, "admission refused: an earlier check refused");
    checks++;
    let approval;
    try {
      const ledgerText = await readLedger();
      approval = validatePrepApproval({ ledgerText, packet: structuredClone(packet), review: structuredClone(review) });
    } catch (error) {
      return refuse(String(error?.message ?? "ledger check failed").slice(0, 200));
    }
    let held;
    try { held = await locks.verify(); } catch { return refuse("project lock check failed"); }
    if (held !== true) return refuse("project locks are not held");
    return Object.freeze({ admitted: true, decisionLine: approval.decisionLine, envelopeId: approval.envelopeId });
  }

  // The run's first admission: the same proof as a check, then the run is marked as started before it may send. An approval covers
  // RECORDINGS_PER_APPROVAL recordings; a run that would be another one is refused, and so is a run that was already marked.
  async function readStarted() {
    let ids;
    try { ids = await usage.startedRunIds(); } catch { return refuse("recording usage unreadable"); }
    if (!Array.isArray(ids) || ids.some((id) => typeof id !== "string") || new Set(ids).size !== ids.length) return refuse("recording usage is malformed");
    return ids;
  }

  return Object.freeze({
    check: verify,
    async begin() {
      if (begun) return refuse("already begun");
      begun = true;
      const seen = await verify();
      const before = await readStarted();
      if (before.includes(runId)) return refuse("run already started");
      if (before.length >= PREP_RECORDINGS_PER_APPROVAL) return refuse("recording budget exhausted");
      try { await usage.markStarted(runId); } catch { return refuse("run could not be marked started"); }
      const after = await readStarted();
      if (!after.includes(runId)) return refuse("run marker is not durable");
      return seen;
    },
    snapshot: () => Object.freeze({ refused, checks, begun }),
  });
}
