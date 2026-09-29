import { validatePresendApproval } from "./approval.mjs";

// The live proof that a run may go on: the owner ledger, read again at every check, still holds this version's
// approval (envelope, version pins, decision) with no revocation in any spelling, and the project locks are still
// this run's. Any failure refuses, and a refusal is permanent, so a ledger that looks valid again later cannot resume the run.
// This module decides nothing about a request; the dispatch gate asks before it starts and before it sends.
const isFunction = (value) => typeof value === "function";
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const KEYS = ["readLedger", "packet", "review", "locks"];

function deepFreezeCopy(value) {
  const copy = structuredClone(value);
  const freeze = (item) => { if (item !== null && typeof item === "object") { Object.values(item).forEach(freeze); Object.freeze(item); } return item; };
  return freeze(copy);
}

export function createAdmission(options) {
  const fail = () => { throw new Error("invalid admission options"); };
  if (!plain(options) || Reflect.ownKeys(options).length !== KEYS.length || !KEYS.every((key) => Object.hasOwn(options, key))) fail();
  if (!isFunction(options.readLedger) || !isFunction(options.locks?.verify) || !plain(options.packet) || !plain(options.review)) fail();
  const { readLedger, locks } = options;
  let packet;
  let review;
  try { packet = deepFreezeCopy(options.packet); review = deepFreezeCopy(options.review); } catch { fail(); }
  let refused = false;
  let checks = 0;

  const refuse = (reason) => { refused = true; throw new Error(`admission refused: ${reason}`); };

  return Object.freeze({
    async check() {
      if (refused) throw new Error("admission refused: an earlier check refused");
      checks++;
      let approval;
      try {
        const ledgerText = await readLedger();
        approval = validatePresendApproval({ ledgerText, packet: structuredClone(packet), review: structuredClone(review) });
      } catch (error) {
        return refuse(String(error?.message ?? "ledger check failed").slice(0, 200));
      }
      let held;
      try { held = await locks.verify(); } catch { return refuse("project lock check failed"); }
      if (held !== true) return refuse("project locks are not held");
      return Object.freeze({ admitted: true, decisionLine: approval.decisionLine, envelopeId: approval.envelopeId });
    },
    snapshot: () => Object.freeze({ refused, checks }),
  });
}
