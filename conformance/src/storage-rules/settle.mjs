// The wait after a Rules publication or a release removal, as a pure reducer. A cycle reads every witness once; it matches
// only when every read gives exactly the verdict that witness expects. The wait settles after the required number of
// consecutive matching cycles and is exhausted when the cycle limit is spent. Only the closed verdicts count: an answer
// that is neither allowed nor denied (`other`) never matches, so it can never stand in for a denial.
const VERDICTS = ["allowed", "denied", "other"];
const bad = (message) => { throw new Error(message); };

function readConfig(input) {
  const fail = () => bad("invalid settle configuration");
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype) fail();
  const keys = Reflect.ownKeys(input);
  const allowed = ["kind", "name", "maxCycles", "requiredConsecutive", "witnesses", "phase"];
  if (keys.some((key) => !allowed.includes(key)) || !["kind", "name", "maxCycles", "requiredConsecutive", "witnesses"].every((key) => keys.includes(key))) fail();
  for (const key of keys) { const field = Object.getOwnPropertyDescriptor(input, key); if (!field?.enumerable || !Object.hasOwn(field, "value")) fail(); }
  const { kind, name, maxCycles, requiredConsecutive } = input;
  const phase = keys.includes("phase") ? input.phase : "normal";
  if (!["publication", "restoration"].includes(kind) || !["normal", "recovery"].includes(phase) || (kind === "publication" && phase !== "normal")) fail();
  if (typeof name !== "string" || !/^[A-Za-z0-9-]{1,32}$/.test(name)) fail();
  const limit = kind === "publication" ? 30 : 15;
  if (!Number.isSafeInteger(maxCycles) || maxCycles < 1 || maxCycles > limit || !Number.isSafeInteger(requiredConsecutive) || requiredConsecutive < 1 || requiredConsecutive > maxCycles) fail();
  const list = input.witnesses;
  if (!Array.isArray(list) || Object.getPrototypeOf(list) !== Array.prototype || Reflect.ownKeys(list).length !== list.length + 1) fail();
  const witnesses = list.map((entry, index) => {
    const field = Object.getOwnPropertyDescriptor(list, String(index));
    if (!field?.enumerable || !Object.hasOwn(field, "value")) fail();
    const witness = field.value;
    if (!witness || typeof witness !== "object" || Object.getPrototypeOf(witness) !== Object.prototype || Reflect.ownKeys(witness).length !== 2) fail();
    for (const key of ["objectName", "expect"]) { const inner = Object.getOwnPropertyDescriptor(witness, key); if (!inner?.enumerable || !Object.hasOwn(inner, "value")) fail(); }
    if (typeof witness.objectName !== "string" || !/^STORAGE-RULES\/[A-Za-z0-9._\/-]{1,900}$/.test(witness.objectName) || !["allowed", "denied"].includes(witness.expect)) fail();
    return Object.freeze({ objectName: witness.objectName, expect: witness.expect });
  });
  if (new Set(witnesses.map((w) => w.objectName)).size !== witnesses.length) fail();
  // A publication reads one witness that must be allowed and one that must be denied; a restoration reads four that must all be denied.
  if (kind === "publication" ? witnesses.length !== 2 || witnesses[0].expect !== "allowed" || witnesses[1].expect !== "denied" : witnesses.length !== 4 || witnesses.some((w) => w.expect !== "denied")) fail();
  return Object.freeze({ kind, name, phase, maxCycles, requiredConsecutive, witnesses: Object.freeze(witnesses) });
}

export const settleRowId = (config, cycle, index) => `${config.phase === "recovery" ? "recovery/" : ""}settle/${config.name}/${cycle}/${index}`;

export function createSettleState(input) {
  const config = readConfig(input);
  return Object.freeze({ config, status: "running", cycle: 1, index: 0, reads: 0, consecutive: 0, cycleMatches: true });
}

/** The next read to make, or null once the wait is over. */
export function nextRead(state) {
  if (state.status !== "running") return null;
  const witness = state.config.witnesses[state.index];
  return Object.freeze({ cycle: state.cycle, index: state.index, witness, rowId: settleRowId(state.config, state.cycle, state.index) });
}

export function applyVerdict(state, verdict) {
  if (state.status !== "running") bad("settle is over");
  if (typeof verdict !== "string" || !VERDICTS.includes(verdict)) bad("invalid settle verdict");
  const { config } = state;
  const matches = state.cycleMatches && verdict === config.witnesses[state.index].expect;
  if (state.index + 1 < config.witnesses.length) return Object.freeze({ ...state, index: state.index + 1, reads: state.reads + 1, cycleMatches: matches });
  const consecutive = matches ? state.consecutive + 1 : 0;
  const reads = state.reads + 1;
  if (consecutive >= config.requiredConsecutive) return Object.freeze({ ...state, status: "settled", consecutive, reads, index: 0, cycleMatches: true });
  if (state.cycle >= config.maxCycles) return Object.freeze({ ...state, status: "exhausted", consecutive, reads, index: 0, cycleMatches: true });
  return Object.freeze({ ...state, cycle: state.cycle + 1, index: 0, reads, consecutive, cycleMatches: true });
}
