// The judge of the S5 recorder (rtdb-s5.mjs): what does production do with an onDisconnect value that carries
// `.priority` after a cancel of one of its children? The official emulator (4.11.2) accepts every request and then
// drops the whole disconnect update; fireemu fires the remaining children. The journal of one round is classified
//
//   A  nothing fires: the value and the write registered next to it stay null (the official emulator's answer)
//   B  the remaining children fire (the cancelled child is gone) and the unrelated write fires (fireemu's answer)
//   C  the value fires whole, the cancel having no effect, and the unrelated write fires
//   D  only the unrelated write fires
//
// and anything else is `unclassified`. Two controls run next to it on their own connections: the same value
// without the priority must split (B-shaped), and a cancel of a key the value does not hold must leave the value
// whole with its priority. A control that does not behave so, a missing or duplicated row, a timeout, an error, a
// rejection, a cancelled listener or a transport other than WebSocket makes the round `unclassified`: the judge never
// picks the nearest letter. It never reads timings.
import { isDeepStrictEqual } from 'node:util';

export const SCENARIO = 's5';
export const CASES = ['main', 'plain', 'whole'];
/** The acknowledgements of the writer's registrations, per case (the page emits them as `ack` rows of actor w). */
export const REGISTRATIONS = Object.fromEntries(CASES.map((c) => [c, [`${c}-register-s`, `${c}-register-cancel`, `${c}-register-t`]]));
export const OUTCOMES = {
  A: 'nothing fires: the whole disconnect update is dropped (the official emulator)',
  B: 'the remaining children fire and the unrelated write fires (fireemu)',
  C: 'the value fires whole, the cancel has no effect, and the unrelated write fires',
  D: 'only the unrelated write fires',
};
export const KEPT = ['scenario', 'step', 'type', 'actor', 'label', 'shape', 'priority', 'code'];
export const ROUNDS = ['r1-ws', 'r2-ws'];

const SPLIT = { 9: 3, 10: 2 }, WHOLE = { b: 1, 9: 3, 10: 2 };
const UNKNOWN = new Set(['timeout', 'error', 'rejected', 'cancel']);

const unclassified = (reason) => ({ outcome: 'unclassified', reason });
const parse = (shape) => { try { return { value: JSON.parse(shape) }; } catch { return null; } };

/** The `get` rows by label, or the reason the journal cannot be read. */
function gets(journal) {
  const wanted = new Set(CASES.flatMap((c) => [`${c}-s`, `${c}-t`])), out = new Map();
  for (const r of journal) {
    if (r.type !== 'get') continue;
    if (!wanted.has(r.label)) return { reason: `a get of an unexpected label ${r.label}` };
    if (out.has(r.label)) return { reason: `${r.label} was read twice` };
    const parsed = typeof r.shape === 'string' ? parse(r.shape) : null;
    if (!parsed) return { reason: `${r.label} has no readable shape` };
    out.set(r.label, { value: parsed.value, priority: r.priority ?? null });
  }
  for (const label of wanted) if (!out.has(label)) return { reason: `${label} was not read` };
  return { out };
}

/** Classifies one round (the journal of one profile). */
export function classify(journal) {
  if (!Array.isArray(journal) || journal.length === 0) return unclassified('no journal');
  const bad = journal.find((r) => UNKNOWN.has(r.type));
  if (bad) return unclassified(`a ${bad.type} row at step ${bad.step ?? '?'}${bad.label ? ` (${bad.label})` : ''}`);
  const transports = journal.filter((r) => r.type === 'transport');
  if (transports.length !== 1 || transports[0].code !== 'ws') return unclassified('the round did not run on WebSocket exactly once');
  for (const c of CASES) {
    for (const label of REGISTRATIONS[c]) if (journal.filter((r) => r.type === 'ack' && r.label === label).length !== 1) return unclassified(`the registration ${label} was not acknowledged once`);
    if (journal.filter((r) => r.type === 'offline' && r.label === c).length !== 1) return unclassified(`the writer of ${c} did not go offline once`);
  }
  const read = gets(journal);
  if (read.reason) return unclassified(read.reason);
  const g = (label) => read.out.get(label);
  const is = (label, value, priority) => isDeepStrictEqual(g(label).value, value) && (priority === undefined || g(label).priority === priority);
  if (!(is('plain-s', SPLIT, null) && is('plain-t', 1))) return unclassified('control plain (the same value without a priority) did not split');
  if (!(is('whole-s', WHOLE, 1) && is('whole-t', 1))) return unclassified('control whole (a cancel of a missing key) did not leave the value whole with its priority');
  const s = g('main-s').value, t = g('main-t').value;
  if (s === null && t === null) return { outcome: 'A', reason: OUTCOMES.A };
  if (isDeepStrictEqual(s, SPLIT) && t === 1) return { outcome: 'B', reason: OUTCOMES.B, priority: g('main-s').priority };
  if (isDeepStrictEqual(s, WHOLE) && t === 1) return { outcome: 'C', reason: OUTCOMES.C };
  if (s === null && t === 1) return { outcome: 'D', reason: OUTCOMES.D };
  return unclassified(`main ended in a state that is none of A to D: s=${JSON.stringify(s)} t=${JSON.stringify(t)}`);
}

/** The answer of a production recording: both WebSocket rounds, which must agree. */
export function judgeRounds(profiles) {
  const mine = (Array.isArray(profiles) ? profiles : []).filter((p) => p.scenario === SCENARIO);
  const names = mine.map((p) => p.name).sort();
  if (mine.length !== ROUNDS.length || names.some((n, i) => n !== ROUNDS[i])) return { verdict: 'unclassified', reason: `needs exactly the rounds ${ROUNDS.join(', ')}`, rounds: [] };
  const rounds = mine.map((p) => ({ name: p.name, ...classify(p.journal) })).sort((a, b) => (a.name < b.name ? -1 : 1));
  if (rounds.some((r) => r.outcome === 'unclassified')) return { verdict: 'unclassified', reason: rounds.find((r) => r.outcome === 'unclassified').reason, rounds };
  if (rounds[0].outcome !== rounds[1].outcome) return { verdict: 'unsettled', reason: `round 1 gave ${rounds[0].outcome}, round 2 gave ${rounds[1].outcome}`, rounds };
  return { verdict: rounds[0].outcome, reason: OUTCOMES[rounds[0].outcome], rounds };
}

/** The journal as kept in the repository: kept fields only, no milliseconds. */
export function sanitizeProfiles(profiles) {
  return profiles.map((p) => ({
    scenario: p.scenario,
    name: p.name,
    journal: p.journal.map((row) => Object.fromEntries(KEPT.filter((k) => k in row && row[k] !== undefined).map((k) => [k, row[k]]))),
  }));
}
