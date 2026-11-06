// Test helpers for the RTDB SDK small observer comparison: a seeded PRNG and generated reduced journals in the
// recorded shape (four profiles, three setup rows and eight cases each, per-role connection events).
export const NAMES = ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'];
const PUSH = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';

/** mulberry32: a small deterministic PRNG, so a failing seed can be replayed. */
export function prng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
export const int = (rand, lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));

/** Two consecutive SDK push ids: 20 characters of the push alphabet, the second one greater. */
export function pushPair(rand) {
  const chars = Array.from({ length: 20 }, () => PUSH[int(rand, 0, 63)]);
  chars[19] = PUSH[int(rand, 0, 62)];
  const first = chars.join(''), second = first.slice(0, 19) + PUSH[PUSH.indexOf(first[19]) + 1];
  return [first, second];
}

/** One profile as the reducer writes it; `rand` varies only what the judge masks (push ids, clock values). */
export function profile(name, rand = prng(1)) {
  const before = int(rand, 1.7e12, 1.9e12), value = before + int(rand, 0, 400), after = value + int(rand, 0, 400);
  const row = (role, id, v) => ({ role, id, ok: true, value: v });
  return {
    name,
    events: { writer: ['disconnected', 'connected', 'disconnected'], observer: ['disconnected', 'connected', 'disconnected'] },
    rows: [
      row('writer', 'startup', null), row('observer', 'startup', null), row('writer', 'seed', null),
      row('observer', 'key_range', [{ key: 'b', value: 2, priority: null }, { key: 'c', value: 2, priority: null }, { key: 'd', value: 3, priority: null }]),
      row('observer', 'value_equal', [{ key: 'b', value: 2, priority: null }, { key: 'c', value: 2, priority: null }]),
      row('observer', 'priority_range', [{ key: 'b', value: 'B', priority: 2 }, { key: 'c', value: 'C', priority: 3 }]),
      row('writer', 'push', { keys: pushPair(rand), a: 'a', b: 'b' }),
      row('writer', 'update', { edit: 2, keep: 1 }),
      row('writer', 'multipath', { x: 1, y: 2 }),
      row('writer', 'server_timestamp', { value, before, after }),
      row('writer', 'increment', { absent: 5, at: value, numeric: 12, string: 5 }),
    ],
  };
}

/** A complete reduced journal (the local side). */
export function journal(rand = prng(1)) {
  return { kind: 'rtdb-sdk-small-journal-v1', result: { status: 'complete', observed: 32, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' } }, faults: [], profiles: NAMES.map((n) => profile(n, rand)) };
}
export const clone = (x) => structuredClone(x);

/** The raw journal rows the observer writes for a reduced journal, with the rows the reducer must drop. */
export function rawRows(doc) {
  const rows = [{ t: '2026-11-01T16:55:59.000Z', kind: 'admin-req', label: 'rules-before', method: 'GET', url: 'https://ns.firebaseio.com/.settings/rules.json', body: null }, { kind: 'admin-res', label: 'rules-before', status: 200, body: '{}' }];
  for (const p of doc.profiles) {
    for (const role of ['writer', 'observer']) rows.push({ t: 'x', kind: 'sdk-event', profile: p.name, role, event: p.events[role][0] });
    rows.push({ kind: 'raw-ws', dir: 'out', conn: 1, data: '{"t":"d"}' }, { kind: 'raw-lp-request', profile: p.name, method: 'GET', url: 'http://x/.lp', body: null }, { kind: 'raw-lp-response', profile: p.name, status: 200, url: 'http://x/.lp', body: '' });
    for (const r of p.rows) rows.push({ t: 'x', kind: 'case', profile: p.name, ...r, ms: 17 });
    for (const role of ['writer', 'observer']) for (const event of p.events[role].slice(1)) rows.push({ kind: 'sdk-event', role, event, profile: p.name });
  }
  rows.push({ kind: 'result', runId: 'x', status: 'complete' });
  return rows;
}

