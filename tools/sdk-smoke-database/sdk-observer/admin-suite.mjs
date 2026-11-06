// The admin suite (G13): firebase-admin 14.3.0 over WebSocket, Node only. One Admin SDK connection does every read,
// write and listen under a profile scope whose Rules deny every client (`.read:false`, `.write:false`), so each answer
// shows the Admin SDK's bypass. The steps run through the events recorder (events-sequence.mjs runCase) with an
// adapter from the namespaced (compat) API the Admin SDK exposes; a failed case does not stop the next one.
import { runCase, shapeOf, STEP_MS, QUIET_MS, SETTLE_MAX_MS } from './events-sequence.mjs';
import { withTimeout } from './sequence.mjs';

export const ADMIN_CASES = ['set', 'get', 'update', 'push', 'transaction_absent', 'transaction_object', 'transaction_abort', 'remove', 'listen_window', 'get_denied'];
const PUSH_ID = /^[-0-9A-Z_a-z]{20}$/;

/** The modular calls runCase makes, over the Admin SDK's namespaced references and queries. */
export const adminAdapter = {
  ...Object.fromEntries([['onValue', 'value'], ['onChildAdded', 'child_added'], ['onChildChanged', 'child_changed'], ['onChildMoved', 'child_moved'], ['onChildRemoved', 'child_removed']]
    .map(([name, event]) => [name, (query, callback, cancel) => { const handler = query.on(event, (snap, prev) => callback(snap, prev), cancel); return () => query.off(event, handler); }])),
  runTransaction: (ref, update) => ref.transaction(update),
};

export function adminCases() {
  const write = (label, run) => ({ kind: 'write', label, run });
  const get = (label, path) => ({ kind: 'get', label, run: o => o(path).get() });
  return [
    { id: 'set', listeners: [], steps: [write('set', w => w('a').set({ x: 1, y: { z: 2 } }))] },
    { id: 'get', listeners: [], steps: [get('get', 'a')] },
    { id: 'update', listeners: [], steps: [write('update', w => w('a').update({ x: 2, 'y/z': 3, w: 4 })), get('get', 'a')] },
    { id: 'push', listeners: [], steps: [{ kind: 'call', label: 'push', run: async w => { const ref = w('list').push(); const key = PUSH_ID.test(ref.key) ? 'push-id' : `other-${String(ref.key).length}`; await ref.set('p1'); return { key, v: shapeOf(await ref.get()) }; } }] },
    { id: 'transaction_absent', listeners: [], steps: [{ kind: 'transaction', label: 'absent', path: 'ta', update: () => 1 }] },
    { id: 'transaction_object', listeners: [], steps: [write('seed', w => w('tc').set({ n: 1 })), { kind: 'transaction', label: 'object', path: 'tc', update: current => ({ n: (current?.n ?? 0) + 1 }) }] },
    { id: 'transaction_abort', listeners: [], steps: [{ kind: 'transaction', label: 'abort', path: 'tc', update: () => undefined }] },
    { id: 'remove', listeners: [], steps: [write('remove', w => w('a').remove()), get('get', 'a')] },
    {
      id: 'listen_window',
      listeners: [{ label: 'S', path: 'w', query: ref => ref.orderByChild('s').limitToFirst(2), kinds: ['value', 'child_added'] }],
      steps: [write('seed', w => w('w').set({ a: { s: 3 }, b: { s: 1 }, c: { s: 2 } })), { kind: 'attach', label: 'attach' }, write('set-d', w => w('w/d').set({ s: 0 }))],
    },
    { id: 'get_denied', listeners: [], steps: [write('seed', w => w('deny').set({ secret: 1 })), get('get', 'deny')] },
  ];
}

/** One admin profile: startup (scope empty), then the cases. `db` is the Admin SDK database of this profile's app. */
export async function runAdminProfile({ db, cfg, emit = () => {}, now = () => Date.now(), sleep = ms => new Promise(r => setTimeout(r, ms)), cases = ADMIN_CASES }) {
  if (typeof cfg.scope !== 'string' || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(cfg.scope) || !/^r[12]-admin$/.test(cfg.name ?? '')) throw Error('Invalid admin binding');
  const root = db.ref(cfg.scope), path = p => (p === '' ? root : root.child(p)), at = { w: path, o: path, t: path };
  const timing = { now, sleep, stepMs: cfg.stepMs ?? STEP_MS, quietMs: cfg.quietMs ?? QUIET_MS, maxMs: cfg.maxMs ?? SETTLE_MAX_MS };
  const rows = [], done = row => { rows.push(row); emit({ kind: 'case', suite: 'admin', ...row }); return row.ok; };
  const startup = await withTimeout(timing.stepMs, 'startup', root.get()).then(s => ({ id: 'startup', ok: s.val() === null, ...(s.val() === null ? {} : { error: 'Error: startup root is not empty' }) }), error => ({ id: 'startup', ok: false, error: `${error?.name}: ${String(error?.message).slice(0, 200)}` }));
  if (!done(startup) && startup.error === 'Error: startup root is not empty') return rows;   // a failed read (an auth answer, say) is recorded and the cases still run
  const specs = adminCases();
  for (const id of cases) done(await runCase(specs.find(s => s.id === id), { D: adminAdapter, at, timing }));
  return rows;
}
