// The events suite recorder, shared by Node (WebSocket profile) and the Chromium page (long-polling profile). Three
// connections: the observer (the profile's transport) holds the listeners and records every callback in arrival
// order; the writer (WebSocket in both profiles: it only writes and awaits acknowledgements, so the long-polling
// profile does not pay a second polling connection) performs the writes; the transaction writer (the profile's
// transport) runs the transactions of case `transactions` with its own local listener. Every await has a deadline; a
// bound that is hit is recorded, never guessed.
//
// Per case: the steps run in order. A step's events are every callback that arrives from the start of that step until
// the start of the next one. After its action a step waits for quiescence: no new callback for QUIET_MS, at most
// SETTLE_MAX_MS; `quiet: false` records that the bound was hit. The `attach` step attaches the listeners and first waits
// until every value listener has had its first value (or a cancel): `ready: false` records that bound. The case ends by
// detaching its listeners.
import { withTimeout } from './sequence.mjs';
import { CHILD_KINDS, EVENT_CASES, PRIORITY_SEED, SEED, eventCases } from './events-actor.mjs';

export const QUIET_MS = 800, SETTLE_MAX_MS = 5000, STEP_MS = 10000;
const ON = { value: 'onValue', child_added: 'onChildAdded', child_changed: 'onChildChanged', child_moved: 'onChildMoved', child_removed: 'onChildRemoved' };
const WITH_PREV = new Set(['child_added', 'child_changed', 'child_moved']);

/**
 * A value or get snapshot as recorded: its ordered children (the query's order) with their exported values (priorities
 * included), or the exported leaf. Child events record the child's exported value only: the SDK cannot iterate the
 * children of a child snapshot under an orderByChild index ("No index defined").
 */
export function shapeOf(snap) {
  if (!snap.hasChildren()) return { leaf: snap.exportVal() ?? null };
  const children = [];
  snap.forEach(child => { children.push([child.key, child.exportVal()]); });
  const priority = snap.getPriority?.() ?? null;
  return priority === null ? { children } : { children, priority };
}
/** A rejection as recorded: the SDK's code, a permission denial, a deadline, or `other` (messages carry the random prefix). */
export function errorCode(error) {
  if (error?.name === 'Timeout') return 'timeout';
  if (typeof error?.code === 'string') return error.code;
  return /permission.denied/i.test(String(error?.message)) ? 'permission-denied' : 'other';
}
const plain = v => (v === undefined ? null : JSON.parse(JSON.stringify(v)));

/** The time of the last callback (or action), for the quiescence wait. */
export function createLog(now) {
  let last = now();
  return { touch() { last = now(); }, lastAt: () => last };
}
/** Waits until nothing was recorded for quietMs (counted from the later of the call and the last callback); false when maxMs passed first. */
export async function quiesce(log, { quietMs = QUIET_MS, maxMs = SETTLE_MAX_MS, now, sleep }) {
  const start = now();
  for (;;) {
    const t = now();
    if (t - log.lastAt() >= quietMs && t - start >= quietMs) return true;
    if (t - start >= maxMs) return false;
    await sleep(Math.min(50, quietMs));
  }
}
/** Polls `done` until it holds or ms passed. */
export async function waitUntil(done, ms, { now, sleep }) {
  for (const end = now() + ms; now() < end; await sleep(20)) if (done()) return true;
  return done();
}

function validate(cfg) {
  const endpoint = new URL(cfg.databaseURL);
  if (typeof cfg.projectId !== 'string' || !/^[a-z0-9-]{1,128}$/.test(cfg.projectId) || (endpoint.protocol !== 'https:' && !(cfg.local === true && endpoint.protocol === 'http:' && endpoint.hostname === '127.0.0.1')) || endpoint.username || endpoint.password || endpoint.hash
    || typeof cfg.scope !== 'string' || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(cfg.scope) || !['ws', 'lp'].includes(cfg.transport) || typeof cfg.name !== 'string' || !/^r[12]-(ws|lp)$/.test(cfg.name)) throw Error('Invalid events binding');
}

/** One case: returns {id, ok, steps} (ok false with `error` when an action threw outside a recorded step outcome). */
export async function runCase(spec, { D, at, timing }) {
  const { now, sleep, stepMs = STEP_MS, quietMs = QUIET_MS, maxMs = SETTLE_MAX_MS } = timing;
  const log = createLog(now), steps = [], offs = [];
  let current = null;
  const record = (role, event) => { if (current) current[role].push(event); log.touch(); };
  const listener = (role, label, kind, firsts) => (snap, prev) => {
    let event;   // never throw into the SDK: a recorder fault is itself recorded
    try { event = { l: label, e: kind, k: snap.key, ...(WITH_PREV.has(kind) ? { p: prev ?? null } : {}), v: kind === 'value' ? shapeOf(snap) : plain(snap.exportVal()) }; } catch (error) { event = { l: label, e: 'recorder-error', error: String(error?.message).slice(0, 120) }; }
    if (kind === 'value') firsts.add(label);
    record(role, event);
  };
  const cancel = (role, label, firsts) => error => { firsts.add(label); record(role, { l: label, e: 'cancel', code: errorCode(error) }); };
  const settle = async () => { log.touch(); return quiesce(log, { quietMs, maxMs, now, sleep }); };
  try {
    for (const step of spec.steps) {
      current = { step: step.label, observer: [], writer: [] }; steps.push(current); log.touch();
      if (step.kind === 'attach') {
        const firsts = new Set(), wanted = spec.listeners.filter(l => l.kinds.includes('value')).map(l => l.label);
        for (const l of spec.listeners) {
          const target = l.query ? l.query(at.o(l.path)) : at.o(l.path);
          for (const kind of l.kinds) offs.push(D[ON[kind]](target, listener('observer', l.label, kind, firsts), cancel('observer', l.label, firsts)));
        }
        current.ready = await waitUntil(() => wanted.every(label => firsts.has(label)), stepMs, { now, sleep });
      } else if (step.kind === 'write') {
        current.ack = await withTimeout(stepMs, step.label, step.run(at.w)).then(() => 'ok', error => ({ error: errorCode(error) }));
      } else if (step.kind === 'get') {
        current.result = await withTimeout(stepMs, step.label, step.run(at.o)).then(snap => ({ exists: snap.exists(), v: shapeOf(snap) }), error => ({ error: errorCode(error) }));
      } else if (step.kind === 'call') {
        current.result = await withTimeout(stepMs, step.label, step.run(at.w)).then(value => value, error => ({ error: errorCode(error) }));
      } else if (step.kind === 'transaction') {
        const firsts = new Set(), ref = at.t(step.path), inputs = [];
        const off = D.onValue(ref, listener('writer', 'W', 'value', firsts), cancel('writer', 'W', firsts));
        try {
          current.ready = await waitUntil(() => firsts.has('W'), stepMs, { now, sleep });
          const outcome = await withTimeout(stepMs, step.label, D.runTransaction(ref, value => { inputs.push(plain(value)); return step.update(value); }))
            .then(r => { record('writer', { l: 'txn', e: 'resolved' }); return { committed: r.committed, snapshot: shapeOf(r.snapshot) }; }, error => { record('writer', { l: 'txn', e: 'rejected' }); return { error: errorCode(error) }; });
          current.result = { inputs, ...outcome };
          current.quiet = await settle();
        } finally { off(); }
        continue;
      } else throw Error(`unknown step kind ${step.kind}`);
      current.quiet = await settle();
    }
    return { id: spec.id, ok: true, steps };
  } catch (error) {
    return { id: spec.id, ok: false, error: `${error?.name}: ${String(error?.message).slice(0, 200)}`, steps };
  } finally {
    current = null;
    for (const off of offs) off();
  }
}

/**
 * The whole events profile: startup (scope empty), seed, then the eight cases; a failed case does not stop the next one
 * (each case has its own paths). `emit` gets one row per finished setup step and case; the rows are also returned.
 */
export async function runEventsProfile({ D, A, cfg, emit = () => {}, onApp = () => {}, now = () => Date.now(), sleep = ms => new Promise(r => setTimeout(r, ms)), cases = EVENT_CASES }) {
  validate(cfg);
  const apps = [], refs = {}, timing = { now, sleep, stepMs: cfg.stepMs ?? STEP_MS, quietMs: cfg.quietMs ?? QUIET_MS, maxMs: cfg.maxMs ?? SETTLE_MAX_MS };
  const open = role => {
    const app = A.initializeApp({ projectId: cfg.projectId, databaseURL: cfg.databaseURL }, `events-${role}-${cfg.name}`), db = D.getDatabase(app), root = D.ref(db, cfg.scope);
    apps.push(app); onApp(app, db);
    refs[role] = p => (p === '' ? root : D.child(root, p));
  };
  const rows = [], done = row => { rows.push(row); emit({ kind: 'case', suite: 'events', ...row }); return row.ok; };
  const empty = (id, ref) => withTimeout(timing.stepMs, id, D.get(ref)).then(s => ({ id, ok: s.val() === null, ...(s.val() === null ? {} : { error: 'Error: startup root is not empty' }) }), error => ({ id, ok: false, error: `${error?.name}: ${error?.message}` }));
  try {
    // The transport is chosen when a connection starts: the writer connects (its startup read) before the long-polling switch.
    D.forceWebSockets(); open('writer');
    if (!done(await empty('startup', refs.writer('')))) return rows;
    if (cfg.transport === 'lp') D.forceLongPolling();
    open('observer'); open('txn');
    if (!done(await empty('startup-observer', refs.observer('')))) return rows;
    const at = { w: refs.writer, o: refs.observer, t: refs.txn };
    const seed = await withTimeout(timing.stepMs, 'seed', (async () => { await D.set(at.w(''), SEED); for (const [key, value, priority] of PRIORITY_SEED) await D.setWithPriority(at.w(`pw/${key}`), value, priority); })())
      .then(() => ({ id: 'seed', ok: true }), error => ({ id: 'seed', ok: false, error: `${error?.name}: ${error?.message}` }));
    if (!done(seed)) return rows;
    const specs = eventCases(D);
    for (const id of cases) done(await runCase(specs.find(s => s.id === id), { D, at, timing }));
    return rows;
  } finally {
    for (const app of apps) await Promise.race([A.deleteApp(app).catch(() => {}), sleep(cfg.closeMs ?? 5000)]);
  }
}
export { CHILD_KINDS, EVENT_CASES };
