// Residual RTDB scenarios (firebase 12.18.0 browser build). Node drives them through window.__rrRun
// and supplies Rules changes through __rrHook; every event goes to __rrEvent at once. No account, no
// token, no key: the Rules grant the anonymous client its own run prefix. Events carry the step, the
// listener label, the key, the previous key and the data shape (our own seed values) only.
//
//   cv08: reconnect and ordering. Observer O listens (value and child events on two query windows, a
//         gated path, a control path), goes offline, queues writes, the writer W changes the server,
//         O comes back. Query-scoped: one window is unsubscribed, another keeps running.
//   cv10: onDisconnect. W registers set/update/remove variants, cancels and re-registers, a Rules
//         change denies two paths, W goes offline, O records what fires.
import { initializeApp, deleteApp } from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
import * as D from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// c.waitScale shortens every wait of this page (the page tests use it with a stub SDK); production leaves it at 1.
const errorCode = (e) => (typeof e?.code === 'string' ? e.code : /permission.denied/i.test(String(e?.message)) ? 'message:permission-denied' : 'other');
// Server timestamps are masked by their field name `at`: inside ten minutes of the browser clock or not.
const shapeOf = (v) => JSON.stringify(v, (k, x) => (k === 'at' && typeof x === 'number' ? (Math.abs(x - Date.now()) < 600000 ? '<TS>' : '<TS-OFF>') : x));
// A query snapshot as the ordered list of its children, so the window order is part of the shape.
const windowOf = (snap) => { const out = []; snap.forEach((c) => { out.push([c.key, c.val()]); }); return shapeOf(out); };

window.__rrRun = async (c) => {
  const t0 = performance.now();
  let step = 'start';
  // The SDK's message names the path it failed on; the run's random prefix is replaced.
  const message = (e) => String(e?.message ?? '').toLowerCase().split(c.base.toLowerCase()).join('<base>').slice(0, 160);
  const emit = (type, fields = {}) => window.__rrEvent({ scenario: c.scenario, step, type, actor: 'o', ms: Math.round(performance.now() - t0), ...fields });
  const scale = c.waitScale ?? 1;
  const nap = (ms) => sleep(ms * scale);
  const waitFor = async (done, ms) => { for (const end = performance.now() + ms * scale; performance.now() < end; await sleep(Math.min(50, Math.max(1, 50 * scale)))) if (done()) return true; return done(); };
  // A wait for a required event: a bound that is hit is a recorded timeout, never a guessed answer.
  const need = async (what, done, ms) => { if (!(await waitFor(done, ms))) emit('timeout', { label: what }); };
  if (c.transport === 'ws') D.forceWebSockets(); else D.forceLongPolling();
  const apps = [];
  const open = (name) => {
    const app = initializeApp({ projectId: c.projectId, databaseURL: c.databaseURL }, `${name}-${c.scenario}-${c.name}`);
    apps.push(app);
    return { app, db: D.getDatabase(app) };
  };
  const at = (x, p) => D.ref(x.db, `${c.base}/${p}`);
  const settle = async (ms) => { await nap(ms); };
  // The actor is the connection a row belongs to: w (writer), o (observer) or host. Rows of two actors race.
  const on = (promise, label, actor = 'w') => promise.then(() => emit('ack', { actor, label }), (e) => emit('rejected', { actor, label, code: errorCode(e), shape: message(e) }));
  try {
    if (c.scenario === 'cv08') await cv08();
    else await cv10();
    step = 'end';
    emit('done');
  } finally {
    await Promise.allSettled(apps.map((a) => deleteApp(a)));
  }

  async function cv08() {
    const w = open('w'), o = open('o');
    const seen = {}, cancelled = {};
    const unsubs = {};
    const count = (label) => { seen[label] = (seen[label] ?? 0) + 1; };
    const items = at(o, 'items');
    const window2 = D.query(items, D.orderByChild('score'), D.limitToFirst(2));
    const top2 = D.query(items, D.orderByChild('score'), D.limitToLast(2));
    const cancel = (label) => (e) => { cancelled[label] = true; emit('cancel', { label, code: errorCode(e), shape: message(e) }); };
    const value = (label, q, render = (s) => shapeOf(s.val())) => D.onValue(q, (s) => { count(label); emit('value', { label, shape: render(s) }); }, cancel(label));
    const children = (label, q) => [
      D.onChildAdded(q, (s, prev) => { count(label); emit('child_added', { label, key: s.key, prev: prev ?? null, shape: shapeOf(s.val()) }); }, cancel(label)),
      D.onChildChanged(q, (s, prev) => { count(label); emit('child_changed', { label, key: s.key, prev: prev ?? null, shape: shapeOf(s.val()) }); }, cancel(label)),
      D.onChildMoved(q, (s, prev) => { count(label); emit('child_moved', { label, key: s.key, prev: prev ?? null, shape: shapeOf(s.val()) }); }, cancel(label)),
      D.onChildRemoved(q, (s) => { count(label); emit('child_removed', { label, key: s.key, shape: shapeOf(s.val()) }); }, cancel(label)),
    ];
    const firstValues = (labels, ms) => need(labels.join('+'), () => labels.every((l) => seen[l] || cancelled[l]), ms);

    step = 'seed';
    await on(D.set(at(w, 'items'), { a: { score: 1 }, b: { score: 2 }, c: { score: 3 }, d: { score: 4 } }), 'seed-items');
    await on(D.set(at(w, 'gate'), true), 'seed-gate');
    await on(D.set(at(w, 'gated'), { v: 1 }), 'seed-gated');
    await on(D.set(at(w, 'other'), { n: 1 }), 'seed-other');

    step = 'attach';
    unsubs.items = value('items', items);
    unsubs.win = [value('win-v', window2, windowOf), ...children('win', window2)];
    unsubs.top = [value('top-v', top2, windowOf), ...children('top', top2)];
    unsubs.gated = value('gated', at(o, 'gated'));
    unsubs.other = value('other', at(o, 'other'));
    await firstValues(['items', 'win-v', 'top-v', 'gated', 'other'], 20000);
    await settle(800);

    // Query-scoped: dropping the limitToLast window must not touch the limitToFirst window on the same path.
    step = 'top-off';
    for (const off of unsubs.top) off();
    const before = seen['win-v'] ?? 0;
    await on(D.set(at(w, 'items/a/score'), 10), 'w-a-score');
    await need('win-v after top-off', () => (seen['win-v'] ?? 0) > before, 20000);
    await settle(1500);

    step = 'offline';
    D.goOffline(o.db);
    await settle(300);
    step = 'offline-writes';
    const queued = [on(D.set(at(o, 'items/e'), { score: 0 }), 'queued-1', 'o'), on(D.remove(at(o, 'items/b')), 'queued-2', 'o'), on(D.set(at(o, 'other/n'), 2), 'queued-3', 'o')];
    await settle(500);

    step = 'server-changes';
    await on(D.set(at(w, 'items/f'), { score: 0.5 }), 'w-f');
    await on(D.set(at(w, 'gate'), false), 'w-gate');
    await on(D.set(at(w, 'other/n'), 7), 'w-other');

    step = 'reconnect';
    const gatedBefore = seen.gated ?? 0;
    D.goOnline(o.db);
    await need('queued acks and gated answer', () => (seen.other ?? 0) >= 2 && (cancelled.gated || (seen.gated ?? 0) > gatedBefore), 30000);
    await Promise.race([Promise.allSettled(queued), nap(30000)]);
    await settle(2500);

    // A fresh listen on the dropped window starts from the server's current state.
    step = 'top-reattach';
    unsubs.top2 = [value('top2-v', top2, windowOf), ...children('top2', top2)];
    await firstValues(['top2-v'], 20000);
    await settle(800);

    step = 'after-reconnect';
    const gatedSeen = seen.gated ?? 0;
    await on(D.set(at(w, 'items/g'), { score: 0.25 }), 'w-g');
    await on(D.set(at(w, 'gated/v'), 2), 'w-gated');
    const otherBefore = seen.other ?? 0;
    await on(D.set(at(w, 'other/n'), 9), 'w-other-2');
    await need('other after reconnect', () => (seen.other ?? 0) > otherBefore, 20000);
    await settle(1500);
    if ((seen.gated ?? 0) === gatedSeen) emit('absent', { label: 'gated' });

    step = 'end';
    for (const u of [unsubs.items, ...unsubs.win, ...unsubs.top2, unsubs.gated, unsubs.other]) u();
  }

  async function cv10() {
    const w = open('w'), o = open('o');
    const od = (p) => D.onDisconnect(at(w, p));
    const seen = {};
    const unsubs = [];
    const PATHS = ['e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'marker'];
    // The probe path follows the same Rules flag as e7 and e8: it tells when a Rules change took effect.
    const probe = async (allowed) => {
      for (let i = 0; i < 60; i++) {
        let ok = true;
        try { await D.set(at(o, 'dprobe'), i); } catch { ok = false; }
        if (ok === allowed) return emit('rules', { code: allowed ? 'allowed' : 'denied' });
        await nap(1000);
      }
      emit('timeout', { label: allowed ? 'rules-allowed' : 'rules-denied' });
    };

    step = 'rules-open';
    emit('admin', { actor: 'host', code: await window.__rrHook('rulesOpen') });
    await probe(true);

    step = 'seed';
    const seeds = { e1: { state: 'online' }, e2: { state: 'online' }, e3: { state: 'online' }, e4: { state: 'online' }, e5: { state: 'online', gone: true, keep: true }, e6: { n: 41 }, e7: { state: 'online' }, e8: { state: 'online' }, e9: { a: 'on', b: 'on' }, marker: false };
    for (const p of PATHS) await on(D.set(at(w, p), seeds[p]), `seed-${p}`);

    step = 'attach';
    for (const p of PATHS) unsubs.push(D.onValue(at(o, p), (s) => { seen[p] = (seen[p] ?? 0) + 1; emit('value', { label: p, shape: shapeOf(s.val()) }); }, (e) => emit('cancel', { label: p, code: errorCode(e) })));
    await need('first values', () => PATHS.every((p) => seen[p]), 20000);
    await nap(500);

    step = 'register';
    await on(od('e1').set({ state: 'offline' }), 'e1-set');
    await on(od('e1').cancel(), 'e1-cancel');
    await on(od('e2').set({ state: 'cancelled' }), 'e2-set');
    await on(od('e2').cancel(), 'e2-cancel');
    await on(od('e2').set({ state: 'offline' }), 'e2-set-again');
    await on(od('e3').set({ state: 'first' }), 'e3-set');
    await on(od('e3').set({ state: 'offline' }), 'e3-set-again');
    await on(od('e4').remove(), 'e4-remove');
    await on(od('e5').update({ state: 'offline', extra: 1, gone: null }), 'e5-update');
    await on(od('e6').update({ n: D.increment(1), at: D.serverTimestamp() }), 'e6-update');
    await on(od('e7').set({ state: 'offline' }), 'e7-set');
    await on(od('e9/a').set('off'), 'e9a-set');
    await on(od('e9/b').set('off'), 'e9b-set');
    await on(od('e9').cancel(), 'e9-cancel');

    step = 'rules-deny';
    emit('admin', { actor: 'host', code: await window.__rrHook('rulesDeny') });
    await probe(false);

    step = 'register-denied';
    await on(od('e8').set({ state: 'offline' }), 'e8-set');
    await on(od('marker').set(true), 'marker-set');

    step = 'disconnect';
    const start = performance.now();
    D.goOffline(w.db);
    await need('marker fire', () => seen.marker > 1, c.transport === 'lp' ? 240000 : 30000);
    const seconds = Math.round((performance.now() - start) / 100) / 10;
    await nap(3000);
    window.__rrEvent({ scenario: c.scenario, step: 'fire', type: 'timing', actor: 'host', seconds, ms: Math.round(performance.now() - t0) });

    step = 'final';
    for (const p of PATHS) {
      try { emit('get', { label: p, shape: shapeOf((await D.get(at(o, p))).val()) }); } catch (e) { emit('rejected', { label: p, code: errorCode(e) }); }
    }
    for (const u of unsubs) u();
  }
};
