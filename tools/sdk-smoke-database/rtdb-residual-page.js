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
  if (c.wsGuardRequired && (!globalThis.__sdkNextWsGuard || typeof globalThis.MozWebSocket !== 'undefined')) throw Error('sdk-next guard unavailable');
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
    else if (c.scenario === 'cv10') await cv10();
    else if (c.scenario === 'sdk-next-startup') await sdkStartup();
    else if (c.scenario === 'sdk-next') {
      await sdkNext();
      if (c.wsGuardRequired) {
        const guard = globalThis.__sdkNextWsGuard;
        const quiet = await waitFor(() => { guard.assertHealthy(); return guard.quiescent(); }, 5000);
        if (!quiet) { guard.freeze(); throw Error('transport not quiescent'); }
        guard.finish();
        await emit('guard', { actor: 'host', code: JSON.stringify(guard.status()) });
      }
    }
    else throw Error('unknown scenario');
    step = 'end';
    if (c.scenario === 'sdk-next-startup') await emit('done'); else emit('done');
  } catch (error) {
    if (c.wsGuardRequired && globalThis.__sdkNextWsGuard) {
      globalThis.__sdkNextWsGuard.freeze();
      await emit('guard', { actor: 'host', code: JSON.stringify(globalThis.__sdkNextWsGuard.status()) });
    }
    throw error;
  } finally {
    try {
      if (c.scenario === 'sdk-next-startup' && globalThis.__sdkNextWsGuard) {
        for (const raw of globalThis.__sdkNextWsGuard.controls()) await emit('raw-control', { actor: 'host', shape: raw });
      }
    } finally { await Promise.allSettled(apps.map((a) => deleteApp(a))); }
  }

  async function sdkStartup() {
    if (!c.wsGuardRequired || c.transport !== 'ws') throw Error('startup requires WS guard');
    const w = open('w'), o = open('o'), guard = globalThis.__sdkNextWsGuard;
    for (const [actor, app] of [['w', w], ['o', o]]) {
      step = 'startup';
      await emit('operation', { actor, label: `startup-${actor}`, code: actor === 'w' ? '1' : '2' });
      guard.beginOperation(`startup-${actor}`);
      let interval, deadline;
      const watch = new Promise((_, reject) => {
        interval = setInterval(() => { if (guard.status().frozen) reject(Error('startup guard frozen')); }, 20);
        deadline = setTimeout(() => reject(Error('startup read timeout')), 20000);
      });
      try {
        const snap = await Promise.race([D.get(at(app, '')), watch]);
        guard.assertHealthy(); guard.endOperation();
        const value = snap.val();
        await emit('startup', { actor, label: 'root-read', shape: JSON.stringify(value) });
        if (value !== null) throw Error('startup root not empty');
        guard.startupRead(actor, value);
      } catch (error) { guard.freeze(); throw error; }
      finally { clearInterval(interval); clearTimeout(deadline); }
    }
    guard.finishStartup();
    await emit('guard', { actor: 'host', code: JSON.stringify(guard.status()) });
  }

  async function sdkNext() {
    const w = open('w'), o = open('o'), unsubs = [];
    let operations = 0, listenerError = null;
    const perform = async (label, action) => {
      if (listenerError) throw listenerError;
      if (++operations > 24) throw Error('sdk operation cap reached');
      emit('operation', { actor: 'w', label, code: String(operations) });
      const guard = c.wsGuardRequired ? globalThis.__sdkNextWsGuard : null;
      if (guard) guard.beginOperation(label);
      try {
        const result = await action();
        if (listenerError) throw listenerError;
        if (guard) { guard.assertHealthy(); guard.endOperation(); }
        return result;
      } catch (error) { if (guard) guard.freeze(); throw error; }
    };
    const get = async (label, path) => {
      const snap = await perform(`get-${label}`, () => D.get(at(w, path)));
      emit('get', { actor: 'w', label, shape: JSON.stringify(snap.val()) });
      return snap.val();
    };
    const observed = [];
    try {
      step = 'startup';
      for (const [actor, app] of [['w', w], ['o', o]]) {
        const snap = await perform(`startup-${actor}`, () => D.get(at(app, '')));
        const value = snap.val();
        emit('startup', { actor, label: 'root-read', shape: JSON.stringify(value) });
        if (value !== null) throw Error('startup root not empty');
        if (c.wsGuardRequired) globalThis.__sdkNextWsGuard.startupRead(actor, value);
      }
      if (c.wsGuardRequired) globalThis.__sdkNextWsGuard.arm();
      step = 'seed';
      await perform('seed', () => D.set(at(w, ''), { items: { a: { score: 1 }, b: { score: 2, note: 'old' }, c: { score: 2 } }, merge: { keep: 1, edit: 1 }, fanout: {}, values: { numeric: 7, string: 'old' }, txn: { abort: 3, apply: 4 } }));
      step = 'attach';
      const query = D.query(at(o, 'items'), D.orderByChild('score'));
      for (const [type, subscribe] of [['child_added', D.onChildAdded], ['child_changed', D.onChildChanged], ['child_moved', D.onChildMoved], ['child_removed', D.onChildRemoved]]) {
        unsubs.push(subscribe(query, (snap, prev) => { observed.push(type); emit(type, { label: 'items', key: snap.key, prev: prev ?? null, shape: JSON.stringify(snap.val()) }); }, (e) => { listenerError = Error('items listener failed'); emit('error', { label: 'items', code: errorCode(e) }); }));
      }
      const valueSeen = new Set();
      for (const label of ['items', 'merge', 'fanout']) {
        unsubs.push(D.onValue(at(o, label), (snap) => { valueSeen.add(label); emit('value', { label, shape: JSON.stringify(snap.val()) }); }, (e) => { listenerError = Error('value listener failed'); emit('error', { label, code: errorCode(e) }); }));
      }
      await need('initial values', () => valueSeen.size === 3, 20000);
      if (valueSeen.size !== 3) throw Error('initial values incomplete');
      await need('initial query', () => observed.filter((x) => x === 'child_added').length >= 3, 20000);
      if (observed.filter((x) => x === 'child_added').length < 3) throw Error('initial query incomplete');
      step = 'push';
      const keys = [];
      for (const label of ['a', 'b']) {
        const ref = await perform(`push-${label}`, () => D.push(at(w, 'list')));
        if (typeof ref.key !== 'string' || !ref.key || keys.includes(ref.key)) throw Error('invalid push key');
        keys.push(ref.key);
        await perform(`write-${label}`, () => D.set(ref, { label }));
        const snap = await perform(`read-${label}`, () => D.get(ref));
        emit('push', { actor: 'w', label, key: ref.key, shape: JSON.stringify(snap.val()) });
      }
      step = 'merge';
      await perform('update', () => D.update(at(w, 'merge'), { edit: 2 }));
      await get('update-preserves-sibling', 'merge');
      await perform('replace', () => D.set(at(w, 'merge'), { edit: 3 }));
      await get('set-replaces-node', 'merge');
      step = 'fanout';
      await perform('fanout', () => D.update(at(w, ''), { 'fanout/x': 1, 'fanout/y': 2 }));
      await get('atomic-multipath-final', 'fanout');
      step = 'events';
      await perform('change', () => D.update(at(w, 'items/b'), { note: 'new' }));
      await need('child_changed', () => observed.includes('child_changed'), 20000);
      if (!observed.includes('child_changed')) throw Error('missing child_changed');
      await perform('move', () => D.update(at(w, 'items/b'), { score: 3 }));
      await need('child_moved', () => observed.includes('child_moved'), 20000);
      if (!observed.includes('child_moved')) throw Error('missing child_moved');
      step = 'server-values';
      const before = Date.now();
      await perform('server-values', () => D.update(at(w, 'values'), { numeric: D.increment(5), absent: D.increment(5), string: D.increment(5), at: D.serverTimestamp() }));
      const after = Date.now();
      const values = await get('server-values', 'values');
      emit('interval', { actor: 'w', label: 'server-timestamp', shape: JSON.stringify({ before, after, value: values?.at }) });
      step = 'transaction';
      let abortInitial;
      unsubs.push(D.onValue(at(w, 'txn/abort'), (snap) => { abortInitial = snap.val(); emit('value', { actor: 'w', label: 'txn-abort', shape: JSON.stringify(abortInitial) }); }, (e) => { listenerError = Error('abort listener failed'); emit('error', { label: 'txn-abort', code: errorCode(e) }); }));
      await need('txn abort initial', () => abortInitial !== undefined, 20000);
      if (abortInitial !== 3) throw Error('transaction abort seed unavailable');
      const callbacks = [];
      const abort = await perform('transaction-abort', () => D.runTransaction(at(w, 'txn/abort'), (v) => { callbacks.push(v); return undefined; }));
      emit('transaction', { actor: 'w', label: 'abort', shape: JSON.stringify({ callbacks, committed: abort.committed, value: abort.snapshot.val() }) });
      let txnSeen = false;
      unsubs.push(D.onValue(at(w, 'txn/apply'), (snap) => { txnSeen = true; emit('value', { actor: 'w', label: 'txn-apply', shape: JSON.stringify(snap.val()) }); }, (e) => { listenerError = Error('transaction listener failed'); emit('error', { label: 'txn-apply', code: errorCode(e) }); }));
      await need('txn initial', () => txnSeen, 20000);
      if (!txnSeen) throw Error('transaction listener incomplete');
      const applyCalls = [];
      const apply = await perform('transaction-apply', () => D.runTransaction(at(w, 'txn/apply'), (v) => { applyCalls.push(v); return (v ?? 0) + 1; }, { applyLocally: false }));
      emit('transaction', { actor: 'w', label: 'applyLocally-false', shape: JSON.stringify({ callbacks: applyCalls, committed: apply.committed, value: apply.snapshot.val() }) });
      emit('gap', { label: 'transaction-retry', code: 'unobserved' });
      emit('operation-count', { actor: 'w', code: String(operations) });
    } finally { for (const off of unsubs) off(); }
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
