// S5 scenario (firebase 12.18.0 browser build): an onDisconnect value that carries a priority, then a cancel of one of
// its children. Node drives it through window.__s5Run and receives every event through __s5Event. No account, no token,
// no key: the Rules give the anonymous client its own run prefix. Three cases, each on its own writer connection so that
// a dropped update of one case cannot hide another:
//   main   setWithPriority({b, 10, 9}, 1) at s, cancel at s/b, set(1) at t     (the question)
//   plain  set({b, 10, 9}) at s, cancel at s/b, set(1) at t                    (control: the split fires)
//   whole  setWithPriority({b, 10, 9}, 1) at s, cancel at s/zz, set(1) at t    (control: a missing key leaves the value whole)
// The writer goes offline; the observer, on its own connection, listens on s and t and reads both back.
import { initializeApp, deleteApp } from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
import * as D from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const errorCode = (e) => (typeof e?.code === 'string' ? e.code : /permission.denied/i.test(String(e?.message)) ? 'message:permission-denied' : 'other');
const VALUE = { b: 1, 10: 2, 9: 3 };
// Order: the controls first. `priority: undefined` registers the value without one.
const CASES = [
  ['plain', { priority: undefined, cancel: 'b' }],
  ['whole', { priority: 1, cancel: 'zz' }],
  ['main', { priority: 1, cancel: 'b' }],
];

window.__s5Run = async (c) => {
  const t0 = performance.now();
  let step = 'start';
  const message = (e) => String(e?.message ?? '').toLowerCase().split(c.base.toLowerCase()).join('<base>').slice(0, 160);
  const emit = (type, fields = {}) => window.__s5Event({ scenario: 's5', step, type, actor: 'o', ms: Math.round(performance.now() - t0), ...fields });
  const scale = c.waitScale ?? 1;
  const nap = (ms) => sleep(ms * scale);
  const waitFor = async (done, ms) => { for (const end = performance.now() + ms * scale; performance.now() < end; await sleep(Math.min(50, Math.max(1, 50 * scale)))) if (done()) return true; return done(); };
  // A wait for a required event: a bound that is hit is a recorded timeout, never a guessed answer.
  const need = async (what, done, ms) => { if (!(await waitFor(done, ms))) emit('timeout', { label: what }); };
  D.forceWebSockets();
  const apps = [];
  const open = (name) => {
    const app = initializeApp({ projectId: c.projectId, databaseURL: c.databaseURL }, `${name}-s5-${c.name}`);
    apps.push(app);
    return { app, db: D.getDatabase(app) };
  };
  const at = (x, p) => D.ref(x.db, `${c.base}/${p}`);
  const on = (promise, label, actor = 'w') => promise.then(() => emit('ack', { actor, label }), (e) => emit('rejected', { actor, label, code: errorCode(e), shape: message(e) }));
  try {
    const o = open('o');
    // The Rules of the run prefix may still be propagating: the observer's own write tells when they allow it.
    step = 'rules';
    let allowed = false;
    for (let i = 0; i < 60 && !allowed; i++) {
      try { await D.set(at(o, 'probe'), i); allowed = true; } catch { await nap(1000); }
    }
    emit(allowed ? 'rules' : 'timeout', allowed ? { code: 'allowed' } : { label: 'rules-allowed' });
    for (const [k, { priority, cancel }] of CASES) {
      step = `case-${k}`;
      const w = open(`w-${k}`);
      const seen = { s: 0, t: 0 }, last = {};
      const unsubs = ['s', 't'].map((p) => D.onValue(at(o, `${k}/${p}`), (snap) => {
        seen[p]++;
        last[p] = snap.val();
        emit('value', { label: `${k}-${p}`, shape: JSON.stringify(snap.val()), priority: snap.priority ?? null });
      }, (e) => emit('cancel', { label: `${k}-${p}`, code: errorCode(e) })));
      await need('first values', () => seen.s > 0 && seen.t > 0, 20000);

      step = `register-${k}`;
      const s = D.onDisconnect(at(w, `${k}/s`));
      await on(priority === undefined ? s.set(VALUE) : s.setWithPriority(VALUE, priority), `${k}-register-s`);
      await on(D.onDisconnect(at(w, `${k}/s/${cancel}`)).cancel(), `${k}-register-cancel`);
      await on(D.onDisconnect(at(w, `${k}/t`)).set(1), `${k}-register-t`);

      step = `disconnect-${k}`;
      D.goOffline(w.db);
      emit('offline', { actor: 'w', label: k });
      // The controls must fire; the question may legitimately fire nothing, so its bound is not a timeout.
      if (k === 'main') await waitFor(() => last.t != null, 20000);
      else await need(`${k} fire`, () => last.t != null, 30000);
      await nap(3000);

      step = `final-${k}`;
      for (const p of ['s', 't']) {
        try {
          const snap = await D.get(at(o, `${k}/${p}`));
          emit('get', { label: `${k}-${p}`, shape: JSON.stringify(snap.val()), priority: snap.priority ?? null });
        } catch (e) { emit('rejected', { label: `${k}-${p}`, code: errorCode(e) }); }
      }
      for (const u of unsubs) u();
    }
    step = 'end';
    emit('done');
  } finally {
    await Promise.allSettled(apps.map((a) => deleteApp(a)));
  }
};
