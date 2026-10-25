// CV11 scenario page (firebase 12.18.0 browser build). Node drives it through window.__cv11Run and
// supplies credentials and admin actions through __cv11Hook; every event goes to __cv11Event at once.
// Events carry step, type, listener epoch, error code and the data shape (our own seed values) only.
import { initializeApp, deleteApp } from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
import * as A from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js';
import * as D from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const errorCode = (e) => (typeof e?.code === 'string' ? e.code : /permission.denied/i.test(String(e?.message)) ? 'message:permission-denied' : 'other');

window.__cv11Run = async (c) => {
  const t0 = performance.now();
  let step = 'start';
  const emit = (type, fields = {}) => window.__cv11Event({ step, type, ms: Math.round(performance.now() - t0), ...fields });
  const waitFor = async (done, ms) => { for (const end = performance.now() + ms; performance.now() < end; await sleep(50)) if (done()) return true; return done(); };
  const attempt = async (name, fn) => {
    step = name;
    try { const shape = await fn(); emit('ok', shape === undefined ? {} : { shape }); } catch (e) { emit('error', { code: errorCode(e) }); }
  };
  if (c.transport === 'ws') D.forceWebSockets(); else D.forceLongPolling();
  const open = (name) => {
    const app = initializeApp({ apiKey: c.apiKey, projectId: c.projectId, databaseURL: c.databaseURL }, `${name}-${c.name}`);
    const auth = A.initializeAuth(app, { persistence: A.inMemoryPersistence }), db = D.getDatabase(app);
    if (c.emulator) { A.connectAuthEmulator(auth, c.emulator.auth, { disableWarnings: true }); D.connectDatabaseEmulator(db, c.emulator.host, c.emulator.dbPort); }
    return { app, auth, db };
  };
  const signIn = async (x, role) => { const s = await window.__cv11Hook('secret', role); return (await A.signInWithEmailAndPassword(x.auth, s.email, s.password)).user; };
  const a = open('a');
  // A listener records every value and its cancellation with the step that was running.
  const listen = (epoch, path) => {
    const l = { values: 0, cancelled: false };
    l.off = D.onValue(D.ref(a.db, path), (s) => { l.values++; emit('value', { epoch, shape: JSON.stringify(s.val()) }); }, (e) => { l.cancelled = true; emit('cancel', { epoch, code: errorCode(e) }); });
    return l;
  };
  A.onAuthStateChanged(a.auth, (u) => emit('auth-state', { present: !!u }));
  let user;
  await attempt('signin-a', async () => { user = await signIn(a, 'a'); });
  step = 'listen-1';
  const l1 = listen(1, c.scopeA);
  if (!(await waitFor(() => l1.values || l1.cancelled, 20000))) emit('timeout', { epoch: 1 });
  await attempt('refresh-1', async () => { await A.getIdToken(user, true); });
  await attempt('signout', () => A.signOut(a.auth));
  step = 'signout-wait';
  if (!(await waitFor(() => l1.cancelled, 8000))) emit('no-cancel', { epoch: 1 });
  l1.off();
  await attempt('resignin-a', async () => { user = await signIn(a, 'a'); });
  step = 'listen-2';
  const l2 = listen(2, c.scopeA);
  if (!(await waitFor(() => l2.values || l2.cancelled, 20000))) emit('timeout', { epoch: 2 });
  // B reads its own scope, then A's (expected: permission denied), from a separate App.
  const b = open('b');
  await attempt('signin-b', async () => { await signIn(b, 'b'); });
  await attempt('b-read-own', async () => JSON.stringify((await D.get(D.ref(b.db, c.scopeB))).val()));
  await attempt('b-read-a', async () => JSON.stringify((await D.get(D.ref(b.db, c.scopeA))).val()));
  await attempt('signout-b', () => A.signOut(b.auth));
  await deleteApp(b.app);
  step = 'delete-a';
  emit('admin', { code: await window.__cv11Hook('deleteA') });
  step = 'write-after-delete';
  const seen = l2.values;
  emit('admin', { code: await window.__cv11Hook('writeA') });
  if (!(await waitFor(() => l2.values > seen || l2.cancelled, 8000))) emit('no-value', { epoch: 2 });
  await attempt('refresh-after-delete', async () => { await A.getIdToken(user, true); });
  step = 'post-refresh-wait';
  if (!(await waitFor(() => l2.cancelled, 8000))) emit('no-cancel', { epoch: 2 });
  step = 'end';
  l2.off();
  await deleteApp(a.app);
  emit('done');
};
