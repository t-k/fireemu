// The long-polling smoke page: the browser build of firebase 12.18.0 forced to long polling.
// Two apps (a writer and a reader) go through writes, reads, listens, a transaction and a
// disconnect with writes on both sides before reconnecting, then the writer's onDisconnect
// writes as it goes offline. The events land in
// window.__result.
import { initializeApp } from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
import * as db from 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';

const params = new URLSearchParams(location.search);
const [host, port] = params.get('emu').split(':');
const suffix = params.get('suffix');
const events = [];
window.__events = events;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const norm = (v) => JSON.parse(JSON.stringify(v ?? null, (k, x) => (typeof x === 'number' && x > 1.7e12 && x < 2e12 ? '<TS>' : x)));
const record = (...e) => events.push(norm(e));

db.forceLongPolling();
const open = (name) => {
  const app = initializeApp({ projectId: 'demo-rtdb', databaseURL: `http://${host}:${port}?ns=lp${suffix}` }, name);
  const d = db.getDatabase(app);
  db.connectDatabaseEmulator(d, host, Number(port));
  return d;
};
const settle = async (label, fn) => {
  try { record(label, await fn()); } catch (e) { record(label, { error: String(e.code || e.message || e) }); }
};

(async () => {
  const a = open('writer');
  const b = open('reader');
  const ref = (d, p) => db.ref(d, p);
  const log = (label) => (snap) => record(label, snap.key, snap.val());
  db.onValue(ref(b, '.info/connected'), (s) => record('reader connected', s.val()));
  await settle('set', () => db.set(ref(a, 'room'), { a: { n: 1 }, b: { n: 2 }, c: { n: 3 } }).then(() => 'ok'));
  await settle('get', async () => (await db.get(ref(a, 'room'))).val());
  await settle('update', () => db.update(ref(a, 'room'), { 'a/n': 5, d: { n: 4 } }).then(() => 'ok'));
  await settle('push', async () => (await db.push(ref(a, 'list'), 'v')).key.length);
  await settle('server values', () => db.set(ref(a, 'sv'), { t: db.serverTimestamp(), n: db.increment(2) }).then(() => 'ok'));
  await settle('get server values', async () => (await db.get(ref(a, 'sv'))).val());
  await settle('priority', () => db.setWithPriority(ref(a, 'p'), 'v', 3).then(() => 'ok'));
  await settle('get priority', async () => (await db.get(ref(a, 'p'))).exportVal());
  await settle('big value', () => db.set(ref(a, 'big'), 'x'.repeat(5000)).then(() => 'ok'));
  await settle('get big', async () => (await db.get(ref(a, 'big'))).val().length);
  await settle('query', async () => (await db.get(db.query(ref(a, 'room'), db.orderByKey(), db.limitToFirst(2)))).val());
  db.onValue(ref(b, 'room'), log('value room'));
  const q = db.query(ref(b, 'room'), db.orderByKey(), db.limitToLast(2));
  db.onChildAdded(q, log('added last2'));
  db.onChildRemoved(q, log('removed last2'));
  db.onChildChanged(q, log('changed last2'));
  await sleep(800);
  const step = async (label, fn) => { record('--', label); await fn(); await sleep(600); };
  await step('set a/n', () => db.set(ref(a, 'room/a/n'), 6));
  await step('add e', () => db.set(ref(a, 'room/e'), { n: 9 }));
  await step('remove e', () => db.remove(ref(a, 'room/e')));
  await step('transaction', () => db.runTransaction(ref(a, 'room/a/n'), (v) => (v || 0) + 1));
  await step('reader write', () => db.set(ref(b, 'room/f'), { n: 1 }));
  await step('reader offline', async () => { db.goOffline(b); });
  await step('write while reader offline', () => db.set(ref(a, 'room/g'), { n: 7 }));
  await step('reader writes offline', async () => { db.set(ref(b, 'room/h'), { n: 8 }); });
  await step('reader online', async () => { db.goOnline(b); await sleep(2500); });
  await step('get after reconnect', async () => record('writer sees h', (await db.get(ref(a, 'room/h'))).val()));
  await step('remove room', () => db.remove(ref(a, 'room')));
  db.onValue(ref(b, 'presence'), log('value presence'));
  // The listen settles before the writes it is to see, so its first value is null.
  await sleep(800);
  await step('writer registers onDisconnect', async () => {
    await db.set(ref(a, 'presence'), { writer: { state: 'online' }, tmp: 1, x: { z: 2 } });
    await db.onDisconnect(ref(a, 'presence/writer')).set({ state: 'offline', at: db.serverTimestamp() });
    await db.onDisconnect(ref(a, 'presence/tmp')).remove();
    await db.onDisconnect(ref(a, 'presence/x')).update({ y: 1 });
    const cancelled = db.onDisconnect(ref(a, 'presence/cancelled'));
    await cancelled.set(1);
    await cancelled.cancel();
  });
  await step('writer offline', async () => { db.goOffline(a); await sleep(1500); });
  await step('reader reads presence', async () => record('presence', (await db.get(ref(b, 'presence'))).val()));
  window.__result = events;
})().catch((e) => { window.__result = { fatal: String((e && e.stack) || e) }; });
