// Node smokes for the Realtime Database with the pinned SDKs (firebase 12.18.0 over the
// WebSocket protocol, firebase-admin 14.3.0). Each smoke returns a list of events in the order
// the SDK reported them, normalized so that two servers can be compared: server timestamps
// become "<TS>" and push ids are reduced to their length.

import { initializeApp, deleteApp } from 'firebase/app';
import * as db from 'firebase/database';
import * as adminApp from 'firebase-admin/app';
import * as adminDatabase from 'firebase-admin/database';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Replaces server timestamps (milliseconds in 2023-2033) with "<TS>". */
export function normalize(value) {
  return JSON.parse(
    JSON.stringify(value ?? null, (_, x) => (typeof x === 'number' && x > 1.7e12 && x < 2e12 ? '<TS>' : x)),
  );
}

function clientApp(hostPort, namespace, name) {
  const [host, port] = hostPort.split(':');
  const app = initializeApp({ projectId: 'demo-rtdb', databaseURL: `http://${hostPort}?ns=${namespace}` }, name);
  const database = db.getDatabase(app);
  db.connectDatabaseEmulator(database, host, Number(port));
  return [app, database];
}

/** Writes, reads, queries and server values with the web SDK and with firebase-admin. */
export async function crud(hostPort, suffix) {
  const out = [];
  const settle = async (step, fn) => {
    try {
      out.push([step, normalize(await fn())]);
    } catch (e) {
      out.push([step, { error: String(e.code || e.message || e) }]);
    }
  };
  const [app, d] = clientApp(hostPort, `sdk${suffix}`, `client${suffix}`);
  const r = (p) => db.ref(d, p);
  await settle('set', () => db.set(r('a'), { x: 1, y: 'two', z: [1, 2] }).then(() => 'ok'));
  await settle('get', async () => (await db.get(r('a'))).val());
  await settle('update', () => db.update(r('a'), { x: 2, 'nested/k': true, y: null }).then(() => 'ok'));
  await settle('get after update', async () => (await db.get(r('a'))).exportVal());
  await settle('push', async () => (await db.push(r('list'), 'v')).key.length);
  await settle('server values', () => db.set(r('sv'), { t: db.serverTimestamp(), n: db.increment(5) }).then(() => 'ok'));
  await settle('get server values', async () => (await db.get(r('sv'))).val());
  await settle('priority', () => db.setWithPriority(r('p'), 'v', 3).then(() => 'ok'));
  await settle('get priority', async () => (await db.get(r('p'))).exportVal());
  await settle('query', async () => (await db.get(db.query(r('a'), db.orderByKey(), db.limitToFirst(1)))).val());
  await settle('query by child without index', async () => (await db.get(db.query(r('a'), db.orderByChild('k')))).val());
  await settle('transaction', async () => (await db.runTransaction(r('counter'), (v) => (v || 0) + 1)).snapshot.val());
  await settle('remove', () => db.remove(r('a')).then(() => 'ok'));
  await settle('get removed', async () => (await db.get(r('a'))).val());
  await deleteApp(app);

  const previous = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  process.env.FIREBASE_DATABASE_EMULATOR_HOST = hostPort;
  const admin = adminApp.initializeApp({ projectId: 'demo-rtdb', databaseURL: `http://${hostPort}?ns=adm${suffix}` }, `admin${suffix}`);
  const ad = adminDatabase.getDatabase(admin);
  await settle('admin set', () => ad.ref('b').set({ q: 1 }).then(() => 'ok'));
  await settle('admin update', () => ad.ref('b').update({ r: 2 }).then(() => 'ok'));
  await settle('admin get', async () => (await ad.ref('b').get()).val());
  await settle('admin push', async () => (await ad.ref('l').push({ w: 1 })).key.length);
  await settle('admin remove', () => ad.ref('b').remove().then(() => 'ok'));
  await settle('admin get removed', async () => (await ad.ref('b').get()).val());
  await adminApp.deleteApp(admin);
  if (previous === undefined) delete process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  else process.env.FIREBASE_DATABASE_EMULATOR_HOST = previous;
  return out;
}

/** A listening app follows a writing app: value and child events, a transaction, writes of the listener. */
export async function listen(hostPort, suffix) {
  const events = [];
  const [wa, w] = clientApp(hostPort, `ls${suffix}`, `writer${suffix}`);
  const [ra, r] = clientApp(hostPort, `ls${suffix}`, `reader${suffix}`);
  const ref = (d, p) => db.ref(d, p);
  await db.set(ref(w, 'room'), { a: { n: 1, t: 'x' }, b: { n: 2, t: 'y' }, c: { n: 3, t: 'z' } });
  const log = (label) => (snap) => events.push([label, snap.key, normalize(snap.val())]);
  const unsubscribe = [
    db.onValue(ref(r, 'room'), log('value room')),
    db.onValue(ref(r, 'room/a/n'), log('value a/n')),
  ];
  await sleep(400);
  const step = async (label, fn) => {
    events.push(['--', label]);
    await fn();
    await sleep(250);
  };
  await step('set a/n', () => db.set(ref(w, 'room/a/n'), 5));
  await step('update', () => db.update(ref(w, 'room'), { 'b/n': 0, d: { n: 4, t: 'w' } }));
  await step('remove c', () => db.remove(ref(w, 'room/c')));
  await step('same value', () => db.set(ref(w, 'room/a/n'), 5));
  await step('add e', () => db.set(ref(w, 'room/e'), { n: 9 }));
  await step('transaction', () => db.runTransaction(ref(w, 'room/a/n'), (v) => (v || 0) + 1));
  await step('reader write', () => db.set(ref(r, 'room/f'), { n: 1 }));
  await step('replace', () => db.set(ref(w, 'room'), { z: { n: 7 } }));
  await step('remove all', () => db.remove(ref(w, 'room')));
  unsubscribe.forEach((u) => u());
  await deleteApp(wa);
  await deleteApp(ra);
  return events;
}

/**
 * One reader app per query, so that each opens its own tagged listen on the server (an app
 * that also listened to the whole location would filter the queries on the client).
 */
export async function queries(hostPort, suffix) {
  const events = [];
  const [wa, w] = clientApp(hostPort, `qs${suffix}`, `qwriter${suffix}`);
  const ref = (d, p) => db.ref(d, p);
  await db.set(ref(w, 'room'), { a: { n: 5 }, b: { n: 1 }, c: { n: 4 }, d: { n: 2 }, e: { n: 3 } });
  await db.setPriority(ref(w, 'room/a'), 3);
  await db.setPriority(ref(w, 'room/c'), 1);
  const readers = [];
  const shapes = {
    first2: (base) => db.query(base, db.orderByKey(), db.limitToFirst(2)),
    last2: (base) => db.query(base, db.orderByKey(), db.limitToLast(2)),
    prio2: (base) => db.query(base, db.orderByPriority(), db.limitToFirst(2)),
    range: (base) => db.query(base, db.orderByKey(), db.startAt('b'), db.endAt('d')),
    // No index on n: the server serves the whole location with a no_index warning.
    child: (base) => db.query(base, db.orderByChild('n'), db.limitToFirst(2)),
  };
  for (const [label, shape] of Object.entries(shapes)) {
    const [app, r] = clientApp(hostPort, `qs${suffix}`, `q-${label}${suffix}`);
    readers.push(app);
    const q = shape(ref(r, 'room'));
    const log = (kind) => (snap) => events.push([`${label} ${kind}`, snap.key, normalize(snap.val())]);
    db.onValue(q, log('value'));
    db.onChildAdded(q, log('added'));
    db.onChildRemoved(q, log('removed'));
    db.onChildChanged(q, log('changed'));
    db.onChildMoved(q, log('moved'));
    // One query at a time, so that events are recorded in a fixed order.
    await sleep(300);
  }
  const step = async (label, fn) => {
    events.push(['--', label]);
    await fn();
    await sleep(500);
  };
  await step('remove first', () => db.remove(ref(w, 'room/a')));
  await step('add before first', () => db.set(ref(w, 'room/0'), { n: 9 }));
  await step('remove last', () => db.remove(ref(w, 'room/e')));
  await step('add after last', () => db.set(ref(w, 'room/z'), { n: 0 }));
  await step('priority moves in', () => db.setPriority(ref(w, 'room/d'), 0));
  await step('child value moves', () => db.set(ref(w, 'room/b/n'), 10));
  await step('multi-path update', () => db.update(ref(w, 'room'), { 'c/n': 7, 'x/n': 6, 0: null }));
  await step('deep write into new child', () => db.update(ref(w, 'room'), { 'bb/n': 2 }));
  await step('replace room', () => db.set(ref(w, 'room'), { m: { n: 1 }, k: { n: 2 } }));
  await step('remove room', () => db.remove(ref(w, 'room')));
  for (const app of readers) await deleteApp(app);
  await deleteApp(wa);
  // Each query's own events, in order: the order between apps depends on socket scheduling.
  const byQuery = {};
  let step_ = 'start';
  for (const e of events) {
    if (e[0] === '--') {
      step_ = e[1];
      continue;
    }
    const label = e[0].split(' ')[0];
    (byQuery[label] ??= []).push([step_, ...e]);
  }
  return byQuery;
}

/**
 * onDisconnect over WebSockets: one app registers set, update, remove and a cancelled write,
 * then goes offline; another app reads what the server wrote for it.
 */
export async function disconnect(hostPort, suffix) {
  const events = [];
  const [wa, w] = clientApp(hostPort, `od${suffix}`, `od-writer${suffix}`);
  const [ra, r] = clientApp(hostPort, `od${suffix}`, `od-reader${suffix}`);
  const ref = (d, p) => db.ref(d, p);
  await db.set(ref(w, 'presence'), { writer: { state: 'online' }, tmp: 1, x: { z: 2 } });
  db.onValue(ref(r, 'presence'), (snap) => events.push(['value presence', normalize(snap.val())]));
  await sleep(300);
  await db.onDisconnect(ref(w, 'presence/writer')).set({ state: 'offline', at: db.serverTimestamp() });
  await db.onDisconnect(ref(w, 'presence/tmp')).remove();
  await db.onDisconnect(ref(w, 'presence/x')).update({ y: 1, 'deep/k': db.increment(3) });
  await db.onDisconnect(ref(w, 'presence/prio')).setWithPriority('p', 4);
  const cancelled = db.onDisconnect(ref(w, 'presence/cancelled'));
  await cancelled.set(1);
  await cancelled.cancel();
  events.push(['--', 'writer offline']);
  db.goOffline(w);
  await sleep(800);
  events.push(['read', normalize((await db.get(ref(r, 'presence'))).exportVal())]);
  await deleteApp(wa);
  await deleteApp(ra);
  return events;
}
