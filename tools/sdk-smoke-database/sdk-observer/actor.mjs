// Fixed SDK commands. Transport and authority are enforced outside this browser actor.
export function createActor(config, D, A) {
  const { projectId, databaseURL, scope, transport, role } = config;
  const endpoint = new URL(databaseURL);
  if (typeof projectId !== 'string' || !/^[a-z0-9-]{1,128}$/.test(projectId) || (endpoint.protocol !== 'https:' && !(config.local === true && endpoint.protocol === 'http:' && endpoint.hostname === '127.0.0.1')) || endpoint.username || endpoint.password || endpoint.hash || typeof scope !== 'string' || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(scope) || !['ws', 'lp'].includes(transport) || !['writer', 'observer'].includes(role)) throw Error('Invalid actor binding');
  if (transport === 'lp') D.forceLongPolling(); else D.forceWebSockets();
  const app = A.initializeApp({ projectId, databaseURL }, `packet-${role}`), db = D.getDatabase(app), root = D.ref(db, scope), at = p => D.child(root, p);
  const order = role === 'writer' ? ['startup', 'seed', 'push', 'update', 'multipath', 'server_timestamp', 'increment'] : ['startup', 'key_range', 'value_equal', 'priority_range'];
  let position = 0, busy = false, stopped = false;
  const ordered = snap => { const out = []; snap.forEach(child => { const exported = child.exportVal(); out.push({ key: child.key, value: child.val(), priority: exported && typeof exported === 'object' && Object.hasOwn(exported, '.priority') ? exported['.priority'] : null }); }); return out; };
  return Object.freeze({
    async execute(id) {
      if (stopped || busy || id !== order[position]) { stopped = true; throw Error('Actor order refused'); }
      busy = true;
      try {
        let value;
        if (id === 'startup') value = (await D.get(root)).val();
        else if (id === 'seed') { await D.set(root, { keys: { a: 1, b: 2, c: 2, d: 3 }, values: { a: 1, b: 2, c: 2, d: 3 }, merge: { keep: 1, edit: 1 }, numbers: { numeric: 7, string: 'old' } }); for (const [key, priority] of [['a', 1], ['b', 2], ['c', 3]]) await D.setWithPriority(at(`priority/${key}`), key.toUpperCase(), priority); value = null; }
        else if (id === 'key_range') value = ordered(await D.get(D.query(at('keys'), D.orderByKey(), D.startAt('b'), D.endAt('d'))));
        else if (id === 'value_equal') value = ordered(await D.get(D.query(at('values'), D.orderByValue(), D.equalTo(2))));
        else if (id === 'priority_range') value = ordered(await D.get(D.query(at('priority'), D.orderByPriority(), D.startAfter(1), D.endBefore(4))));
        else if (id === 'push') { const a = D.push(at('list')), b = D.push(at('list')); await D.set(a, 'a'); await D.set(b, 'b'); value = { keys: [a.key, b.key], a: (await D.get(a)).val(), b: (await D.get(b)).val() }; }
        else if (id === 'update') { await D.update(at('merge'), { edit: 2 }); value = (await D.get(at('merge'))).val(); }
        else if (id === 'multipath') { await D.update(root, { 'fanout/x': 1, 'fanout/y': 2 }); value = (await D.get(at('fanout'))).val(); }
        else if (id === 'server_timestamp') { const before = Date.now(); await D.update(at('numbers'), { at: D.serverTimestamp() }); value = { value: (await D.get(at('numbers/at'))).val(), before, after: Date.now() }; }
        else if (id === 'increment') { await D.update(at('numbers'), { numeric: D.increment(5), absent: D.increment(5), string: D.increment(5) }); value = (await D.get(at('numbers'))).val(); }
        position++; return value;
      } catch (error) { stopped = true; throw error; } finally { busy = false; }
    },
    async close() { stopped = true; await A.deleteApp(app); },
  });
}
