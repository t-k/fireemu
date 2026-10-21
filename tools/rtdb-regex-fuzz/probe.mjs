// node probe.mjs <host:port> <corpus.json> <out.json> [workers]
//
// Judges each expression in every rule context (rulings 15 and 16): `.read` without a query and
// with one, `.read` as an event stream and as a realtime listen (both without a query), `.write`,
// and `.validate` beside `.write: true`, each as a signed-in user (an unsigned token) and
// anonymously. Each worker owns a namespace, seeds it again before every rules load and write,
// and records per expression:
//   loadR/loadW/loadV (and errR/errW/errV): the rules load answer of each context;
//   ra/ru: GET /t/o, qa/qu: the same with a query, sa/su: an event stream of /t/o,
//   la/lu: a WebSocket listen of /t/o (200 for "ok", 401 for "permission_denied"),
//   wa/wu: PUT /t/o under `.write`, va/vu: PUT /t/o under `.validate`;
//   "a" signed in, "u" anonymous.
// Long polling runs the same realtime session as the WebSocket on both servers, so the listen
// cells stand for it.
// A request that times out stops the run with exit status 2.
import { readFileSync, writeFileSync } from 'node:fs';

const [hostPort, corpusFile, outFile, workerArg] = process.argv.slice(2);
const workers = Number(workerArg ?? 4);
const corpus = JSON.parse(readFileSync(corpusFile, 'utf8'));
const e = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const token = `${e({ alg: 'none', typ: 'JWT' })}.${e({ sub: 'u1', uid: 'u1', iat: 1, exp: 9999999999, email: 'A@b.co', admin: true, n: 3, roles: ['x', 'y'] })}.`;
// `data` is /t/o: the fields the generators read, a child with a priority, an array-like
// child, and `m` for the query's index.
const seed = JSON.stringify({
  t: {
    o: {
      s: 'Hello', n: 5, d: 2.5, b: true, z: 0, e: '', num: '5', k: 'v', m: 1,
      o: { k: 'v', m: 1, '.priority': 3 }, arr: { 0: 'a', 1: 'b' }, '.priority': 7,
    },
    p: { m: 2 },
  },
  u: 'u1',
});
const written = JSON.stringify({ k: 'w', m: 2, s: 'Hi', b: false });
const query = 'orderBy=%22m%22&startAt=0&limitToFirst=2';
const contexts = {
  R: (x) => ({ t: { $k: { '.read': x, '.indexOn': ['m'] } } }),
  W: (x) => ({ t: { $k: { '.read': true, '.write': x } } }),
  V: (x) => ({ t: { $k: { '.read': true, '.write': true, '.validate': x } } }),
};
const owner = { authorization: 'Bearer owner' };
const timeout = () => AbortSignal.timeout(15000);
const results = new Array(corpus.length);

// A request that fails to connect is tried again (the official emulator sometimes refuses a
// connection while streams it served are being torn down).
async function retried(run) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await run();
    } catch (error) {
      if (attempt >= 8) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
    }
  }
}

async function status(url, init = {}) {
  return retried(async () => {
    const response = await fetch(url, { ...init, signal: timeout() });
    await response.arrayBuffer();
    if (response.status === 503) throw new Error(`503 from ${url}`);
    return response.status;
  });
}

async function stream(url) {
  return retried(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(url, { headers: { accept: 'text/event-stream' }, signal: controller.signal });
      if (response.status === 503) throw new Error(`503 from ${url}`);
      return response.status;
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  });
}

// A realtime listen of `path`, signed in with `credential` when one is given: the status of
// the listen's answer, 200 for "ok" and 401 for "permission_denied".
function listen(hostPort, ns, path, credential) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`ws://${hostPort}/.ws?v=5&ns=${ns}`);
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error(`listen timed out: ${path}`));
    }, 15000);
    let request = 0;
    const send = (action, body) => socket.send(JSON.stringify({ t: 'd', d: { r: ++request, a: action, b: body } }));
    const query = () => send('q', { p: path, h: '' });
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.t === 'c') {
        if (credential) send('auth', { cred: credential });
        else query();
        return;
      }
      const data = message.d ?? {};
      if (data.r === 1 && credential) {
        query();
        return;
      }
      if (data.r === request && data.b) {
        clearTimeout(timer);
        socket.close();
        const status = data.b.s;
        resolve(status === 'ok' ? 200 : status === 'permission_denied' ? 401 : status);
      }
    };
    socket.onerror = () => {
      clearTimeout(timer);
      reject(new Error('listen failed'));
    };
  });
}

async function worker(k) {
  const base = `http://${hostPort}`;
  // A namespace the official emulator shut down after an internal error answers 503 from
  // then on; the worker moves to a fresh one and judges the expression again.
  let generation = 0;
  let ns = `cells${k}`;
  const reseed = () => status(`${base}/.json?ns=${ns}`, { method: 'PUT', headers: owner, body: seed });
  for (let i = k; i < corpus.length; i += workers) {
    const entry = corpus[i];
    const expr = typeof entry === 'string' ? entry : entry.expr;
    results[i] = await judge(expr);
  }

  // The official emulator shuts a namespace down after some internal errors (it answers 503
  // from then on, or closes the connection). A cell that meets that is asked again once in a
  // fresh namespace, with the context's rules loaded there; if it fails again it is recorded
  // (503 or "gone"), which compare.py never counts as an agreement.
  async function judge(expr) {
    const row = { expr };
    for (const [name, rules] of Object.entries(contexts)) {
      const body = JSON.stringify({ rules: rules(expr) });
      const load = async () => {
        await reseed();
        return retried(async () => {
          const response = await fetch(`${base}/.settings/rules.json?ns=${ns}`, { method: 'PUT', headers: owner, body, signal: timeout() });
          if (response.status === 503) throw new Error('503 while loading rules');
          return response;
        });
      };
      const revive = async () => {
        ns = `cells${k}g${++generation}`;
        await load();
      };
      const cell = async (run) => {
        try {
          return await run();
        } catch (error) {
          try {
            await revive();
            return await run();
          } catch (again) {
            await revive().catch(() => {});
            return String(again).includes('503') ? 503 : 'gone';
          }
        }
      };
      let response;
      try {
        response = await load();
      } catch (error) {
        ns = `cells${k}g${++generation}`;
        response = await load();
      }
      const text = await response.text();
      row[`load${name}`] = response.status;
      if (response.status !== 200) {
        try {
          row[`err${name}`] = JSON.parse(text).error;
        } catch {
          row[`err${name}`] = text.slice(0, 200);
        }
        continue;
      }
      if (name === 'R') {
        row.ra = await cell(() => status(`${base}/t/o.json?ns=${ns}&auth=${token}`));
        row.ru = await cell(() => status(`${base}/t/o.json?ns=${ns}`));
        row.qa = await cell(() => status(`${base}/t/o.json?ns=${ns}&${query}&auth=${token}`));
        row.qu = await cell(() => status(`${base}/t/o.json?ns=${ns}&${query}`));
        row.sa = await cell(() => stream(`${base}/t/o.json?ns=${ns}&auth=${token}`));
        row.su = await cell(() => stream(`${base}/t/o.json?ns=${ns}`));
        row.la = await cell(() => retried(() => listen(hostPort, ns, '/t/o', token)));
        row.lu = await cell(() => retried(() => listen(hostPort, ns, '/t/o', null)));
      } else {
        const c = name.toLowerCase();
        row[`${c}a`] = await cell(() => status(`${base}/t/o.json?ns=${ns}&auth=${token}`, { method: 'PUT', body: written }));
        await cell(() => reseed());
        row[`${c}u`] = await cell(() => status(`${base}/t/o.json?ns=${ns}`, { method: 'PUT', body: written }));
      }
    }
    return row;
  }
}

try {
  await Promise.all(Array.from({ length: workers }, (_, k) => worker(k)));
} catch (error) {
  writeFileSync(outFile, `${JSON.stringify(results.filter(Boolean), null, 1)}\n`);
  console.log(`stopped: ${error} ${error?.cause ?? ''}`);
  process.exit(2);
}
writeFileSync(outFile, `${JSON.stringify(results, null, 1)}\n`);
console.log(`${results.length} expressions`);
