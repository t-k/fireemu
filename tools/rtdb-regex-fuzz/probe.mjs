// node probe.mjs <host:port> <corpus.json> <out.json> [workers]
//
// Judges each expression in every rule context (ruling 15): `.read` without a query and with
// one, `.write`, and `.validate` beside `.write: true`, each as a signed-in user (an unsigned
// token) and anonymously. Each worker owns a namespace, seeds it again before every rules load
// and write, and records per expression:
//   loadR/loadW/loadV (and errR/errW/errV): the rules load answer of each context;
//   ra/ru: GET /t/o, qa/qu: the same with a query, wa/wu: PUT /t/o under `.write`,
//   va/vu: PUT /t/o under `.validate`; "a" signed in, "u" anonymous.
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

async function status(url, init = {}) {
  const response = await fetch(url, { ...init, signal: timeout() });
  await response.arrayBuffer();
  return response.status;
}

async function worker(k) {
  const base = `http://${hostPort}`;
  const ns = `cells${k}`;
  const reseed = () => fetch(`${base}/.json?ns=${ns}`, { method: 'PUT', headers: owner, body: seed, signal: timeout() }).then((r) => r.arrayBuffer());
  for (let i = k; i < corpus.length; i += workers) {
    const entry = corpus[i];
    const expr = typeof entry === 'string' ? entry : entry.expr;
    const row = { expr };
    for (const [name, rules] of Object.entries(contexts)) {
      await reseed();
      const load = await fetch(`${base}/.settings/rules.json?ns=${ns}`, {
        method: 'PUT',
        headers: owner,
        body: JSON.stringify({ rules: rules(expr) }),
        signal: timeout(),
      });
      const text = await load.text();
      row[`load${name}`] = load.status;
      if (load.status !== 200) {
        try {
          row[`err${name}`] = JSON.parse(text).error;
        } catch {
          row[`err${name}`] = text.slice(0, 200);
        }
        continue;
      }
      if (name === 'R') {
        row.ra = await status(`${base}/t/o.json?ns=${ns}&auth=${token}`);
        row.ru = await status(`${base}/t/o.json?ns=${ns}`);
        row.qa = await status(`${base}/t/o.json?ns=${ns}&${query}&auth=${token}`);
        row.qu = await status(`${base}/t/o.json?ns=${ns}&${query}`);
      } else {
        const cell = name.toLowerCase();
        row[`${cell}a`] = await status(`${base}/t/o.json?ns=${ns}&auth=${token}`, { method: 'PUT', body: written });
        await reseed();
        row[`${cell}u`] = await status(`${base}/t/o.json?ns=${ns}`, { method: 'PUT', body: written });
      }
    }
    results[i] = row;
  }
}

try {
  await Promise.all(Array.from({ length: workers }, (_, k) => worker(k)));
} catch (error) {
  writeFileSync(outFile, `${JSON.stringify(results.filter(Boolean), null, 1)}\n`);
  console.log(`stopped: ${error}`);
  process.exit(2);
}
writeFileSync(outFile, `${JSON.stringify(results, null, 1)}\n`);
console.log(`${results.length} expressions`);
