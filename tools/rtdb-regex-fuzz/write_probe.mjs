// The write-kind runner for gen11.py (the r11 review wrote it): each entry, as E and !(E), in
// its placement, over 18 write operations, signed in ("a") and anonymous ("u"). After each
// operation the owner reads /t back (format=export), so a write that was answered one way but
// stored another shows. A control's "bodies" replace the body its named operations send.
// node write_probe.mjs <host:port> <corpus.json> <out.json> [workers] [corpus offset]
// Loopback only.
import { readFileSync, writeFileSync } from 'node:fs';

const [host, corpusFile, outFile, w, offsetText] = process.argv.slice(2);
const workers = Number(w ?? 6);
const corpus = JSON.parse(readFileSync(corpusFile, 'utf8'));
const offset = Number(offsetText ?? 0);
if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(offset + corpus.length)) {
  throw new Error('The corpus offset must be a non-negative safe integer within the corpus index range.');
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const TOKEN = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'u1', uid: 'u1', iat: 1, exp: 9999999999, email: 'A@b.co', n: 3, roles: ['x', 'y'] })}.`;
const SEED = JSON.stringify({ t: { o: { a: 1, b: 2, s: 'Hello', '.priority': 7 }, p: { m: 2 } }, n: { x: 1 } });
const OWNER = { authorization: 'Bearer owner' };

const P = {
  obj: [{ a: 5, b: 5 }, { a: 1, x: 2 }, { s: 'Hi', a: { b: 1 } }, { '.priority': 5, a: 1 }, { a: 5 }, { '.value': 'w', '.priority': 1 }, { a: 2, b: 2, s: 'Hello' }, { x: { y: 1 } }],
  leaf: [5, 'w', { b: 1 }, 2, 'Hello', true],
  patchO: [{ a: 5, b: 5 }, { a: null, x: 1 }, { x: 1 }, { 'a/b': 1, s: null }, { '.priority': 3 }, { a: 2 }, { b: null }, { a: 9, 'q/r': 1 }],
  patchT: [{ 'o/a': 5, 'p/m': 5 }, { 'o/a': 5, 'o/b': 5 }, { o: null, 'p/m': 1 }, { 'n/a': 1, 'o/x': 1 }, { 'o/a': 2, 'p/m': 2 }, { 'o/.priority': 4, 'p/m': 7 }],
  patchRoot: [{ 't/o/a': 5, 't/p/m': 5 }, { 't/o': { a: 5, b: 5 }, 'n/x': 2 }, { 't/o/a': null, 't/p': null }, { 't/o/x': 1, 'u': 1 }],
  post: [{ a: 1 }, 5, { a: { '.sv': 'timestamp' } }, { a: 5, b: 5 }],
};
const sel = (pool, i, k) => pool[(i * 7 + k * 13) % pool.length];
const OPS = [
  ['put_obj', (i) => ({ rest: ['PUT', '/t/o', sel(P.obj, i, 1)] })],
  ['put_leaf', (i) => ({ rest: ['PUT', '/t/o/a', sel(P.leaf, i, 2)] })],
  ['patch_o', (i) => ({ rest: ['PATCH', '/t/o', sel(P.patchO, i, 3)] })],
  ['patch_t', (i) => ({ rest: ['PATCH', '/t', sel(P.patchT, i, 4)] })],
  ['patch_root', (i) => ({ rest: ['PATCH', '/', sel(P.patchRoot, i, 5)] })],
  ['post', (i) => ({ rest: ['POST', '/t', sel(P.post, i, 6)] })],
  ['del_o', () => ({ rest: ['DELETE', '/t/o'] })],
  ['del_a', () => ({ rest: ['DELETE', '/t/o/a'] })],
  ['ws_set', (i) => ({ ws: { a: 'p', b: { p: '/t/o', d: sel(P.obj, i, 9) } } })],
  ['ws_merge', (i) => ({ ws: { a: 'm', b: { p: '/t/o', d: sel(P.patchO, i, 10) } } })],
  ['ws_merge_t', (i) => ({ ws: { a: 'm', b: { p: '/t', d: sel(P.patchT, i, 11) } } })],
  ['od_set', (i) => ({ ws: { a: 'o', b: { p: '/t/o', d: sel(P.obj, i, 12) } }, od: true })],
  ['od_merge', (i) => ({ ws: { a: 'om', b: { p: '/t/o', d: sel(P.patchO, i, 13) } }, od: true })],
  ['od_merge_t', (i) => ({ ws: { a: 'om', b: { p: '/t', d: sel(P.patchT, i, 14) } }, od: true })],
  ['txn_new', (i) => ({ ws: { a: 'p', b: { p: '/t/n', d: sel(P.obj, i, 15), h: '' } } })],
  ['cond_new', (i) => ({ rest: ['PUT', '/t/n', sel(P.obj, i, 16), { 'if-match': 'null_etag' }] })],
  ['prio', () => ({ rest: ['PUT', '/t/o/.priority', 5] })],
  ['sv', (i) => ({ rest: ['PUT', '/t/o', (i % 2 ? { a: { '.sv': { increment: 1 } }, b: 2, s: 'Hello' } : { a: { '.sv': 'timestamp' }, b: 2 })] })],
];

function rulesFor(place, e) {
  const ek = e.replaceAll('$k', "'o'");
  switch (place) {
    case 'W': return { t: { $k: { '.read': true, '.write': e } } };
    case 'V': return { t: { $k: { '.read': true, '.write': true, '.validate': e } } };
    case 'VC': return { t: { $k: { '.read': true, '.write': true, $c: { '.validate': e } } } };
    case 'WC': return { t: { $k: { '.read': true, '.write': false, $c: { '.write': e } } } };
    case 'WT': return { t: { '.read': true, '.write': ek } };
    case 'VA': return { t: { $k: { '.read': true, '.write': true, a: { '.validate': e } } } };
    case 'VO': return { t: { $k: { '.read': true, '.write': true, a: { '.validate': true }, b: { '.validate': true }, $other: { '.validate': e } } } };
    default: throw new Error(place);
  }
}

async function http(method, path, ns, body, who, headers = {}) {
  let url = `http://${host}${path === '/' ? '/' : path}.json?ns=${ns}`;
  if (path === '/') url = `http://${host}/.json?ns=${ns}`;
  const h = { ...headers };
  if (who === 'o') Object.assign(h, OWNER);
  if (who === 'a') url += `&auth=${TOKEN}`;
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
      const t = await r.text();
      return [r.status, t];
    } catch (e) {
      if (attempt >= 4) return ['ERR', String(e)];
      await new Promise((r) => setTimeout(r, 200 * (attempt + 1)));
    }
  }
}

function ws(ns, msg, who, od) {
  return new Promise((done) => {
    const sock = new WebSocket(`ws://${host}/.ws?v=5&ns=${ns}`);
    const msgs = who === 'a' ? [{ a: 'auth', b: { cred: TOKEN } }, msg] : [msg];
    let finished = false;
    let answer = 'none';
    const finish = (a) => {
      if (finished) return;
      finished = true;
      answer = a;
      try { sock.close(); } catch {}
      setTimeout(() => done(answer), od ? 500 : 0);
    };
    sock.onmessage = (ev) => {
      const m = JSON.parse(String(ev.data));
      if (m.t === 'c') { msgs.forEach((x, k) => sock.send(JSON.stringify({ t: 'd', d: { r: k + 1, ...x } }))); return; }
      if (m.t === 'd' && m.d.r === msgs.length) {
        const s = m.d.b?.s;
        finish(s === 'ok' ? 200 : s === 'permission_denied' ? 401 : `${s}`);
      }
    };
    sock.onerror = () => finish('wserr');
    setTimeout(() => finish('timeout'), 10000);
  });
}

const strip = (v) => {
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      const s = strip(x);
      if (s !== undefined) o[k] = s;
    }
    const keys = Object.keys(o).sort();
    if (keys.length === 0 || (keys.length === 1 && keys[0] === '.priority')) return undefined;
    return Object.fromEntries(keys.map((x) => [x, o[x]]));
  }
  return v;
};

const results = new Array(corpus.length * 2);
async function worker(k) {
  let gen = 0;
  let ns = `g11w${k}`;
  for (let i = k; i < corpus.length; i += workers) {
    const globalIndex = offset + i;
    for (const [j, e] of [[0, corpus[i].expr], [1, `!(${corpus[i].expr})`]]) {
      const row = { i: globalIndex, pol: j ? 'neg' : 'pos', place: corpus[i].place, expr: e };
      const rules = rulesFor(corpus[i].place, e);
      await http('PUT', '/', ns, JSON.parse(SEED), 'o');
      const [ls, lt] = await http('PUT', '/.settings/rules', ns, { rules }, 'o');
      row.load = ls;
      if (ls !== 200) { row.err = lt.slice(0, 200); results[2 * i + j] = row; continue; }
      for (const [name, mk] of OPS) {
        for (const who of ['a', 'u']) {
          const op = mk(globalIndex);
          const fixed = corpus[i].bodies?.[name];
          if (fixed !== undefined) {
            if (op.rest) op.rest[2] = fixed;
            else op.ws.b.d = fixed;
          }
          await http('PUT', '/', ns, JSON.parse(SEED), 'o');
          let st;
          if (op.rest) {
            const [m, p, body, hd] = op.rest;
            st = (await http(m, p, ns, body, who, hd))[0];
          } else {
            st = await ws(ns, op.ws, who, op.od);
          }
          const [rs, rt] = await http('GET', '/t', ns, undefined, 'o', {});
          let state = rt;
          try { state = JSON.stringify(strip(JSON.parse(rt))) ?? 'null'; } catch {}
          state = state.replace(/"-[A-Za-z0-9_-]{19}"/g, '"PUSH"').replace(/\b1[78]\d{11}(\.0)?\b/g, 'TS');
          if (st === 503 || rs === 503) { ns = `g11w${k}x${++gen}`; await http('PUT', '/', ns, JSON.parse(SEED), 'o'); await http('PUT', '/.settings/rules', ns, { rules }, 'o'); }
          row[`${name}.${who}`] = [st, state];
        }
      }
      results[2 * i + j] = row;
    }
  }
}
await Promise.all(Array.from({ length: workers }, (_, k) => worker(k)));
writeFileSync(outFile, JSON.stringify(results));
console.log(results.length, 'rows');
