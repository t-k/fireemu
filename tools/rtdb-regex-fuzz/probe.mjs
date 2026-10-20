// node probe.mjs <host:port> <corpus.json> <out.json>: loads {"rules":{"t":{".read":<expr>}}} into
// a fresh namespace, seeds /t, reads /t as a fixed unsigned-token user, and records the load and read
// answers, with a timeout per request; a request that times out is recorded as load "timeout".
import { readFileSync, writeFileSync } from 'node:fs';
const [hostPort, corpusFile, outFile] = process.argv.slice(2);
const corpus = JSON.parse(readFileSync(corpusFile, 'utf8'));
const e = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const token = `${e({ alg: 'none', typ: 'JWT' })}.${e({ sub: 'u1', uid: 'u1', iat: 1, exp: 9999999999, email: 'A@b.co', admin: true, n: 3, roles: ['x'] })}.`;
const seed = { t: { s: 'Hello', n: 5, d: 2.5, b: true, z: 0, o: { k: 'v', m: 1 }, arr: { 0: 'a', 1: 'b' }, '.priority': 7 }, u: 'u1' };
const owner = { authorization: 'Bearer owner' };
const t = () => AbortSignal.timeout(15000);
const results = [];
let i = 0;
for (const entry of corpus) {
  const expr = typeof entry === 'string' ? entry : entry.expr;
  const ns = `fz${Date.now().toString(36)}${i++}`;
  try {
    await fetch(`http://${hostPort}/.json?ns=${ns}`, { method: 'PUT', headers: owner, body: JSON.stringify(seed), signal: t() });
    const rules = JSON.stringify({ rules: { t: { '.read': expr } } });
    const load = await fetch(`http://${hostPort}/.settings/rules.json?ns=${ns}`, { method: 'PUT', headers: owner, body: rules, signal: t() });
    const loadText = await load.text();
    let read = null;
    if (load.status === 200) read = (await fetch(`http://${hostPort}/t.json?ns=${ns}&auth=${token}`, { signal: t() })).status;
    results.push({ expr, query: '', load: load.status, error: load.status === 200 ? null : JSON.parse(loadText).error, read });
  } catch (error) {
    results.push({ expr, query: '', load: 'timeout', error: String(error), read: null });
    writeFileSync(outFile, `${JSON.stringify(results, null, 1)}\n`);
    console.log(`stopped at ${i - 1}: ${expr}`);
    process.exit(2);
  }
}
writeFileSync(outFile, `${JSON.stringify(results, null, 1)}\n`);
console.log(`${results.length} expressions`);
