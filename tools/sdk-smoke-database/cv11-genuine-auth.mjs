// CV11 genuine-auth public SDK recorder. One scenario (cv11-genuine-auth-page.js) runs for four
// profiles (round 1/2 x WebSocket/long polling) with the firebase 12.18.0 web SDK in headless
// Chromium, against fireemu (local) or the production sandbox (production, packet-gated).
//
//   node cv11-genuine-auth.mjs local --out <new dir> --modules <node_modules> [--fireemu <bin>]
//   node cv11-genuine-auth.mjs production --packet <file> --packet-sha256 <hex> --out <new dir>
//   node cv11-genuine-auth.mjs compare <journal.json> <journal.json>
//
// Outputs never hold tokens, emails, passwords or API keys (assertNoSecrets guards every write).
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SOURCES = ['cv11-genuine-auth.mjs', 'cv11-genuine-auth-page.js'];
export const PROFILES = [[1, 'ws'], [1, 'lp'], [2, 'ws'], [2, 'lp']].map(([round, transport]) => ({ round, transport, name: `r${round}-${transport}` }));
// observe/cleanup: admin requests per phase; mutations: admin writes overall; browser caps per profile.
export const CAPS = { observe: 70, cleanup: 30, mutations: 45, pollsPerOperation: 12, browserHttp: 150, browserWs: 6 };
const INSTANCE = 'fireemu-q-rtdb2', LOCATION = 'us-central1', TIMEOUT_MS = 25000;
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
class Stop extends Error {}

export function rulesFor(prefix) {
  const [top, run] = prefix.split('/'), own = 'auth != null && auth.uid == $uid';
  return { rules: { '.read': false, '.write': false, [top]: { [run]: { $round: { users: { $uid: { '.read': own, '.write': own } } } } } } };
}

// Every admin request is counted against the caps before it is sent. Only a complete 2xx with a
// readable body ('ok') or a complete 4xx ('refused') is a known answer; anything else is 'unknown'.
export function adminClient({ fetchImpl = fetch, headers, log, caps = CAPS }) {
  const counts = { observe: 0, cleanup: 0, mutations: 0 };
  let phase = 'observe';
  async function call(step, method, url, body, { raw = false } = {}) {
    const mutation = method !== 'GET' && !new URL(url).pathname.endsWith('accounts:lookup');
    if (counts[phase] >= caps[phase] || (mutation && counts.mutations >= caps.mutations)) throw new Stop(`cap reached before ${step}`);
    counts[phase]++;
    if (mutation) counts.mutations++;
    const sent = body === undefined || typeof body === 'string' ? body : JSON.stringify(body);
    let status = 0, text = '', outcome, value;
    try {
      const res = await fetchImpl(url, { method, body: sent, redirect: 'manual', headers: { 'content-type': 'application/json', ...headers }, signal: AbortSignal.timeout(TIMEOUT_MS) });
      status = res.status;
      text = await res.text();
      outcome = status >= 200 && status < 300 ? 'ok' : status >= 400 && status < 500 ? 'refused' : 'unknown';
      if (outcome === 'ok' && !raw) try { value = text === '' ? undefined : JSON.parse(text); } catch { outcome = 'unknown'; }
    } catch { outcome = 'unknown'; }
    log({ step, phase, method, url, status, outcome, bytes: Buffer.byteLength(text) });
    return { outcome, value, text };
  }
  return { call, counts, cleanup: () => { phase = 'cleanup'; } };
}

function urls(o) {
  if (o.mode === 'local') {
    const q = `?ns=${o.local.ns}`;
    return { auth: `${o.local.auth}/identitytoolkit.googleapis.com/v1/projects/${o.local.projectId}`, data: (p) => `${o.local.db}/${p}.json${q}` };
  }
  const n = o.packet.projectNumber, mgmt = `https://firebasedatabase.googleapis.com/v1beta/projects/${n}/locations`;
  return {
    auth: `https://identitytoolkit.googleapis.com/v1/projects/${o.packet.projectId}`, data: (p) => `https://${INSTANCE}.firebaseio.com/${p}.json`,
    service: `https://serviceusage.googleapis.com/v1/projects/${n}/services/firebasedatabase.googleapis.com`, serviceName: `projects/${n}/services/firebasedatabase.googleapis.com`,
    op: (name) => `https://serviceusage.googleapis.com/v1/${name}`, list: `${mgmt}/-/instances`,
    instance: `${mgmt}/${LOCATION}/instances/${INSTANCE}`, instanceName: `projects/${n}/locations/${LOCATION}/instances/${INSTANCE}`,
  };
}

// The run's view of what it owns. state.* is 'baseline', 'ours' or 'unknown'; users map uid to
// 'live' | 'deleted' (own 2xx delete, awaiting read-back) | 'gone' | 'unknown-delete'.
// unresolved holds unknown creates and deletes: they are sticky and never re-sent.
async function read(run, step, method, url, accept, body) {
  const r = await run.call(step, method, url, body, { raw: method === 'GET' && url.includes('.settings/rules') });
  if (r.outcome !== 'ok' || !accept(r.value, r.text)) throw new Stop(`${step}: ${r.outcome}`);
  return r.value ?? r.text;
}
async function mutate(run, step, key, method, url, body, accept = () => true, sticky = true) {
  const r = await run.call(step, method, url, body);
  if (r.outcome === 'refused') throw new Stop(`${step}: refused`);
  if (r.outcome === 'unknown' || !accept(r.value)) {
    if (key) run.state[key] = 'unknown';
    if (sticky) run.unresolved.push({ step, key });
    throw new Stop(`${step}: unknown`);
  }
  return r.value;
}
async function waitOperation(run, step, op, sleep) {
  for (let i = 0; op?.done !== true; i++) {
    if (i >= CAPS.pollsPerOperation) return false;
    await sleep(5000);
    const r = await run.call(`${step}-poll-${i}`, 'GET', run.u.op(op.name));
    if (r.outcome !== 'ok' || r.value?.name !== op.name) return false;
    op = r.value;
  }
  return !op.error;
}
const isInstance = (run, state) => (v) => v?.name === run.u.instanceName && v.type === 'USER_DATABASE' && v.state === state;

async function setApi(run, verb, sleep) {
  const op = await mutate(run, `api-${verb}`, 'api', 'POST', `${run.u.service}:${verb}`, {}, (v) => /^operations\//.test(v?.name));
  run.state.api = verb === 'enable' ? 'ours' : 'unknown'; // acknowledged: no longer the starting state until read back
  if (!(await waitOperation(run, `api-${verb}`, op, sleep))) { run.state.api = 'unknown'; run.unresolved.push({ step: `api-${verb}`, key: 'api' }); throw new Stop(`api-${verb}: operation`); }
  const want = verb === 'enable' ? 'ENABLED' : 'DISABLED';
  await read(run, `api-${want.toLowerCase()}`, 'GET', run.u.service, (v) => v?.name === run.u.serviceName && v.state === want);
  run.state.api = verb === 'enable' ? 'ours' : 'baseline';
}

async function setupProduction(run, sleep) {
  const u = run.u;
  await read(run, 'api-before', 'GET', u.service, (v) => v?.name === u.serviceName && v.state === 'DISABLED');
  await setApi(run, 'enable', sleep);
  await read(run, 'instance-before', 'GET', u.instance, isInstance(run, 'DELETED'));
  await read(run, 'active-before', 'GET', u.list, (v) => !v?.instances?.length && !v?.nextPageToken);
  const back = await mutate(run, 'instance-undelete', 'instance', 'POST', `${u.instance}:undelete`, undefined, (v) => isInstance(run, 'ACTIVE')(v) || isInstance(run, 'DISABLED')(v));
  run.state.instance = 'ours';
  if (back.state === 'DISABLED') await mutate(run, 'instance-reenable', 'instance', 'POST', `${u.instance}:reenable`, undefined, isInstance(run, 'ACTIVE'));
  await read(run, 'instance-active', 'GET', u.instance, isInstance(run, 'ACTIVE'));
}

async function installRules(run, o) {
  const rulesUrl = run.u.data('.settings/rules'), want = rulesFor(o.prefix);
  run.baseline = await read(run, 'rules-before', 'GET', rulesUrl, (_, text) => !o.packet || sha256(text) === o.packet.baselineRulesSha256);
  await read(run, 'prefix-before', 'GET', run.u.data(o.prefix), (v) => v === null);
  run.state.rules = 'ours';
  await mutate(run, 'rules-install', 'rules', 'PUT', rulesUrl, want, (v) => v?.status === 'ok', false);
  await read(run, 'rules-installed', 'GET', rulesUrl, (_, text) => { try { return isDeepStrictEqual(JSON.parse(text), want); } catch { return false; } });
}

async function createUser(run, step, cred) {
  const r = await run.call(step, 'POST', `${run.u.auth}/accounts`, { email: cred.email, password: cred.password });
  let uid = r.outcome === 'ok' && typeof r.value?.localId === 'string' ? r.value.localId : undefined;
  if (r.outcome === 'unknown' || (r.outcome === 'ok' && !uid)) {
    // An unknown create settles only on our own positive read; otherwise it stays open.
    const l = await run.call(`${step}-lookup`, 'POST', `${run.u.auth}/accounts:lookup`, { email: [cred.email] });
    uid = l.outcome === 'ok' && l.value?.users?.length === 1 ? l.value.users[0].localId : undefined;
    if (!uid) run.unresolved.push({ step, key: 'user' });
  }
  if (!uid) throw new Stop(`${step}: ${r.outcome}`);
  run.users.set(uid, 'live');
  return uid;
}
async function deleteUser(run, step, uid) {
  if (run.users.get(uid) !== 'live') return 'skipped';
  const r = await run.call(step, 'POST', `${run.u.auth}/accounts:delete`, { localId: uid });
  if (r.outcome === 'ok') run.users.set(uid, 'deleted');
  if (r.outcome === 'unknown') { run.users.set(uid, 'unknown-delete'); run.unresolved.push({ step, key: 'user' }); }
  return r.outcome;
}
async function confirmGone(run, step, uid) {
  if (run.users.get(uid) !== 'deleted') return;
  const r = await run.call(step, 'POST', `${run.u.auth}/accounts:lookup`, { localId: [uid] });
  if (r.outcome === 'ok' && r.value && !r.value.users) run.users.set(uid, 'gone');
}

async function runProfile(run, o, prof) {
  const tag = (s) => `${prof.name}:${s}`, nonce = randomBytes(6).toString('hex');
  const creds = Object.fromEntries(['a', 'b'].map((role) => [role, { email: `cv11-${nonce}-${role}@example.com`, password: `pw-${randomBytes(12).toString('hex')}` }]));
  o.secrets.push(creds.a.email, creds.a.password, creds.b.email, creds.b.password);
  const a = await createUser(run, tag('a-create'), creds.a), b = await createUser(run, tag('b-create'), creds.b);
  const scope = (uid) => `${o.prefix}/r${prof.round}/users/${uid}`;
  run.state.data = 'ours';
  for (const [role, uid] of [['a', a], ['b', b]]) await mutate(run, tag(`${role}-seed`), null, 'PUT', run.u.data(scope(uid)), { value: prof.round }, undefined, false);
  const hooks = {
    secret: (role) => creds[role],
    deleteA: () => deleteUser(run, tag('a-delete'), a),
    writeA: async () => (await run.call(tag('a-write-after-delete'), 'PUT', run.u.data(scope(a)), { value: prof.round, after: 1 })).outcome,
    event: o.event ?? (() => {}),
  };
  const out = await o.browser({ ...prof, scopeA: scope(a), scopeB: scope(b) }, hooks);
  await confirmGone(run, tag('a-gone'), a);
  await deleteUser(run, tag('b-delete'), b);
  await confirmGone(run, tag('b-gone'), b);
  return { name: prof.name, ...out };
}

async function cleanup(run, o, sleep) {
  run.admin.cleanup();
  const steps = [
    async () => { for (const uid of run.users.keys()) { await deleteUser(run, 'cleanup-user-delete', uid); await confirmGone(run, 'cleanup-user-gone', uid); } },
    async () => {
      if (run.state.data === 'baseline') return;
      await mutate(run, 'prefix-delete', 'data', 'DELETE', run.u.data(o.prefix), undefined, (v) => v === null);
      await read(run, 'prefix-null', 'GET', run.u.data(o.prefix), (v) => v === null);
      run.state.data = 'baseline';
    },
    async () => {
      if (run.state.rules === 'baseline') return;
      await mutate(run, 'rules-restore', null, 'PUT', run.u.data('.settings/rules'), run.baseline, (v) => v?.status === 'ok', false);
      await read(run, 'rules-restored', 'GET', run.u.data('.settings/rules'), (_, text) => text === run.baseline);
      run.state.rules = 'baseline';
    },
    async () => {
      if (o.mode !== 'production' || run.state.instance !== 'ours' || run.state.rules !== 'baseline' || run.state.data !== 'baseline') return;
      await mutate(run, 'instance-disable', 'instance', 'POST', `${run.u.instance}:disable`, undefined, isInstance(run, 'DISABLED'));
      await read(run, 'instance-disabled', 'GET', run.u.instance, isInstance(run, 'DISABLED'));
      await mutate(run, 'instance-delete', 'instance', 'DELETE', run.u.instance, undefined, isInstance(run, 'DELETED'));
      await read(run, 'instance-deleted', 'GET', run.u.instance, isInstance(run, 'DELETED'));
      await read(run, 'active-after', 'GET', run.u.list, (v) => !v?.instances?.length && !v?.nextPageToken);
      run.state.instance = 'baseline';
    },
    async () => { if (run.state.api === 'ours' && run.state.instance === 'baseline') await setApi(run, 'disable', sleep); },
  ];
  for (const step of steps) try { await step(); } catch (e) { if (!(e instanceof Stop)) throw e; run.errors.push(e.message); }
}

// Runs setup, the four profiles and cleanup. The status is 'closed' only when nothing is unknown
// and every owned resource read back at its starting state; otherwise 'needs-recovery'.
export async function runScenario(o) {
  const admin = adminClient({ fetchImpl: o.fetchImpl, headers: o.headers, log: o.log });
  const run = { admin, call: admin.call, u: urls(o), state: { api: 'baseline', instance: 'baseline', rules: 'baseline', data: 'baseline' }, users: new Map(), unresolved: [], errors: [] };
  const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  o.secrets ??= [];
  const profiles = [];
  try {
    if (o.mode === 'production') await setupProduction(run, sleep);
    await installRules(run, o);
    for (const prof of PROFILES) profiles.push(await runProfile(run, o, prof));
  } catch (e) {
    if (!(e instanceof Stop)) run.errors.push(`unexpected: ${e.message}`);
    else run.errors.push(e.message);
  } finally {
    await cleanup(run, o, sleep);
  }
  const restored = Object.values(run.state).every((s) => s === 'baseline') && [...run.users.values()].every((s) => s === 'gone');
  return { status: run.unresolved.length === 0 && restored ? 'closed' : 'needs-recovery', observationComplete: profiles.length === PROFILES.length, profiles, state: run.state, users: [...run.users.values()], unresolved: run.unresolved, errors: run.errors, counts: admin.counts };
}

// Compares two runs profile by profile. Step order is the observation; within one step the order
// of events is a latency race, so each step's events are compared sorted. Timing (ms) is ignored.
export function compareJournals(a, b) {
  const key = (e) => JSON.stringify([e.step, e.type, e.epoch ?? null, e.code ?? null, e.shape ?? null, e.present ?? null]);
  const canonical = (journal = []) => {
    const out = [];
    for (const e of journal) (out.at(-1)?.step === e.step ? out.at(-1).keys : (out.push({ step: e.step, keys: [] }), out.at(-1).keys)).push(key(e));
    return out.flatMap((s) => s.keys.sort());
  };
  const differences = [];
  for (const [i, p] of a.entries()) {
    const x = canonical(p.journal), y = canonical(b[i]?.journal), n = x.findIndex((k, j) => k !== y[j]);
    if (n >= 0 || x.length !== y.length) differences.push({ profile: p.name, index: n >= 0 ? n : x.length, left: x[n >= 0 ? n : x.length] ?? null, right: y[n >= 0 ? n : x.length] ?? null });
  }
  return { match: differences.length === 0 && a.length === b.length, differences };
}

export function assertNoSecrets(text, secrets) {
  if (/AIza[0-9A-Za-z_-]{20,}|eyJ[0-9A-Za-z_-]{8,}|ya29\.|[^\s"]+@example\.com/.test(text) || secrets.some((s) => s && text.includes(s))) throw Error('refusing to write output that holds a secret');
  return text;
}

export function verifyPacket(file, expected) {
  if (!file || !expected) throw Error('production needs --packet <file> and --packet-sha256 <hex>');
  const raw = readFileSync(file);
  if (sha256(raw) !== expected) throw Error('packet SHA-256 does not match --packet-sha256');
  const packet = JSON.parse(raw);
  for (const s of SOURCES) if (packet.sources?.[s] !== sha256(readFileSync(path.join(here, s)))) throw Error(`source pin differs: ${s}`);
  return packet;
}

// One profile in headless Chromium. The page and SDK bundles are served from loopback; only the
// allowed hosts are reached, and HTTP requests and WebSockets are counted against the caps.
export function browserRunner({ modules, allowHost, page: pageConfig }) {
  const require = createRequire(path.join(modules, 'x.js'));
  const { chromium } = require('playwright');
  return async (prof, hooks) => {
    const server = createServer((req, res) => {
      const file = req.url === '/page.js' ? path.join(here, 'cv11-genuine-auth-page.js') : null;
      res.writeHead(200, { 'content-type': file ? 'text/javascript' : 'text/html' });
      res.end(file ? readFileSync(file) : '<!doctype html><script type="module" src="/page.js"></script>');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const origin = `127.0.0.1:${server.address().port}`, counts = { http: 0, ws: 0, blocked: 0 }, journal = [];
    const browser = await chromium.launch({ headless: true });
    let overCap;
    const capped = new Promise((_, reject) => { overCap = () => reject(Error('browser request cap reached')); });
    try {
      const context = await browser.newContext();
      if (pageConfig.emulator) await context.grantPermissions(['local-network-access'], { origin: `http://${origin}` }).catch(() => {});
      const page = await context.newPage();
      await page.route('**/*', (route) => {
        const url = new URL(route.request().url());
        if (url.host === origin) return route.continue();
        if (url.host === 'www.gstatic.com' && url.pathname.startsWith('/firebasejs/12.18.0/')) return route.fulfill({ contentType: 'text/javascript', body: readFileSync(path.join(modules, 'firebase', path.basename(url.pathname))) });
        if (!allowHost(url.host)) { counts.blocked++; return route.abort(); }
        if (++counts.http > CAPS.browserHttp) { overCap(); return route.abort(); }
        return route.continue();
      });
      page.on('websocket', () => { if (++counts.ws > CAPS.browserWs) overCap(); });
      await page.exposeFunction('__cv11Event', (e) => { const row = { step: e.step, type: e.type, epoch: e.epoch, code: e.code, shape: e.shape, present: e.present, ms: e.ms }; journal.push(row); hooks.event(prof.name, row); });
      await page.exposeFunction('__cv11Hook', (name, arg) => hooks[name](arg));
      await page.goto(`http://${origin}/`);
      await page.waitForFunction(() => typeof window.__cv11Run === 'function');
      const timeout = new Promise((_, reject) => setTimeout(() => reject(Error('profile timeout')), 150000).unref());
      await Promise.race([page.evaluate((c) => window.__cv11Run(c), { ...pageConfig, ...prof }), capped, timeout]);
      // Evidence of the transport the SDK actually used (long polling opens no WebSocket).
      const transport = { step: 'runner', type: 'transport', code: counts.ws > 0 ? 'ws' : 'lp' };
      journal.push(transport);
      hooks.event(prof.name, transport);
      return { journal, counts };
    } catch (e) {
      journal.push({ step: 'runner', type: 'error', code: e.message.slice(0, 80) });
      return { journal, counts };
    } finally {
      await browser.close();
      server.close();
    }
  };
}

async function freePort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

async function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] === 'compare') {
    const [a, b] = argv.slice(1).map((f) => JSON.parse(readFileSync(f)).profiles);
    const r = compareJournals(a, b);
    console.log(JSON.stringify(r, null, 2));
    return r.match ? 0 : 1;
  }
  const mode = argv[0], out = opt('--out');
  if (!['local', 'production'].includes(mode) || !out) throw Error('usage: local|production --out <new dir> (see the header)');
  const packet = mode === 'production' ? verifyPacket(opt('--packet'), opt('--packet-sha256')) : undefined;
  mkdirSync(out); // refuses an existing directory
  const secrets = [], write = (f, text) => writeFileSync(path.join(out, f), assertNoSecrets(text, secrets));
  const append = (f, row) => appendFileSync(path.join(out, f), assertNoSecrets(`${JSON.stringify(row)}\n`, secrets));
  const prefix = `${packet?.prefixRoot ?? 'parity20261025'}/cv11${randomBytes(5).toString('hex')}`;
  const common = { prefix, secrets, log: (row) => append('requests.jsonl', row), event: (name, row) => append('events.jsonl', { profile: name, ...row }) };
  let child, o;
  try {
    if (mode === 'local') {
      const [authPort, dbPort] = [await freePort(), await freePort()], projectId = 'demo-cv11', ns = 'demo-cv11-default-rtdb';
      child = spawn(opt('--fireemu') ?? 'fireemu', ['up', '--only', 'auth,database', '--no-config-discovery', '--project', projectId, '--http-port', String(authPort), '--database-port', String(dbPort), '--ui-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet', '--owner-stdin'], { stdio: ['pipe', 'ignore', 'inherit'] });
      const db = `http://127.0.0.1:${dbPort}`, auth = `http://127.0.0.1:${authPort}`;
      for (let i = 0; ; i++) { try { await fetch(`${db}/.json?ns=${ns}`); await fetch(`${auth}/`); break; } catch { if (i > 150) throw Error('fireemu did not start'); await new Promise((r) => setTimeout(r, 200)); } }
      const browser = browserRunner({ modules: opt('--modules') ?? path.join(here, 'node_modules'), allowHost: (h) => h === `127.0.0.1:${authPort}` || h === `127.0.0.1:${dbPort}`, page: { apiKey: 'fake-api-key', projectId, databaseURL: `${db}?ns=${ns}`, emulator: { auth, host: '127.0.0.1', dbPort } } });
      o = { mode, local: { auth, db, ns, projectId }, headers: { authorization: 'Bearer owner' }, browser, ...common };
    } else {
      const doc = JSON.parse(readFileSync(packet.keyFile, 'utf8'));
      const apiKey = typeof doc === 'string' ? doc : doc.keyString ?? doc.apiKey ?? doc.key;
      const token = execFileSync(packet.gcloud, ['auth', 'application-default', 'print-access-token'], { stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000 }).toString().trim();
      secrets.push(apiKey, token);
      const browser = browserRunner({ modules: packet.modules, allowHost: (h) => ['identitytoolkit.googleapis.com', 'securetoken.googleapis.com'].includes(h) || /^[a-z0-9-]+\.firebaseio\.com$/.test(h), page: { apiKey, projectId: packet.projectId, databaseURL: `https://${INSTANCE}.firebaseio.com` } });
      o = { mode, packet, headers: { authorization: `Bearer ${token}`, 'x-goog-user-project': packet.projectId }, browser, ...common };
    }
    const result = await runScenario(o);
    write('journal.json', `${JSON.stringify({ mode, profiles: result.profiles }, null, 2)}\n`);
    write('result.json', `${JSON.stringify({ ...result, profiles: undefined, prefixRoot: prefix.split('/')[0] }, null, 2)}\n`);
    console.log(`${mode}: ${result.status}, observationComplete=${result.observationComplete}`);
    return result.status === 'closed' && result.observationComplete ? 0 : 3;
  } finally {
    if (child) { child.stdin.end(); child.kill('SIGTERM'); }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`cv11: ${e.message}`); process.exitCode = 2; });
}
