// Residual RTDB public SDK recorder: CV08 (reconnect, event and query-window order, query-scoped
// cancellation) and CV10 (onDisconnect cancel, re-register, update/remove, server values, a Rules
// change between registration and firing). Two scenarios (rtdb-residual-page.js) x four profiles
// (round 1/2 x WebSocket/long polling) with the firebase 12.18.0 web SDK in headless Chromium, against
// fireemu (local) or the production sandbox (production, packet-gated).
//
//   node rtdb-residual.mjs local --out <new dir> --fireemu <bin> [--profile strict|emulator] [--modules <node_modules>]
//   node rtdb-residual.mjs local --out <new dir> --official [--jar <path>]   (the pinned official emulator, as a reference)
//   node rtdb-residual.mjs production --packet <file> --packet-sha256 <hex> --out <new dir>
//   node rtdb-residual.mjs compare <production journal.json> <local journal.json> [--out <comparison.json>]
//
// No account, token or key reaches the page: the Rules give the anonymous client its own run prefix.
// The management calls (API, instance, Rules, prefix delete) use the ADC token and never reach an
// output (assertNoSecrets guards every write). Setup and cleanup follow the CV11 recorder.
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

import { adminClient, assertNoSecrets, LAUNCH, redact } from './cv11-genuine-auth.mjs';
import { DEFAULT_JAR, startJar } from './jar.mjs';
import { judgeRuns, sanitizeProfiles, SCENARIOS } from './rtdb-residual-judge.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SOURCES = ['rtdb-residual.mjs', 'rtdb-residual-page.js', 'rtdb-residual-judge.mjs'];
export const PROFILES = [[1, 'ws'], [1, 'lp'], [2, 'ws'], [2, 'lp']].map(([round, transport]) => ({ round, transport, name: `r${round}-${transport}` }));
// observe/cleanup: admin requests per phase; mutations: admin writes overall; browser caps per profile.
export const CAPS = { observe: 80, cleanup: 30, mutations: 40, pollsPerOperation: 12, browserHttp: 400, browserWs: 24, browserFrames: 2500 };
// A profile that never reaches the writer's disconnect can leave onDisconnect writes pending; the
// server fires them when it drops the idle long-polling connection (production: about 105 s).
export const FIRE_GRACE_MS = 150000;
// Longer than the worst case of the page's own waits (Rules probes up to 60 s each, marker wait 30 s / 240 s).
export const PROFILE_TIMEOUT_MS = { cv08: 240000, cv10: { ws: 300000, lp: 540000 } };
const PROPAGATION_MS = 120000;
const INSTANCE = 'fireemu-q-rtdb2', LOCATION = 'us-central1', TIMEOUT_MS = 25000;
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
class Stop extends Error {}

const OPEN = { '.read': true, '.write': true };
/** The Rules of one run: the anonymous client owns the run prefix; `deny` closes the writes of e7, e8 and dprobe. */
export function rulesFor(prefix, { deny = false } = {}) {
  const [top, run] = prefix.split('/'), W = { '.write': true }, flag = { '.write': !deny };
  return {
    rules: {
      '.read': false,
      '.write': false,
      [top]: {
        [run]: {
          cv08: { $cell: { items: { ...OPEN, '.indexOn': ['score'] }, gate: OPEN, gated: { '.read': "data.parent().child('gate').val() === true", '.write': true }, other: OPEN } },
          cv10: { $cell: { '.read': true, e1: W, e2: W, e3: W, e4: W, e5: W, e6: W, e7: flag, e8: flag, e9: W, marker: W, dprobe: flag } },
        },
      },
    },
  };
}

/** The ADC token comes from `gcloud auth application-default print-access-token`; the scopes are those of the login. */
export const ADC_ARGS = ['auth', 'application-default', 'print-access-token'];
/** Every management and data request carries the token as a Bearer header (never in the URL) and the quota project. */
export const productionHeaders = (token, projectId) => ({ authorization: `Bearer ${token}`, 'x-goog-user-project': projectId });

/** Chromium may reach loopback and Firebase hosts only: the page and SDK bundles are served locally. */
export const hostRules = () => '--host-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE *.firebaseio.com';

export function urls(o) {
  if (o.mode === 'local') {
    const q = `?ns=${o.local.ns}`;
    return { data: (p) => `${o.local.db}/${p}.json${q}` };
  }
  const n = o.packet.projectNumber, mgmt = `https://firebasedatabase.googleapis.com/v1beta/projects/${n}/locations`;
  return {
    data: (p) => `https://${INSTANCE}.firebaseio.com/${p}.json`,
    service: `https://serviceusage.googleapis.com/v1/projects/${n}/services/firebasedatabase.googleapis.com`, serviceName: `projects/${n}/services/firebasedatabase.googleapis.com`,
    op: (name) => `https://serviceusage.googleapis.com/v1/${name}`, list: `${mgmt}/-/instances`,
    instance: `${mgmt}/${LOCATION}/instances/${INSTANCE}`, instanceName: `projects/${n}/locations/${LOCATION}/instances/${INSTANCE}`,
  };
}

// The run's view of what it owns. state.* is 'baseline' or 'ours' ('unknown' after an unknown answer);
// unresolved holds unknown creates and deletes: sticky, never re-sent. (Same flow as the CV11 recorder.)
async function read(run, step, method, url, accept, body) {
  const options = { raw: method === 'GET' && url.includes('.settings/rules') };
  let r = await run.call(step, method, url, body, options);
  // Bounded backoff 2, 4, 8, 16, 30, 30, 30 s (120 s in all), counted against the caps; GETs only.
  // 403: the management API list right after the enable (CV11 production-1). 401: the instance host's first
  // Rules GET right after the reenable (this recorder's production-1, body "Unauthorized request.").
  for (let k = 1; method === 'GET' && run.propagation && r.outcome === 'refused' && (r.status === 403 || r.status === 401); k++) {
    const wait = Math.min(2000 * 2 ** (k - 1), 30000, PROPAGATION_MS - run.propagationWaited);
    if (wait <= 0) break;
    run.propagationWaited += wait;
    await run.sleep(wait);
    r = await run.call(`${step}-retry-${k}`, method, url, body, options);
  }
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
  run.propagation = true;
  await read(run, 'instance-before', 'GET', u.instance, isInstance(run, 'DELETED'));
  await read(run, 'active-before', 'GET', u.list, (v) => !v?.instances?.length && !v?.nextPageToken);
  const back = await mutate(run, 'instance-undelete', 'instance', 'POST', `${u.instance}:undelete`, undefined, (v) => isInstance(run, 'ACTIVE')(v) || isInstance(run, 'DISABLED')(v));
  run.state.instance = 'ours';
  if (back.state === 'DISABLED') await mutate(run, 'instance-reenable', 'instance', 'POST', `${u.instance}:reenable`, undefined, isInstance(run, 'ACTIVE'));
  await read(run, 'instance-active', 'GET', u.instance, isInstance(run, 'ACTIVE'));
}

/** Installs the Rules (open or deny) and reads them back; the first install also checks the baseline. */
async function putRules(run, step, want) {
  const rulesUrl = run.u.data('.settings/rules');
  run.state.rules = 'ours';
  await mutate(run, `${step}-put`, 'rules', 'PUT', rulesUrl, want, (v) => v?.status === 'ok', false);
  await read(run, `${step}-read`, 'GET', rulesUrl, (_, text) => { try { return isDeepStrictEqual(JSON.parse(text), want); } catch { return false; } });
}
async function installRules(run, o) {
  const rulesUrl = run.u.data('.settings/rules');
  run.baseline = await read(run, 'rules-before', 'GET', rulesUrl, (_, text) => !o.packet || sha256(text) === o.packet.baselineRulesSha256);
  await read(run, 'prefix-before', 'GET', run.u.data(o.prefix), (v) => v === null);
  run.state.data = 'ours';
  await putRules(run, 'rules-install', rulesFor(o.prefix));
}

async function cleanup(run, o, sleep) {
  run.admin.cleanup();
  const steps = [
    async () => {
      if (run.state.data === 'baseline') return;
      // Pending onDisconnect writes of an unfinished cv10 profile would recreate data after the delete.
      if (run.fireWait) await sleep(FIRE_GRACE_MS);
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
  for (const step of steps) try { await step(); } catch (e) { run.errors.push(e instanceof Stop ? e.message : `unexpected: ${e?.message}`); }
}

const fired = (journal) => journal.some((e) => e.type === 'timing' && e.step === 'fire' && typeof e.seconds === 'number') && !journal.some((e) => e.type === 'timeout' && e.label === 'marker fire');

async function runProfile(run, o, scenario, prof) {
  const cfg = { ...prof, scenario, base: `${o.prefix}/${scenario}/${prof.name}` };
  let nth = 0;
  const rules = (deny) => async () => {
    try { await putRules(run, `rules-${deny ? 'deny' : 'open'}-${scenario}-${prof.name}-${++nth}`, rulesFor(o.prefix, { deny })); return 'ok'; } catch (e) {
      if (!(e instanceof Stop)) throw e;
      run.errors.push(e.message);
      throw e; // the page's scenario ends with the hook
    }
  };
  const hooks = { rulesOpen: rules(false), rulesDeny: rules(true), event: o.event ?? (() => {}) };
  const out = await o.browser(cfg, hooks);
  // Sticky: a profile that did not observe the writer's disconnect may leave onDisconnect writes pending.
  if (scenario === 'cv10' && !fired(out.journal)) run.fireWait = true;
  return { scenario, name: prof.name, ...out };
}

// Runs setup, the scenarios x profiles and cleanup. The status is 'closed' only when nothing is
// unknown and every owned resource read back at its starting state; otherwise 'needs-recovery'.
export async function runScenario(o) {
  o.secrets ??= [];
  const admin = adminClient({ fetchImpl: o.fetchImpl, headers: o.headers, log: o.log, stop: o.stop, secrets: o.secrets, caps: CAPS });
  const run = { admin, call: admin.call, u: urls(o), propagation: false, propagationWaited: 0, state: { api: 'baseline', instance: 'baseline', rules: 'baseline', data: 'baseline' }, unresolved: [], errors: [], fireWait: false };
  const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  run.sleep = sleep;
  const profiles = [];
  // Local runs may be narrowed (--scenarios, --transports); production always runs all eight.
  const scenarios = o.scenarios ?? SCENARIOS, profilesToRun = o.profiles ?? PROFILES;
  try {
    if (o.mode === 'production') await setupProduction(run, sleep);
    await installRules(run, o);
    run.propagation = false;
    for (const scenario of scenarios) {
      for (const prof of profilesToRun) {
        if (run.errors.length || o.stop?.requested) break;
        profiles.push(await runProfile(run, o, scenario, prof));
      }
    }
  } catch (e) {
    run.errors.push(e instanceof Stop ? e.message : `unexpected: ${e?.message}`);
  } finally {
    run.propagation = false;
    await cleanup(run, o, sleep);
  }
  const restored = Object.values(run.state).every((s) => s === 'baseline');
  // An unexpected error or an unwritten log row means a sent request may be unaccounted for.
  const accounted = admin.counts.logFailures === 0 && !run.errors.some((e) => e.startsWith('unexpected'));
  return { status: run.unresolved.length === 0 && restored && accounted ? 'closed' : 'needs-recovery', unknownAnswers: admin.unknownAnswers, observationComplete: profiles.length === scenarios.length * profilesToRun.length && !run.errors.length, profiles, state: run.state, unresolved: run.unresolved, errors: run.errors, counts: admin.counts };
}

/** Compares a production and a local journal file's profiles; the timing verdict is part of `match`. */
export function compareFiles(production, local) {
  const verdict = judgeRuns(production, local);
  return { ...verdict, match: verdict.verdict === 'match' && verdict.timing.within };
}

/** The SDK bundles the page loads are the ones the packet pins (the browser serves them from disk). */
export function verifyBundles(packet) {
  for (const [name, expected] of Object.entries(packet.bundleSha256 ?? {})) {
    if (sha256(readFileSync(path.join(path.resolve(packet.modules), 'firebase', name))) !== expected) throw Error(`SDK bundle differs from the packet: ${name}`);
  }
  if (!['firebase-app.js', 'firebase-database.js'].every((n) => packet.bundleSha256?.[n])) throw Error('the packet must pin firebase-app.js and firebase-database.js');
}

export function verifyPacket(file, expected) {
  if (!file || !expected) throw Error('production needs --packet <file> and --packet-sha256 <hex>');
  const raw = readFileSync(file);
  if (sha256(raw) !== expected) throw Error('packet SHA-256 does not match --packet-sha256');
  const packet = JSON.parse(raw);
  for (const s of SOURCES) if (packet.sources?.[s] !== sha256(readFileSync(path.join(here, s)))) throw Error(`source pin differs: ${s}`);
  return packet;
}

// Long polling opens no WebSocket; any WebSocket means the SDK used that transport.
export const transportOf = (counts) => (counts.ws > 0 ? 'ws' : 'lp');
export const profileTimeout = (cfg) => (cfg.scenario === 'cv10' ? PROFILE_TIMEOUT_MS.cv10[cfg.transport] : PROFILE_TIMEOUT_MS.cv08);

// One profile in headless Chromium. The page and SDK bundles are served from loopback; HTTP requests,
// WebSockets and WebSocket frames are counted against the caps, and Chromium itself resolves nothing
// but loopback and Firebase hosts (--host-rules).
export function browserRunner({ modules, page: pageConfig, stop = {} }) {
  const require = createRequire(path.join(path.resolve(modules), 'x.js'));
  const { chromium } = require('playwright');
  return async (cfg, hooks) => {
    const server = createServer((req, res) => {
      const file = req.url === '/page.js' ? path.join(here, 'rtdb-residual-page.js') : null;
      res.writeHead(200, { 'content-type': file ? 'text/javascript' : 'text/html' });
      res.end(file ? readFileSync(file) : '<!doctype html><script type="module" src="/page.js"></script>');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const origin = `127.0.0.1:${server.address().port}`, counts = { http: 0, ws: 0, frames: 0, blocked: 0 }, journal = [];
    const browser = await chromium.launch({ ...LAUNCH, args: [hostRules()] });
    stop.closeBrowser = () => browser.close().catch(() => {});
    let overCap;
    const capped = new Promise((_, reject) => { overCap = () => reject(Error('browser request cap reached')); });
    capped.catch(() => {});
    try {
      const context = await browser.newContext();
      if (pageConfig.emulator) await context.grantPermissions(['local-network-access'], { origin: `http://${origin}` }).catch(() => {});
      const page = await context.newPage();
      await page.route('**/*', (route) => {
        const url = new URL(route.request().url());
        if (url.host === origin) return route.continue();
        if (url.host === 'www.gstatic.com' && url.pathname.startsWith('/firebasejs/12.18.0/')) return route.fulfill({ contentType: 'text/javascript', body: readFileSync(path.resolve(modules, 'firebase', path.basename(url.pathname))) });
        if (!pageConfig.allowHost(url.host)) { counts.blocked++; return route.abort(); }
        if (++counts.http > CAPS.browserHttp) { overCap(); return route.abort(); }
        return route.continue();
      });
      page.on('websocket', (ws) => {
        if (++counts.ws > CAPS.browserWs) overCap();
        for (const kind of ['framesent', 'framereceived']) ws.on(kind, () => { if (++counts.frames > CAPS.browserFrames) overCap(); });
      });
      await page.exposeFunction('__rrEvent', (e) => { const row = Object.fromEntries(Object.entries(e).filter(([, v]) => v !== undefined)); journal.push(row); hooks.event(`${cfg.scenario}:${cfg.name}`, row); });
      await page.exposeFunction('__rrHook', (name) => hooks[name]());
      await page.goto(`http://${origin}/`);
      await page.waitForFunction(() => typeof window.__rrRun === 'function');
      const timeout = new Promise((_, reject) => setTimeout(() => reject(Error('profile timeout')), profileTimeout(cfg)).unref());
      timeout.catch(() => {});
      await Promise.race([page.evaluate((c) => window.__rrRun(c), { ...pageConfig, ...cfg, allowHost: undefined }), capped, timeout]);
      // Evidence of the transport the SDK actually used.
      const transport = { scenario: cfg.scenario, step: 'runner', type: 'transport', code: transportOf(counts) };
      journal.push(transport);
      hooks.event(`${cfg.scenario}:${cfg.name}`, transport);
      return { journal, counts };
    } catch (e) {
      journal.push({ scenario: cfg.scenario, step: 'runner', type: 'error', code: e.message.slice(0, 80) });
      return { journal, counts };
    } finally {
      await browser.close();
      server.close();
    }
  };
}

async function freePort() {
  const s = createNetServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

// result.json first, then journal.json. If either refuses (it would hold a secret), result.json is
// replaced by a minimal record that is never 'closed'. Returns the status written.
export function writeOutputs(out, mode, result, prefixRoot, secrets) {
  const write = (f, text) => writeFileSync(path.join(out, f), assertNoSecrets(text, secrets));
  let refused;
  for (const [f, value] of [['result.json', { ...result, profiles: undefined, prefixRoot }], ['journal.json', { mode, profiles: result.profiles.map((p) => ({ scenario: p.scenario, name: p.name, counts: p.counts, journal: p.journal })) }]]) {
    try { write(f, `${JSON.stringify(value, null, 2)}\n`); } catch { refused ??= f; }
  }
  if (!refused) return result.status;
  writeFileSync(path.join(out, 'result.json'), `${JSON.stringify({ status: 'needs-recovery', outputRefused: refused, resultStatus: result.status, counts: result.counts, unknownAnswers: result.unknownAnswers }, null, 2)}\n`);
  return 'needs-recovery';
}

/** `--scenarios cv08,cv10` and `--transports ws,lp` narrow a local run (the mutation harness uses it). */
export function narrowing(scenarios, transports) {
  const pick = (spec, all, what) => {
    const want = spec.split(',');
    if (!want.length || want.some((w) => !all.includes(w))) throw Error(`${what} must be a comma-separated subset of ${all.join(',')}`);
    return all.filter((a) => want.includes(a));
  };
  return {
    ...(scenarios ? { scenarios: pick(scenarios, SCENARIOS, '--scenarios') } : {}),
    ...(transports ? { profiles: PROFILES.filter((p) => pick(transports, ['ws', 'lp'], '--transports').includes(p.transport)) } : {}),
  };
}

/** Production always runs all eight profiles: narrowing is for local runs. */
export function refuseNarrowing(mode, scenarios, transports) {
  if (mode === 'production' && (scenarios || transports)) throw Error('--scenarios and --transports are for local runs only');
}

async function waitFor(check, what, tries = 150) {
  for (let i = 0; i < tries; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw Error(`${what} did not happen`);
}

async function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] === 'compare') {
    const [a, b] = argv.slice(1, 3).map((f) => sanitizeProfiles(JSON.parse(readFileSync(f)).profiles));
    const r = compareFiles(a, b);
    if (opt('--out')) writeFileSync(opt('--out'), `${JSON.stringify(r, null, 2)}\n`);
    console.log(JSON.stringify({ verdict: r.verdict, match: r.match, timingWithin: r.timing.within, differing: r.profiles.filter((p) => p.verdict !== 'match').map((p) => [p.scenario, p.name, p.verdict]) }));
    return r.match ? 0 : 1;
  }
  const mode = argv[0], out = opt('--out');
  if (!['local', 'production'].includes(mode) || !out) throw Error('usage: local|production --out <new dir> (see the header)');
  refuseNarrowing(mode, opt('--scenarios'), opt('--transports'));
  const packet = mode === 'production' ? verifyPacket(opt('--packet'), opt('--packet-sha256')) : undefined;
  if (packet) verifyBundles(packet);
  mkdirSync(out); // refuses an existing directory
  const secrets = [], stop = { requested: false };
  // Logs are redacted, never refused: a row that cannot be written would hide a sent request.
  const append = (f, row) => appendFileSync(path.join(out, f), `${redact(JSON.stringify(row), secrets).replace(/\n/g, ' ')}\n`);
  // A signal or a crash stops the observation; cleanup then runs once through runScenario's finally.
  const onStop = (why) => { if (!stop.requested) console.error(`rtdb-residual: ${why}: stopping the observation, cleanup continues`); stop.requested = true; stop.closeBrowser?.(); };
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => onStop(signal));
  process.on('unhandledRejection', () => onStop('unhandled rejection'));
  process.on('uncaughtException', () => onStop('uncaught exception'));
  const prefix = `${packet?.prefixRoot ?? 'parity20261027'}/rr${randomBytes(5).toString('hex')}`;
  const common = { prefix, secrets, stop, log: (row) => append('requests.jsonl', row), event: (name, row) => append('events.jsonl', { profile: name, ...row }) };
  let child, official, o;
  try {
    if (mode === 'local') {
      const ns = 'fireemu-q-rtdb2', profile = opt('--profile') ?? 'strict';
      if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
      let db;
      if (argv.includes('--official')) {
        official = await startJar(opt('--jar') ?? DEFAULT_JAR); // the pinned jar: a reference, not a target
        db = `http://${official.host}`;
      } else {
        const [dbPort, httpPort] = [await freePort(), await freePort()];
        const config = path.join(out, 'config.json'), ready = path.join(out, 'ready.json');
        writeFileSync(config, `${JSON.stringify({ schemaVersion: 1, profile, daemon: { authProject: 'demo-rtdb-residual', databasePort: dbPort, httpPort, hubPort: 0, uiPort: 0, loggingPort: 0 } })}\n`);
        child = spawn(opt('--fireemu') ?? 'fireemu', ['up', '--no-config-discovery', '--config', config, '--only', 'database', '--database-port', String(dbPort), '--http-port', String(httpPort), '--hub-port', '0', '--ui-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet', '--ready-file', ready, '--owner-stdin'], { stdio: ['pipe', 'ignore', 'inherit'], detached: true }); // own group: a terminal Ctrl-C reaches only us
        await waitFor(() => existsSync(ready) && readFileSync(ready, 'utf8').length > 0, 'fireemu readiness');
        db = `http://127.0.0.1:${dbPort}`;
      }
      const dbPort = new URL(db).port;
      const browser = browserRunner({ modules: opt('--modules') ?? path.join(here, 'node_modules'), stop, page: { projectId: 'demo-rtdb-residual', databaseURL: `${db}/?ns=${ns}`, emulator: true, allowHost: (h) => h === `127.0.0.1:${dbPort}` } });
      o = { mode, local: { db, ns }, headers: { authorization: 'Bearer owner' }, browser, ...common, ...narrowing(opt('--scenarios'), opt('--transports')) };
    } else {
      const token = execFileSync(packet.gcloud, ADC_ARGS, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000 }).toString().trim();
      if (!/^[\x21-\x7e]{20,4096}$/.test(token)) throw Error('ADC token has an unexpected shape');
      secrets.push(token);
      const browser = browserRunner({ modules: packet.modules, stop, page: { projectId: packet.projectId, databaseURL: `https://${INSTANCE}.firebaseio.com`, allowHost: (h) => /^[a-z0-9-]+\.firebaseio\.com$/.test(h) } });
      o = { mode, packet, headers: productionHeaders(token, packet.projectId), browser, ...common };
    }
    const result = await runScenario(o);
    const status = writeOutputs(out, mode, result, prefix.split('/')[0], secrets);
    console.log(`${mode}: ${status}, observationComplete=${result.observationComplete}`);
    return status === 'closed' && result.observationComplete ? 0 : 3;
  } finally {
    if (child) { child.stdin.end(); try { process.kill(-child.pid, 'SIGTERM'); } catch {} }
    await official?.stop();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`rtdb-residual: ${e.message}`); process.exitCode = 2; });
}
