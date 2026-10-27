// S5 recorder: what does production do with an onDisconnect value that carries `.priority` after a cancel of one of
// its children? (The official emulator drops the whole disconnect update; see rtdb-s5-judge.mjs for the four answers.)
// One scenario (rtdb-s5-page.js: the question and two controls, each on its own writer connection) in two rounds over
// WebSocket, with the firebase 12.18.0 web SDK in headless Chromium, against fireemu or the official emulator
// (local) or the production sandbox (production, packet-gated). It runs next to rtdb-residual.mjs and imports its
// pieces without changing them (that file's digest is pinned by a closure record).
//
//   node rtdb-s5.mjs local --out <new dir> --fireemu <bin> [--profile strict|emulator] [--modules <node_modules>]
//   node rtdb-s5.mjs local --out <new dir> --official [--jar <path>]
//   node rtdb-s5.mjs production --packet <file> --packet-sha256 <hex> --out <new dir>
//   node rtdb-s5.mjs judge <journal.json>
//
// No account, token or key reaches the page: the Rules give the anonymous client its own run prefix. The management
// calls (API, instance, Rules, prefix delete) use the ADC token and never reach an output (assertNoSecrets guards every
// write). Setup and cleanup are those of the residual recorder (rtdb-admin.mjs).
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { adminClient, assertNoSecrets, LAUNCH, redact } from './cv11-genuine-auth.mjs';
import { ADC_ARGS, runPreflight } from './adc-preflight.mjs';
import { DEFAULT_JAR, startJar } from './jar.mjs';
import { createRtdbAdmin, Stop } from './rtdb-admin.mjs';
import { hostRules, productionHeaders, transportOf, verifyBundles, writeOutputs } from './rtdb-residual.mjs';
import { judgeRounds, ROUNDS, SCENARIO, sanitizeProfiles } from './rtdb-s5-judge.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SOURCES = ['rtdb-s5.mjs', 'rtdb-s5-page.js', 'rtdb-s5-judge.mjs', 'rtdb-admin.mjs', 'rtdb-residual.mjs', 'adc-preflight.mjs', 'cv11-genuine-auth.mjs'];
export const PROFILES = ROUNDS.map((name, i) => ({ round: i + 1, transport: 'ws', name }));
// observe/cleanup: admin requests per phase; mutations: admin writes overall; browser caps per profile. The dry run
// needs about 14 observe + 12 cleanup requests (30 with the operation polls); the caps leave room for the propagation retries.
export const CAPS = { observe: 40, cleanup: 24, mutations: 12, pollsPerOperation: 12, browserHttp: 80, browserWs: 16, browserFrames: 800 };
// A profile with a case that did not fire may leave onDisconnect writes pending; the server fires them when it drops the connection.
export const FIRE_GRACE_MS = 150000;
export const PROFILE_TIMEOUT_MS = 300000;
const PROPAGATION_MS = 120000;
const INSTANCE = 'fireemu-q-rtdb2', LOCATION = 'us-central1';
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/** The Rules of one run: the anonymous client owns the run prefix and nothing else. */
export function rulesFor(prefix) {
  const [top, run] = prefix.split('/');
  return { rules: { '.read': false, '.write': false, [top]: { [run]: { '.read': true, '.write': true } } } };
}

const admin = createRtdbAdmin({ instance: INSTANCE, location: LOCATION, caps: CAPS, propagationMs: PROPAGATION_MS, fireGraceMs: FIRE_GRACE_MS, rulesFor });
export const { urls } = admin;
const { setupProduction, installRules, cleanup } = admin;

/** True when a case did not fire although it had to: its onDisconnect writes may still be pending. */
const unfired = (journal) => journal.some((e) => e.type === 'timeout');

async function runProfile(run, o, prof) {
  const cfg = { ...prof, scenario: SCENARIO, base: `${o.prefix}/${SCENARIO}/${prof.name}` };
  const out = await o.browser(cfg, { event: o.event ?? (() => {}) });
  if (unfired(out.journal)) run.fireWait = true;
  return { scenario: SCENARIO, name: prof.name, ...out };
}

// Runs setup, the two rounds and cleanup. The status is 'closed' only when nothing is unknown and every owned
// resource read back at its starting state; otherwise 'needs-recovery'.
export async function runScenario(o) {
  o.secrets ??= [];
  const client = adminClient({ fetchImpl: o.fetchImpl, headers: o.headers, log: o.log, stop: o.stop, secrets: o.secrets, caps: CAPS });
  const run = { admin: client, call: client.call, u: urls(o), propagation: false, propagationWaited: 0, state: { api: 'baseline', instance: 'baseline', rules: 'baseline', data: 'baseline' }, unresolved: [], errors: [], fireWait: false };
  const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  run.sleep = sleep;
  const profiles = [];
  try {
    if (o.mode === 'production') await setupProduction(run, sleep);
    await installRules(run, o);
    run.propagation = false;
    for (const prof of PROFILES) {
      if (run.errors.length || o.stop?.requested) break;
      profiles.push(await runProfile(run, o, prof));
    }
  } catch (e) {
    run.errors.push(e instanceof Stop ? e.message : `unexpected: ${e?.message}`);
  } finally {
    run.propagation = false;
    await cleanup(run, o, sleep);
  }
  const restored = Object.values(run.state).every((s) => s === 'baseline');
  // An unexpected error or an unwritten log row means a sent request may be unaccounted for.
  const accounted = client.counts.logFailures === 0 && !run.errors.some((e) => e.startsWith('unexpected'));
  return { status: run.unresolved.length === 0 && restored && accounted ? 'closed' : 'needs-recovery', unknownAnswers: client.unknownAnswers, observationComplete: profiles.length === PROFILES.length && !run.errors.length, profiles, state: run.state, unresolved: run.unresolved, errors: run.errors, counts: client.counts };
}

/** The packet pins the sources this recorder is made of. */
export function verifyPacket(file, expected) {
  if (!file || !expected) throw Error('production needs --packet <file> and --packet-sha256 <hex>');
  const raw = readFileSync(file);
  if (sha256(raw) !== expected) throw Error('packet SHA-256 does not match --packet-sha256');
  const packet = JSON.parse(raw);
  for (const s of SOURCES) if (packet.sources?.[s] !== sha256(readFileSync(path.join(here, s)))) throw Error(`source pin differs: ${s}`);
  return packet;
}

// One profile in headless Chromium. The page and SDK bundles are served from loopback; HTTP requests, WebSockets and
// WebSocket frames are counted against the caps, and Chromium itself resolves nothing but loopback and Firebase hosts.
export function browserRunner({ modules, page: pageConfig, stop = {} }) {
  const require = createRequire(path.join(path.resolve(modules), 'x.js'));
  const { chromium } = require('playwright');
  return async (cfg, hooks) => {
    const server = createServer((req, res) => {
      const file = req.url === '/page.js' ? path.join(here, 'rtdb-s5-page.js') : null;
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
      await page.exposeFunction('__s5Event', (e) => { const row = Object.fromEntries(Object.entries(e).filter(([, v]) => v !== undefined)); journal.push(row); hooks.event(`${cfg.scenario}:${cfg.name}`, row); });
      await page.goto(`http://${origin}/`);
      await page.waitForFunction(() => typeof window.__s5Run === 'function');
      const timeout = new Promise((_, reject) => setTimeout(() => reject(Error('profile timeout')), PROFILE_TIMEOUT_MS).unref());
      timeout.catch(() => {});
      await Promise.race([page.evaluate((c) => window.__s5Run(c), { ...pageConfig, ...cfg, allowHost: undefined }), capped, timeout]);
      // Evidence of the transport the SDK actually used (a WebSocket must have been opened).
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

async function waitFor(check, what, tries = 150) {
  for (let i = 0; i < tries; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw Error(`${what} did not happen`);
}

async function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] === 'judge') {
    const verdict = judgeRounds(sanitizeProfiles(JSON.parse(readFileSync(argv[1])).profiles));
    console.log(JSON.stringify(verdict));
    return ['A', 'B', 'C', 'D'].includes(verdict.verdict) ? 0 : 1;
  }
  const mode = argv[0], out = opt('--out');
  if (!['local', 'production'].includes(mode) || !out) throw Error('usage: local|production --out <new dir> (see the header)');
  const packet = mode === 'production' ? verifyPacket(opt('--packet'), opt('--packet-sha256')) : undefined;
  if (packet) verifyBundles(packet);
  mkdirSync(out); // refuses an existing directory
  const secrets = [], stop = { requested: false };
  // Logs are redacted, never refused: a row that cannot be written would hide a sent request.
  const append = (f, row) => appendFileSync(path.join(out, f), `${redact(JSON.stringify(row), secrets).replace(/\n/g, ' ')}\n`);
  // A signal or a crash stops the observation; cleanup then runs once through runScenario's finally.
  const onStop = (why) => { if (!stop.requested) console.error(`rtdb-s5: ${why}: stopping the observation, cleanup continues`); stop.requested = true; stop.closeBrowser?.(); };
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => onStop(signal));
  process.on('unhandledRejection', () => onStop('unhandled rejection'));
  process.on('uncaughtException', () => onStop('uncaught exception'));
  const prefix = `${packet?.prefixRoot ?? 'parity20261027'}/s5${randomBytes(5).toString('hex')}`;
  const common = { prefix, secrets, stop, log: (row) => append('requests.jsonl', row), event: (name, row) => append('events.jsonl', { profile: name, ...row }) };
  let child, official, o;
  try {
    if (mode === 'local') {
      const ns = INSTANCE, profile = opt('--profile') ?? 'strict';
      if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
      let db;
      if (argv.includes('--official')) {
        official = await startJar(opt('--jar') ?? DEFAULT_JAR); // the pinned jar: a reference, not a target
        db = `http://${official.host}`;
      } else {
        const [dbPort, httpPort] = [await freePort(), await freePort()];
        const config = path.join(out, 'config.json'), ready = path.join(out, 'ready.json');
        writeFileSync(config, `${JSON.stringify({ schemaVersion: 1, profile, daemon: { authProject: 'demo-rtdb-s5', databasePort: dbPort, httpPort, hubPort: 0, uiPort: 0, loggingPort: 0 } })}\n`);
        child = spawn(opt('--fireemu') ?? 'fireemu', ['up', '--no-config-discovery', '--config', config, '--only', 'database', '--database-port', String(dbPort), '--http-port', String(httpPort), '--hub-port', '0', '--ui-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet', '--ready-file', ready, '--owner-stdin'], { stdio: ['pipe', 'ignore', 'inherit'], detached: true }); // own group: a terminal Ctrl-C reaches only us
        await waitFor(() => existsSync(ready) && readFileSync(ready, 'utf8').length > 0, 'fireemu readiness');
        db = `http://127.0.0.1:${dbPort}`;
      }
      const dbPort = new URL(db).port;
      const browser = browserRunner({ modules: opt('--modules') ?? path.join(here, 'node_modules'), stop, page: { projectId: 'demo-rtdb-s5', databaseURL: `${db}/?ns=${ns}`, emulator: true, allowHost: (h) => h === `127.0.0.1:${dbPort}` } });
      o = { mode, local: { db, ns }, headers: { authorization: 'Bearer owner' }, browser, ...common };
    } else {
      const token = execFileSync(packet.gcloud, ADC_ARGS, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 60000 }).toString().trim();
      if (!/^[\x21-\x7e]{20,4096}$/.test(token)) throw Error('ADC token has an unexpected shape');
      secrets.push(token);
      const stopped = await runPreflight(out, token, fetch, (text) => assertNoSecrets(text, secrets));
      if (stopped) return stopped;
      const browser = browserRunner({ modules: packet.modules, stop, page: { projectId: packet.projectId, databaseURL: `https://${INSTANCE}.firebaseio.com`, allowHost: (h) => /^[a-z0-9-]+\.firebaseio\.com$/.test(h) } });
      o = { mode, packet, headers: productionHeaders(token, packet.projectId), browser, ...common };
    }
    const result = await runScenario(o);
    const status = writeOutputs(out, mode, result, prefix.split('/')[0], secrets);
    const verdict = judgeRounds(sanitizeProfiles(result.profiles));
    console.log(`${mode}: ${status}, observationComplete=${result.observationComplete}, answer=${verdict.verdict}`);
    return status === 'closed' && result.observationComplete ? 0 : 3;
  } finally {
    if (child) { child.stdin.end(); try { process.kill(-child.pid, 'SIGTERM'); } catch {} }
    await official?.stop();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`rtdb-s5: ${e.message}`); process.exitCode = 2; });
}
