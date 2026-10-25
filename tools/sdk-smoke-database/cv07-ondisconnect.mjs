// CV07: the anonymous web SDK onDisconnect lifecycle over WebSocket and long polling, replayed
// against a local fireemu and compared with the production recording.
//
//   node tools/sdk-smoke-database/cv07-ondisconnect.mjs local --fireemu <binary> --out <new dir> [--modules <node_modules>]
//   node tools/sdk-smoke-database/cv07-ondisconnect.mjs fixture <production sdk-events.jsonl> <fixture.json>
//
// `local` starts `fireemu up --only auth,database` in the strict profile on free loopback ports,
// installs the Rules the production instance had, runs the production scenario (`sdkScenario` in
// production-live.mjs, unchanged) in headless Chromium for the four flows (round 1 and 2,
// WebSocket then long polling) and stops the server. It writes `result.json`: the 36 durable SDK
// events projected on the eight comparison keys, the ordered comparison with the fixture, and the
// onDisconnect fire delay of each flow in seconds (0.1 s). Raw millisecond timings are not kept.
// `fixture` rebuilds fixtures/production-sdk-ondisconnect.json from the private recording.
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { createRequire } from 'node:module';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { sdkScenario } from './production-live.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE = './fixtures/production-sdk-ondisconnect.json';
export const KEYS = ['type', 'step', 'value', 'code', 'message', 'name', 'prefix', 'transport'];
export const PREFIXES = ['parity20261023/sdk/round1/ws', 'parity20261023/sdk/round1/lp', 'parity20261023/sdk/round2/ws', 'parity20261023/sdk/round2/lp'];
// The production instance name; the local server serves it as a namespace (`?ns=`).
export const NAMESPACE = 'fireemu-q-rtdb2';
export const RULES = { rules: { '.read': false, '.write': false, parity20261023: { sdk: { '.read': true, '.write': true } } } };
// A WebSocket onDisconnect fires as the socket closes; a long-polling one fires when the server
// drops the idle connection (production: 100.8 s and 104.0 s). Timing is a tolerance, not a match.
export const WS_FIRE_MAX_SECONDS = 2;
export const LP_TOLERANCE_SECONDS = 5;
const APP_URL = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js';
const DATABASE_URL = 'https://www.gstatic.com/firebasejs/12.18.0/firebase-database.js';

export const projectEvent = (event) => Object.fromEntries(KEYS.filter((k) => k in event).map((k) => [k, event[k]]));

/** Ordered comparison of the projected events: every index must be equal, and the lengths too. */
export function compareEvents(native, local) {
  const mismatches = [];
  for (let i = 0; i < Math.max(native.length, local.length); i++) {
    if (JSON.stringify(native[i]) !== JSON.stringify(local[i])) mismatches.push({ index: i, native: native[i] ?? null, local: local[i] ?? null });
  }
  return { matched: mismatches.length === 0, mismatches };
}

/** Seconds (0.1 s) from each flow's writer-offline step to the observer's next callback. */
export function fireDelays(events) {
  const delays = {};
  const offline = new Map();
  for (const e of events) {
    if (e.type === 'sdk-step' && e.step === 'writer-offline') { offline.set(e.prefix, e.ms); delays[e.prefix] = null; }
    else if (e.type === 'sdk-callback' && offline.has(e.prefix)) { delays[e.prefix] = Math.round((e.ms - offline.get(e.prefix)) / 100) / 10; offline.delete(e.prefix); }
  }
  return delays;
}

/** WebSocket flows fire within WS_FIRE_MAX_SECONDS; long-polling flows within the tolerance around production's range. */
export function timingJudgement(local, production) {
  const lp = PREFIXES.filter((p) => p.endsWith('/lp')).map((p) => production[p]);
  const [low, high] = [Math.min(...lp) - LP_TOLERANCE_SECONDS, Math.max(...lp) + LP_TOLERANCE_SECONDS];
  const outside = [];
  for (const prefix of PREFIXES) {
    const seconds = local[prefix];
    const ok = typeof seconds === 'number' && (prefix.endsWith('/ws') ? seconds >= 0 && seconds <= WS_FIRE_MAX_SECONDS : seconds >= low && seconds <= high);
    if (!ok) outside.push({ prefix, seconds: seconds ?? null });
  }
  return { within: outside.length === 0, outside };
}

/** The result kept as evidence: projections, comparison and rounded fire delays only. */
export function sanitizeResult({ local, native, fire, nativeFire }) {
  const projected = local.filter((e) => e.type.startsWith('sdk-') || e.type === 'page-error').map(projectEvent);
  const comparison = compareEvents(native, projected);
  return {
    nativeEvents: native.length,
    localEvents: projected.length,
    matched: comparison.matched,
    mismatches: comparison.mismatches,
    onDisconnectFireSeconds: { local: fire, production: nativeFire },
    timing: timingJudgement(fire, nativeFire),
    events: projected,
  };
}

/** The fixture from the private production journal: projected sdk-* events and fire delays. */
export function fixtureFromRecording(lines) {
  const raw = lines.map((line) => JSON.parse(line)).filter((e) => e.type.startsWith('sdk-'));
  return {
    recording: 'rtdb-sdk03-v1',
    recordedOn: '2026-10-23',
    project: 'fireemu-oracle-query',
    instance: NAMESPACE,
    sdk: 'firebase 12.18.0 (web, headless Chromium)',
    keys: KEYS,
    onDisconnectFireSeconds: fireDelays(raw.map((e) => ({ ...e, ms: e.monotonicMs }))),
    events: raw.map(projectEvent),
  };
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
  });
}

async function runBrowser({ modules, origin, databaseURL }) {
  const appBytes = readFileSync(path.join(modules, 'firebase/firebase-app.js'));
  const dbBytes = readFileSync(path.join(modules, 'firebase/firebase-database.js'));
  const { chromium } = createRequire(path.join(modules, 'playwright/package.json'))('playwright');
  const events = [];
  const t0 = performance.now();
  const browser = await chromium.launch({ headless: true, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false });
  try {
    for (const [i, prefix] of PREFIXES.entries()) {
      const transport = i % 2 ? 'lp' : 'ws';
      const context = await browser.newContext({ serviceWorkers: 'block' });
      try {
        await context.grantPermissions(['local-network-access'], { origin });
        const page = await context.newPage();
        page.on('pageerror', (error) => events.push({ type: 'page-error', message: error.message, prefix, transport, ms: performance.now() - t0 }));
        await page.exposeFunction('__probeRecord', (event) => { events.push({ ...event, prefix, transport, ms: performance.now() - t0 }); });
        await page.route('**/*', async (route) => {
          const url = route.request().url();
          if (url === origin) return route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><html><head><link rel="icon" href="data:,"></head><body></body></html>' });
          if (url === APP_URL || url === DATABASE_URL) return route.fulfill({ status: 200, headers: { 'access-control-allow-origin': '*' }, contentType: 'text/javascript', body: url === APP_URL ? appBytes : dbBytes });
          if (!url.startsWith(origin)) return route.abort('blockedbyclient');
          return route.continue();
        });
        await page.goto(origin, { waitUntil: 'load' });
        await page.evaluate(sdkScenario, { appUrl: APP_URL, databaseUrl: DATABASE_URL, config: { projectId: 'demo-rtdb-prodcompare', databaseURL }, prefix, transport });
      } finally {
        await context.close();
      }
    }
  } finally {
    await browser.close();
  }
  return events;
}

async function waitFor(check, what, tries = 150) {
  for (let i = 0; i < tries; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw Error(`${what} did not happen`);
}

async function runLocal({ fireemu, modules, out }) {
  mkdirSync(out); // refuses an existing directory
  const [dbPort, httpPort] = [await freePort(), await freePort()];
  const config = path.join(out, 'config.json');
  writeFileSync(config, `${JSON.stringify({ schemaVersion: 1, profile: 'strict', daemon: { authProject: 'demo-rtdb-prodcompare', databasePort: dbPort, httpPort, hubPort: 0, uiPort: 0, loggingPort: 0 } })}\n`);
  const ready = path.join(out, 'ready.json');
  const child = spawn(fireemu, ['up', '--no-config-discovery', '--config', config, '--only', 'auth,database', '--database-port', String(dbPort), '--http-port', String(httpPort), '--hub-port', '0', '--ui-port', '0', '--logging-port', '0', '--ready-file', ready, '--owner-stdin'], { stdio: ['pipe', 'ignore', 'inherit'], detached: true });
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  try {
    await waitFor(() => existsSync(ready) && readFileSync(ready, 'utf8').length > 0, 'fireemu readiness');
    const origin = `http://127.0.0.1:${dbPort}/`;
    const rules = await fetch(`${origin}.settings/rules.json?ns=${NAMESPACE}`, { method: 'PUT', headers: { authorization: 'Bearer owner' }, body: JSON.stringify(RULES) });
    if (rules.status !== 200) throw Error(`installing the Rules answered ${rules.status}`);
    const events = await runBrowser({ modules, origin, databaseURL: `${origin}?ns=${NAMESPACE}` });
    const fixture = JSON.parse(readFileSync(new URL(FIXTURE, import.meta.url), 'utf8'));
    return sanitizeResult({ local: events, native: fixture.events, fire: fireDelays(events), nativeFire: fixture.onDisconnectFireSeconds });
  } finally {
    child.stdin.end(); // --owner-stdin: closing stdin stops the server
    const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }, 10000);
    const status = await exited;
    clearTimeout(timer);
    console.error(`fireemu exited (${status.code ?? status.signal})`);
  }
}

async function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] === 'fixture') {
    const [input, output] = argv.slice(1);
    const fixture = fixtureFromRecording(readFileSync(input, 'utf8').trim().split('\n'));
    writeFileSync(output, `${JSON.stringify(fixture, null, 1)}\n`);
    return 0;
  }
  if (argv[0] !== 'local' || !opt('--out') || !opt('--fireemu')) throw Error('usage: local --fireemu <binary> --out <new dir> [--modules <dir>] | fixture <jsonl> <json>');
  const out = opt('--out');
  const result = await runLocal({ fireemu: opt('--fireemu'), modules: opt('--modules') ?? path.join(here, 'node_modules'), out });
  writeFileSync(path.join(out, 'result.json'), `${JSON.stringify(result, null, 1)}\n`);
  console.log(JSON.stringify({ nativeEvents: result.nativeEvents, localEvents: result.localEvents, matched: result.matched, mismatches: result.mismatches.length, timing: result.timing, onDisconnectFireSeconds: result.onDisconnectFireSeconds.local }));
  return result.matched && result.timing.within ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`cv07: ${e.message}`); process.exitCode = 2; });
}
