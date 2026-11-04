#!/usr/bin/env node
// RTDB SDK small observer (owner decision 2026-11-02, replaces the gen2 harness): 4 profiles (r1/r2 x ws/lp) x 8 cases against one RTDB, talking to it directly.
// Suites (--suite, default small): small (the recorded RTDB-SMALL cases), events (G6: listener events and queries, 4 profiles x 8 cases),
// admin (G13: firebase-admin over WebSocket, 2 rounds x 10 cases), events+admin (both in one run, one ADC token),
// rest (G7, packet 2: plain REST requests through the admin REST path, 2 rounds x 72 cases, no SDK, no browser).
//   node --max-old-space-size=1024 observer.mjs --target production|emulator [--suite small|events|admin|events+admin|rest] --run-id ID --prefix /p --direct-cap N --out <new dir> [--production-config <file>] [--continue-on-failure] | --print-manifest
// The SDK comes from the parent package (tools/sdk-smoke-database/node_modules). --production-config names a file outside the
// repository with the private inputs: principalSha256, legacyPacket, runtimeProposal and paths {owner, lease, recording}.
// Restoration (prefix delete, Rules back byte-equal) runs in `finally`; the ledgers are never written by this script.
// Contract: the observer never re-sends its own admin requests. The SDK does resend its own outstanding writes after a reconnect (observed behaviour, not prevented); the cleanup deletes whatever they leave under the prefix.
import { readFileSync, existsSync, mkdirSync, openSync, writeSync, closeSync, constants } from 'node:fs';
import { createServer } from 'node:http';
import { isDeepStrictEqual } from 'node:util';
import { getHeapStatistics } from 'node:v8';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adcVerdict, checkApproval, claim, clip, createAdmin, createCounter, createJournal, mintToken, scriptManifest, sha256, targetUrls, writeAll } from './lib.mjs';
import { CASE_ORDER, runCases, withTimeout } from './sequence.mjs';
import { readback } from './readback.mjs';
import { packetRules } from './rules.mjs';
import { ADMIN_PROFILES, EVENTS_PROFILES, SUITE_AREAS, suiteRules } from './events-rules.mjs';
import { EVENT_CASES } from './events-actor.mjs';
import { ADMIN_CASES } from './admin-suite.mjs';
import { REST_AREA, REST_CASES, REST_PROFILES, restRules, runRestProfile } from './rest-suite.mjs';
import tls from 'node:tls';
import net from 'node:net';

const HERE = path.dirname(fileURLToPath(import.meta.url)), MODULES = path.resolve(HERE, '../node_modules');
export const PROFILES = [[1, 'ws'], [1, 'lp'], [2, 'ws'], [2, 'lp']];
// The suites: profile order, the cases each profile must finish, approval basis (owner ledger row) and the direct cap range.
const eventsPlan = EVENTS_PROFILES.map(name => ({ name, suite: 'events', transport: name.slice(3) }));
const adminPlan = ADMIN_PROFILES.map(name => ({ name, suite: 'admin', transport: 'admin' }));
const restPlan = REST_PROFILES.map(name => ({ name, suite: 'rest', transport: 'rest' }));
export const SUITES = {
  small: { parts: ['small'], basis: '2196', capMax: 180, plan: PROFILES.map(([round, transport]) => ({ name: `r${round}-${transport}`, suite: 'small', transport })), profileMs: 90000, runMs: 600000 },
  events: { parts: ['events'], basis: '2217', capMax: 250, plan: eventsPlan, profileMs: 150000, runMs: 900000 },
  admin: { parts: ['admin'], basis: '2217', capMax: 250, plan: adminPlan, profileMs: 200000, runMs: 900000 },
  'events+admin': { parts: ['events', 'admin'], basis: '2217', capMax: 250, plan: [...eventsPlan, ...adminPlan], profileMs: 200000, runMs: 900000 },
  rest: { parts: ['rest'], basis: '2217', capMax: 250, plan: restPlan, profileMs: 120000, runMs: 360000 },   // 72 requests per profile, 10 s timeout each, a transport failure stops the profile
};
const SUITE_CASES = { small: null, events: EVENT_CASES, admin: ADMIN_CASES, rest: REST_CASES };
const AREAS = { small: 'sdk-next', ...SUITE_AREAS, rest: REST_AREA };
/** The process backstop: above the suite's run deadline plus the bounded cleanup (small: 12 min as before). */
export const backstopMs = suite => (Object.hasOwn(SUITES, suite) ? SUITES[suite].runMs : SUITES.small.runMs) + 2 * 60 * 1000;
/** How many case rows a finished run of the suite holds. */
export const expectedObservations = suite => SUITES[suite].plan.reduce((n, p) => n + (p.suite === 'small' ? CASE_ORDER.length : SUITE_CASES[p.suite].length), 0);
const PINS = { firebase: ['firebase', '12.18.0'], database: ['@firebase/database', '1.1.5'], playwright: ['playwright', '1.62.1'] };
const PRODUCTION = { kind: 'production', projectId: 'fireemu-oracle-query', namespace: 'fireemu-q-rtdb2', region: 'us-central1' };
/** The private production inputs: exactly these fields, absolute paths. */
export function productionConfig(doc) {
  const paths = doc?.paths, abs = v => typeof v === 'string' && path.isAbsolute(v);
  if (!doc || Object.keys(doc).sort().join() !== 'legacyPacket,paths,principalSha256,runtimeProposal' || !/^[a-f0-9]{64}$/.test(doc.principalSha256 ?? '') || !abs(doc.legacyPacket) || !abs(doc.runtimeProposal)
    || !paths || Object.keys(paths).sort().join() !== 'lease,owner,recording' || !Object.values(paths).every(abs)) throw new Error('--production-config: principalSha256, legacyPacket, runtimeProposal, paths {owner, lease, recording}');
  return { ...PRODUCTION, principalSha256: doc.principalSha256, legacyPacket: doc.legacyPacket, runtimeProposal: doc.runtimeProposal, paths: { ...paths } };
}
export const writeNew = (file, text, write = writeSync) => { const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); try { writeAll(fd, text, write); } finally { closeSync(fd); } };
const ADMIN_PIN = ['firebase-admin', '14.3.0'];
/** The installed Admin SDK version (only the admin suites use it; the small result keeps its recorded `sdk` members). */
export const adminVersion = (modules = MODULES) => JSON.parse(readFileSync(path.join(modules, ADMIN_PIN[0], 'package.json'), 'utf8')).version;
/** Refuses a run whose installed SDKs are not the pinned ones; the Admin SDK only when the suite uses it. */
export function checkSdkPins(suite, modules = MODULES) {
  for (const [, [pkg, version]] of Object.entries(PINS)) if (JSON.parse(readFileSync(path.join(modules, pkg, 'package.json'), 'utf8')).version !== version) throw new Error(`${pkg} is not ${version}`);
  if (SUITES[suite].parts.includes('admin') && adminVersion(modules) !== ADMIN_PIN[1]) throw new Error(`${ADMIN_PIN[0]} is not ${ADMIN_PIN[1]}`);
}
export const sdkVersions = () => Object.fromEntries(Object.entries(PINS).map(([k, [pkg]]) => [k, JSON.parse(readFileSync(path.join(MODULES, pkg, 'package.json'), 'utf8')).version]));

// ---- profiles --------------------------------------------------------------------------------------------------------------------------------
let wsJournal = null, wsAttempt = () => {};
// Passive: counts every socket the SDK creates (before it dials), and records send and the events faye-websocket dispatches to the SDK. Nothing is routed or changed.
// Must run before firebase/database is imported: the SDK keeps the Client it finds on the module at import time.
export async function captureWs(journal, attempt) {
  wsJournal = journal; wsAttempt = attempt;
  const { default: Ws } = await import('faye-websocket'), Base = Ws.Client;
  if (Base.captured) return;
  const ids = new WeakMap(); let n = 0; const conn = s => { if (!ids.has(s)) ids.set(s, ++n); return ids.get(s); };
  class Counted extends Base {
    static captured = true;
    constructor(...args) { wsAttempt(); super(...args); }
    send(data) { wsJournal?.write({ kind: 'raw-ws', dir: 'out', conn: conn(this), data: clip(String(data)) }, { optional: true }); return super.send(data); }
    dispatchEvent(event) { if (event?.type) wsJournal?.write({ kind: 'raw-ws', dir: 'in', conn: conn(this), type: event.type, data: event.type === 'message' ? clip(String(event.data)) : undefined }, { optional: true }); return super.dispatchEvent(event); }
  }
  Ws.Client = Counted;
}
async function wsProfile(ctx) {
  await captureWs(ctx.journal, () => { try { ctx.counter.take('ws-attempt'); } catch (error) { ctx.abort(error.message); throw error; } });
  const A = await import('firebase/app'), D = await import('firebase/database'), { createActor } = await import('./actor.mjs');
  if (ctx.cancelled) throw new Error('cancelled');
  const actors = {};
  for (const role of ['writer', 'observer']) {
    actors[role] = createActor({ projectId: ctx.projectId, databaseURL: ctx.databaseURL, scope: ctx.scope, transport: 'ws', role, local: ctx.local }, D, A);
    const db = D.getDatabase(A.getApp(`packet-${role}`));
    ctx.closers.push(async () => { D.goOffline(db); await actors[role].close(); });
    D.onValue(D.ref(db, '.info/connected'), s => ctx.journal.write({ kind: 'sdk-event', profile: ctx.profile, role, event: s.val() ? 'connected' : 'disconnected' }));
  }
  return runCases(actors, { caseMs: ctx.caseMs, onCase: row => ctx.journal.write({ kind: 'case', profile: ctx.profile, ...row }) });
}
/**
 * Browser traffic (long-polling requests and the page's WebSocket) is counted when Chromium reports it, which is after it left.
 * Nothing is routed (owner 2196), so the cap of browser traffic is stop-on-detection, not a hard pre-dispatch cap: once
 * `direct >= cap - margin` the run is aborted and the page closed, and the requests already in flight, plus any the SDK
 * issues before the page is gone (its 25 s keepalive re-polls without cancelling the old request, a writer reconnect
 * after the transport switch can open a third long-polling connection, completions during a slow close trigger
 * replacements), can still arrive. Every request is still charged with the hard cap, and one over it is recorded in
 * `overflow`. The margin (16 since packet 2, was 8) is headroom for that, not a proof.
 */
export const BROWSER_MARGIN = 16;
export function watchBrowserTraffic(page, ctx, isDb, margin = BROWSER_MARGIN) {
  let inFlight = 0, maxInFlight = 0, stopped = false;
  const open = () => { inFlight += 1; maxInFlight = Math.max(maxInFlight, inFlight); }, shut = () => { inFlight = Math.max(0, inFlight - 1); };
  const stop = reason => { if (stopped) return; stopped = true; ctx.abort(reason); void page.close().catch(() => {}); };
  const charge = label => {
    try { ctx.counter.take(label); } catch (error) { ctx.counter.overflow(); stop(error.message); return; }
    const { direct } = ctx.counter.used(), cap = ctx.counter.caps().direct;
    if (direct >= cap - margin) stop(`browser traffic stopped at the margin: direct ${direct} of cap ${cap} (margin ${margin})`);
  };
  const note = row => { try { ctx.journal.write({ ...row, profile: ctx.profile }, { optional: true }); } catch { /* journal full: the count is what matters */ } };
  page.on('request', request => {
    if (!isDb(request.url())) return;
    open(); charge('lp-request');
    note({ kind: 'raw-lp-request', method: request.method(), url: request.url(), body: request.postData() ? clip(request.postData()) : null });
  });
  page.on('requestfinished', request => { if (isDb(request.url())) shut(); });
  page.on('requestfailed', request => { if (isDb(request.url())) shut(); });
  page.on('websocket', socket => {   // the events suite's writer connects over WebSocket from the page
    if (!isDb(socket.url())) return;
    open(); charge('page-ws'); socket.on('close', shut);
    note({ kind: 'raw-page-ws', url: socket.url() });
  });
  return { stats: () => ({ maxInFlight, inFlight, stopped }) };
}
const SERVED = { '/page.mjs': 'page.mjs', '/sequence.mjs': 'sequence.mjs', '/actor.mjs': 'actor.mjs' };
const EVENTS_PAGE = { html: 'events-page.html', served: { '/events-page.mjs': 'events-page.mjs', '/events-sequence.mjs': 'events-sequence.mjs', '/events-actor.mjs': 'events-actor.mjs', '/sequence.mjs': 'sequence.mjs' } };
export async function lpProfile(ctx, pageFiles = { html: 'page.html', served: SERVED }, invoke = (page, cfg) => page.evaluate(c => window.__run(c), cfg)) {
  const { chromium } = await import('playwright'), mod = path.join(MODULES, 'firebase');
  const server = createServer((req, res) => {
    const served = pageFiles.served, p = new URL(req.url, 'http://x').pathname, file = p === '/' ? path.join(HERE, pageFiles.html) : Object.hasOwn(served, p) ? path.join(HERE, served[p]) : /^\/firebase-(app|database)\.js$/.test(p) ? path.join(mod, p.slice(1)) : null;
    if (!file) { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'content-type': file.endsWith('.html') ? 'text/html' : 'text/javascript' }).end(readFileSync(file));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  ctx.closers.push(async () => { server.close(); server.closeAllConnections?.(); });
  const alive = () => { if (ctx.cancelled) throw new Error('cancelled'); };   // the profile may finish starting after its deadline: it then stops by itself, run() closes what it registered
  alive();
  {
    const dbHost = ctx.local ? ctx.target.host : '*.firebaseio.com', isDb = url => { try { const h = new URL(url); return ctx.local ? h.host === ctx.target.host : h.hostname.endsWith('.firebaseio.com'); } catch { return false; } };
    const browser = await chromium.launch({ headless: true, args: [`--host-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ${dbHost.replace(/:\d+$/, '')}`] });
    ctx.closers.push(() => browser.close()); alive();
    const page = await browser.newPage(); alive();
    await page.exposeFunction('__emit', row => { try { ctx.journal.write({ ...row, profile: ctx.profile }); } catch { /* journal full: the result still comes back */ } });
    page.on('pageerror', error => ctx.journal.write({ kind: 'page-error', profile: ctx.profile, error: clip(String(error), 2000) }));
    const watch = watchBrowserTraffic(page, ctx, isDb, ctx.browserMargin ?? BROWSER_MARGIN); alive();   // counts what the page sends and stops it at the margin below the cap
    ctx.closers.push(async () => { try { ctx.journal.write({ kind: 'lp-inflight', profile: ctx.profile, ...watch.stats() }, { optional: true }); } catch { /* journal full */ } });
    page.on('response', async response => {
      if (!isDb(response.url())) return;
      const body = await withTimeout(3000, 'lp-body', response.text()).catch(() => null);
      ctx.journal.write({ kind: 'raw-lp-response', profile: ctx.profile, status: response.status(), url: response.url(), body: body === null ? null : clip(body) }, { optional: true });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/`); alive();
    await page.waitForFunction(() => window.__ready === true, null, { timeout: 15000 }); alive();
    return await invoke(page, { projectId: ctx.projectId, databaseURL: ctx.databaseURL, scope: ctx.scope, transport: 'lp', local: ctx.local, caseMs: ctx.caseMs, closeMs: ctx.closeMs, name: ctx.profile });
  }
}
const realProfiles = { ws: wsProfile, lp: lpProfile };

// ---- events (G6) and admin (G13) profiles ------------------------------------------------------------------------------------------------
const eventsCfg = ctx => ({ projectId: ctx.projectId, databaseURL: ctx.databaseURL, scope: ctx.scope, transport: ctx.transport, local: ctx.local, name: ctx.profile, closeMs: ctx.closeMs });
export async function eventsWsProfile(ctx) {
  await captureWs(ctx.journal, () => { try { ctx.counter.take('ws-attempt'); } catch (error) { ctx.abort(error.message); throw error; } });
  const A = await import('firebase/app'), D = await import('firebase/database'), { runEventsProfile } = await import('./events-sequence.mjs');
  if (ctx.cancelled) throw new Error('cancelled');
  return runEventsProfile({ D, A, cfg: eventsCfg(ctx), emit: row => ctx.journal.write({ ...row, profile: ctx.profile }), onApp: (app, db) => ctx.closers.push(eventsAppCloser(D, A, app, db)) });
}
/** The closer of one events app: offline, then deleted (the recorder's own `finally` normally deleted it already). */
export const eventsAppCloser = (D, A, app, db) => async () => { if (!app.isDeleted) { try { D.goOffline(db); } catch { /* deleted meanwhile */ } } await A.deleteApp(app).catch(() => {}); };   // goOffline on a deleted database logs FIREBASE FATAL ERROR (packet 2 B2)
export const eventsLpProfile = ctx => lpProfile(ctx, EVENTS_PAGE, (page, cfg) => page.evaluate(c => window.__runEvents(c), cfg));
/** The endpoint a tls.connect / net.connect call dials: (options[, cb]) or (port[, host][, options][, cb]). */
export function endpointOf(args) {
  const [a, b] = args;
  if (a && typeof a === 'object') return { host: String(a.host ?? a.servername ?? 'localhost'), port: Number(a.port) };
  return { host: typeof b === 'string' ? b : 'localhost', port: Number(a) };
}
/**
 * Passive counter of the Admin SDK's sockets: the Admin SDK bundles its own faye-websocket (database-compat/standalone),
 * which captureWs cannot see, so every tls.connect / net.connect to the database host made while an admin profile runs
 * is counted before it dials (`take` throws over the cap: nothing is dialled). No other code of this process dials the
 * database during an admin profile (the observer's own admin REST runs before and after the profiles). Returns the restore.
 */
export function countConnects(isDb, take, journal) {
  const original = { tls: tls.connect, net: net.connect };
  const wrap = (kind, real) => function connect(...args) { const at = endpointOf(args); if (isDb(at)) { take(); journal?.write({ kind: 'raw-admin-connect', via: kind, host: at.host, port: at.port }, { optional: true }); } return real.apply(this, args); };
  tls.connect = wrap('tls', original.tls); net.connect = wrap('net', original.net);
  return () => { tls.connect = original.tls; net.connect = original.net; };
}
async function adminProfile(ctx) {
  const isDb = ctx.local ? at => `${at.host}:${at.port}` === ctx.target.host : at => at.host.endsWith('.firebaseio.com');
  const restore = countConnects(isDb, () => { try { ctx.counter.take('admin-ws-attempt'); } catch (error) { ctx.abort(error.message); throw error; } }, ctx.journal);
  ctx.closers.push(async () => restore());
  const { initializeApp, deleteApp } = await import('firebase-admin/app'), { getDatabase } = await import('firebase-admin/database'), { runAdminProfile } = await import('./admin-suite.mjs');
  if (ctx.cancelled) throw new Error('cancelled');
  const token = ctx.local ? 'owner' : ctx.adminToken;   // emulator: the Admin SDK itself uses the owner credential once FIREBASE_DATABASE_EMULATOR_HOST is set
  const app = initializeApp({ credential: { getAccessToken: async () => ({ access_token: token, expires_in: 3600 }) }, databaseURL: ctx.databaseURL, projectId: ctx.projectId }, `admin-${ctx.profile}`), db = getDatabase(app);
  ctx.closers.push(async () => { db.goOffline(); await deleteApp(app).catch(() => {}); });
  return runAdminProfile({ db, cfg: { scope: ctx.scope, name: ctx.profile, closeMs: ctx.closeMs }, emit: row => ctx.journal.write({ ...row, profile: ctx.profile }) });
}
/** One rest profile: the case table through the run's guarded admin REST (ctx.rest), under the profile scope. */
export const restProfile = ctx => runRestProfile({ send: ctx.rest, url: ctx.restUrl, scope: ctx.scope, cancelled: () => ctx.cancelled === true, emit: row => ctx.journal.write({ ...row, profile: ctx.profile }) });
const suiteProfiles = { events: { ws: eventsWsProfile, lp: eventsLpProfile }, admin: { admin: adminProfile }, rest: { rest: restProfile } };

// ---- the run -----------------------------------------------------------------------------------------------------------------------------------
export async function run(opts, deps = {}) {
  const suite = opts.suite ?? 'small', S = SUITES[suite];
  if (!S) throw new Error(`unknown suite ${suite}`);
  const o = { caseMs: 15000, profileMs: S.profileMs, runMs: S.runMs, adminMs: 10000, closeMs: 5000, continueOnFailure: false, ...opts, suite }, d = { fetchImpl: fetch, profiles: realProfiles, suiteProfiles, mint: mintToken, createJournal, ...deps };
  const T = o.target, urls = targetUrls(T), production = T.kind === 'production', scriptSha = scriptManifest(HERE).sha256, nonce = randomBytes(16).toString('hex');
  mkdirSync(path.dirname(o.outDir), { recursive: true, mode: 0o700 }); mkdirSync(o.outDir, { mode: 0o700 });
  const journal = d.createJournal(path.join(o.outDir, 'journal.jsonl')), counter = createCounter({ direct: o.directCap, reserve: 12 });
  const result = { runId: o.runId, ...(suite === 'small' ? {} : { suite, prefix: o.prefix }), target: T.kind, scriptSha256: scriptSha, sdk: { ...sdkVersions(), ...(S.parts.includes('admin') ? { firebaseAdmin: adminVersion() } : {}) }, startedAt: new Date().toISOString(), status: 'started', cases: [], unverified: [], cleanup: { prefix: 'not-needed', rules: 'not-needed' } };
  const releases = [], pending = new Set(), state = { touched: false, baselineText: null };
  const jw = row => { try { journal.write(row); } catch { /* the journal must not stop the restoration */ } };
  let abortReason = null, abortFn; const aborted = new Promise(r => { abortFn = reason => { if (abortReason) return; abortReason = reason; jw({ kind: 'abort', reason }); r(); }; });
  const guard = (ms, label, p) => withTimeout(ms, label, Promise.race([p, aborted.then(() => { throw new Error(`aborted: ${abortReason}`); })]));
  const onSignal = s => abortFn(s), onFault = e => abortFn(`uncaught: ${String(e?.message ?? e).slice(0, 200)}`);   // an error thrown in an SDK or page callback aborts into the cleanup instead of killing the process
  process.on('SIGINT', onSignal); process.on('SIGTERM', onSignal); process.on('uncaughtException', onFault); process.on('unhandledRejection', onFault);
  const runTimer = setTimeout(() => abortFn('run deadline'), o.runMs);
  let admin, adminToken, exit = 1;
  const fail = (code, status, error) => { exit = code; result.status = status; result.error = String(error?.message ?? error); jw({ kind: 'error', status, error: result.error }); };
  try {
    if (production) {   // refusals here send nothing except the one tokeninfo POST
      checkApproval(readFileSync(T.paths.owner, 'utf8'), { runId: o.runId, scriptSha256: scriptSha, directCap: o.directCap, prefix: o.prefix, suite });
      releases.push(claim(T.paths.lease, JSON.stringify({ pid: process.pid, envelopeId: o.runId, packetSha256: scriptSha, nonce })));
      releases.push(claim(T.paths.recording, JSON.stringify({ envelopeId: o.runId, nonce, packetSha256: scriptSha, pid: process.pid, purpose: 'RTDB-SMALL-OBSERVER' })));
      counter.take('adc', 'adc'); const token = d.mint(T.gcloud);
      if (!/^[\x21-\x7e]{20,4096}$/.test(token)) throw new Error('ADC token shape');
      journal.addSecret(token); adminToken = token; counter.take('tokeninfo');
      const verdict = await adcVerdict(d.fetchImpl, token, T.principalSha256);
      if (!verdict.ok) throw new Error(verdict.reason);
      admin = createAdmin({ headers: { authorization: `Bearer ${token}`, 'x-goog-user-project': T.projectId }, journal, counter, fetchImpl: d.fetchImpl, timeoutMs: o.adminMs });
    } else admin = createAdmin({ headers: { authorization: 'Bearer owner' }, journal, counter, fetchImpl: d.fetchImpl, timeoutMs: o.adminMs });
    const rest = (label, method, url, extra) => {   // a mutation that guard() abandons stays tracked until it settles: the cleanup waits for it
      const p = admin.rest(label, method, url, extra);
      if (method !== 'GET') { pending.add(p); p.catch(() => {}).finally(() => pending.delete(p)); }
      return guard(o.adminMs + 2000, label, p);
    };
    const rulesUrl = urls.data('.settings/rules'), prefixUrl = urls.data(o.prefix.slice(1));
    const want = suite === 'small' ? packetRules(o.prefix) : suite === 'rest' ? restRules(o.prefix) : suiteRules(S.parts, o.prefix);
    if (production) {
      const r = await rest('instance', 'GET', urls.instance), v = JSON.parse(r.text);
      if (r.status !== 200 || v.type !== 'USER_DATABASE' || v.state !== 'ACTIVE' || !v.name.endsWith(`/instances/${T.namespace}`)) throw new Error('instance is not ACTIVE');
    }
    const before = await rest('rules-before', 'GET', rulesUrl);
    if (before.status !== 200 || (production && sha256(before.text) !== T.baselineRulesSha256)) throw new Error('Rules are not the baseline');
    state.baselineText = before.text;
    const pre = await rest('prefix-before', 'GET', prefixUrl);
    if (pre.status !== 200 || pre.text.trim() !== 'null') throw new Error('prefix is not null');
    state.touched = true;   // from the PUT on, the cleanup runs even if the answer never arrives
    const put = await rest('rules-install', 'PUT', rulesUrl, { body: JSON.stringify(want) });
    const back = await rest('rules-installed', 'GET', rulesUrl);
    if (put.status !== 200 || back.status !== 200 || !isDeepStrictEqual(JSON.parse(back.text), want)) throw new Error('Rules install not read back');
    for (const { name: profile, suite: part, transport } of S.plan) {
      if (abortReason) break;
      const area = AREAS[part];
      const ctx = { profile, scope: `${o.prefix}/${area}/${profile}`.slice(1), transport, databaseURL: urls.databaseURL, projectId: T.projectId, local: !production, target: T, journal, counter, abort: abortFn, caseMs: o.caseMs, closeMs: o.closeMs, closers: [], ...(part === 'admin' ? { adminToken } : {}), ...(part === 'rest' ? { rest, restUrl: urls.raw } : {}) };
      let rows;
      const profilePromise = (async () => (part === 'small' ? d.profiles[transport](ctx) : d.suiteProfiles[part][transport](ctx)))(), drain = async () => { for (const close of ctx.closers.splice(0).reverse()) await withTimeout(o.closeMs, `close ${profile}`, close()).catch(() => result.unverified.push(`close ${profile}`)); };
      try { rows = await guard(o.profileMs, `profile ${profile}`, profilePromise); }
      catch (error) { ctx.cancelled = true; rows = [{ role: '-', id: 'profile', ok: false, error: `${error?.name}: ${error?.message}` }]; jw({ kind: 'profile-error', profile, error: String(error?.message) }); if (part !== 'small') result.unverified.push(`${part === 'rest' ? 'REST' : 'SDK'} mutations possibly in flight: profile ${profile} aborted`); if (part === 'rest') abortFn(`rest profile ${profile} hit its deadline`); }   // an abandoned SDK profile may have sent writes whose outcome is unknown
      await drain();   // actors, page, browser stopped and awaited before anything else
      if (ctx.cancelled) { await withTimeout(o.closeMs, `settle ${profile}`, profilePromise.catch(() => {})).catch(() => result.unverified.push(`profile ${profile} did not settle`)); await drain(); }   // a profile still starting up registers more closers when it finishes
      for (const label of rows.flatMap(row => row.unknown ?? [])) result.unverified.push(`unknown ${part === 'rest' ? 'REST' : 'SDK'} mutation outcome: ${profile}/${label}`);   // a write, push or transaction that hit its deadline: like an unknown REST mutation it keeps the claims for the A2 read-back
      result.cases.push(...rows.map(({ value, steps, ...row }) => ({ profile, ...row })));
      if (rows.some(row => !row.ok) && !o.continueOnFailure) break;
    }
    const partOf = name => S.plan.find(p => p.name === name)?.suite;
    const adminNames = S.plan.filter(p => p.suite === 'admin').map(p => p.name);
    if (adminNames.length) {   // an Admin SDK profile counts only when its startup read was answered: a refused credential is a credential outcome, not G13 evidence
      result.adminStartup = Object.fromEntries(adminNames.map(name => [name, result.cases.some(c => c.profile === name && c.id === 'startup' && c.ok === true)]));
      const refused = adminNames.filter(name => !result.adminStartup[name]);
      if (refused.length) result.credentialOutcome = refused;
    }
    const counted = c => c.ok && !(result.credentialOutcome ?? []).includes(c.profile);
    const observed = result.cases.filter(c => counted(c) && (partOf(c.profile) === 'small' ? CASE_ORDER.some(([r, id]) => r === c.role && id === c.id) : SUITE_CASES[partOf(c.profile)]?.includes(c.id))).length;
    result.observed = observed; exit = observed === expectedObservations(suite) && !abortReason ? 0 : 1; result.status = exit === 0 ? 'complete' : 'incomplete';
    if (abortReason) result.error = `aborted: ${abortReason}`;
  } catch (error) { fail(state.touched ? 1 : 2, state.touched ? 'failed' : 'refused', error); }   // nothing changed yet: a refusal
  finally {
    clearTimeout(runTimer);
    if (pending.size) await withTimeout(o.adminMs + 500, 'in-flight admin request', Promise.allSettled([...pending])).catch(() => {});
    if (pending.size) result.unverified.push('in-flight admin request');
    if (state.touched) {   // restoration: bounded, independent steps, never re-sent on an unknown answer, paid from the reserve
      const cleanup = async (label, method, url, extra, ok) => { try { const r = await admin.rest(label, method, url, { ...extra, cleanup: true }); return ok(r) ? 'verified' : 'unverified'; } catch { return 'unverified'; } };
      const rulesUrl = urls.data('.settings/rules'), prefixUrl = urls.data(o.prefix.slice(1));
      const del = await cleanup('prefix-delete', 'DELETE', prefixUrl, {}, r => r.status === 200), nul = await cleanup('prefix-null', 'GET', prefixUrl, {}, r => r.status === 200 && r.text.trim() === 'null');
      result.cleanup.prefix = del === 'verified' && nul === 'verified' ? 'verified' : 'unverified';
      const restore = await cleanup('rules-restore', 'PUT', urls.data('.settings/rules'), { body: state.baselineText }, r => r.status === 200), same = await cleanup('rules-restored', 'GET', rulesUrl, {}, r => r.status === 200 && r.text === state.baselineText);
      result.cleanup.rules = restore === 'verified' && same === 'verified' ? 'verified' : 'unverified';
      if (result.cleanup.prefix !== 'verified' || result.cleanup.rules !== 'verified') result.unverified.push('cleanup');
    }
    if (admin?.unknownMutations.length) result.unverified.push(`unknown mutation outcome: ${admin.unknownMutations.join()}`);
    if (result.unverified.length) { exit = 3; result.status = 'unverified'; }
    for (const [event, handler] of [['SIGINT', onSignal], ['SIGTERM', onSignal], ['uncaughtException', onFault], ['unhandledRejection', onFault]]) process.off(event, handler);
    result.counts = counter.used(); result.caps = counter.caps(); result.exit = exit; result.endedAt = new Date().toISOString();
    if (exit !== 3) for (const release of releases.reverse()) try { release(); } catch { /* claim already gone */ }
    else result.claims = 'left in place: cleanup unverified';
    jw({ kind: 'result', ...result, cases: undefined });
    try { journal.close(); } catch { /* disk */ }
    try { writeNew(path.join(o.outDir, 'result.json'), `${JSON.stringify(result, null, 2)}\n`); } catch (error) { console.error(`result.json not written: ${error.message}`); }
  }
  return { exit, result };
}

// ---- command line ----------------------------------------------------------------------------------------------------------------------------
/** The production target out of the private config file (the same inputs for a run and for the read-back). */
export function productionTarget(configPath) {
  const config = productionConfig(JSON.parse(readFileSync(configPath, 'utf8')));
  const packet = JSON.parse(readFileSync(config.legacyPacket, 'utf8'));
  const gcloud = JSON.parse(readFileSync(config.runtimeProposal, 'utf8')).gcloudRealPath;   // the legacy packet's gcloud path is stale
  if (packet.projectId !== PRODUCTION.projectId || typeof gcloud !== 'string' || !gcloud.startsWith('/nix/store/') || !existsSync(gcloud)) throw new Error('packet or gcloud path does not match');
  return { ...config, projectNumber: String(packet.projectNumber), baselineRulesSha256: packet.baselineRulesSha256, gcloud };
}
function productionEnvironment() {
  const env = ['GOOGLE_APPLICATION_CREDENTIALS', 'FIREBASE_TOKEN', 'HTTPS_PROXY', 'HTTP_PROXY', 'NODE_OPTIONS', 'FIREBASE_DATABASE_EMULATOR_HOST'].filter(k => process.env[k]);
  if (env.length) throw new Error(`environment variable set: ${env.join()}`);
  if (getHeapStatistics().heap_size_limit > 1.3 * 2 ** 30) throw new Error('run with --max-old-space-size=1024');
}
/** observer.mjs readback --run-dir <finished run dir> --production-config <file> --out <new dir>: the reviewed read-only A2 (readback.mjs). */
async function readbackCommand(argv) {
  const arg = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (!arg('--run-dir') || !arg('--production-config') || !arg('--out')) throw new Error('usage: readback --run-dir <finished run dir> --production-config <file> --out <new dir>');
  productionEnvironment();
  const target = productionTarget(arg('--production-config')), ledgerText = readFileSync(target.paths.owner, 'utf8');
  const { exit, report } = await readback({ runDir: path.resolve(arg('--run-dir')), outDir: path.resolve(arg('--out')), target, ledgerText });
  console.log(JSON.stringify({ runId: report.runId, verdict: report.verdict, checks: report.checks, counts: report.counts, exit }));
  return exit;
}

async function main(argv) {
  const arg = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv.includes('--print-manifest')) { console.log(JSON.stringify(scriptManifest(HERE))); return 0; }
  if (argv[0] === 'readback') return readbackCommand(argv);
  if (arg('--target') === 'production') productionEnvironment();
  const kind = arg('--target'), runId = arg('--run-id'), prefix = arg('--prefix'), directCap = Number(arg('--direct-cap')), suite = arg('--suite') ?? 'small';
  if (!Object.hasOwn(SUITES, suite)) throw new Error('usage: --suite small|events|admin|events+admin|rest');
  const capMax = SUITES[suite].capMax;
  if (!['production', 'emulator'].includes(kind) || !/^[A-Za-z0-9-]{4,64}$/.test(runId ?? '') || !Number.isSafeInteger(directCap) || directCap < 20 || directCap > capMax) throw new Error(`usage: --target production|emulator --run-id ID --prefix /p --direct-cap 20..${capMax}`);
  packetRules(prefix);
  checkSdkPins(suite);
  let target;
  const outDir = arg('--out');
  if (!outDir) throw new Error('usage: --out <new dir>');
  if (kind === 'production') {
    target = productionTarget(arg('--production-config') ?? '');
  } else {
    if (!/^127\.0\.0\.1:\d+$/.test(process.env.FIREBASE_DATABASE_EMULATOR_HOST ?? '')) throw new Error('FIREBASE_DATABASE_EMULATOR_HOST must be 127.0.0.1:<port> (run under fireemu exec --only database)');
    target = { kind, host: process.env.FIREBASE_DATABASE_EMULATOR_HOST, namespace: 'fireemu-small-observer', projectId: 'demo-small-observer' };
  }
  const { exit, result } = await run({ target, runId, prefix, directCap, suite, outDir: path.resolve(outDir), continueOnFailure: argv.includes('--continue-on-failure') });
  console.log(JSON.stringify({ runId, status: result.status, exit, observed: result.observed, counts: result.counts, cleanup: result.cleanup }));
  return exit;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const suite = process.argv.includes('--suite') ? process.argv[process.argv.indexOf('--suite') + 1] : 'small';
  setTimeout(() => process.exit(4), process.argv[2] === 'readback' ? 5 * 60 * 1000 : backstopMs(suite)).unref();   // hard backstop above runMs plus the bounded cleanup; leaves the claims in place
  main(process.argv.slice(2)).then(code => process.exit(code), error => { console.error(String(error?.message)); process.exit(2); });
}
