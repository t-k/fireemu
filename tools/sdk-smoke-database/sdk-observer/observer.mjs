#!/usr/bin/env node
// RTDB SDK small observer (owner decision 2026-11-02, replaces the gen2 harness): 4 profiles (r1/r2 x ws/lp) x 8 cases against one RTDB, talking to it directly.
//   node --max-old-space-size=1024 observer.mjs --target production|emulator --run-id ID --prefix /p --direct-cap N --out <new dir> [--production-config <file>] [--continue-on-failure] | --print-manifest
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
import { adcVerdict, checkApproval, claim, clip, createAdmin, createCounter, createJournal, mintToken, scriptManifest, sha256, targetUrls } from './lib.mjs';
import { CASE_ORDER, runCases, withTimeout } from './sequence.mjs';
import { packetRules } from './rules.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url)), MODULES = path.resolve(HERE, '../node_modules');
export const PROFILES = [[1, 'ws'], [1, 'lp'], [2, 'ws'], [2, 'lp']];
const PINS = { firebase: ['firebase', '12.18.0'], database: ['@firebase/database', '1.1.5'], playwright: ['playwright', '1.62.1'] };
const PRODUCTION = { kind: 'production', projectId: 'fireemu-oracle-query', namespace: 'fireemu-q-rtdb2', region: 'us-central1' };
/** The private production inputs: exactly these fields, absolute paths. */
export function productionConfig(doc) {
  const paths = doc?.paths, abs = v => typeof v === 'string' && path.isAbsolute(v);
  if (!doc || Object.keys(doc).sort().join() !== 'legacyPacket,paths,principalSha256,runtimeProposal' || !/^[a-f0-9]{64}$/.test(doc.principalSha256 ?? '') || !abs(doc.legacyPacket) || !abs(doc.runtimeProposal)
    || !paths || Object.keys(paths).sort().join() !== 'lease,owner,recording' || !Object.values(paths).every(abs)) throw new Error('--production-config: principalSha256, legacyPacket, runtimeProposal, paths {owner, lease, recording}');
  return { ...PRODUCTION, principalSha256: doc.principalSha256, legacyPacket: doc.legacyPacket, runtimeProposal: doc.runtimeProposal, paths: { ...paths } };
}
const writeNew = (file, text) => { const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); try { writeSync(fd, text); } finally { closeSync(fd); } };
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
const SERVED = { '/page.mjs': 'page.mjs', '/sequence.mjs': 'sequence.mjs', '/actor.mjs': 'actor.mjs' };
export async function lpProfile(ctx) {
  const { chromium } = await import('playwright'), mod = path.join(MODULES, 'firebase');
  const server = createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname, file = p === '/' ? path.join(HERE, 'page.html') : SERVED[p] ? path.join(HERE, SERVED[p]) : /^\/firebase-(app|database)\.js$/.test(p) ? path.join(mod, p.slice(1)) : null;
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
    page.on('request', request => {   // passive: counts and records, never routes
      if (!isDb(request.url())) return;
      try { ctx.counter.take('lp-request'); } catch (error) { ctx.counter.overflow(); ctx.abort(error.message); void page.close().catch(() => {}); }   // the request is already out: count it anyway and stop the page now
      ctx.journal.write({ kind: 'raw-lp-request', profile: ctx.profile, method: request.method(), url: request.url(), body: request.postData() ? clip(request.postData()) : null }, { optional: true });
    });
    page.on('response', async response => {
      if (!isDb(response.url())) return;
      const body = await withTimeout(3000, 'lp-body', response.text()).catch(() => null);
      ctx.journal.write({ kind: 'raw-lp-response', profile: ctx.profile, status: response.status(), url: response.url(), body: body === null ? null : clip(body) }, { optional: true });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/`); alive();
    await page.waitForFunction(() => window.__ready === true, null, { timeout: 15000 }); alive();
    return await page.evaluate(cfg => window.__run(cfg), { projectId: ctx.projectId, databaseURL: ctx.databaseURL, scope: ctx.scope, transport: 'lp', local: ctx.local, caseMs: ctx.caseMs, closeMs: ctx.closeMs });
  }
}
const realProfiles = { ws: wsProfile, lp: lpProfile };

// ---- the run -----------------------------------------------------------------------------------------------------------------------------------
export async function run(opts, deps = {}) {
  const o = { caseMs: 15000, profileMs: 90000, runMs: 600000, adminMs: 10000, closeMs: 5000, continueOnFailure: false, ...opts }, d = { fetchImpl: fetch, profiles: realProfiles, mint: mintToken, createJournal, ...deps };
  const T = o.target, urls = targetUrls(T), production = T.kind === 'production', scriptSha = scriptManifest(HERE).sha256, nonce = randomBytes(16).toString('hex');
  mkdirSync(path.dirname(o.outDir), { recursive: true, mode: 0o700 }); mkdirSync(o.outDir, { mode: 0o700 });
  const journal = d.createJournal(path.join(o.outDir, 'journal.jsonl')), counter = createCounter({ direct: o.directCap, reserve: 12 });
  const result = { runId: o.runId, target: T.kind, scriptSha256: scriptSha, sdk: sdkVersions(), startedAt: new Date().toISOString(), status: 'started', cases: [], unverified: [], cleanup: { prefix: 'not-needed', rules: 'not-needed' } };
  const releases = [], pending = new Set(), state = { touched: false, baselineText: null };
  const jw = row => { try { journal.write(row); } catch { /* the journal must not stop the restoration */ } };
  let abortReason = null, abortFn; const aborted = new Promise(r => { abortFn = reason => { if (abortReason) return; abortReason = reason; jw({ kind: 'abort', reason }); r(); }; });
  const guard = (ms, label, p) => withTimeout(ms, label, Promise.race([p, aborted.then(() => { throw new Error(`aborted: ${abortReason}`); })]));
  const onSignal = s => abortFn(s), onFault = e => abortFn(`uncaught: ${String(e?.message ?? e).slice(0, 200)}`);   // an error thrown in an SDK or page callback aborts into the cleanup instead of killing the process
  process.on('SIGINT', onSignal); process.on('SIGTERM', onSignal); process.on('uncaughtException', onFault); process.on('unhandledRejection', onFault);
  const runTimer = setTimeout(() => abortFn('run deadline'), o.runMs);
  let admin, exit = 1;
  const fail = (code, status, error) => { exit = code; result.status = status; result.error = String(error?.message ?? error); jw({ kind: 'error', status, error: result.error }); };
  try {
    if (production) {   // refusals here send nothing except the one tokeninfo POST
      checkApproval(readFileSync(T.paths.owner, 'utf8'), { runId: o.runId, scriptSha256: scriptSha, directCap: o.directCap, prefix: o.prefix });
      releases.push(claim(T.paths.lease, JSON.stringify({ pid: process.pid, envelopeId: o.runId, packetSha256: scriptSha, nonce })));
      releases.push(claim(T.paths.recording, JSON.stringify({ envelopeId: o.runId, nonce, packetSha256: scriptSha, pid: process.pid, purpose: 'RTDB-SMALL-OBSERVER' })));
      counter.take('adc', 'adc'); const token = d.mint(T.gcloud);
      if (!/^[\x21-\x7e]{20,4096}$/.test(token)) throw new Error('ADC token shape');
      journal.addSecret(token); counter.take('tokeninfo');
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
    const want = packetRules(o.prefix);
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
    for (const [round, transport] of PROFILES) {
      if (abortReason) break;
      const profile = `r${round}-${transport}`, ctx = { profile, scope: `${o.prefix}/sdk-next/${profile}`.slice(1), transport, databaseURL: urls.databaseURL, projectId: T.projectId, local: !production, target: T, journal, counter, abort: abortFn, caseMs: o.caseMs, closeMs: o.closeMs, closers: [] };
      let rows;
      const profilePromise = (async () => d.profiles[transport](ctx))(), drain = async () => { for (const close of ctx.closers.splice(0).reverse()) await withTimeout(o.closeMs, `close ${profile}`, close()).catch(() => result.unverified.push(`close ${profile}`)); };
      try { rows = await guard(o.profileMs, `profile ${profile}`, profilePromise); }
      catch (error) { ctx.cancelled = true; rows = [{ role: '-', id: 'profile', ok: false, error: `${error?.name}: ${error?.message}` }]; jw({ kind: 'profile-error', profile, error: String(error?.message) }); }
      await drain();   // actors, page, browser stopped and awaited before anything else
      if (ctx.cancelled) { await withTimeout(o.closeMs, `settle ${profile}`, profilePromise.catch(() => {})).catch(() => result.unverified.push(`profile ${profile} did not settle`)); await drain(); }   // a profile still starting up registers more closers when it finishes
      result.cases.push(...rows.map(({ value, ...row }) => ({ profile, ...row })));
      if (rows.some(row => !row.ok) && !o.continueOnFailure) break;
    }
    const observed = result.cases.filter(c => c.ok && CASE_ORDER.some(([r, id]) => r === c.role && id === c.id)).length;
    result.observed = observed; exit = observed === PROFILES.length * CASE_ORDER.length && !abortReason ? 0 : 1; result.status = exit === 0 ? 'complete' : 'incomplete';
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
async function main(argv) {
  const arg = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv.includes('--print-manifest')) { console.log(JSON.stringify(scriptManifest(HERE))); return 0; }
  if (arg('--target') === 'production') {
    const env = ['GOOGLE_APPLICATION_CREDENTIALS', 'FIREBASE_TOKEN', 'HTTPS_PROXY', 'HTTP_PROXY', 'NODE_OPTIONS'].filter(k => process.env[k]);
    if (env.length) throw new Error(`environment variable set: ${env.join()}`);
    if (getHeapStatistics().heap_size_limit > 1.3 * 2 ** 30) throw new Error('run with --max-old-space-size=1024');
  }
  const kind = arg('--target'), runId = arg('--run-id'), prefix = arg('--prefix'), directCap = Number(arg('--direct-cap'));
  if (!['production', 'emulator'].includes(kind) || !/^[A-Za-z0-9-]{4,64}$/.test(runId ?? '') || !Number.isSafeInteger(directCap) || directCap < 20 || directCap > 180) throw new Error('usage: --target production|emulator --run-id ID --prefix /p --direct-cap 20..180');
  packetRules(prefix);
  for (const [k, [pkg, version]] of Object.entries(PINS)) if (sdkVersions()[k] !== version) throw new Error(`${pkg} is not ${version}`);
  let target;
  const outDir = arg('--out');
  if (!outDir) throw new Error('usage: --out <new dir>');
  if (kind === 'production') {
    const config = productionConfig(JSON.parse(readFileSync(arg('--production-config') ?? '', 'utf8')));
    const packet = JSON.parse(readFileSync(config.legacyPacket, 'utf8'));
    const gcloud = JSON.parse(readFileSync(config.runtimeProposal, 'utf8')).gcloudRealPath;   // the legacy packet's gcloud path is stale
    if (packet.projectId !== PRODUCTION.projectId || typeof gcloud !== 'string' || !gcloud.startsWith('/nix/store/') || !existsSync(gcloud)) throw new Error('packet or gcloud path does not match');
    target = { ...config, projectNumber: String(packet.projectNumber), baselineRulesSha256: packet.baselineRulesSha256, gcloud };
  } else {
    if (!/^127\.0\.0\.1:\d+$/.test(process.env.FIREBASE_DATABASE_EMULATOR_HOST ?? '')) throw new Error('FIREBASE_DATABASE_EMULATOR_HOST must be 127.0.0.1:<port> (run under fireemu exec --only database)');
    target = { kind, host: process.env.FIREBASE_DATABASE_EMULATOR_HOST, namespace: 'fireemu-small-observer', projectId: 'demo-small-observer' };
  }
  const { exit, result } = await run({ target, runId, prefix, directCap, outDir: path.resolve(outDir), continueOnFailure: argv.includes('--continue-on-failure') });
  console.log(JSON.stringify({ runId, status: result.status, exit, observed: result.observed, counts: result.counts, cleanup: result.cleanup }));
  return exit;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  setTimeout(() => process.exit(4), 12 * 60 * 1000).unref();   // hard backstop above runMs plus the bounded cleanup; leaves the claims in place
  main(process.argv.slice(2)).then(code => process.exit(code), error => { console.error(String(error?.message)); process.exit(2); });
}
