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
import { appendFileSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, writeFileSync, writeSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { adminClient, assertNoSecrets, LAUNCH, redact } from './cv11-genuine-auth.mjs';
import { ADC_ARGS, runPreflight } from './adc-preflight.mjs';
import { DEFAULT_JAR, startJar } from './jar.mjs';
import { judgeRuns, sanitizeProfiles, SCENARIOS, validateSdkNext, validateSdkStartup } from './rtdb-residual-judge.mjs';
import { createRtdbAdmin, Stop } from './rtdb-admin.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SOURCES = ['rtdb-residual.mjs', 'rtdb-residual-page.js', 'rtdb-residual-judge.mjs', 'adc-preflight.mjs', 'cv11-genuine-auth.mjs'];
export const PROFILES = [[1, 'ws'], [1, 'lp'], [2, 'ws'], [2, 'lp']].map(([round, transport]) => ({ round, transport, name: `r${round}-${transport}` }));
// observe/cleanup: admin requests per phase; mutations: admin writes overall; browser caps per profile.
export const CAPS = { observe: 80, cleanup: 30, mutations: 40, pollsPerOperation: 12, browserHttp: 400, browserWs: 24, browserFrames: 2500 };
// A profile that never reaches the writer's disconnect can leave onDisconnect writes pending; the
// server fires them when it drops the idle long-polling connection (production: about 105 s).
export const FIRE_GRACE_MS = 150000;
// Longer than the worst case of the page's own waits (Rules probes up to 60 s each, marker wait 30 s / 240 s).
export const PROFILE_TIMEOUT_MS = { cv08: 240000, startup: 30000, cv10: { ws: 300000, lp: 540000 } };
const PROPAGATION_MS = 120000;
const INSTANCE = 'fireemu-q-rtdb2', LOCATION = 'us-central1', TIMEOUT_MS = 25000;
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const OPEN = { '.read': true, '.write': true };
/** The Rules of one run: the anonymous client owns the run prefix; `deny` closes the writes of e7, e8 and dprobe. */
export function rulesFor(prefix, { deny = false, startup = false } = {}) {
  const [top, run] = prefix.split('/'), W = { '.write': true }, flag = { '.write': !deny };
  return {
    rules: {
      '.read': false,
      '.write': false,
      [top]: {
        [run]: {
          ...(startup ? { 'sdk-next-startup': { $cell: { '.read': true, '.write': false } } } : {
            cv08: { $cell: { items: { ...OPEN, '.indexOn': ['score'] }, gate: OPEN, gated: { '.read': "data.parent().child('gate').val() === true", '.write': true }, other: OPEN } },
            'sdk-next': { $cell: { '.read': true, '.write': true, items: { '.indexOn': ['score'] } } },
            cv10: { $cell: { '.read': true, e1: W, e2: W, e3: W, e4: W, e5: W, e6: W, e7: flag, e8: flag, e9: W, marker: W, dprobe: flag } },
          }),
        },
      },
    },
  };
}

export { ADC_ARGS };
/** Every management and data request carries the token as a Bearer header (never in the URL) and the quota project. */
export const productionHeaders = (token, projectId) => ({ authorization: `Bearer ${token}`, 'x-goog-user-project': projectId });

/** Chromium may reach loopback and Firebase hosts only: the page and SDK bundles are served locally. */
export const hostRules = () => '--host-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE *.firebaseio.com';

const admin = createRtdbAdmin({ instance: INSTANCE, location: LOCATION, caps: CAPS, propagationMs: PROPAGATION_MS, fireGraceMs: FIRE_GRACE_MS, rulesFor });
export const { urls, isDisabledByOwner } = admin;
const { read, mutate, waitOperation, setApi, setupProduction, putRules, installRules, cleanup } = admin;

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
  if (scenario === 'sdk-next' && (!validateSdkNext(out.journal).valid || !out.journal.some((e) => e.type === 'done'))) run.errors.push('sdk-next profile incomplete');
  if (scenario === 'sdk-next-startup' && (!validateSdkStartup(out.journal).valid || !out.journal.some((e) => e.type === 'done'))) run.errors.push('sdk-next-startup profile incomplete');
  return { scenario, name: prof.name, ...out };
}

// Runs setup, the scenarios x profiles and cleanup. The status is 'closed' only when nothing is
// unknown and every owned resource read back at its starting state; otherwise 'needs-recovery'.
const startupTicket = Symbol('validated startup');

export async function runScenario(o) {
  if (o.mode === 'production') {
    for (const scenario of [o.packet?.scenario, ...(o.scenarios ?? [])]) if (scenario === 'sdk-next' || (scenario === 'sdk-next-startup' && o.ticket !== startupTicket)) assertProductionSdkNextReady({ scenario });
  }
  o.secrets ??= [];
  const u = urls(o);
  if (o.strictStartup && (o.scenarios?.length !== 1 || o.scenarios[0] !== 'sdk-next-startup' || typeof o.strictJournal !== 'function')) throw Error('strict startup requires fixed scenario and durable journal');
  const allowed = startupAllowedTargets(u, o.prefix);
  const client = o.strictStartup ? createStartupStrictClient({ fetchImpl: o.fetchImpl, headers: o.headers, stop: o.stop, caps: CAPS, allowed, journal: o.strictJournal }) : adminClient({ fetchImpl: o.fetchImpl, headers: o.headers, log: o.log, stop: o.stop, secrets: o.secrets, caps: CAPS });
  const run = { admin: client, call: client.call, u, propagation: false, propagationWaited: 0, state: { api: 'baseline', instance: 'baseline', rules: 'baseline', data: 'baseline' }, unresolved: [], errors: [], fireWait: false };
  const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  run.sleep = sleep;
  const profiles = [];
  // Production startup is blocked above; local startup has exactly two WS profiles.
  const scenarios = o.scenarios ?? (o.mode === 'production' && o.packet?.scenario === 'sdk-next' ? ['sdk-next'] : ['cv08', 'cv10']);
  const isStartup = scenarios.includes('sdk-next-startup');
  if (isStartup && (scenarios.length !== 1 || (o.profiles && (o.profiles.length !== 2 || o.profiles.some((p, i) => p.name !== ['r1-ws', 'r2-ws'][i] || p.transport !== 'ws'))))) throw Error('startup requires exactly two WS profiles');
  const profilesToRun = isStartup ? PROFILES.filter((p) => p.transport === 'ws') : o.profiles ?? PROFILES;
  const scoped = isStartup ? createRtdbAdmin({ instance: INSTANCE, location: LOCATION, caps: CAPS, propagationMs: PROPAGATION_MS, fireGraceMs: FIRE_GRACE_MS, strictStartup: o.strictStartup, rulesFor: (prefix, options) => rulesFor(prefix, { ...options, startup: true }) }) : admin;
  const { setupProduction, installRules, cleanup } = scoped;
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
    if (!o.strictStartup || run.errors.length === 0) await cleanup(run, o, sleep);
  }
  const restored = Object.values(run.state).every((s) => s === 'baseline');
  // An unexpected error or an unwritten log row means a sent request may be unaccounted for.
  const accounted = client.counts.logFailures === 0 && !run.errors.some((e) => e.startsWith('unexpected'));
  return { status: run.unresolved.length === 0 && (!o.strictStartup || (client.unknownAnswers.length === 0 && run.errors.length === 0)) && restored && accounted ? 'closed' : 'needs-recovery', unknownAnswers: client.unknownAnswers, observationComplete: profiles.length === scenarios.length * profilesToRun.length && !run.errors.length, profiles, state: run.state, unresolved: run.unresolved, errors: run.errors, counts: client.counts };
}

export function startupAllowedTargets(u, prefix) {
  const fixedTargets = new Map([[u.data(prefix), ['GET', 'DELETE']], [u.data('.settings/rules'), ['GET', 'PUT']], [u.service, ['GET']], [u.list, ['GET']], [u.instance, ['GET', 'DELETE']], [u.service && `${u.service}:enable`, ['POST']], [u.service && `${u.service}:disable`, ['POST']], [u.instance && `${u.instance}:undelete`, ['POST']], [u.instance && `${u.instance}:reenable`, ['POST']], [u.instance && `${u.instance}:disable`, ['POST']]]);
  const operations = new Set();
  const allowed = (url, method) => (fixedTargets.get(url) ?? []).includes(method) || (method === 'GET' && operations.has(url));
  allowed.register = (name) => { if (!u.op || !validStartupOperation(name)) throw Error('invalid startup operation'); operations.add(u.op(name)); };
  return allowed;
}

// This opt-in client is still disarmed from production until packet and lifecycle admission.
export const validStartupOperation = (name) => typeof name === 'string' && /^operations\/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/.test(name);

// The Root-owned launcher must read and pin the real ledger and carry; caller-supplied rows alone are not authority.
export function validateStartupAdmission({ admission: a, packetSha256, sourceSha256, carrySha256, ledger }) {
  const hash = (x) => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
  if (!a || a.booked !== true || a.scenario !== 'sdk-next-startup' || ![packetSha256, sourceSha256, carrySha256].every(hash) || a.packetSha256 !== packetSha256 || a.sourceSha256 !== sourceSha256 || a.carrySha256 !== carrySha256 || a.previousDirect !== 1177 || a.previousAdc !== 20 || a.previousUsd !== 19 || a.incrementUsd !== 1 || a.totalCap !== 1399 || JSON.stringify(a.profiles) !== JSON.stringify(['r1-ws', 'r2-ws']) || !Array.isArray(a.ownerRows) || a.ownerRows.length !== 3 || !Array.isArray(ledger)) throw Error('startup admission mismatch');
  if (typeof a.envelopeId !== 'string' || !/^RTDB-SDK-STARTUP-[A-Z0-9-]+$/.test(a.envelopeId)) throw Error('startup envelope');
  const positions = a.ownerRows.map((row, i) => { const fields = typeof row === 'string' ? row.split(' | ') : []; if (fields.length !== 5 || fields[1] !== `${['A', 'E', 'V'][i]} ${a.envelopeId}` || ledger.filter((x) => x === row).length !== 1 || !row.includes(packetSha256)) throw Error('startup admission row'); return ledger.indexOf(row); });
  if (!(positions[0] < positions[1] && positions[1] < positions[2]) || ledger.some((x) => /REVOKED/i.test(x) && (x.includes(packetSha256) || x.includes(a.envelopeId)))) throw Error('startup admission order or revocation');
  return true;
}

export function validateStartupEntrypoint(input) {
  validateStartupAdmission(input);
  const { admission: a, nodeSha256, launcherSha256, carry } = input;
  if (!/^[a-f0-9]{40}$/.test(a.sourceCommit ?? '') || !a.ownerRows[2].includes(`sourceCommit=${a.sourceCommit}`)) throw Error('startup source commit not bound');
  if (a.nodeSha256 !== nodeSha256 || a.launcherSha256 !== launcherSha256 || !a.ownerRows[2].includes(`launcherSha256=${launcherSha256}`) || !a.ownerRows[2].includes(`nodeSha256=${nodeSha256}`) || carry?.taskRequests !== 1177 || carry?.taskAdcAcquisitions !== 20 || carry?.taskCarriedUsd !== 19 || carry?.taskLimitUsd !== 20 || carry?.sandboxAtBaseline !== false || carry?.outcome !== 'cleanup-verified') throw Error('startup entrypoint custody mismatch');
  return true;
}

export function packageTreeHash(directory) {
  const root = realpathSync(directory), entries = [];
  const visit = (dir) => { for (const entry of readdirSync(dir, { withFileTypes: true })) { const f = path.join(dir, entry.name); if (entry.isDirectory()) visit(f); else if (entry.isFile()) entries.push(f); } };
  visit(root);
  const digest = createHash('sha256');
  for (const file of entries.sort((a, b) => Buffer.compare(Buffer.from(path.relative(root, a).split(path.sep).join('/')), Buffer.from(path.relative(root, b).split(path.sep).join('/'))))) {
    const name = Buffer.from(path.relative(root, file).split(path.sep).join('/')), data = readFileSync(file), n = Buffer.alloc(4), size = Buffer.alloc(8);
    n.writeUInt32BE(name.length); size.writeBigUInt64BE(BigInt(data.length)); digest.update(n).update(name).update(size).update(createHash('sha256').update(data).digest());
  }
  return digest.digest('hex');
}

export function verifyStartupBrowser(modules, admission) {
  const req = createRequire(path.join(path.resolve(modules), 'x.js'));
  const playwrightRoot = path.dirname(realpathSync(req.resolve('playwright')));
  const coreRoot = path.dirname(realpathSync(req.resolve('playwright-core', { paths: [playwrightRoot] })));
  if (packageTreeHash(playwrightRoot) !== admission.playwrightTreeSha256 || packageTreeHash(coreRoot) !== admission.playwrightCoreTreeSha256) throw Error('startup browser module custody mismatch');
  const chromium = req('playwright').chromium;
  const executable = realpathSync(chromium.executablePath());
  if (sha256(readFileSync(executable)) !== admission.chromiumSha256) throw Error('startup browser custody mismatch');
  return executable;
}

export function nixClosureHash(closure) {
  if (!closure || typeof closure !== 'object' || Array.isArray(closure) || !Object.keys(closure).length) throw Error('invalid Nix closure');
  const rows = Object.keys(closure).sort().map((name) => {
    const v = closure[name];
    if (!name.startsWith('/nix/store/') || !v || typeof v.narHash !== 'string' || !Number.isSafeInteger(v.narSize) || v.narSize < 0 || !Array.isArray(v.references) || v.references.some((r) => typeof r !== 'string')) throw Error('invalid Nix closure entry');
    return [name, v.narHash, v.narSize, [...v.references].sort()];
  });
  return sha256(JSON.stringify(rows));
}

export function verifyStartupGcloud(gcloud, admission, run = (exe, args) => execFileSync(exe, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 8 * 1024 * 1024, env: { PATH: '/usr/bin:/bin', HOME: process.env.HOME ?? '/' } })) {
  const nix = realpathSync(admission.nixPath), executable = realpathSync(gcloud);
  if (executable !== admission.gcloudRealPath || sha256(readFileSync(nix)) !== admission.nixSha256) throw Error('startup Nix runtime mismatch');
  const closure = JSON.parse(run(nix, ['path-info', '--offline', '--json-format', '1', '--json', '--recursive', executable]));
  if (nixClosureHash(closure) !== admission.gcloudClosureSha256) throw Error('startup gcloud closure mismatch');
}

export function startupTokeninfoFetch({ journal, fetchImpl = fetch }) {
  let used = false;
  return async (url, init) => {
    if (used || url !== 'https://oauth2.googleapis.com/tokeninfo' || init?.method !== 'POST') throw Error('startup tokeninfo stopped');
    used = true;
    try {
      await journal({ kind: 'before', step: 'tokeninfo', method: 'POST', url, body: '[REDACTED]' });
      const response = await fetchImpl(url, init);
      await journal({ kind: 'headers', step: 'tokeninfo', status: response.status, headers: Object.fromEntries(response.headers?.entries?.() ?? []) });
      const body = await response.text();
      await journal({ kind: 'after', step: 'tokeninfo', outcome: 'complete', bytes: Buffer.byteLength(body, 'utf8'), body });
      let consumed = false;
      return { status: response.status, async text() { if (consumed) throw Error('tokeninfo body already read'); consumed = true; return body; } };
    } catch (error) {
      try { await journal({ kind: 'unknown', step: 'tokeninfo', outcome: 'unknown' }); } catch { /* journal may itself be unavailable */ }
      throw error;
    }
  };
}

export function createStartupStrictClient({ caps, allowed, journal, fetchImpl = fetch, headers = {}, stop = {} }) {
  const counts = { observe: 0, cleanup: 0, mutations: 0, unknown: 0, logFailures: 0 }, unknownAnswers = [];
  let phase = 'observe', latched = false;
  async function call(step, method, url, body, { raw = false } = {}) {
    if (latched || stop.requested) throw Error('strict admin latched stop');
    if (!allowed(url, method)) { latched = true; throw Error('strict admin target rejected'); }
    const mutation = method !== 'GET';
    if (counts[phase] >= caps[phase] || (mutation && counts.mutations >= caps.mutations)) { latched = true; throw Error('strict admin cap'); }
    const sent = body === undefined || typeof body === 'string' ? body : JSON.stringify(body);
    counts[phase]++; if (mutation) counts.mutations++;
    let status = 0, text = '', value;
    try {
      await journal({ kind: 'before', step, phase, method, url, body: sent ?? null });
      const response = await fetchImpl(url, { method, body: sent, redirect: 'manual', headers: { 'content-type': 'application/json', ...headers }, signal: AbortSignal.timeout(30000) });
      status = response.status;
      await journal({ kind: 'headers', step, phase, method, url, status, headers: Object.fromEntries(response.headers?.entries?.() ?? []) });
      text = await response.text();
      await journal({ kind: 'after', step, phase, method, url, status, body: text });
      if (status < 200 || status >= 300) throw Error('non-success response');
      if (!raw && text !== '') value = JSON.parse(text);
      if (['api-enable', 'api-disable'].includes(step) && method === 'POST') { if (!validStartupOperation(value?.name)) throw Error('invalid startup operation'); allowed.register?.(value.name); }
      return { outcome: 'ok', status, text, value };
    } catch {
      latched = true; counts.unknown++; unknownAnswers.push(step);
      return { outcome: 'unknown', status, text };
    }
  }
  return { call, counts, unknownAnswers, cleanup: () => { phase = 'cleanup'; } };
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
  if (packet.scenario === 'sdk-next-startup' && packet.sources?.['rtdb-admin.mjs'] !== sha256(readFileSync(path.join(here, 'rtdb-admin.mjs')))) throw Error('startup admin source pin differs');
  return packet;
}

export function verifyRootStartup(packet, packetSha256, { root = path.resolve(here, '../../../..'), ownerPid = process.pid, nodePath = process.execPath, baselinePacketSha = 'b4fc959098c7a4dfe3e5294cc22729fbeb052ca369a7d949390b65bbc3fd9652' } = {}) {
  const ops = path.join(root, 'docs.local/runs/remaining-compat-20261028/rtdb-sdk-startup-runtime-v3/root-ops');
  for (const file of [path.join(ops, 'booked-admission.json'), path.join(ops, 'launch-startup.sh'), path.join(root, 'docs.local/instructions/owner-decisions.md'), path.join(root, 'docs.local/runs/sandbox-ledger.jsonl')]) if (!lstatSync(file).isFile()) throw Error('startup authority must be regular files');
  const booked = readFileSync(path.join(ops, 'booked-admission.json'));
  const admission = JSON.parse(booked);
  const baselineRaw = readFileSync(path.join(root, 'docs.local/runs/remaining-compat-20261028/rtdb-rules-operators-03/root-ops/v1-snapshot/packet.json'));
  if (sha256(baselineRaw) !== baselinePacketSha) throw Error('startup baseline pin differs');
  const baseline = JSON.parse(baselineRaw);
  if (baseline.project !== 'fireemu-oracle-query' || baseline.projectNumber !== packet.projectNumber || baseline.instance !== INSTANCE || baseline.baselineRulesSha256 !== packet.baselineRulesSha256) throw Error('startup baseline identity differs');
  const ledger = readFileSync(path.join(root, 'docs.local/instructions/owner-decisions.md'), 'utf8').split(/\r?\n/);
  admission.ownerRows = ['A', 'E', 'V'].map((kind) => { const rows = ledger.filter((line) => line.split(' | ')[1] === `${kind} ${admission.envelopeId}`); if (rows.length !== 1) throw Error('startup authority row is not unique'); return rows[0]; });
  if (!admission.ownerRows[2]?.includes(`admissionSha256=${sha256(booked)}`)) throw Error('startup booked admission not bound');
  const lease = JSON.parse(readFileSync(path.join(root, 'docs.local/runs/sandbox-locks/fireemu-oracle-query.lock'), 'utf8'));
  if (lease.pid !== ownerPid || lease.envelopeId !== admission.envelopeId || !existsSync(path.join(root, 'docs.local/runs/heavy-slots/RECORDING'))) throw Error('startup lease not owned by launcher');
  const gcloudSha256 = sha256(readFileSync(packet.gcloud));
  if (admission.gcloudSha256 !== gcloudSha256 || !admission.ownerRows[2].includes(`gcloudSha256=${gcloudSha256}`)) throw Error('startup credential executable mismatch');
  const raw = readFileSync(path.join(root, 'docs.local/runs/sandbox-ledger.jsonl'), 'utf8').split('\n').filter(Boolean);
  const parsed = raw.map((line) => ({ line, value: JSON.parse(line) })), row = parsed[1195];
  if (!row || packet.projectId !== 'fireemu-oracle-query' || row.value.project !== packet.projectId || parsed.filter(({ value }) => value.project === packet.projectId).at(-1) !== row || admission.projectId !== packet.projectId || !/^[0-9]{1,20}$/.test(packet.projectNumber ?? '') || admission.projectNumber !== packet.projectNumber) throw Error('startup sandbox mismatch');
  const carrySha256 = sha256(`${row.line}\n`);
  validateStartupEntrypoint({ admission, packetSha256, sourceSha256: sha256(readFileSync(path.join(here, 'rtdb-residual.mjs'))), carrySha256, nodeSha256: sha256(readFileSync(nodePath)), launcherSha256: sha256(readFileSync(path.join(ops, 'launch-startup.sh'))), ledger, carry: row.value });
  for (const field of ['chromiumSha256', 'playwrightTreeSha256', 'playwrightCoreTreeSha256', 'nixSha256', 'gcloudClosureSha256', 'gcloudRealPath']) if (typeof admission[field] !== 'string' || !admission.ownerRows[2].includes(`${field}=${admission[field]}`)) throw Error('startup runtime pins not bound');
  verifyStartupGcloud(packet.gcloud, admission);
  return verifyStartupBrowser(packet.modules, admission);
}

/** Production remains unavailable until the SDK transport retry barrier is reviewed. */
export function assertProductionSdkNextReady(packet) {
  if (['sdk-next', 'sdk-next-startup'].includes(packet?.scenario)) throw Error('sdk-next transport guard unverified');
}

// Conservative fixed-corpus diagnostic. Production remains blocked pending source/transport review.
export function installSdkNextWsGuard({ host, namespace, base, secure = false, noMutations = false, maxConnections = 2, maxMessages = 1250, maxControls = 4 }) {
  const Native = globalThis.WebSocket, originalSend = Native.prototype.send;
  if (noMutations) {
    if (![maxConnections, maxMessages, maxControls].every((n) => Number.isSafeInteger(n) && n >= 0)) throw Error('invalid startup limits');
    maxConnections = Math.min(maxConnections, 2); maxMessages = Math.min(maxMessages, 16); maxControls = Math.min(maxControls, 4);
  }
  Object.defineProperty(globalThis, 'MozWebSocket', { value: undefined, writable: false, configurable: false });
  if (typeof window !== 'undefined' && window.top !== window) {
    Object.defineProperty(globalThis, 'WebSocket', { value: new Proxy(Native, { construct() { throw Error('sdk-next child frame blocked'); } }), writable: false, configurable: false });
    return;
  }
  if (typeof window !== 'undefined') Object.defineProperty(globalThis, 'open', { value: () => { throw Error('sdk-next popup blocked'); }, writable: false, configurable: false });
  const order = ['startup-w', 'startup-o', 'seed', 'push-a', 'write-a', 'read-a', 'push-b', 'write-b', 'read-b', 'update', 'get-update-preserves-sibling', 'replace', 'get-set-replaces-node', 'fanout', 'get-atomic-multipath-final', 'change', 'move', 'server-values', 'get-server-values', 'transaction-abort', 'transaction-apply'];
  const writes = { seed: 'p', 'write-a': 'p', 'write-b': 'p', update: 'm', replace: 'p', fanout: 'm', change: 'm', move: 'm', 'server-values': 'm', 'transaction-apply': 'p' };
  let frozen = false, armed = false, terminal = false, unknown = false, connections = 0, messages = 0, operation = null, operationIndex = 0, mutationSent = false;
  const sockets = new Set(), sessions = new Map(), pending = new Map(), startup = new Set(), seenMutations = new Set(), requests = new WeakMap(), pendingReads = new Map(), stats = new Set(), controls = [];
  let readSent = false;
  const freeze = () => { if (!terminal) { if (pending.size) unknown = true; frozen = true; } };
  const fail = (why) => { freeze(); throw new Error(`sdk-next transport frozen: ${why}`); };
  const within = (p) => typeof p === 'string' && (p === `/${base}` || p.startsWith(`/${base}/`)) && !p.split('/').some((part) => part === '.' || part === '..');
  const request = (socket, data) => {
    if (data === '0') return;
    if (typeof data !== 'string' || data.length > 16384) return fail('nontext or oversize send');
    if (/^\d+$/.test(data)) return fail('fragment send');
    let msg;
    try { msg = JSON.parse(data); } catch { return fail('unknown outgoing message'); }
    if (msg?.t !== 'd' || !msg.d || !Number.isSafeInteger(msg.d.r) || typeof msg.d.a !== 'string') return fail('unknown outgoing protocol');
    const { r, a, b } = msg.d;
    if (noMutations) {
      if (a === 'p' || a === 'm') return fail('startup-only mutation');
      if (a === 's') { if (stats.has(socket)) return fail('startup stats retry'); stats.add(socket); }
      else if (a === 'g') {
        if (b?.p !== `/${base}`) return fail('startup root scope');
        if (!operation?.startsWith('startup-') || readSent || pendingReads.size) return fail('startup read retry');
        readSent = true; pendingReads.set(socket, r);
      } else return fail('startup-only unsupported action');
    }
    const tracker = requests.get(socket);
    if (!tracker || tracker.seen.has(r)) return fail('request id reuse');
    tracker.seen.add(r); tracker.waiting.add(r);
    if (a !== 's' && (!['g', 'q', 'n', 'p', 'm'].includes(a) || !within(b?.p))) return fail('outgoing scope');
    if (a === 'm' && (!b?.d || typeof b.d !== 'object' || Array.isArray(b.d) || Object.keys(b.d).some((key) => key.split('/').some((part) => !part || part === '.' || part === '..' || /[.#$\[\]]/.test(part))))) return fail('outgoing scope');
    if (a === 'p' || a === 'm') {
      if (!armed) return fail('startup mutation');
      if (!operation || writes[operation] !== a || mutationSent) return fail('mutation retransmit or unexpected operation');
      if (pending.size) return fail('pending mutation');
      const fingerprint = JSON.stringify([a, b]);
      if (seenMutations.has(fingerprint)) return fail('mutation retransmit');
      seenMutations.add(fingerprint);
      mutationSent = true;
      pending.set(socket, r);
    }
  };
  const guardedSend = function (data) {
    if (frozen || terminal || !sockets.has(this)) return fail('send refused');
    request(this, data);
    if (++messages > maxMessages) return fail('send limit');
    try { return Reflect.apply(originalSend, this, [data]); } catch (e) { freeze(); throw e; }
  };
  Object.defineProperty(Native.prototype, 'send', { value: guardedSend, writable: false, configurable: false });
  const Guarded = new Proxy(Native, {
    construct(target, args) {
      if (frozen || terminal || armed) return fail('new connection refused');
      let url;
      try { url = new URL(String(args[0])); } catch { return fail('invalid URL'); }
      const ns = url.searchParams.getAll('ns');
      const hostBindsNamespace = secure && host === `${namespace}.firebaseio.com`;
      if (url.protocol !== (secure ? 'wss:' : 'ws:') || url.host !== host || url.pathname !== '/.ws' || !((ns.length === 1 && ns[0] === namespace) || (ns.length === 0 && hostBindsNamespace))) return fail('connection scope/host/namespace');
      if (++connections > maxConnections) return fail('connection limit');
      let ws;
      try { ws = Reflect.construct(target, args, target); } catch (e) { freeze(); throw e; }
      sockets.add(ws);
      requests.set(ws, { seen: new Set(), waiting: new Set() });
      ws.addEventListener('error', freeze);
      ws.addEventListener('close', freeze);
      ws.addEventListener('message', (event) => {
        if (frozen || terminal) return;
        const data = event.data;
        if (data === '0') return;
        if (typeof data !== 'string' || data.length > 16384 || /^\d+$/.test(data)) { freeze(); return; }
        let msg;
        try { msg = JSON.parse(data); } catch { freeze(); return; }
        if (msg?.t === 'c') {
          const ctrl = msg.d;
          if (noMutations && ['h', 'r'].includes(ctrl?.t)) {
            if (controls.length >= maxControls || new TextEncoder().encode(data).length > 4096) { freeze(); return; }
            controls.push(data);
          }
          if (ctrl?.t === 'h' && !armed && !sessions.has(ws) && ctrl.d?.h === host && ctrl.d?.v === '5' && typeof ctrl.d?.s === 'string' && ctrl.d.s.length > 0) { sessions.set(ws, ctrl.d.s); return; }
          if (ctrl?.t === 'o') return;
          freeze(); return;
        }
        if (msg?.t !== 'd' || !msg.d || typeof msg.d !== 'object') { freeze(); return; }
        if (Object.hasOwn(msg.d, 'r')) {
          const tracker = requests.get(ws);
          if (!Number.isSafeInteger(msg.d.r) || !tracker?.waiting.has(msg.d.r)) { freeze(); return; }
          tracker.waiting.delete(msg.d.r);
          if (msg.d.b?.s !== 'ok') { freeze(); return; }
          if (pendingReads.has(ws) && msg.d.r === pendingReads.get(ws)) pendingReads.delete(ws);
          if (pending.has(ws) && msg.d.r === pending.get(ws)) pending.delete(ws);
        } else if (!['d', 'm'].includes(msg.d.a) || typeof msg.d.b?.p !== 'string' || !within(msg.d.b.p.startsWith('/') ? msg.d.b.p : `/${msg.d.b.p}`)) { freeze(); }
      });
      return ws;
    },
  });
  Object.defineProperty(globalThis, 'WebSocket', { value: Guarded, writable: false, configurable: false });
  Object.defineProperty(globalThis, '__sdkNextWsGuard', { value: Object.freeze({
    startupRead(actor, value) { if (frozen || armed || operation || value !== null || !['w', 'o'].includes(actor) || startup.has(actor) || (actor === 'w' ? operationIndex !== 1 : operationIndex !== 2 || !startup.has('w'))) return fail('startup read'); startup.add(actor); },
    arm() { if (noMutations) return fail('startup-only mutation arm'); if (frozen || terminal || operationIndex !== 2 || startup.size !== 2 || sockets.size !== 2 || sessions.size !== 2 || new Set(sessions.values()).size !== 2 || [...sockets].some((s) => s.readyState !== Native.OPEN)) return fail('startup sessions incomplete'); armed = true; },
    beginOperation(label) { if (frozen || terminal || operation || label !== order[operationIndex] || (!armed && !label.startsWith('startup-'))) return fail('startup or operation order'); operation = label; mutationSent = false; readSent = false; },
    endOperation() { if (frozen || terminal || !operation || pending.size || pendingReads.size || (noMutations && operation.startsWith('startup-') && !readSent) || (writes[operation] && !mutationSent)) return fail('pending or invalid operation'); operation = null; operationIndex++; },
    finishStartup() { if (!noMutations || frozen || terminal || armed || operation || operationIndex !== 2 || startup.size !== 2 || sockets.size !== 2 || sessions.size !== 2 || new Set(sessions.values()).size !== 2 || pendingReads.size || [...sockets].some((socket) => requests.get(socket).waiting.size)) return fail('startup not quiescent'); terminal = true; },
    controls() { return controls.slice(); },
    freeze,
    assertHealthy() { if (frozen || terminal) return fail('unhealthy'); },
    quiescent() { return pending.size === 0 && [...sockets].every((socket) => requests.get(socket).waiting.size === 0); },
    finish() { if (noMutations) return fail('startup-only terminal'); if (pending.size) return fail('pending mutation'); if (frozen || !armed || operation || operationIndex !== order.length || [...sockets].some((socket) => requests.get(socket).waiting.size)) return fail('terminal not quiescent'); terminal = true; },
    status() { return { frozen, armed, terminal, unknown, noMutations, connections, messages, pending: pending.size, operationIndex, controlCount: controls.length }; },
  }), writable: false, configurable: false });
}

// Long polling opens no WebSocket; any WebSocket means the SDK used that transport.
export const transportOf = (counts) => (counts.ws > 0 ? 'ws' : 'lp');
export const profileTimeout = (cfg) => (cfg.scenario === 'cv10' ? PROFILE_TIMEOUT_MS.cv10[cfg.transport] : cfg.scenario === 'sdk-next-startup' ? PROFILE_TIMEOUT_MS.startup : PROFILE_TIMEOUT_MS.cv08);

// One profile in headless Chromium. The page and SDK bundles are served from loopback; HTTP requests,
// WebSockets and WebSocket frames are counted against the caps, and Chromium itself resolves nothing
// but loopback and Firebase hosts (--host-rules).
export const browserContextOptions = (scenario) => ['sdk-next', 'sdk-next-startup'].includes(scenario) ? { serviceWorkers: 'block' } : {};

export function harnessPort(value) {
  if (value === undefined) return 0;
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || Number(value) > 65535) throw Error('invalid harness port');
  return Number(value);
}

export function createPrivateControlWriter(write, secrets) {
  let count = 0;
  return (profile, raw) => {
    if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 4096 || count >= 8) throw Error('private control limit');
    const line = `${JSON.stringify({ profile, raw })}\n`;
    assertNoSecrets(line, secrets);
    write(Buffer.from(line));
    count++;
  };
}

export function createPrivateAdminJournal(file, secrets) {
  return (row) => {
    const line = `${JSON.stringify(row)}\n`;
    assertNoSecrets(line, secrets);
    const bytes = Buffer.from(line);
    const fd = openSync(file, 'a', 0o600);
    try { let offset = 0; while (offset < bytes.length) { const n = writeSync(fd, bytes, offset); if (!n) throw Error('short admin journal write'); offset += n; } fsyncSync(fd); } finally { closeSync(fd); }
  };
}

export function prepareStartupJournals(out, syncDirectory = (directory) => { const fd = openSync(directory, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); } }) {
  for (const name of ['private-admin.jsonl', 'private-controls.jsonl']) { const fd = openSync(path.join(out, name), 'wx', 0o600); try { fsyncSync(fd); } finally { closeSync(fd); } }
  syncDirectory(out);
}

export function browserRunner({ modules, page: pageConfig, stop = {}, startupExecutable }) {
  const require = createRequire(path.join(path.resolve(modules), 'x.js'));
  const { chromium } = require('playwright');
  return async (cfg, hooks) => {
    const server = createServer((req, res) => {
      const file = req.url === '/page.js' ? path.join(here, 'rtdb-residual-page.js') : null;
      res.writeHead(200, { 'content-type': file ? 'text/javascript' : 'text/html' });
      res.end(file ? readFileSync(file) : '<!doctype html><script type="module" src="/page.js"></script>');
    });
    await new Promise((r) => server.listen(harnessPort(process.env.PORT), '127.0.0.1', r));
    const origin = `127.0.0.1:${server.address().port}`, counts = { http: 0, ws: 0, frames: 0, blocked: 0 }, journal = [];
    const browser = await chromium.launch({ ...LAUNCH, ...(cfg.scenario === 'sdk-next-startup' && startupExecutable ? { executablePath: startupExecutable } : {}), args: [hostRules()] });
    stop.closeBrowser = () => browser.close().catch(() => {});
    let overCap;
    const capped = new Promise((_, reject) => { overCap = () => reject(Error('browser request cap reached')); });
    capped.catch(() => {});
    try {
      const context = await browser.newContext(browserContextOptions(cfg.scenario));
      if (['sdk-next', 'sdk-next-startup'].includes(cfg.scenario) && cfg.transport === 'ws') {
        const target = new URL(pageConfig.databaseURL);
        await context.addInitScript(installSdkNextWsGuard, { host: target.host, namespace: target.searchParams.get('ns') ?? INSTANCE, base: cfg.base, secure: target.protocol === 'https:', noMutations: cfg.scenario === 'sdk-next-startup', maxMessages: cfg.scenario === 'sdk-next-startup' ? 16 : 1250, maxControls: 4 });
      }
      if (['sdk-next', 'sdk-next-startup'].includes(cfg.scenario) && cfg.transport === 'ws') await context.addInitScript(() => { for (const name of ['Worker', 'SharedWorker']) if (name in globalThis) Object.defineProperty(globalThis, name, { value: function () { throw Error('worker blocked'); }, writable: false, configurable: false }); });
      if (pageConfig.emulator) await context.grantPermissions(['local-network-access'], { origin: `http://${origin}` }).catch(() => {});
      const page = await context.newPage();
      const routeRequests = (route) => {
        const url = new URL(route.request().url());
        if (url.host === origin) return route.continue();
        if (url.host === 'www.gstatic.com' && url.pathname.startsWith('/firebasejs/12.18.0/')) {
          if (['sdk-next', 'sdk-next-startup'].includes(cfg.scenario) && cfg.transport === 'ws' && (url.origin !== 'https://www.gstatic.com' || url.search || !['/firebasejs/12.18.0/firebase-app.js', '/firebasejs/12.18.0/firebase-database.js'].includes(url.pathname))) { counts.blocked++; return route.abort(); }
          return route.fulfill({ contentType: 'text/javascript', body: readFileSync(path.resolve(modules, 'firebase', path.basename(url.pathname))) });
        }
        if (['sdk-next', 'sdk-next-startup'].includes(cfg.scenario) && cfg.transport === 'ws') { counts.blocked++; return route.abort(); }
        if (!pageConfig.allowHost(url.host)) { counts.blocked++; return route.abort(); }
        if (++counts.http > CAPS.browserHttp) { overCap(); return route.abort(); }
        return route.continue();
      };
      if (['sdk-next', 'sdk-next-startup'].includes(cfg.scenario) && cfg.transport === 'ws') await context.route('**/*', routeRequests);
      else await page.route('**/*', routeRequests);
      page.on('websocket', (ws) => {
        if (++counts.ws > CAPS.browserWs) overCap();
        for (const kind of ['framesent', 'framereceived']) ws.on(kind, () => { if (++counts.frames > CAPS.browserFrames) overCap(); });
      });
      await page.exposeFunction('__rrEvent', (e) => { const row = Object.fromEntries(Object.entries(e).filter(([, v]) => v !== undefined)); hooks.event(`${cfg.scenario}:${cfg.name}`, row); journal.push(row); });
      await page.exposeFunction('__rrHook', (name) => hooks[name]());
      await page.goto(`http://${origin}/`);
      await page.waitForFunction(() => typeof window.__rrRun === 'function');
      const timeout = new Promise((_, reject) => setTimeout(() => reject(Error('profile timeout')), profileTimeout(cfg)).unref());
      timeout.catch(() => {});
      await Promise.race([page.evaluate((c) => window.__rrRun(c), { ...pageConfig, ...cfg, allowHost: undefined, wsGuardRequired: ['sdk-next', 'sdk-next-startup'].includes(cfg.scenario) && cfg.transport === 'ws' }), capped, timeout]);
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
  for (const [f, value] of [['result.json', { ...result, profiles: undefined, prefixRoot }], ['journal.json', { mode, profiles: result.profiles.map((p) => ({ scenario: p.scenario, name: p.name, counts: p.counts, journal: p.journal.filter((r) => r.type !== 'raw-control') })) }]]) {
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
  const selected = scenarios ? pick(scenarios, SCENARIOS, '--scenarios') : undefined;
  if (selected?.includes('sdk-next-startup')) {
    if (selected.length !== 1 || (transports && transports !== 'ws')) throw Error('startup requires exactly two WS profiles');
    return { scenarios: selected, profiles: PROFILES.filter((p) => p.transport === 'ws') };
  }
  return {
    ...(selected ? { scenarios: selected } : {}),
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
  if (packet?.scenario === 'sdk-next-startup') harnessPort(process.env.PORT);
  let startup = false, startupExecutable;
  if (packet) { if (packet.scenario !== undefined && !['sdk-next', 'sdk-next-startup'].includes(packet.scenario)) throw Error('invalid fixed packet scenario'); if (packet.scenario === 'sdk-next-startup') { startupExecutable = verifyRootStartup(packet, opt('--packet-sha256')); startup = true; } else assertProductionSdkNextReady(packet); verifyBundles(packet); }
  mkdirSync(out); // refuses an existing directory
  const secrets = [], stop = { requested: false };
  if (startup) prepareStartupJournals(out);
  const strictJournal = startup ? createPrivateAdminJournal(path.join(out, 'private-admin.jsonl'), secrets) : undefined;
  // Logs are redacted, never refused: a row that cannot be written would hide a sent request.
  const append = (f, row) => appendFileSync(path.join(out, f), `${redact(JSON.stringify(row), secrets).replace(/\n/g, ' ')}\n`);
  const privateControl = createPrivateControlWriter((bytes) => {
    const fd = openSync(path.join(out, 'private-controls.jsonl'), 'a', 0o600);
    try { let offset = 0; while (offset < bytes.length) { const n = writeSync(fd, bytes, offset); if (!n) throw Error('short private control write'); offset += n; } fsyncSync(fd); } finally { closeSync(fd); }
  }, secrets);
  // A signal or a crash stops the observation; cleanup then runs once through runScenario's finally.
  const onStop = (why) => { if (!stop.requested) console.error(`rtdb-residual: ${why}: stopping the observation, cleanup continues`); stop.requested = true; stop.closeBrowser?.(); };
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => onStop(signal));
  process.on('unhandledRejection', () => onStop('unhandled rejection'));
  process.on('uncaughtException', () => onStop('uncaught exception'));
  const prefix = `${packet?.prefixRoot ?? 'parity20261027'}/rr${randomBytes(5).toString('hex')}`;
  const common = { prefix, secrets, stop, log: (row) => append('requests.jsonl', row), event: (name, row) => row.type === 'raw-control' ? privateControl(name, row.shape) : append('events.jsonl', { profile: name, ...row }) };
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
      const stopped = await runPreflight(out, token, startup ? startupTokeninfoFetch({ journal: strictJournal }) : fetch, (text) => assertNoSecrets(text, secrets));
      if (stopped) return stopped;
      const browser = browserRunner({ modules: packet.modules, stop, startupExecutable, page: { projectId: packet.projectId, databaseURL: `https://${INSTANCE}.firebaseio.com`, allowHost: (h) => /^[a-z0-9-]+\.firebaseio\.com$/.test(h) } });
      o = { mode, packet, headers: productionHeaders(token, packet.projectId), browser, ...common, ...(startup ? { scenarios: ['sdk-next-startup'], strictStartup: true, strictJournal, ticket: startupTicket } : {}) };
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
