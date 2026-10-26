// node --test rtdb-residual.test.mjs: the residual recorder's production state machine, hooks, caps and
// outputs against an in-memory fake of the production APIs (no network, no browser).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { LAUNCH } from './cv11-genuine-auth.mjs';
import { ADC_ARGS, isDisabledByOwner, CAPS, FIRE_GRACE_MS, PROFILES, PROFILE_TIMEOUT_MS, SOURCES, compareFiles, hostRules, narrowing, productionHeaders, profileTimeout, refuseNarrowing, rulesFor, runScenario, transportOf, urls, verifyBundles, verifyPacket, writeOutputs } from './rtdb-residual.mjs';

const N = '000000000000', P = 'demo-project', BASE = '// baseline\n{"rules":{".read":false,".write":false}}', PREFIX = 'parity1/rr1';
const json = (status, v) => ({ status, text: async () => (typeof v === 'string' ? v : JSON.stringify(v)) });
const FORBIDDEN = JSON.stringify({ error: { code: 403, message: 'denied for ya29.a0secret and AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', status: 'PERMISSION_DENIED' } });

// A fake of the production APIs. A fault {method, path (regexp), kind, applied, skip} fires once, on the
// (skip+1)th match; kind 'lie' answers 200 with a plausible body without applying the request.
function fakeWorld(faults = []) {
  const w = { api: 'DISABLED', inst: 'DELETED', rules: BASE, rulesPuts: [], data: {}, ops: 0, sent: [] };
  const inst = (state) => ({ name: `projects/${N}/locations/us-central1/instances/fireemu-q-rtdb2`, type: 'USER_DATABASE', state });
  function apply(method, u, body) {
    const p = u.pathname;
    if (u.host === 'serviceusage.googleapis.com') {
      if (p.startsWith('/v1/operations/')) return json(200, { name: p.slice(4), done: true });
      if (method === 'GET') return json(200, { name: `projects/${N}/services/firebasedatabase.googleapis.com`, state: w.api });
      w.api = p.endsWith(':enable') ? 'ENABLED' : 'DISABLED';
      return json(200, { name: `operations/op${++w.ops}`, done: w.ops % 2 === 0 });
    }
    if (u.host === 'firebasedatabase.googleapis.com') {
      if (p.endsWith('/-/instances')) return json(200, { instances: [...(w.inst === 'DELETED' ? [] : [inst(w.inst)]), ...(w.foreign ? [{ name: 'other' }] : [])] });
      const verb = p.split(':')[1];
      if (method === 'DELETE') w.inst = 'DELETED';
      else if (verb) w.inst = { undelete: 'DISABLED', reenable: 'ACTIVE', disable: 'DISABLED' }[verb];
      return json(200, inst(w.inst));
    }
    const key = decodeURIComponent(p.replace(/\.json$/, '').slice(1));
    if (key === '.settings/rules') { if (method === 'PUT') { w.rules = body; w.rulesPuts.push(body); return json(200, { status: 'ok' }); } return json(200, w.rules); }
    if (method === 'PUT') { w.data[key] = body; return json(200, body); }
    if (method === 'DELETE') { for (const k of Object.keys(w.data)) if (k.startsWith(key)) delete w.data[k]; return json(200, null); }
    return json(200, Object.keys(w.data).some((k) => k.startsWith(key)) ? {} : null);
  }
  w.fetch = async (url, init) => {
    const u = new URL(url), body = init.body === undefined ? undefined : /rules/.test(u.pathname) ? init.body : JSON.parse(init.body);
    w.sent.push(`${init.method} ${u.pathname}`);
    if (init.method === 'GET' && w.forbid?.path.test(u.pathname) && w.forbid.remaining-- > 0) return json(w.forbid.status ?? 403, w.forbid.body ?? FORBIDDEN);
    const f = faults.find((x) => !x.used && x.method === init.method && x.path.test(u.pathname) && !(x.skip-- > 0));
    if (!f) return apply(init.method, u, body);
    f.used = true;
    if (f.kind === 'lie') return json(200, /rules/.test(u.pathname) ? { status: 'ok' } : init.method === 'DELETE' ? null : {});
    const answer = f.applied ? apply(init.method, u, body) : undefined;
    if (f.kind === 'timeout') throw new Error('timeout');
    return json(f.kind === '5xx' ? 503 : f.kind === '3xx' ? 302 : f.kind === '4xx' ? 400 : 199, answer ? await answer.text() : '');
  };
  w.baseline = () => w.api === 'DISABLED' && w.inst === 'DELETED' && w.rules === BASE && !Object.keys(w.data).length;
  return w;
}
// The rules PUT body in the fake is the parsed object; the first GET before the install returns BASE as text.
const fire = (seconds = 0.1) => ({ scenario: 'cv10', step: 'fire', type: 'timing', seconds });
// The browser stand-in follows the page: cv10 opens the Rules, denies them, then the writer fires.
const fakeBrowser = (w, extra = {}) => async (cfg, hooks) => {
  w.data[`${cfg.base}/seed`] = 1; // the page's data under the run prefix
  const journal = [];
  if (cfg.scenario === 'cv10') {
    journal.push({ scenario: 'cv10', step: 'rules-open', type: 'admin', code: await hooks.rulesOpen() });
    journal.push({ scenario: 'cv10', step: 'rules-deny', type: 'admin', code: await hooks.rulesDeny() });
    if (!extra.noFire) journal.push(fire());
  } else journal.push({ scenario: 'cv08', step: 'end', type: 'done' });
  return { journal, counts: { http: 1, ws: 1, frames: 1 } };
};
const packet = { projectId: P, projectNumber: N, baselineRulesSha256: createHash('sha256').update(BASE).digest('hex') };
const prod = (w, extra = {}) => runScenario({ mode: 'production', packet, fetchImpl: w.fetch, headers: {}, browser: fakeBrowser(w), sleep: async () => {}, log: () => {}, prefix: PREFIX, ...extra });
const local = (w, extra = {}) => prod(w, { mode: 'local', packet: undefined, local: { db: 'http://127.0.0.1:2', ns: 'demo' }, ...extra });

test('rules: the run prefix is the only open part; deny closes e7, e8 and dprobe writes and nothing else', () => {
  const open = rulesFor(PREFIX), deny = rulesFor(PREFIX, { deny: true });
  assert.equal(open.rules['.read'], false); assert.equal(open.rules['.write'], false);
  assert.deepEqual(Object.keys(open.rules), ['.read', '.write', 'parity1']);
  const cell = (r) => r.rules.parity1.rr1.cv10.$cell;
  for (const p of ['e7', 'e8', 'dprobe']) { assert.deepEqual(cell(open)[p], { '.write': true }); assert.deepEqual(cell(deny)[p], { '.write': false }); }
  const strip = (r) => { const c = JSON.parse(JSON.stringify(r)); for (const p of ['e7', 'e8', 'dprobe']) delete c.rules.parity1.rr1.cv10.$cell[p]; return c; };
  assert.deepEqual(strip(open), strip(deny));
  assert.equal(cell(open)['.read'], true);
  assert.deepEqual(cell(open).marker, { '.write': true });
  const cv08 = open.rules.parity1.rr1.cv08.$cell;
  assert.equal(cv08.gated['.read'], "data.parent().child('gate').val() === true");
  assert.deepEqual(cv08.items['.indexOn'], ['score']);
  assert.deepEqual(rulesFor('a/b').rules.a.b.cv08.$cell.gate, { '.read': true, '.write': true });
});

test('production dry run: eight profiles, setup and cleanup request list, world back at baseline, closed', async () => {
  const w = fakeWorld(), r = await prod(w);
  assert.equal(r.status, 'closed'); assert.ok(r.observationComplete); assert.ok(w.baseline());
  assert.deepEqual(r.profiles.map((p) => `${p.scenario}:${p.name}`), ['cv08', 'cv10'].flatMap((s) => PROFILES.map((p) => `${s}:${p.name}`)));
  assert.deepEqual(w.sent.slice(0, 3), ['GET /v1/projects/000000000000/services/firebasedatabase.googleapis.com', 'POST /v1/projects/000000000000/services/firebasedatabase.googleapis.com:enable', 'GET /v1/operations/op1']);
  assert.equal(r.counts.observe + r.counts.cleanup, w.sent.length);
  assert.ok(r.counts.observe <= CAPS.observe && r.counts.cleanup <= CAPS.cleanup && r.counts.mutations <= CAPS.mutations, JSON.stringify(r.counts));
  assert.equal(w.rulesPuts.length, 1 + 8 + 1, 'install, open and deny for each of four cv10 profiles, and the restore');
  assert.equal(w.rulesPuts.at(-1), BASE, 'the last write is the baseline text, byte for byte');
  assert.deepEqual(w.rulesPuts.slice(0, -1).map((x) => JSON.parse(x).rules.parity1.rr1.cv10.$cell.e7['.write']), [true, true, false, true, false, true, false, true, false]);
});

test('the Rules hooks install and read back the open and deny Rules, and cleanup restores the baseline text', async () => {
  const w = fakeWorld(), seen = [];
  await prod(w, { browser: async (cfg, hooks) => { await hooks.rulesOpen(); seen.push(w.rules); await hooks.rulesDeny(); seen.push(w.rules); return { journal: [fire()], counts: {} }; } });
  assert.deepEqual(seen.slice(0, 2).map((x) => JSON.parse(x)), [rulesFor(PREFIX), rulesFor(PREFIX, { deny: true })]);
  assert.equal(w.rules, BASE);
});

test('a hook whose Rules PUT is refused ends the profile, stops later profiles, and the run restores the baseline', async () => {
  const w = fakeWorld([{ method: 'PUT', path: /rules/, kind: '4xx', skip: 2 }]);
  const r = await prod(w);
  assert.ok(!r.observationComplete); assert.ok(w.baseline()); assert.equal(r.status, 'closed');
  assert.ok(r.errors.some((e) => /rules-deny-cv10-r1-ws-2-put: refused/.test(e)), r.errors.join());
  assert.equal(r.profiles.filter((p) => p.scenario === 'cv10').length, 0, 'the failing profile is not kept and no profile follows it');
  assert.equal(w.rulesPuts.length, 3, 'install, open and the baseline restore were applied; the refused deny was not');
});

test('a Rules PUT with an unknown answer is settled by the restore: closed when the baseline reads back', async () => {
  const w = fakeWorld([{ method: 'PUT', path: /rules/, kind: '5xx', applied: true, skip: 1 }]);
  const r = await prod(w);
  assert.ok(w.baseline()); assert.equal(r.status, 'closed'); assert.ok(!r.observationComplete);
  assert.equal(r.counts.unknown, 1);
});

test('a cv10 profile that never saw the writer disconnect makes cleanup wait for pending onDisconnect writes before the prefix delete', async () => {
  const w = fakeWorld(), slept = [], order = [];
  const r = await prod(w, { sleep: async (ms) => { slept.push(ms); order.push(`sleep ${ms}`); }, log: (x) => { if (x.step === 'prefix-delete') order.push('delete'); }, browser: fakeBrowser(w, { noFire: true }) });
  assert.ok(w.baseline()); assert.equal(r.status, 'closed');
  assert.ok(slept.includes(FIRE_GRACE_MS));
  assert.ok(order.indexOf(`sleep ${FIRE_GRACE_MS}`) < order.indexOf('delete'));
  const ok = [];
  await prod(fakeWorld(), { sleep: async (ms) => { ok.push(ms); } });
  assert.ok(!ok.includes(FIRE_GRACE_MS), 'no wait when every writer disconnect was observed');
});

test('a marker-fire timeout row does not count as an observed disconnect', async () => {
  const slept = [];
  const browser = async (cfg, hooks) => ({ journal: cfg.scenario === 'cv10' ? [{ scenario: 'cv10', step: 'disconnect', type: 'timeout', label: 'marker fire' }, fire(240)] : [], counts: {} });
  await prod(fakeWorld(), { browser, sleep: async (ms) => { slept.push(ms); } });
  assert.ok(slept.includes(FIRE_GRACE_MS));
  const other = [];
  const browser2 = async (cfg) => ({ journal: cfg.scenario === 'cv10' ? [{ scenario: 'cv10', step: 'attach', type: 'timeout', label: 'first values' }, fire(0.1)] : [], counts: {} });
  await prod(fakeWorld(), { browser: browser2, sleep: async (ms) => { other.push(ms); } });
  assert.ok(!other.includes(FIRE_GRACE_MS), 'only the marker timeout means the writer disconnect was not seen');
  const missingSeconds = [];
  await prod(fakeWorld(), { browser: async (cfg) => ({ journal: cfg.scenario === 'cv10' ? [{ scenario: 'cv10', step: 'fire', type: 'timing' }] : [], counts: {} }), sleep: async (ms) => { missingSeconds.push(ms); } });
  assert.ok(missingSeconds.includes(FIRE_GRACE_MS), 'a timing row without seconds is no observation');
});

test('a different baseline Rules text or a non-empty prefix stops before any Rules or data write', async () => {
  for (const tweak of [(w) => { w.rules = `${BASE} `; }, (w) => { w.data[`${PREFIX}/x`] = 1; }]) {
    const w = fakeWorld();
    tweak(w);
    const r = await prod(w);
    assert.ok(!r.observationComplete);
    assert.ok(!w.sent.some((s) => s.startsWith('PUT')), w.sent.join());
    assert.equal(w.api, 'DISABLED'); assert.equal(w.inst, 'DELETED');
  }
});

test('local dry run uses no management API and restores the baseline Rules text', async () => {
  const w = fakeWorld(), r = await local(w);
  assert.equal(r.status, 'closed'); assert.equal(w.rules, BASE);
  assert.ok(!w.sent.some((s) => /serviceusage|instances|:enable|:undelete/.test(s)));
  assert.ok(r.observationComplete);
});

// Unknown-answer rules (checklist section 3): a fault on one request, then the run's final status.
const unknowns = [
  ['unknown undelete stops before data and keeps the API enabled', { method: 'POST', path: /:undelete$/, kind: '5xx', applied: true }, 'needs-recovery', 'instance-undelete'],
  ['unknown instance DELETE is sticky; API stays enabled', { method: 'DELETE', path: /instances\/fireemu-q-rtdb2$/, kind: 'timeout', applied: true }, 'needs-recovery', 'instance-delete'],
  ['unknown prefix DELETE is sticky', { method: 'DELETE', path: /^\/parity1\/rr1\.json$/, kind: '3xx', applied: true }, 'needs-recovery', 'prefix-delete'],
  ['sub-200 API disable is unknown', { method: 'POST', path: /googleapis\.com:disable$/, kind: 'sub200', applied: true }, 'needs-recovery', 'api-disable'],
  ['unknown Rules install is settled by the restored baseline read-back', { method: 'PUT', path: /rules/, kind: '5xx', applied: true }, 'closed'],
  ['refused (4xx) undelete is known: nothing changed, API disabled again', { method: 'POST', path: /:undelete$/, kind: '4xx', applied: false }, 'closed'],
  ['a 200 prefix DELETE that did not delete keeps the run open', { method: 'DELETE', path: /^\/parity1\/rr1\.json$/, kind: 'lie' }, 'needs-recovery'],
  ['a 200 Rules restore that did not restore keeps the run open', { method: 'PUT', path: /rules/, kind: 'lie', skip: 9 }, 'needs-recovery'],
  ['an unrestored Rules text keeps the instance (no retirement)', { method: 'PUT', path: /rules/, kind: '5xx', applied: false, skip: 9 }, 'needs-recovery'],
];
for (const [name, fault, status, unresolved] of unknowns) {
  test(name, async () => {
    const w = fakeWorld([fault]), r = await prod(w);
    assert.equal(r.status, status, JSON.stringify(r.unresolved));
    if (unresolved) assert.equal(r.unresolved[0]?.step, unresolved);
    if (/keeps the instance/.test(name)) assert.ok(!w.sent.some((x) => x.endsWith('fireemu-q-rtdb2:disable')));
    if (status === 'closed') assert.ok(w.baseline());
    const deletes = w.sent.filter((s) => s.startsWith('DELETE'));
    assert.equal(new Set(deletes).size, deletes.length, 'no DELETE re-sent');
    if (/undelete|instance DELETE/.test(name) && status !== 'closed') assert.ok(!w.sent.some((s) => s.endsWith('googleapis.com:disable')));
  });
}

// Property, exhaustive: one fault on every request position, of every kind, applied or not, in both
// modes. Closed implies the world is at baseline; off baseline implies needs-recovery; caps hold.
test('every single fault: closed only when the world is restored and nothing is unknown', async () => {
  const kinds = { timeout: 0, '5xx': 500, '3xx': 307, sub200: 101, '4xx': 409 };
  for (const [mode, run] of [['production', prod], ['local', local]]) {
    const total = (await run(fakeWorld())).counts;
    for (let nth = 0; nth < total.observe + total.cleanup; nth++) {
      for (const [kind, status] of Object.entries(kinds)) {
        for (const applied of kind === '4xx' ? [false] : [false, true]) {
          const w = fakeWorld(), real = w.fetch;
          let n = 0;
          w.fetch = async (url, init) => {
            if (n++ !== nth) return real(url, init);
            if (applied) await real(url, init); else w.sent.push(`${init.method} ${new URL(url).pathname}`);
            if (!status) throw new Error('timeout');
            return json(status, '');
          };
          const r = await run(w), at = `${mode} #${nth} ${w.sent[nth]} ${kind} applied=${applied}`;
          if (r.status === 'closed') assert.ok(w.baseline(), at);
          if (!w.baseline()) assert.equal(r.status, 'needs-recovery', at);
          assert.ok(r.counts.observe <= CAPS.observe && r.counts.cleanup <= CAPS.cleanup && r.counts.mutations <= CAPS.mutations, at);
        }
      }
    }
  }
});

test('a stop request ends the observation and still runs cleanup to baseline', async () => {
  const w = fakeWorld(), stop = { requested: false };
  const r = await prod(w, { stop, browser: async (cfg, hooks) => { stop.requested = true; return fakeBrowser(w)(cfg, hooks); } });
  assert.ok(!r.observationComplete); assert.ok(w.baseline()); assert.equal(r.status, 'closed');
  assert.equal(r.profiles.length, 1, 'the profile in progress finishes; no later profile starts');
});

test('a log row that cannot be written is unknown and the run is not closed; cleanup continues', async () => {
  const w = fakeWorld(), r = await prod(w, { log: (x) => { if (x.step === 'prefix-delete') throw Error('output refused'); } });
  assert.equal(r.status, 'needs-recovery'); assert.equal(w.rules, BASE); assert.ok(r.unknownAnswers.includes('prefix-delete'));
});

test('an API already enabled stops after one request', async () => {
  const w = fakeWorld();
  w.api = 'ENABLED';
  await prod(w);
  assert.deepEqual(w.sent, ['GET /v1/projects/000000000000/services/firebasedatabase.googleapis.com']);
});

test('outputs refuse API keys, tokens and emails; an output refused for a secret leaves result.json not closed', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'rr-out-'));
  const result = { status: 'closed', counts: {}, unknownAnswers: [], profiles: [{ scenario: 'cv08', name: 'p', counts: {}, journal: [{ shape: 'AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }] }] };
  assert.equal(writeOutputs(dir, 'local', result, 'parity1', []), 'needs-recovery');
  const written = JSON.parse(readFileSync(path.join(dir, 'result.json'), 'utf8'));
  assert.equal(written.status, 'needs-recovery'); assert.equal(written.outputRefused, 'journal.json');
  const ok = mkdtempSync(path.join(tmpdir(), 'rr-out-'));
  assert.equal(writeOutputs(ok, 'local', { ...result, profiles: [{ scenario: 'cv08', name: 'p', counts: {}, journal: [{ shape: '{"a":1}' }] }] }, 'parity1', []), 'closed');
  assert.equal(JSON.parse(readFileSync(path.join(ok, 'journal.json'), 'utf8')).profiles[0].scenario, 'cv08');
});

test('production refuses without a packet whose SHA-256 and all three source pins match', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'rr-'));
  const file = path.join(dir, 'packet.json'), body = JSON.stringify({ sources: Object.fromEntries(SOURCES.map((s) => [s, '0'.repeat(64)])) });
  writeFileSync(file, body);
  assert.deepEqual(SOURCES, ['rtdb-residual.mjs', 'rtdb-residual-page.js', 'rtdb-residual-judge.mjs', 'adc-preflight.mjs', 'cv11-genuine-auth.mjs']);
  assert.throws(() => verifyPacket(undefined, undefined), /--packet/);
  assert.throws(() => verifyPacket(file, 'f'.repeat(64)), /packet SHA-256/);
  assert.throws(() => verifyPacket(file, createHash('sha256').update(body).digest('hex')), /source pin differs: rtdb-residual.mjs/);
  const real = Object.fromEntries(SOURCES.map((s) => [s, createHash('sha256').update(readFileSync(new URL(`./${s}`, import.meta.url))).digest('hex')]));
  for (const s of SOURCES) {
    const bad = JSON.stringify({ sources: { ...real, [s]: '1'.repeat(64) } });
    writeFileSync(file, bad);
    assert.throws(() => verifyPacket(file, createHash('sha256').update(bad).digest('hex')), new RegExp(`source pin differs: ${s.replace('.', '\\.')}`));
  }
  const good = JSON.stringify({ sources: real });
  writeFileSync(file, good);
  assert.deepEqual(verifyPacket(file, createHash('sha256').update(good).digest('hex')).sources, real);
});

test('browser plumbing: transport from what opened, per-profile timeouts, host rules and launch flags', () => {
  assert.equal(transportOf({ ws: 1 }), 'ws'); assert.equal(transportOf({ ws: 0 }), 'lp');
  assert.equal(profileTimeout({ scenario: 'cv08', transport: 'lp' }), PROFILE_TIMEOUT_MS.cv08);
  assert.equal(profileTimeout({ scenario: 'cv10', transport: 'ws' }), PROFILE_TIMEOUT_MS.cv10.ws);
  assert.equal(profileTimeout({ scenario: 'cv10', transport: 'lp' }), PROFILE_TIMEOUT_MS.cv10.lp);
  assert.ok(PROFILE_TIMEOUT_MS.cv10.lp > 240000 + 2 * 60000 + 60000, 'the long-polling profile outlasts the marker wait of 240 s and two Rules probes of 60 s');
  assert.ok(PROFILE_TIMEOUT_MS.cv10.ws > 30000 + 2 * 60000 + 60000 && PROFILE_TIMEOUT_MS.cv08 > 150000);
  assert.equal(hostRules(), '--host-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE *.firebaseio.com');
  assert.deepEqual(LAUNCH, { headless: true, handleSIGINT: false, handleSIGTERM: false, handleSIGHUP: false });
  assert.ok(FIRE_GRACE_MS > 105000, 'longer than the recorded long-polling idle close (about 105 s)');
});

test('urls: production data goes to the instance host without a namespace; local carries ?ns=', () => {
  assert.equal(urls({ mode: 'production', packet: { projectNumber: N } }).data('a/b'), 'https://fireemu-q-rtdb2.firebaseio.com/a/b.json');
  assert.equal(urls({ mode: 'local', local: { db: 'http://127.0.0.1:5', ns: 'x' } }).data('a/b'), 'http://127.0.0.1:5/a/b.json?ns=x');
});

test('compareFiles is a match only when the verdict is a match and the fire timing is within tolerance', () => {
  const rows = (s) => [{ step: 'fire', type: 'timing', seconds: s }];
  const mk = (ws, lp) => ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'].map((n) => ({ scenario: 'cv10', name: n, journal: rows(n.endsWith('ws') ? ws : lp) }));
  assert.equal(compareFiles(mk(0.1, 104), mk(0.2, 103)).match, true);
  assert.equal(compareFiles(mk(0.1, 104), mk(9, 103)).match, false);
  assert.equal(compareFiles(mk(0.1, 104), mk(0.2, 103).slice(0, 3)).match, false);
});

test('the caps are the ones the packet states', () => {
  assert.deepEqual(CAPS, { observe: 80, cleanup: 30, mutations: 40, pollsPerOperation: 12, browserHttp: 400, browserWs: 24, browserFrames: 2500 });
});

// production-1 of the CV11 recorder (2026-10-25 14:22Z): after the API enable, the instance GET answered 200
// and the active-instance list answered 403. Read-only GETs are retried for up to 120 s, never mutations.
const PRODUCTION_1 = ['api-before', 'api-enable', 'api-enable-poll-0', 'api-enabled', 'instance-before', 'active-before'];
const clocked = () => { const c = { slept: [] }; c.sleep = async (ms) => { c.slept.push(ms); }; return c; };
test('production-1 replay: a 403 list that clears within 120 s is retried and the run completes', async () => {
  const w = fakeWorld(), c = clocked(), rows = [];
  w.forbid = { path: /\/-\/instances$/, remaining: 3 };
  const r = await prod(w, { sleep: c.sleep, log: (x) => rows.push(x) });
  assert.equal(r.status, 'closed'); assert.ok(r.observationComplete);
  assert.deepEqual(rows.slice(0, 9).map((x) => x.step), [...PRODUCTION_1, 'active-before-retry-1', 'active-before-retry-2', 'active-before-retry-3']);
  const denied = rows.filter((x) => x.status === 403);
  assert.equal(denied.length, 3);
  for (const x of denied) { assert.match(x.body, /PERMISSION_DENIED/); assert.doesNotMatch(x.body, /ya29\.a0|AIzaSy/); }
  assert.deepEqual(c.slept.slice(1, 4), [2000, 4000, 8000]);
});

test('production-1 replay: a 403 that outlasts 120 s stops before any instance write and restores the API', async () => {
  const w = fakeWorld(), c = clocked(), rows = [];
  w.forbid = { path: /\/-\/instances$/, remaining: Infinity };
  const r = await prod(w, { sleep: c.sleep, log: (x) => rows.push(x) });
  const steps = rows.map((x) => x.step), retries = steps.filter((x) => x.startsWith('active-before-retry-'));
  assert.deepEqual(steps.slice(0, 6), PRODUCTION_1);
  assert.deepEqual(steps.slice(6 + retries.length), ['api-disable', 'api-disabled']);
  assert.ok(retries.length >= 3 && retries.length <= 7, String(retries.length));
  assert.equal(c.slept.slice(1).reduce((a, b) => a + b, 0), 120000, 'the whole 120 s budget is used and not exceeded');
  assert.equal(r.status, 'closed'); assert.ok(!r.observationComplete); assert.ok(w.baseline());
  assert.ok(!w.sent.some((x) => x.startsWith('POST') && x.includes('instances')));
});

test('a 403 on a mutation, on a 404, before the API enable or after setup is never retried', async () => {
  const w1 = fakeWorld([{ method: 'POST', path: /:undelete$/, kind: '4xx' }]);
  await prod(w1, { sleep: clocked().sleep });
  assert.equal(w1.sent.filter((x) => x.endsWith(':undelete')).length, 1);
  const w2 = fakeWorld();
  w2.forbid = { path: /firebasedatabase\.googleapis\.com$/, remaining: 1 };
  await prod(w2, { sleep: clocked().sleep });
  assert.deepEqual(w2.sent, ['GET /v1/projects/000000000000/services/firebasedatabase.googleapis.com']);
  const w3 = fakeWorld(), rows3 = [];
  w3.forbid = { path: /\/-\/instances$/, remaining: 1, status: 404 };
  await prod(w3, { sleep: clocked().sleep, log: (x) => rows3.push(x.step) });
  assert.ok(!rows3.some((x) => x.includes('-retry-')), 'a 404 is not propagation');
  const w4 = fakeWorld(), rows4 = [];
  const r4 = await prod(w4, { sleep: clocked().sleep, log: (x) => rows4.push(x.step), browser: async (c, h) => { w4.forbid = { path: /fireemu-q-rtdb2$/, remaining: 1 }; return fakeBrowser(w4)(c, h); } });
  assert.ok(!rows4.some((x) => x.includes('-retry-')), 'no retry after setup'); assert.equal(r4.status, 'needs-recovery');
});

test('an operation done with an error, or a poll naming another operation, is unknown; one that never reads done stops at the poll cap', async () => {
  for (const answer of [(name) => ({ name, done: true, error: { code: 9 } }), () => ({ name: 'operations/other', done: true })]) {
    const w = fakeWorld(), base = w.fetch;
    w.fetch = async (url, init) => (url.includes('/operations/') ? json(200, answer(new URL(url).pathname.slice(4))) : base(url, init));
    const r = await prod(w);
    assert.equal(r.status, 'needs-recovery'); assert.equal(r.unresolved[0].step, 'api-enable'); assert.ok(!w.sent.some((x) => x.includes(':undelete')));
  }
  const w = fakeWorld(), base = w.fetch;
  w.fetch = async (url, init) => (url.includes('/operations/') ? (w.sent.push('GET /operations/'), json(200, { name: new URL(url).pathname.slice(4), done: false })) : base(url, init));
  const r = await prod(w);
  assert.equal(r.status, 'needs-recovery');
  assert.equal(w.sent.filter((s) => s.includes('/operations/')).length, CAPS.pollsPerOperation);
});

test('a Rules read-back that differs from what was written, or a foreign instance at the end, stops safely', async () => {
  const w2 = fakeWorld(), base = w2.fetch;
  w2.fetch = async (url, init) => (init.method === 'GET' && url.includes('rules') && w2.rules !== BASE ? json(200, '{"rules":{}}') : base(url, init));
  const r2 = await prod(w2);
  assert.ok(!r2.observationComplete); assert.equal(r2.profiles.length, 0, 'the install read-back failed before any profile');
  const w3 = fakeWorld(), r3 = await prod(w3, { browser: async (c, h) => { w3.foreign = true; return fakeBrowser(w3)(c, h); } });
  assert.equal(r3.status, 'needs-recovery'); assert.equal(w3.api, 'ENABLED'); assert.ok(r3.errors.some((e) => /active-after/.test(e)));
});

test('a hook failure that the page runner swallows is still an error of the run and stops later profiles', async () => {
  const w = fakeWorld([{ method: 'PUT', path: /rules/, kind: '4xx', skip: 2 }]);
  const swallowing = async (cfg, hooks) => {
    w.data[`${cfg.base}/seed`] = 1;
    const journal = [];
    try { if (cfg.scenario === 'cv10') { await hooks.rulesOpen(); await hooks.rulesDeny(); } } catch { journal.push({ scenario: cfg.scenario, step: 'runner', type: 'error', code: 'hook' }); }
    return { journal, counts: {} };
  };
  const r = await prod(w, { browser: swallowing });
  assert.ok(r.errors.some((e) => /rules-deny-.*refused/.test(e)), r.errors.join());
  assert.equal(r.profiles.length, 5, 'four cv08 profiles and the failing cv10 profile; nothing after it');
  assert.ok(!r.observationComplete); assert.ok(w.baseline());
});

test('the wait for pending onDisconnect writes is sticky: a later profile that fired does not cancel it', async () => {
  const slept = [];
  const w = fakeWorld(), fireOnlyAfterFirst = (() => { let n = 0; return async (cfg, hooks) => fakeBrowser(w, { noFire: cfg.scenario === 'cv10' && n++ === 0 })(cfg, hooks); })();
  await prod(w, { browser: fireOnlyAfterFirst, sleep: async (ms) => { slept.push(ms); } });
  assert.ok(slept.includes(FIRE_GRACE_MS));
});

test('a stop requested after the first profile leaves the run incomplete even with no error', async () => {
  const w = fakeWorld(), stop = { requested: false };
  const r = await prod(w, { stop, browser: async (cfg, hooks) => { const out = await fakeBrowser(w)(cfg, hooks); stop.requested = true; return out; } });
  assert.equal(r.profiles.length, 1); assert.deepEqual(r.errors, []); assert.equal(r.observationComplete, false);
});

test('a request whose log row cannot be written, or an unexpected error, is never closed even when the world is back at baseline', async () => {
  const w = fakeWorld(), r = await prod(w, { log: (x) => { if (x.step === 'rules-open-cv10-r1-ws-1-read') throw Error('output refused'); } });
  assert.ok(w.baseline()); assert.equal(r.counts.logFailures, 1); assert.equal(r.status, 'needs-recovery');
  assert.deepEqual(r.unresolved, []);
  const w2 = fakeWorld();
  let calls = 0;
  const r2 = await prod(w2, { sleep: async () => { if (++calls === 1) throw Error('boom'); } });
  assert.ok(w2.baseline()); assert.equal(r2.status, 'needs-recovery'); assert.ok(r2.errors.some((e) => e === 'unexpected: boom'));
  const w3 = fakeWorld(), base3 = w3.fetch;
  w3.fetch = async (url, init) => { const x = await base3(url, init); return url.endsWith(':disable') && url.includes('serviceusage') ? json(200, { name: 'operations/slow' }) : x; };
  let n3 = 0;
  const r3 = await prod(w3, { sleep: async () => { if (++n3 === 2) throw Error('boom in cleanup'); } });
  assert.equal(r3.status, 'needs-recovery'); assert.ok(r3.errors.some((e) => e === 'unexpected: boom in cleanup'));
});

test('narrowing: --scenarios and --transports pick subsets in order, anything else is refused', () => {
  assert.deepEqual(narrowing(undefined, undefined), {});
  assert.deepEqual(narrowing('cv10', undefined), { scenarios: ['cv10'] });
  assert.deepEqual(narrowing('cv10,cv08', 'lp'), { scenarios: ['cv08', 'cv10'], profiles: PROFILES.filter((p) => p.transport === 'lp') });
  for (const bad of ['cv11', 'cv08,x', '']) assert.throws(() => narrowing(bad || ',', undefined), /--scenarios/);
  assert.throws(() => narrowing(undefined, 'http'), /--transports/);
});

test('a narrowed local run is complete when its own profiles ran, and the full run still needs all eight', async () => {
  const w = fakeWorld(), r = await local(w, { scenarios: ['cv08'], profiles: PROFILES.filter((p) => p.transport === 'ws') });
  assert.deepEqual(r.profiles.map((p) => `${p.scenario}:${p.name}`), ['cv08:r1-ws', 'cv08:r2-ws']);
  assert.ok(r.observationComplete); assert.equal(r.status, 'closed');
  const full = await local(fakeWorld());
  assert.equal(full.profiles.length, 8);
});

test('production refuses a narrowed run before any request; local accepts it', () => {
  assert.throws(() => refuseNarrowing('production', 'cv08', undefined), /local runs only/);
  assert.throws(() => refuseNarrowing('production', undefined, 'ws'), /local runs only/);
  assert.doesNotThrow(() => refuseNarrowing('production', undefined, undefined));
  assert.doesNotThrow(() => refuseNarrowing('local', 'cv08', 'ws'));
});

test('the command line refuses a narrowed production run before the packet is even read, and an unknown mode', () => {
  const run = (...args) => spawnSync(process.execPath, [new URL('./rtdb-residual.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8' });
  const dir = mkdtempSync(path.join(tmpdir(), 'rr-cli-'));
  const narrowed = run('production', '--scenarios', 'cv08', '--out', path.join(dir, 'a'));
  assert.equal(narrowed.status, 2); assert.match(narrowed.stderr, /local runs only/);
  const plain = run('production', '--out', path.join(dir, 'b'));
  assert.equal(plain.status, 2); assert.match(plain.stderr, /--packet/);
  const bad = run('bogus', '--out', path.join(dir, 'c'));
  assert.equal(bad.status, 2); assert.match(bad.stderr, /usage/);
});

test('a hook failure in the last profile leaves the run incomplete even though all eight profiles returned', async () => {
  const w = fakeWorld([{ method: 'PUT', path: /rules/, kind: '4xx', skip: 8 }]);
  const swallowing = async (cfg, hooks) => {
    const journal = [];
    try { if (cfg.scenario === 'cv10') { await hooks.rulesOpen(); await hooks.rulesDeny(); } } catch { journal.push({ scenario: cfg.scenario, step: 'runner', type: 'error', code: 'hook' }); }
    return { journal, counts: {} };
  };
  const r = await prod(w, { browser: swallowing });
  assert.equal(r.profiles.length, 8); assert.ok(r.errors.some((e) => /rules-deny-cv10-r2-lp-2-put: refused/.test(e)), r.errors.join());
  assert.equal(r.observationComplete, false); assert.ok(w.baseline());
});

test('the SDK bundles must be the pinned ones, and both bundles the page loads must be pinned', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'rr-mod-'));
  const fb = path.join(dir, 'firebase');
  mkdirSync(fb);
  writeFileSync(path.join(fb, 'firebase-app.js'), 'app');
  writeFileSync(path.join(fb, 'firebase-database.js'), 'db');
  const sha = (x) => createHash('sha256').update(x).digest('hex');
  const packet = { modules: dir, bundleSha256: { 'firebase-app.js': sha('app'), 'firebase-database.js': sha('db') } };
  assert.doesNotThrow(() => verifyBundles(packet));
  assert.throws(() => verifyBundles({ ...packet, bundleSha256: { ...packet.bundleSha256, 'firebase-database.js': sha('other') } }), /SDK bundle differs from the packet: firebase-database.js/);
  assert.throws(() => verifyBundles({ ...packet, bundleSha256: { ...packet.bundleSha256, 'firebase-app.js': sha('other') } }), /firebase-app.js/);
  assert.throws(() => verifyBundles({ ...packet, bundleSha256: { 'firebase-app.js': sha('app') } }), /must pin firebase-app.js and firebase-database.js/);
  assert.throws(() => verifyBundles({ modules: dir }), /must pin firebase-app.js and firebase-database.js/);
});

test('the command line stops on a bundle that differs from the packet before creating the output or asking for a token', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'rr-cli2-'));
  const fb = path.join(dir, 'modules', 'firebase');
  mkdirSync(fb, { recursive: true });
  writeFileSync(path.join(fb, 'firebase-app.js'), 'app');
  writeFileSync(path.join(fb, 'firebase-database.js'), 'db');
  const sha = (x) => createHash('sha256').update(x).digest('hex');
  const sources = Object.fromEntries(SOURCES.map((s) => [s, sha(readFileSync(new URL(`./${s}`, import.meta.url)))]));
  const packet = JSON.stringify({ sources, modules: path.join(dir, 'modules'), gcloud: '/nonexistent/gcloud', bundleSha256: { 'firebase-app.js': sha('app'), 'firebase-database.js': sha('different') } });
  const file = path.join(dir, 'packet.json');
  writeFileSync(file, packet);
  const out = path.join(dir, 'out');
  const r = spawnSync(process.execPath, [new URL('./rtdb-residual.mjs', import.meta.url).pathname, 'production', '--packet', file, '--packet-sha256', sha(packet), '--out', out], { encoding: 'utf8' });
  assert.equal(r.status, 2); assert.match(r.stderr, /SDK bundle differs from the packet: firebase-database.js/);
  assert.throws(() => readFileSync(out), /ENOENT/, 'the output directory was not created');
});

// production-1 of the residual recorder (2026-10-26 11:26Z): after the API enable, the undelete, the reenable and an
// ACTIVE instance read (all 200), the first Rules GET on the instance host answered 401 with this body. CV11's
// identical flow got 200. The instance host had not started accepting the token yet; the setup window covers it.
const UNAUTHORIZED = '{\n  "error" : "Unauthorized request."\n}\n';
test('production-1 replay: a 401 on the first Rules GET is retried inside the setup window and the run completes', async () => {
  const w = fakeWorld(), c = clocked(), rows = [];
  w.forbid = { path: /\.settings\/rules\.json$/, remaining: 3, status: 401, body: UNAUTHORIZED };
  const r = await prod(w, { sleep: c.sleep, log: (x) => rows.push(x) });
  assert.equal(r.status, 'closed'); assert.ok(r.observationComplete); assert.ok(w.baseline());
  const steps = rows.map((x) => x.step);
  assert.deepEqual(steps.slice(8, 15), ['instance-active', 'rules-before', 'rules-before-retry-1', 'rules-before-retry-2', 'rules-before-retry-3', 'prefix-before', 'rules-install-put']);
  assert.deepEqual(rows.filter((x) => x.status === 401).map((x) => x.body), [UNAUTHORIZED, UNAUTHORIZED, UNAUTHORIZED]);
  assert.deepEqual(c.slept.slice(1, 4), [2000, 4000, 8000]);
});

test('production-1 replay: a 401 that outlasts 120 s stops before any Rules or data write and retires the instance and the API', async () => {
  const w = fakeWorld(), c = clocked(), rows = [];
  w.forbid = { path: /\.settings\/rules\.json$/, remaining: Infinity, status: 401, body: UNAUTHORIZED };
  const r = await prod(w, { sleep: c.sleep, log: (x) => rows.push(x) });
  assert.equal(c.slept.slice(1).reduce((a, b) => a + b, 0), 120000);
  assert.equal(r.status, 'closed'); assert.ok(!r.observationComplete); assert.ok(w.baseline());
  assert.ok(!w.sent.some((x) => x.startsWith('PUT')), 'no Rules or data write');
});

test('a 401 is retried only for read-only GETs during setup: not a mutation, not after setup, and a 404 stays unretried', async () => {
  const w1 = fakeWorld(), rows1 = [];
  w1.forbid = { path: /\.settings\/rules\.json$/, remaining: 1, status: 401, body: UNAUTHORIZED };
  const base1 = w1.fetch;
  w1.fetch = async (url, init) => (init.method === 'PUT' && url.includes('rules') && !w1.putSeen ? (w1.putSeen = true, w1.sent.push('PUT /.settings/rules.json'), json(401, UNAUTHORIZED)) : base1(url, init));
  await prod(w1, { sleep: clocked().sleep, log: (x) => rows1.push(x.step) });
  assert.ok(!rows1.some((x) => x.startsWith('rules-install-put-retry')), 'a refused PUT is not re-sent');
  assert.equal(w1.sent.filter((x) => x === 'PUT /.settings/rules.json').length >= 1, true);
  const w2 = fakeWorld(), rows2 = [];
  const r2 = await prod(w2, { sleep: clocked().sleep, log: (x) => rows2.push(x.step), browser: async (c, h) => { w2.forbid = { path: /\.settings\/rules\.json$/, remaining: 1, status: 401, body: UNAUTHORIZED }; return fakeBrowser(w2)(c, h); } });
  assert.ok(!rows2.some((x) => x.includes('-retry-')), 'no retry after setup'); assert.ok(r2.errors.length > 0);
  const w3 = fakeWorld(), rows3 = [];
  w3.forbid = { path: /\.settings\/rules\.json$/, remaining: 1, status: 404, body: UNAUTHORIZED };
  await prod(w3, { sleep: clocked().sleep, log: (x) => rows3.push(x.step) });
  assert.ok(!rows3.some((x) => x.includes('-retry-')), 'a 404 is not propagation');
});

// production-1 and production-2 (2026-10-26): the first Rules GET on the instance host answered 401 "Unauthorized
// request." with the same flow that got 200 in CV11 lean-02. This pins the exact request the recorder sends, so a
// change in how the token travels shows up here. It is the CV11 request: Bearer header, quota project header,
// content-type from the admin client, no query, no body, redirects not followed.
test('the first Rules GET is exactly the request CV11 sent: URL, Bearer header, quota project, no token in the URL', async () => {
  const w = fakeWorld(), sent = [];
  const base = w.fetch;
  const TOKEN = 'ya29.TESTTOKEN-not-real', headers = productionHeaders(TOKEN, P);
  w.fetch = async (url, init) => { sent.push({ url, init }); return base(url, init); };
  await runScenario({ mode: 'production', packet, fetchImpl: w.fetch, headers, browser: fakeBrowser(w), sleep: async () => {}, log: () => {}, prefix: PREFIX });
  const rules = sent.find((x) => x.init.method === 'GET' && x.url.includes('.settings/rules'));
  assert.equal(rules.url, 'https://fireemu-q-rtdb2.firebaseio.com/.settings/rules.json');
  assert.deepEqual(rules.init.headers, { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}`, 'x-goog-user-project': P });
  assert.equal(rules.init.body, undefined); assert.equal(rules.init.redirect, 'manual'); assert.equal(rules.init.method, 'GET');
  for (const { url, init } of sent) {
    assert.ok(!/[?&](access_token|auth|key|token)=/.test(url), url);
    assert.equal(init.headers.authorization, `Bearer ${TOKEN}`, `${init.method} ${url}`);
    assert.equal(init.headers['x-goog-user-project'], P);
  }
  assert.equal(sent.findIndex((x) => x.url.includes('.settings/rules')) > sent.findIndex((x) => x.url.endsWith('/instances/fireemu-q-rtdb2') && x.init.method === 'GET' && sent.indexOf(x) > 6), true, 'after the instance is ACTIVE');
});

test('the token is asked of gcloud ADC with no scopes argument, and travels only as a Bearer header', () => {
  assert.deepEqual(ADC_ARGS, ['auth', 'application-default', 'print-access-token']);
  assert.deepEqual(productionHeaders('T', 'proj'), { authorization: 'Bearer T', 'x-goog-user-project': 'proj' });
  const cv11 = readFileSync(new URL('./cv11-genuine-auth.mjs', import.meta.url), 'utf8');
  const own = readFileSync(new URL('./rtdb-residual.mjs', import.meta.url), 'utf8');
  assert.ok(own.includes('execFileSync(packet.gcloud, ADC_ARGS,') && own.includes('headers: productionHeaders(token, packet.projectId)'), 'main() uses them for the production run');
  assert.ok(cv11.includes("['auth', 'application-default', 'print-access-token']") && cv11.includes("headers: { authorization: `Bearer ${token}`, 'x-goog-user-project': packet.projectId }"), 'the CV11 recorder that got 200 builds the same token request');
});

// Preflight of the ADC scopes: the verdict and the request are tested in adc-preflight.test.mjs; here the recorder's use.
test('preflight: main() runs it right after the token and before any admin request', () => {
  const own = readFileSync(new URL('./rtdb-residual.mjs', import.meta.url), 'utf8');
  const at = (x) => own.indexOf(x);
  assert.ok(at('const token = execFileSync') > 0 && at('const token = execFileSync') < at('await runPreflight(out, token, fetch, (text) => assertNoSecrets(text, secrets))') && at('await runPreflight(out, token, fetch, (text) => assertNoSecrets(text, secrets))') < at('await runScenario(o)'));
  assert.ok(own.includes('if (stopped) return stopped;'));
});

// production-4 (2026-10-27): preflight ok and rules-before 200, then prefix-before answered 423 with this body right
// after the reenable (CV11 lean-02 got 200 at the same position). The data host still saw the disabled state.
const DISABLED_423 = "{\n  \"error\" : \"The Firebase database 'fireemu-q-rtdb2' has been disabled by a database owner.\"\n}\n";
const PREFIX_GET = /^\/parity1\/rr1\.json$/;
test('isDisabledByOwner: only the recorded 423 body of this instance', () => {
  assert.equal(DISABLED_423.length, 97, 'the recorded body is 97 bytes');
  assert.equal(isDisabledByOwner(423, DISABLED_423), true);
  assert.equal(isDisabledByOwner(423, JSON.stringify(JSON.parse(DISABLED_423))), true, 'compact JSON of the same document');
  for (const [status, body] of [[400, DISABLED_423], [403, DISABLED_423], [500, DISABLED_423], [423, DISABLED_423.replace('fireemu-q-rtdb2', 'other-db')], [423, DISABLED_423.replace('disabled by a database owner', 'disabled by a billing issue')], [423, JSON.stringify({ error: JSON.parse(DISABLED_423).error, extra: 1 })], [423, JSON.stringify({ message: JSON.parse(DISABLED_423).error })], [423, '{"error":5}'], [423, 'not json'], [423, ''], [423, 'null'], [423, '[]'], [423, undefined]]) {
    assert.equal(isDisabledByOwner(status, body), false, `${status} ${body}`);
  }
});

test('production-4 replay: a 423 disabled-by-owner on the first prefix GET is retried inside the setup window and the run completes', async () => {
  const w = fakeWorld(), c = clocked(), rows = [];
  w.forbid = { path: PREFIX_GET, remaining: 3, status: 423, body: DISABLED_423 };
  const r = await prod(w, { sleep: c.sleep, log: (x) => rows.push(x) });
  assert.equal(r.status, 'closed'); assert.ok(r.observationComplete); assert.ok(w.baseline());
  const steps = rows.map((x) => x.step);
  assert.deepEqual(steps.slice(9, 16), ['rules-before', 'prefix-before', 'prefix-before-retry-1', 'prefix-before-retry-2', 'prefix-before-retry-3', 'rules-install-put', 'rules-install-read']);
  assert.deepEqual(rows.filter((x) => x.status === 423).map((x) => x.body), [DISABLED_423, DISABLED_423, DISABLED_423, DISABLED_423].slice(0, 3));
  assert.deepEqual(c.slept.slice(1, 4), [2000, 4000, 8000]);
});

test('production-4 replay: a 423 that outlasts 120 s stops before any Rules or data write and retires the instance and the API', async () => {
  const w = fakeWorld(), c = clocked();
  w.forbid = { path: PREFIX_GET, remaining: Infinity, status: 423, body: DISABLED_423 };
  const r = await prod(w, { sleep: c.sleep });
  assert.equal(c.slept.slice(1).reduce((a, b) => a + b, 0), 120000);
  assert.equal(r.status, 'closed'); assert.ok(!r.observationComplete); assert.ok(w.baseline());
  assert.ok(!w.sent.some((x) => x.startsWith('PUT')), 'no Rules or data write');
});

test('a 423 is retried only when it is that body, on a read-only GET, during setup', async () => {
  const other = DISABLED_423.replace('disabled by a database owner', 'disabled by a billing issue');
  const w1 = fakeWorld(), rows1 = [];
  w1.forbid = { path: PREFIX_GET, remaining: 1, status: 423, body: other };
  await prod(w1, { sleep: clocked().sleep, log: (x) => rows1.push(x.step) });
  assert.ok(!rows1.some((x) => x.includes('-retry-')), 'another 423 is not retried');
  const w2 = fakeWorld(), rows2 = [];
  const base2 = w2.fetch;
  w2.fetch = async (url, init) => (init.method === 'PUT' && url.includes('rules') && !w2.seen ? (w2.seen = true, w2.sent.push('PUT /.settings/rules.json'), json(423, DISABLED_423)) : base2(url, init));
  const r2 = await prod(w2, { sleep: clocked().sleep, log: (x) => rows2.push(x.step) });
  assert.ok(!rows2.some((x) => x.startsWith('rules-install-put-retry')), 'a refused PUT is not re-sent'); assert.ok(!r2.observationComplete);
  const w3 = fakeWorld(), rows3 = [];
  const r3 = await prod(w3, { sleep: clocked().sleep, log: (x) => rows3.push(x.step), browser: async (c, h) => { w3.forbid = { path: /\.settings\/rules\.json$/, remaining: 1, status: 423, body: DISABLED_423 }; return fakeBrowser(w3)(c, h); } });
  assert.ok(!rows3.some((x) => x.includes('-retry-')), 'no retry after setup'); assert.ok(r3.errors.length > 0);
});
