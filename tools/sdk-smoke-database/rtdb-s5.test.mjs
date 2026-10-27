// node --test rtdb-s5.test.mjs: the S5 recorder's production state machine, caps, pins and outputs against an
// in-memory fake of the production APIs (no network, no browser). The fake and the setup/cleanup flow are those of
// rtdb-residual.test.mjs; what differs is one scenario in two WebSocket rounds and Rules without a deny switch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { CAPS, FIRE_GRACE_MS, PROFILES, PROFILE_TIMEOUT_MS, SOURCES, rulesFor, runScenario, verifyPacket } from './rtdb-s5.mjs';

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

const fire = () => ({ scenario: 's5', step: 'final-main', type: 'get', label: 'main-t', shape: '1' });
// The browser stand-in follows the page: it writes under the run prefix and returns a journal.
const fakeBrowser = (w, journal = []) => async (cfg) => {
  w.data[`${cfg.base}/main/t`] = 1;
  return { journal: [...journal, { scenario: 's5', step: 'end', type: 'done' }], counts: { http: 1, ws: 4, frames: 1 } };
};
const packet = { projectId: P, projectNumber: N, baselineRulesSha256: createHash('sha256').update(BASE).digest('hex') };
const prod = (w, extra = {}) => runScenario({ mode: 'production', packet, fetchImpl: w.fetch, headers: {}, browser: fakeBrowser(w), sleep: async () => {}, log: () => {}, prefix: PREFIX, ...extra });
const local = (w, extra = {}) => prod(w, { mode: 'local', packet: undefined, local: { db: 'http://127.0.0.1:2', ns: 'demo' }, ...extra });

test('rules: the run prefix is the only open part', () => {
  const open = rulesFor(PREFIX);
  assert.deepEqual(open, { rules: { '.read': false, '.write': false, parity1: { rr1: { '.read': true, '.write': true } } } });
  assert.deepEqual(rulesFor('a/b').rules.a.b, { '.read': true, '.write': true });
});

test('two WebSocket rounds of one scenario, and a bounded budget', () => {
  assert.deepEqual(PROFILES, [{ round: 1, transport: 'ws', name: 'r1-ws' }, { round: 2, transport: 'ws', name: 'r2-ws' }]);
  assert.ok(CAPS.observe + CAPS.cleanup <= 64 && CAPS.mutations <= 12, JSON.stringify(CAPS));
  assert.ok(FIRE_GRACE_MS > 105000);
  assert.ok(PROFILE_TIMEOUT_MS >= 3 * (20 + 30 + 3 + 20 + 3) * 1000 / 2, 'longer than the worst case of the page\'s own waits');
});

test('production dry run: two profiles, setup and cleanup request list, world back at baseline, closed, 24 admin requests in the fake', async () => {
  const w = fakeWorld(), r = await prod(w);
  assert.equal(r.status, 'closed'); assert.ok(r.observationComplete); assert.ok(w.baseline());
  assert.deepEqual(r.profiles.map((p) => `${p.scenario}:${p.name}`), ['s5:r1-ws', 's5:r2-ws']);
  assert.deepEqual(w.sent.slice(0, 3), ['GET /v1/projects/000000000000/services/firebasedatabase.googleapis.com', 'POST /v1/projects/000000000000/services/firebasedatabase.googleapis.com:enable', 'GET /v1/operations/op1']);
  assert.equal(r.counts.observe + r.counts.cleanup, w.sent.length);
  assert.ok(r.counts.observe <= CAPS.observe && r.counts.cleanup <= CAPS.cleanup && r.counts.mutations <= CAPS.mutations, JSON.stringify(r.counts));
  assert.ok(w.sent.length >= 22 && w.sent.length <= 30, `the dry run sends ${w.sent.length} requests`);
  assert.equal(w.rulesPuts.length, 2, 'the install and the restore');
  assert.deepEqual(JSON.parse(w.rulesPuts[0]), rulesFor(PREFIX));
  assert.equal(w.rulesPuts.at(-1), BASE, 'the last write is the baseline text, byte for byte');
});

test('cleanup waits for pending onDisconnect writes before the prefix delete only after a timeout row', async () => {
  const slept = [], order = [];
  const timeout = fakeBrowser(fakeWorld(), [{ scenario: 's5', step: 'disconnect-plain', type: 'timeout', label: 'plain fire' }]);
  const w = fakeWorld();
  const r = await prod(w, { sleep: async (ms) => { slept.push(ms); order.push(`sleep ${ms}`); }, log: (x) => { if (x.step === 'prefix-delete') order.push('delete'); }, browser: async (cfg) => { const out = await timeout(cfg); w.data[`${cfg.base}/x`] = 1; return out; } });
  assert.ok(w.baseline()); assert.equal(r.status, 'closed');
  assert.ok(order.indexOf(`sleep ${FIRE_GRACE_MS}`) >= 0 && order.indexOf(`sleep ${FIRE_GRACE_MS}`) < order.indexOf('delete'));
  const quiet = [];
  await prod(fakeWorld(), { sleep: async (ms) => { quiet.push(ms); } });
  assert.ok(!quiet.includes(FIRE_GRACE_MS), 'no wait when every case fired or was legitimately silent');
  const error = [];
  await prod(fakeWorld(), { browser: async () => ({ journal: [{ scenario: 's5', step: 'runner', type: 'error', code: 'profile timeout' }], counts: {} }), sleep: async (ms) => { error.push(ms); } });
  assert.ok(!error.includes(FIRE_GRACE_MS), 'an error row alone is not a timeout row');
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

test('a stop request ends the observation after the profile in progress, and cleanup still runs to baseline', async () => {
  const w = fakeWorld(), stop = { requested: false };
  const r = await prod(w, { stop, browser: async (cfg) => { stop.requested = true; return fakeBrowser(w)(cfg); } });
  assert.ok(!r.observationComplete); assert.ok(w.baseline()); assert.equal(r.status, 'closed');
  assert.equal(r.profiles.length, 1);
});

test('an unknown answer to a mutation is sticky: the run is not closed and the request is not re-sent', async () => {
  const w = fakeWorld([{ method: 'DELETE', path: /rr1/, kind: '5xx', applied: true }]);
  const r = await prod(w);
  assert.equal(r.status, 'needs-recovery');
  assert.ok(r.unresolved.some((u) => u.step === 'prefix-delete'));
  assert.equal(w.sent.filter((s) => s.startsWith('DELETE') && /rr1/.test(s)).length, 1);
});

test('a profile that throws is a failed run: no later profile, cleanup to baseline', async () => {
  const w = fakeWorld(), r = await prod(w, { browser: async () => { throw new Error('boom'); } });
  assert.ok(!r.observationComplete); assert.ok(w.baseline());
  assert.ok(r.errors.some((e) => /unexpected: boom/.test(e)));
  assert.equal(r.status, 'needs-recovery', 'an unexpected error leaves requests unaccounted for');
});

test('the packet pins every source this recorder is made of', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 's5-packet-')), here = path.dirname(new URL(import.meta.url).pathname);
  const real = Object.fromEntries(SOURCES.map((s) => [s, createHash('sha256').update(readFileSync(path.join(here, s))).digest('hex')]));
  const write = (sources) => { const body = JSON.stringify({ sources }); const file = path.join(dir, `p${Math.random()}.json`); writeFileSync(file, body); return [file, createHash('sha256').update(body).digest('hex')]; };
  assert.throws(() => verifyPacket(undefined, undefined), /--packet/);
  const [file] = write(real);
  assert.throws(() => verifyPacket(file, 'f'.repeat(64)), /packet SHA-256/);
  assert.deepEqual(SOURCES, ['rtdb-s5.mjs', 'rtdb-s5-page.js', 'rtdb-s5-judge.mjs', 'rtdb-admin.mjs', 'rtdb-residual.mjs', 'adc-preflight.mjs', 'cv11-genuine-auth.mjs']);
  for (const s of SOURCES) {
    const bad = { ...real, [s]: '0'.repeat(64) };
    assert.throws(() => verifyPacket(...write(bad)), new RegExp(`source pin differs: ${s.replace('.', '\\.')}`), s);
    const missing = { ...real }; delete missing[s];
    assert.throws(() => verifyPacket(...write(missing)), /source pin differs/, s);
  }
  assert.deepEqual(verifyPacket(...write(real)).sources, real);
});
