// node --test cv11-genuine-auth.test.mjs: the recorder's admin client, production state machine and
// local flow against an in-memory fake of the production APIs (no network, no browser).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { adminClient, rulesFor, runScenario, compareJournals, assertNoSecrets, verifyPacket, transportOf, SOURCES, CAPS } from './cv11-genuine-auth.mjs';

const N = '000000000000', P = 'demo-project', BASE = '// baseline\n{"rules":{".read":false,".write":false}}';
const json = (status, v) => ({ status, text: async () => (typeof v === 'string' ? v : JSON.stringify(v)) });

// A fake of the production APIs. A fault {method, path (regexp), kind, applied, skip} fires once, on the
// (skip+1)th match; kind 'lie' answers 200 with a plausible body without applying the request.
function fakeWorld(faults = []) {
  const w = { api: 'DISABLED', inst: 'DELETED', rules: BASE, data: {}, users: new Map(), ops: 0, sent: [] };
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
    if (u.host === 'identitytoolkit.googleapis.com' || p.includes('/identitytoolkit.googleapis.com/')) {
      if (p.endsWith('/accounts')) { const uid = `u${w.users.size + 1}x`; w.users.set(uid, body.email); return json(200, { localId: uid }); }
      if (p.endsWith(':delete')) { w.users.delete(body.localId); return json(200, {}); }
      const found = [...w.users].filter(([uid, email]) => body.localId?.includes(uid) || body.email?.includes(email));
      return json(200, found.length ? { users: found.map(([localId]) => ({ localId })) } : {});
    }
    const key = decodeURIComponent(p.replace(/\.json$/, '').slice(1));
    if (key === '.settings/rules') { if (method === 'PUT') { w.rules = body; return json(200, { status: 'ok' }); } return json(200, w.rules); }
    if (method === 'PUT') { w.data[key] = body; return json(200, body); }
    if (method === 'DELETE') { for (const k of Object.keys(w.data)) if (k.startsWith(key)) delete w.data[k]; return json(200, null); }
    return json(200, Object.keys(w.data).some((k) => k.startsWith(key)) ? {} : null);
  }
  w.fetch = async (url, init) => {
    const u = new URL(url), body = init.body === undefined ? undefined : /rules/.test(u.pathname) ? init.body : JSON.parse(init.body);
    w.sent.push(`${init.method} ${u.pathname}`);
    const f = faults.find((x) => !x.used && x.method === init.method && x.path.test(u.pathname) && !(x.skip-- > 0));
    if (!f) return apply(init.method, u, body);
    f.used = true;
    if (f.kind === 'lie') return json(200, /rules/.test(u.pathname) ? { status: 'ok' } : init.method === 'DELETE' ? null : {});
    const answer = f.applied ? apply(init.method, u, body) : undefined;
    if (f.kind === 'timeout') throw new Error('timeout');
    return json(f.kind === '5xx' ? 503 : f.kind === '3xx' ? 302 : f.kind === '4xx' ? 400 : 199, answer ? await answer.text() : '');
  };
  w.baseline = () => w.api === 'DISABLED' && w.inst === 'DELETED' && w.rules === BASE && !Object.keys(w.data).length && !w.users.size;
  return w;
}

// The browser stand-in follows the page's hook order: secrets, delete A, write after delete.
const fakeBrowser = async (cfg, hooks) => {
  await hooks.secret('a'); await hooks.secret('b');
  return { journal: [{ step: 'delete-a', type: 'admin', code: await hooks.deleteA() }, { step: 'write-after-delete', type: 'admin', code: await hooks.writeA() }], counts: { http: 1, ws: 1 } };
};
const packet = { projectId: P, projectNumber: N, baselineRulesSha256: createHash('sha256').update(BASE).digest('hex') };
const prod = (w, extra = {}) => runScenario({ mode: 'production', packet, fetchImpl: w.fetch, headers: {}, browser: fakeBrowser, sleep: async () => {}, log: () => {}, prefix: 'parity1/run1', ...extra });
const localOptions = { local: { auth: 'http://127.0.0.1:1', db: 'http://127.0.0.1:2', ns: 'demo', projectId: P } };
const scenario = (mode, w) => (mode === 'production' ? prod(w) : prod(w, { mode: 'local', packet: undefined, ...localOptions }));

test('rules grant only the owner of each users/$uid scope under the run prefix', () => {
  const own = 'auth != null && auth.uid == $uid';
  assert.deepEqual(rulesFor('parity1/run1'), { rules: { '.read': false, '.write': false, parity1: { run1: { $round: { users: { $uid: { '.read': own, '.write': own } } } } } } });
});

test('admin client: only complete 2xx and 4xx answers are known; caps refuse before sending', async () => {
  const cases = [[200, '{}', 'ok'], [404, '{}', 'refused'], [503, '', 'unknown'], [302, '', 'unknown'], [199, '', 'unknown'], [200, 'not json', 'unknown']];
  for (const [status, body, outcome] of cases) {
    const c = adminClient({ fetchImpl: async () => json(status, body), headers: {}, log: () => {} });
    assert.equal((await c.call('s', 'POST', 'https://x/a', {})).outcome, outcome, `status ${status}`);
  }
  const thrown = adminClient({ fetchImpl: async () => { throw new Error('t'); }, headers: {}, log: () => {} });
  assert.equal((await thrown.call('s', 'GET', 'https://x/a')).outcome, 'unknown');
  let sent = 0;
  const c = adminClient({ fetchImpl: async () => (sent++, json(200, '{}')), headers: {}, log: () => {}, caps: { ...CAPS, observe: 3, cleanup: 1, mutations: 1 } });
  await c.call('a', 'GET', 'https://x/a'); await c.call('b', 'PUT', 'https://x/a', {});
  await assert.rejects(c.call('c', 'PUT', 'https://x/a', {}), /cap/);
  await c.call('c2', 'GET', 'https://x/a');
  await assert.rejects(c.call('c3', 'GET', 'https://x/a'), /cap/);
  c.cleanup(); await c.call('d', 'GET', 'https://x/a');
  await assert.rejects(c.call('e', 'GET', 'https://x/a'), /cap/);
  assert.equal(sent, 4);
});

test('production dry run: four profiles, exact request list, world back at baseline, closed', async () => {
  const w = fakeWorld(), r = await prod(w);
  assert.equal(r.status, 'closed'); assert.ok(r.observationComplete); assert.ok(w.baseline());
  assert.equal(r.profiles.length, 4);
  assert.deepEqual(r.profiles.map((p) => p.journal[0].code), ['ok', 'ok', 'ok', 'ok']);
  const head = ['GET /v1/projects/000000000000/services/firebasedatabase.googleapis.com', 'POST /v1/projects/000000000000/services/firebasedatabase.googleapis.com:enable', 'GET /v1/operations/op1'];
  assert.deepEqual(w.sent.slice(0, 3), head);
  assert.equal(w.sent.filter((s) => s.startsWith('POST') && s.endsWith(':delete')).length, 8);
  assert.equal(r.counts.observe + r.counts.cleanup, w.sent.length);
  assert.ok(r.counts.observe <= CAPS.observe && r.counts.cleanup <= CAPS.cleanup && r.counts.mutations <= CAPS.mutations);
});

test('a different baseline Rules text or a non-empty prefix stops before any Rules or data write', async () => {
  for (const tweak of [(w) => { w.rules = `${BASE} `; }, (w) => { w.data['parity1/run1/x'] = 1; }]) {
    const w = fakeWorld();
    tweak(w);
    const r = await prod(w);
    assert.ok(!r.observationComplete);
    assert.ok(!w.sent.some((s) => s.startsWith('PUT') || s.includes('/accounts')), w.sent.join());
    assert.equal(w.api, 'DISABLED'); assert.equal(w.inst, 'DELETED');
  }
});

test('local dry run uses no management API and restores the baseline Rules text', async () => {
  const w = fakeWorld(), r = await scenario('local', w);
  assert.equal(r.status, 'closed'); assert.equal(w.rules, BASE); assert.equal(w.users.size, 0);
  assert.ok(!w.sent.some((s) => /serviceusage|instances|:enable|:undelete/.test(s)));
});

// Unknown-answer rules (checklist §3): a fault on one request, then the run's final status.
const unknowns = [
  ['unknown user create that never reads back stays open', { method: 'POST', path: /\/accounts$/, kind: 'timeout', applied: false }, 'needs-recovery', 'r1-ws:a-create'],
  ['unknown user create settled by own positive lookup', { method: 'POST', path: /\/accounts$/, kind: '5xx', applied: true }, 'closed'],
  ['unknown user delete is sticky and never re-sent', { method: 'POST', path: /:delete$/, kind: 'timeout', applied: true }, 'needs-recovery', 'r1-ws:a-delete'],
  ['unknown undelete stops before data and keeps the API enabled', { method: 'POST', path: /:undelete$/, kind: '5xx', applied: true }, 'needs-recovery', 'instance-undelete'],
  ['unknown instance DELETE is sticky; API stays enabled', { method: 'DELETE', path: /instances\/fireemu-q-rtdb2$/, kind: 'timeout', applied: true }, 'needs-recovery', 'instance-delete'],
  ['unknown prefix DELETE is sticky', { method: 'DELETE', path: /^\/parity1\/run1\.json$/, kind: '3xx', applied: true }, 'needs-recovery', 'prefix-delete'],
  ['sub-200 API disable is unknown', { method: 'POST', path: /googleapis\.com:disable$/, kind: 'sub200', applied: true }, 'needs-recovery', 'api-disable'],
  ['unknown Rules install is settled by the restored baseline read-back', { method: 'PUT', path: /rules/, kind: '5xx', applied: true }, 'closed'],
  ['refused (4xx) undelete is known: nothing changed, API disabled again', { method: 'POST', path: /:undelete$/, kind: '4xx', applied: false }, 'closed'],
  ['a 200 user delete that did not delete keeps the run open', { method: 'POST', path: /accounts:delete$/, kind: 'lie' }, 'needs-recovery'],
  ['a 200 prefix DELETE that did not delete keeps the run open', { method: 'DELETE', path: /^\/parity1\/run1\.json$/, kind: 'lie' }, 'needs-recovery'],
  ['a 200 Rules restore that did not restore keeps the run open', { method: 'PUT', path: /rules/, kind: 'lie', skip: 1 }, 'needs-recovery'],
  ['an unrestored Rules text keeps the instance (no retirement)', { method: 'PUT', path: /rules/, kind: '5xx', applied: false, skip: 1 }, 'needs-recovery'],
];
for (const [name, fault, status, unresolved] of unknowns) {
  test(name, async () => {
    const w = fakeWorld([fault]), r = await prod(w);
    assert.equal(r.status, status, JSON.stringify(r.unresolved));
    if (unresolved) assert.equal(r.unresolved[0]?.step, unresolved);
    if (/keeps the instance/.test(name)) assert.ok(!w.sent.some((x) => x.endsWith('fireemu-q-rtdb2:disable')));
    if (status === 'closed') assert.ok(w.baseline());
    const deletes = w.sent.filter((s) => s.startsWith('POST') && s.endsWith(':delete') || s.startsWith('DELETE'));
    assert.ok(w.sent.filter((s) => s.endsWith('accounts:delete')).length <= 8, 'no user delete re-sent');
    assert.equal(new Set(deletes.filter((s) => !s.includes('accounts'))).size, deletes.filter((s) => !s.includes('accounts')).length, 'no DELETE re-sent');
    if (/undelete|instance DELETE/.test(name) && status !== 'closed') assert.ok(!w.sent.some((s) => s.endsWith('googleapis.com:disable')));
  });
}

test('an operation done with an error, or a poll naming another operation, is unknown', async () => {
  for (const answer of [(name) => ({ name, done: true, error: { code: 9 } }), () => ({ name: 'operations/other', done: true })]) {
    const w = fakeWorld(), base = w.fetch;
    w.fetch = async (url, init) => (url.includes('/operations/') ? json(200, answer(new URL(url).pathname.slice(4))) : base(url, init));
    const r = await prod(w);
    assert.equal(r.status, 'needs-recovery'); assert.equal(r.unresolved[0].step, 'api-enable'); assert.ok(!w.sent.some((x) => x.includes(':undelete')));
  }
});

test('an API already enabled, a Rules read-back that differs, or a foreign instance appearing stops safely', async () => {
  const w1 = fakeWorld();
  w1.api = 'ENABLED';
  await prod(w1);
  assert.deepEqual(w1.sent, ['GET /v1/projects/000000000000/services/firebasedatabase.googleapis.com']);
  const w2 = fakeWorld(), base = w2.fetch;
  w2.fetch = async (url, init) => (init.method === 'GET' && url.includes('rules') && w2.rules !== BASE ? json(200, '{"rules":{}}') : base(url, init));
  const r2 = await prod(w2);
  assert.ok(!w2.sent.some((x) => x.includes('/accounts'))); assert.ok(!r2.observationComplete);
  const w3 = fakeWorld(), r3 = await prod(w3, { browser: async (c, h) => { w3.foreign = true; return fakeBrowser(c, h); } });
  assert.equal(r3.status, 'needs-recovery'); assert.equal(w3.api, 'ENABLED');
});

test('operation that never reads done leaves the run needs-recovery within the poll cap', async () => {
  const w = fakeWorld(), base = w.fetch;
  w.fetch = async (url, init) => (url.includes('/operations/') ? (w.sent.push('GET /operations/'), json(200, { name: new URL(url).pathname.slice(4), done: false })) : base(url, init));
  const r = await prod(w);
  assert.equal(r.status, 'needs-recovery');
  assert.equal(w.sent.filter((s) => s.includes('/operations/')).length, CAPS.pollsPerOperation);
});

// Property, exhaustive: one fault on every request position, of every kind, applied or not, in both
// modes. Closed implies the world is at baseline; off baseline implies needs-recovery; caps hold.
test('every single fault: closed only when the world is restored and nothing is unknown', async () => {
  const kinds = { timeout: 0, '5xx': 500, '3xx': 307, sub200: 101, '4xx': 409 };
  for (const mode of ['production', 'local']) {
    const total = (await scenario(mode, fakeWorld())).counts;
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
          const r = await scenario(mode, w), at = `${mode} #${nth} ${w.sent[nth]} ${kind} applied=${applied}`;
          if (r.status === 'closed') assert.ok(w.baseline(), at);
          if (!w.baseline()) assert.equal(r.status, 'needs-recovery', at);
          assert.ok(r.counts.observe <= CAPS.observe && r.counts.cleanup <= CAPS.cleanup && r.counts.mutations <= CAPS.mutations, at);
        }
      }
    }
  }
});

test('journal comparison ignores timing and reports the first differing event', () => {
  const a = [{ name: 'r1-ws', journal: [{ step: 's', type: 'value', epoch: 1, shape: '{"value":1}', ms: 5 }] }];
  const b = [{ name: 'r1-ws', journal: [{ step: 's', type: 'value', epoch: 1, shape: '{"value":1}', ms: 900 }] }];
  assert.deepEqual(compareJournals(a, b), { match: true, differences: [] });
  b[0].journal[0].type = 'cancel';
  assert.equal(compareJournals(a, b).differences[0].index, 0);
  // Within one step the order is a latency race; across steps it is the observation.
  const ev = (step, type) => ({ step, type });
  const x = [{ name: 'p', journal: [ev('w', 'value'), ev('w', 'admin'), ev('z', 'cancel')] }];
  assert.ok(compareJournals(x, [{ name: 'p', journal: [ev('w', 'admin'), ev('w', 'value'), ev('z', 'cancel')] }]).match);
  assert.ok(!compareJournals(x, [{ name: 'p', journal: [ev('w', 'admin'), ev('w', 'value'), ev('w', 'cancel')] }]).match);
  assert.ok(!compareJournals(x, [{ name: 'p', journal: [ev('w', 'admin'), ev('w', 'value')] }]).match);
  assert.ok(!compareJournals([{ name: 'p', journal: [ev('w', 'value')] }], [{ name: 'p', journal: [ev('w', 'value'), ev('z', 'cancel')] }]).match);
});

test('outputs refuse API keys, ID tokens, emails and passwords', () => {
  assert.doesNotThrow(() => assertNoSecrets('{"step":"signin-a","code":"ok"}', ['pw-123456']));
  for (const bad of ['AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIi', 'a@example.com', 'pw-123456']) assert.throws(() => assertNoSecrets(`{"x":"${bad}"}`, ['pw-123456']), /secret/);
});

test('production refuses without a packet whose SHA-256 and source pins match', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'cv11-')), file = path.join(dir, 'packet.json');
  assert.throws(() => verifyPacket(undefined, undefined), /--packet/);
  writeFileSync(file, JSON.stringify({ sources: Object.fromEntries(SOURCES.map((s) => [s, '0'.repeat(64)])) }));
  const sha = createHash('sha256').update(JSON.stringify({ sources: Object.fromEntries(SOURCES.map((s) => [s, '0'.repeat(64)])) })).digest('hex');
  assert.throws(() => verifyPacket(file, 'f'.repeat(64)), /packet SHA-256/);
  assert.throws(() => verifyPacket(file, sha), /source pin/);
});

test('the transport is read from what the browser opened, not from the profile', () => {
  assert.equal(transportOf({ ws: 1 }), 'ws'); assert.equal(transportOf({ ws: 0 }), 'lp');
});
