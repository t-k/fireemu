import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CapExceeded } from './lib.mjs';
const baselineRules = readFileSync(new URL('../rest-observer/baseline.rules.jsonc', import.meta.url), 'utf8');
import { TABLE, runRulesLoadProfile } from './rules-load-suite.mjs';

test('raw documents are sent once and accepted rules are restored before the next case', async () => {
  const calls = [], baseline = baselineRules;
  const send = async (label, method, url, options = {}) => {
    calls.push({ label, method, url, body: options.body });
    return { status: method === 'GET' ? 200 : label === TABLE[0].id || label.startsWith('restore-') ? 200 : 400, text: method === 'GET' ? baseline : '{}', utf8: true, bodyBytes: 2, headers: {} };
  };
  const rows = await runRulesLoadProfile({ send, url: p => p, baselineText: baseline });
  assert.equal(rows.length, 7);
  assert.deepEqual(calls.filter(c => TABLE.some(s => s.id === c.label)).map(c => c.body), TABLE.map(s => s.body));
  assert.deepEqual(calls.slice(0, 4).map(c => c.label), [TABLE[0].id, 'restore-' + TABLE[0].id, 'readback-' + TABLE[0].id, TABLE[1].id]);
});

test('unknown outcome restores and stops', async () => {
  const calls = [], baseline = baselineRules;
  const send = async (label, method) => { calls.push(label); return { status: label === TABLE[0].id ? 500 : 200, text: method === 'GET' ? baseline : '{}', utf8: true, bodyBytes: 2, headers: {} }; };
  const rows = await runRulesLoadProfile({ send, url: p => p, baselineText: baseline });
  assert.equal(rows.length, 1);
  assert.deepEqual(calls, [TABLE[0].id, 'restore-' + TABLE[0].id, 'readback-' + TABLE[0].id]);
});

test('the complete observer sends two rounds within the cap and never touches a prefix', async () => {
  const { run, localTarget } = await import('./observer.mjs');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const path = await import('node:path');
  const dir = mkdtempSync(path.join(tmpdir(), 'rules-load-'));
  const baseline = baselineRules, calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), method: init.method, body: init.body });
    return new Response(init.method === 'GET' ? baseline : '{"status":"ok"}', { status: 200 });
  };
  try {
    const { result } = await run({ target: localTarget('rules-load', '127.0.0.1:1'), runId: 'TEST-RULES-LOAD', prefix: '/unused', directCap: 60, outDir: path.join(dir, 'run'), suite: 'rules-load' }, { fetchImpl });
    assert.equal(result.status, 'complete');
    assert.equal(result.observed, 14);
    assert.ok(calls.length <= 60);
    assert.ok(calls.every(c => c.url.includes('/.settings/rules.json')));
    assert.deepEqual(calls.filter(c => TABLE.some(s => s.body === c.body)).map(c => c.body), [...TABLE, ...TABLE].map(c => c.body));
    assert.deepEqual(result.cleanup, { prefix: 'not-needed', rules: 'verified' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a fake HTTP server receives exact bodies and restores between accepted cases', async () => {
  const { createServer } = await import('node:http');
  const { once } = await import('node:events');
  const { createAdmin, createCounter } = await import('./lib.mjs');
  const baseline = baselineRules, calls = [];
  const server = createServer(async (req, res) => {
    let body = ''; for await (const part of req) body += part;
    calls.push({ method: req.method, url: req.url, body });
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(req.method === 'GET' ? baseline : '{}');
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const admin = createAdmin({ headers: { authorization: 'Bearer owner' }, journal: { write() {} }, counter: createCounter({ direct: 60 }) });
    const url = () => `http://127.0.0.1:${server.address().port}/.settings/rules.json`;
    for (let i = 0; i < 2; i++) await runRulesLoadProfile({ send: admin.rest, url, baselineText: baseline });
    assert.equal(calls.length, 42);
    for (let i = 0; i < 14; i++) assert.deepEqual(calls.slice(i * 3, i * 3 + 3).map(c => [c.method, c.body]), [['PUT', TABLE[i % 7].body], ['PUT', baseline], ['GET', '']]);
  } finally { server.close(); await once(server, 'close'); }
});

test('the budget reserves enough direct requests to restore an accepted case', async () => {
  const { run, localTarget } = await import('./observer.mjs');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const path = await import('node:path');
  const dir = mkdtempSync(path.join(tmpdir(), 'rules-cap-'));
  const baseline = baselineRules; let count = 0;
  try {
    const { result } = await run({ target: localTarget('rules-load', '127.0.0.1:1'), runId: 'TEST-RULES-CAP', prefix: '/unused', directCap: 20, outDir: path.join(dir, 'run'), suite: 'rules-load' }, { fetchImpl: async (_url, init) => { count++; return new Response(init.method === 'GET' ? baseline : '{}', { status: 200 }); } });
    assert.equal(result.status, 'incomplete'); assert.equal(result.cleanup.rules, 'verified'); assert.ok(count <= 22); assert.ok(result.counts.direct <= 20);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('non-Rules statuses are unknown, restored, and stop the profile', async () => {
  for (const status of [201, 403, 429]) {
    const calls = [], baseline = baselineRules;
    const rows = await runRulesLoadProfile({ baselineText: baseline, url: p => p, send: async (label, method) => {
      calls.push(label);
      return { status: label === TABLE[0].id ? status : 200, text: method === 'GET' ? baseline : '{}', utf8: true, clipped: false };
    } });
    assert.equal(rows.length, 1, String(status));
    assert.equal(rows[0].outcome, 'unknown'); assert.equal(rows[0].ok, false); assert.deepEqual(rows[0].unknown, [TABLE[0].id]);
    assert.deepEqual(calls, [TABLE[0].id, `restore-${TABLE[0].id}`, `readback-${TABLE[0].id}`]);
  }
});

test('rules-load is admitted for read-only recovery', async () => {
  const { READBACK_SUITES } = await import('./readback.mjs');
  assert.ok(READBACK_SUITES.includes('rules-load'));
});

test('restore failures are unknown, emitted, and stop before another case', async () => {
  for (const fault of ['restore-status', 'readback-status', 'readback-body']) {
    const calls = [], emitted = [];
    const rows = await runRulesLoadProfile({ baselineText: baselineRules, url: p => p, emit: row => emitted.push(structuredClone(row)), send: async (label, method, _url, options) => {
      calls.push({ label, body: options.body });
      const status = (fault === 'restore-status' && label.startsWith('restore-')) || (fault === 'readback-status' && method === 'GET') ? 500 : 200;
      return { status, text: method === 'GET' ? (fault === 'readback-body' ? '{}' : baselineRules) : '{}', utf8: true, clipped: false };
    } });
    assert.equal(rows.length, 1, fault); assert.equal(rows[0].ok, false); assert.equal(rows[0].outcome, 'restore-unverified');
    assert.deepEqual(rows[0].unknown, [TABLE[0].id]); assert.deepEqual(emitted, rows);
    assert.deepEqual(calls.map(c => c.label), [TABLE[0].id, `restore-${TABLE[0].id}`, `readback-${TABLE[0].id}`]);
    assert.equal(calls[1].body, baselineRules);
  }
});

test('unknown responses and thrown requests restore, mark unknown, and stop', async () => {
  for (const fault of ['throw', 'utf8', 'clipped', 'status']) {
    const calls = [];
    const rows = await runRulesLoadProfile({ baselineText: baselineRules, url: p => p, send: async (label, method) => {
      calls.push(label);
      if (label === TABLE[0].id && fault === 'throw') throw Error('transport');
      return { status: label === TABLE[0].id && fault === 'status' ? 503 : 200, text: method === 'GET' ? baselineRules : '{}', utf8: !(label === TABLE[0].id && fault === 'utf8'), clipped: label === TABLE[0].id && fault === 'clipped' };
    } });
    assert.equal(rows.length, 1, fault); assert.equal(rows[0].ok, false); assert.equal(rows[0].outcome, 'unknown'); assert.deepEqual(rows[0].unknown, [TABLE[0].id]);
    assert.deepEqual(calls, [TABLE[0].id, `restore-${TABLE[0].id}`, `readback-${TABLE[0].id}`]);
  }
});

test('400 answers do not require a per-case restore', async () => {
  const calls = [];
  const rows = await runRulesLoadProfile({ baselineText: baselineRules, url: p => p, send: async label => { calls.push(label); return { status: 400, text: '{}', utf8: true, clipped: false }; } });
  assert.equal(rows.length, TABLE.length); assert.deepEqual(calls, TABLE.map(c => c.id));
});

test('cancellation and cap prevent further sends, and cap exceptions are not sent', async () => {
  let calls = 0;
  const send = async () => { calls++; throw new CapExceeded('cap'); };
  assert.deepEqual(await runRulesLoadProfile({ send, url: p => p, baselineText: baselineRules, cancelled: () => true }), []);
  assert.deepEqual(await runRulesLoadProfile({ send, url: p => p, baselineText: baselineRules, canSend: () => false }), []);
  assert.equal(calls, 0);
  const rows = await runRulesLoadProfile({ send, url: p => p, baselineText: baselineRules });
  assert.equal(calls, 1); assert.equal(rows[0].outcome, 'not-sent'); assert.equal(rows[0].ok, false); assert.equal(Object.hasOwn(rows[0], 'unknown'), false);
});

test('a failed first round stops the second even when continuation is enabled', async () => {
  const { run, localTarget } = await import('./observer.mjs');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const path = await import('node:path');
  const dir = mkdtempSync(path.join(tmpdir(), 'rules-failed-')); let cases = 0;
  try {
    const { result } = await run({ target: localTarget('rules-load', '127.0.0.1:1'), runId: 'TEST-RULES-FAIL', prefix: '/unused', directCap: 60, outDir: path.join(dir, 'run'), suite: 'rules-load', continueOnFailure: true }, { fetchImpl: async (_url, init) => {
      if (TABLE.some(c => c.body === init.body)) { cases++; return new Response('{}', { status: 403 }); }
      return new Response(init.method === 'GET' ? baselineRules : '{}', { status: 200 });
    } });
    assert.equal(cases, 1); assert.equal(result.status, 'unverified'); assert.equal(result.exit, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('rules-load cap maximum is 60', async () => {
  const { SUITES } = await import('./observer.mjs');
  assert.equal(SUITES['rules-load'].capMax, 60);
});

test('status, UTF-8, and clipping combinations classify the first answer and restore when required', async () => {
  for (const [status, utf8, clipped] of [[200, true, false], [400, true, false], [403, true, false], [403, false, true], [400, false, true], [200, false, false], [200, true, true]]) {
    const calls = [];
    const rows = await runRulesLoadProfile({ baselineText: baselineRules, url: p => p, send: async (label, method) => {
      calls.push(label);
      if (label === TABLE[0].id) return { status, utf8, clipped, text: '{}' };
      if (method === 'GET') return { status: 200, text: baselineRules, utf8: true, clipped: false };
      if (label.startsWith('restore-')) return { status: 200, text: '{}', utf8: true, clipped: false };
      return { status: 400, text: '{}', utf8: true, clipped: false };
    } });
    const unknown = !utf8 || clipped || ![200, 400].includes(status);
    assert.equal(rows[0].outcome, unknown ? 'unknown' : 'answered', `${status}/${utf8}/${clipped}`);
    assert.equal(calls.includes(`restore-${TABLE[0].id}`), unknown || status === 200);
    assert.equal(rows.length, unknown ? 1 : TABLE.length);
  }
});
