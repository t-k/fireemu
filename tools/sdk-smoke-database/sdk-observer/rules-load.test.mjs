import test from 'node:test';
import assert from 'node:assert/strict';
import { TABLE, runRulesLoadProfile } from './rules-load-suite.mjs';

test('raw documents are sent once and accepted rules are restored before the next case', async () => {
  const calls = [], baseline = '{"rules":{}}';
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
  const calls = [], baseline = '{"rules":{}}';
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
  const baseline = '{"rules":{}}', calls = [];
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
  const baseline = '{"rules":{}}', calls = [];
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
  const baseline = '{"rules":{}}'; let count = 0;
  try {
    const { result } = await run({ target: localTarget('rules-load', '127.0.0.1:1'), runId: 'TEST-RULES-CAP', prefix: '/unused', directCap: 20, outDir: path.join(dir, 'run'), suite: 'rules-load' }, { fetchImpl: async (_url, init) => { count++; return new Response(init.method === 'GET' ? baseline : '{}', { status: 200 }); } });
    assert.equal(result.status, 'incomplete'); assert.equal(result.cleanup.rules, 'verified'); assert.ok(count <= 22); assert.ok(result.counts.direct <= 20);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
