import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execute, runCorpus } from './runner.mjs';

const rows = readFileSync(new URL('./cases.tsv', import.meta.url), 'utf8').trim().split('\n').slice(1).map(x => x.split('\t'));
for (const [method, result, phase, budget] of rows) test(`PICT ${method} ${result} ${phase} ${budget}`, async () => {
  const sent = [];
  const state = { used: budget === 'available' ? 0 : 2, max: 2, cleanupReserve: phase === 'normal' && budget === 'exhausted' ? 1 : 0, unknown: false, journal: [] };
  const tx = async req => { sent.push(req); return result === 'complete' ? { status: 200, body: 'null', headers: {} } : undefined; };
  const request = { method, path: '/x.json', phase };
  if (budget === 'exhausted') await assert.rejects(execute(state, tx, request));
  else if (result === 'unknown') { await assert.rejects(execute(state, tx, request)); assert.equal(state.unknown, true); await assert.rejects(execute(state, tx, request)); assert.equal(sent.length, 1); }
  else { await execute(state, tx, request); assert.equal(state.journal.at(-1).state, 'response-persisted'); }
});

test('two rounds use returned push key and cleanup each round', async () => {
  const requests = [];
  const values = new Map();
  const tx = async r => { requests.push(r); if (r.method === 'PUT') { const v=JSON.parse(r.body); if (r.path.endsWith('/query.json')) delete v.d; values.set(r.path, JSON.stringify(v)); } if (r.method === 'POST') values.set(r.path.replace('.json', '/-abc.json'), r.body); if (r.method === 'DELETE') values.delete(r.path); return { status: 200, headers: {}, body: r.method === 'POST' ? '{"name":"-abc"}' : r.method === 'GET' ? values.get(r.path) ?? 'null' : 'null' }; };
  const state = { used: 0, max: 100, cleanupReserve: 24, unknown: false, journal: [] };
  await runCorpus(state, tx, 'owned');
  assert.equal(requests.filter(r => r.method === 'POST').length, 2);
  assert.equal(requests.filter(r => r.path.includes('/push/-abc.json')).length, 6);
  assert.equal(requests.filter(r => r.method === 'DELETE' && /\/r[12]\.json$/.test(r.path)).length, 2);
});

test('invalid generated key stops before child request', async () => {
  const sent = [];
  const values = new Map();
  const tx = async r => { sent.push(r); if (r.method === 'PUT') { const v=JSON.parse(r.body); if (r.path.endsWith('/query.json')) delete v.d; values.set(r.path, JSON.stringify(v)); } return { status: 200, headers: {}, body: r.method === 'POST' ? '{"name":"../bad"}' : r.method === 'GET' ? values.get(r.path) ?? 'null' : 'null' }; };
  const state = { used: 0, max: 100, cleanupReserve: 24, unknown: false, journal: [] };
  await assert.rejects(runCorpus(state, tx, 'owned'));
  assert.equal(sent.filter(r => r.method === 'POST').length, 1);
});

test('seed mismatch stops before observations', async () => {
  const sent = [];
  const tx = async r => { sent.push(r); return { status: 200, headers: {}, body: 'null' }; };
  const state = { used: 0, max: 100, cleanupReserve: 24, unknown: false, journal: [] };
  await assert.rejects(runCorpus(state, tx, 'owned'), /seed mismatch/);
  assert.equal(sent.some(r => r.method === 'POST'), false);
});

test('wrong POST child readback stops before deletion', async () => {
  const sent = [], values = new Map();
  const tx = async r => { sent.push(r); if (r.method === 'PUT') { const v=JSON.parse(r.body); if (r.path.endsWith('/query.json')) delete v.d; values.set(r.path, JSON.stringify(v)); } return { status: 200, headers: {}, body: r.method === 'POST' ? '{"name":"-abc"}' : r.method === 'GET' ? values.get(r.path) ?? 'null' : 'null' }; };
  const state = { used: 0, max: 100, cleanupReserve: 24, unknown: false, journal: [] };
  await assert.rejects(runCorpus(state, tx, 'owned'), /child mismatch/);
  assert.equal(sent.some(r => r.method === 'DELETE'), false);
});
