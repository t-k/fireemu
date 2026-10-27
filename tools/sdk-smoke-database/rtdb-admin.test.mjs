// Tests of the lifted RTDB administration module: only what the lift adds, the parameters. The behaviour
// itself is covered by the unchanged tests of the residual recorder (rtdb-residual.test.mjs), which run
// through this module.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRtdbAdmin, Stop } from './rtdb-admin.mjs';

const config = (extra = {}) => ({
  instance: 'other-instance',
  location: 'europe-west1',
  caps: { pollsPerOperation: 2 },
  propagationMs: 1000,
  fireGraceMs: 7,
  rulesFor: (prefix) => ({ rules: { prefix } }),
  ...extra,
});
const production = { mode: 'production', packet: { projectNumber: '123456789012' } };

test('the urls follow the configured instance and location', () => {
  const u = createRtdbAdmin(config()).urls(production);
  assert.equal(u.data('a/b'), 'https://other-instance.firebaseio.com/a/b.json');
  assert.equal(u.instanceName, 'projects/123456789012/locations/europe-west1/instances/other-instance');
  assert.equal(u.instance, 'https://firebasedatabase.googleapis.com/v1beta/projects/123456789012/locations/europe-west1/instances/other-instance');
  assert.equal(u.list, 'https://firebasedatabase.googleapis.com/v1beta/projects/123456789012/locations/-/instances');
  assert.equal(createRtdbAdmin(config()).urls({ mode: 'local', local: { db: 'http://x', ns: 'n' } }).data('p'), 'http://x/p.json?ns=n');
});

test('only the exact disabled-by-owner answer of the configured instance counts', () => {
  const { isDisabledByOwner } = createRtdbAdmin(config());
  const body = JSON.stringify({ error: "The Firebase database 'other-instance' has been disabled by a database owner." });
  assert.equal(isDisabledByOwner(423, body), true);
  assert.equal(isDisabledByOwner(423, body.replace('other-instance', 'fireemu-q-rtdb2')), false);
  assert.equal(isDisabledByOwner(403, body), false);
  assert.equal(isDisabledByOwner(423, 'not json'), false);
});

test('an operation is polled at most caps.pollsPerOperation times and a Stop is a plain Error', async () => {
  const { waitOperation } = createRtdbAdmin(config());
  const calls = [];
  const run = { u: { op: (name) => `https://x/${name}` }, call: async (step) => (calls.push(step), { outcome: 'ok', value: { name: 'operations/o', done: false } }) };
  assert.equal(await waitOperation(run, 'api-enable', { name: 'operations/o', done: false }, async () => {}), false);
  assert.equal(calls.length, 2);
  assert.ok(new Stop('x') instanceof Error);
});

test('the run prefix is deleted after the configured fire grace when pending writes are possible', async () => {
  const { cleanup } = createRtdbAdmin(config());
  const waits = [];
  const run = {
    admin: { cleanup() {} },
    u: { data: (p) => `https://x/${p}.json` },
    state: { api: 'baseline', instance: 'baseline', rules: 'baseline', data: 'ours' },
    errors: [],
    fireWait: true,
    call: async () => ({ outcome: 'ok', value: null }),
  };
  await cleanup(run, { mode: 'local', prefix: 'p/r' }, async (ms) => waits.push(ms));
  assert.deepEqual(waits, [7]);
  assert.equal(run.state.data, 'baseline');
  assert.deepEqual(run.errors, []);
});
