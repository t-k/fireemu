// Replay the finite sanitized RTDB Rules identity observations against a local fireemu.
import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const [host, out] = process.argv.slice(2);
if (!/^(?:127\.0\.0\.1|localhost|\[::1\]):[0-9]+$/.test(host ?? '') || !out) {
  throw Error('usage: node rules-identity-replay.mjs <loopback-host:port> <output.json>');
}
const fixture = JSON.parse(readFileSync(new URL('./fixtures/production-rules-identity.json', import.meta.url)));
const base = `http://${host}`;
const prefix = fixture.provenance.prefix;
const settings = `${base}/.settings/rules.json?ns=identity`;
const data = `${base}/${prefix}/probe.json?ns=identity`;
const owner = { authorization: 'Bearer owner' };
async function request(url, init = {}) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(15000) });
  return { status: response.status, body: await response.text() };
}
async function put(url, body) {
  return request(url, { method: 'PUT', headers: { ...owner, 'content-type': 'application/json' }, body });
}
const rows = [];
assert.equal((await put(data, '{"v":1}')).status, 200);
let previous;
for (const cell of fixture.cases) {
  const rules = JSON.stringify({ rules: { '.read': false, '.write': false, [prefix]: { probe: { '.read': cell.expression } } } });
  const load = await put(settings, rules);
  const readback = await request(settings, { headers: owner });
  const reads = [];
  assert.equal(load.status, cell.loadStatus, cell.id);
  if (cell.error === null) {
    assert.deepEqual(JSON.parse(load.body), { status: 'ok' }, cell.id);
    previous = rules;
  } else {
    assert.deepEqual(JSON.parse(load.body), { error: cell.error }, cell.id);
  }
  assert.equal(readback.status, 200, cell.id);
  assert.equal(readback.body, previous, cell.id);
  for (const expected of cell.readStatus) {
    const auth = cell.id.startsWith('A');
    const url = data + (auth ? '&auth_variable_override=' + encodeURIComponent(JSON.stringify({ uid: 'synthetic-user' })) : '');
    const read = await request(url, auth ? { headers: owner } : {});
    assert.equal(read.status, expected, cell.id);
    assert.deepEqual(JSON.parse(read.body), expected === 401 ? { error: 'Permission denied' } : { v: 1 }, cell.id);
    reads.push(read);
  }
  rows.push({ id: cell.id, load, readback, reads });
}
writeFileSync(out, JSON.stringify(rows, null, 2) + '\n', { flag: 'wx' });
