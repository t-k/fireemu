import test from 'node:test';
import assert from 'node:assert/strict';
import { serverValueCases, runServerValueCorpus, serverValueRules } from './server-values.mjs';

const prefix = 'rnext1_0123456789abcdef01234567';
test('five cases and two rounds retain requests, preimages, results, and atomic timestamp relationship', async () => {
  assert.equal(serverValueCases().length, 5);
  assert.ok(serverValueRules(prefix).rules[prefix].ready);
  const db = new Map(), calls = [];
  const transport = async request => {
    calls.push(request);
    const key = request.path;
    if (request.method === 'PUT') {
      const input = JSON.parse(request.body);
      if (input && input['.sv']) {
        const prior = db.get(key);
        const value = input['.sv'] === 'timestamp' ? 1710000000000 : (typeof prior === 'number' ? prior : 0) + input['.sv'].increment;
        db.set(key, value);
      } else db.set(key, input);
    }
    if (request.method === 'PATCH') db.set(key, { first: 1710000000001, second: 1710000000001, counter: 12 });
    return { status: 200, body: JSON.stringify(db.get(key) ?? null), headers: { etag: '"v"' } };
  };
  const rows = await runServerValueCorpus(transport, prefix);
  assert.equal(rows.length, 10);
  assert.equal(new Set(rows.map(x => `${x.round}/${x.id}`)).size, 10);
  assert.equal(rows.find(x => x.id === 'increment-nonnumeric').preimage, 'old');
  assert.equal(rows.find(x => x.id === 'increment-absent').preimage, null);
  assert.equal(rows.find(x => x.id === 'multipath-one-clock').sameClock, true);
  assert.ok(calls.every(x => x.path.startsWith(`/${prefix}/`) && x.phase === 'normal'));
});

test('unreadable or unknown response cannot yield an observed case', async () => {
  await assert.rejects(runServerValueCorpus(async () => ({ status: 500, body: '' }), prefix));
  await assert.rejects(runServerValueCorpus(async () => ({ status: 200, body: 'not-json' }), prefix));
});

test('a seed readback that differs from the declared preimage stops before placeholder write',async()=>{const calls=[];await assert.rejects(runServerValueCorpus(async req=>{calls.push(req);return {status:200,body:req.step==='sv-before'?'99':'null',headers:{}};},prefix),/preimage/);assert.equal(calls.some(req=>req.step==='sv-write'),false);});
