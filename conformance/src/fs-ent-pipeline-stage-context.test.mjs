import assert from 'node:assert/strict';
import { test } from 'node:test';



test('fixed corpus preserves 11 distinct cases and original nested ASTs', async () => {
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { O8A_PROGRAMS } = await import('./fs-ent-pipeline/o8a-corpus.mjs');
  const cases = stageContextCases();
  assert.equal(cases.length, 11);
  assert.equal(new Set(cases.map(x => x.id)).size, 11);
  assert.deepEqual(cases.filter(x => x.id.startsWith('replace-')).map(x => x.body.structuredPipeline.pipeline.stages[1].args[1].stringValue), ['full_replace', 'merge_overwrite_existing', 'merge_keep_existing', 'full_replace']);
  const original = O8A_PROGRAMS.find(x => x.id.endsWith('/nesting-main'));
  for (const depth of [48, 100]) assert.deepEqual(cases.find(x => x.id === `chain-${depth}-grpc`).body, original.steps.find(x => x.id === `chain-${depth}-grpc`).body);
});



test('new context is bound to the exact fresh database without widening generic targets', async () => {
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const { createContext } = await import('./fs-ent-pipeline/harness.mjs');
  const target = { kind: 'local', origin: 'http://127.0.0.1:1', grpcHost: '127.0.0.1', grpcPort: 1 };
  assert.throws(() => createContext({run: 1, target, database: 'entpipe2-20261029'}));
  const fresh = createStageContext({run: 1, target, database: 'entpipe2-20261029', approvedDatabase: 'entpipe2-20261029'});
  assert.equal(fresh.database, 'entpipe2-20261029');
  for (const database of ['entpipe1', '(default)', 'foreign']) assert.throws(() => createStageContext({run: 1, target, database, approvedDatabase: 'entpipe2-20261029'}));
});

test('owned seed includes distinct vector rankings and the original nesting seed', async () => {
  const { stageContextSeed } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const seed = stageContextSeed();
  assert.deepEqual(seed.map(([path]) => path), ['stage/a', 'stage/b', 'stage/c', 'other/a', 'ne/d1']);
  const vectors = seed.slice(0, 3).map(([, fields]) => fields.vec.mapValue.fields.value.arrayValue.values.map(x => x.doubleValue));
  const measures = [v => Math.hypot(v[0] - 1, v[1] - 2), v => (v[0] + 2 * v[1]) / (Math.hypot(...v) * Math.sqrt(5)), v => v[0] + 2 * v[1]];
  for (const f of measures) assert.equal(new Set(vectors.map(f)).size, 3);
  assert.deepEqual(seed.at(-1)[1], {i: {integerValue: '1'}});
});


test('isolated protobuf codec round-trips only original 48/100 nested requests', async () => {
  const { spawnSync } = await import('node:child_process');
  const script = new URL('./fs-ent-pipeline/stage-context-nesting-codec.mjs', import.meta.url);
  for (const depth of [48, 100]) {
    const out = spawnSync(process.execPath, [script.pathname, String(depth)], { encoding: 'utf8', timeout: 10000 });
    assert.equal(out.status, 0, out.stderr);
    const report = JSON.parse(out.stdout);
    assert.equal(report.depth, depth); assert.equal(report.roundTrip, true); assert.equal(report.recursionLimit, 1024);
  }
  const denied = spawnSync(process.execPath, [script.pathname, '47'], { encoding: 'utf8', timeout: 10000 });
  assert.notEqual(denied.status, 0);
});


test('two scoped rounds count observations and support separately', async () => {
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  const calls = [];
  const io = async (op, detail) => { calls.push([op, detail]); return { known: true, ok: true }; };
  const result = await runStageContextRounds(io);
  assert.equal(result.observations, 22); assert.equal(result.support, 10); assert.equal(calls.length, 32);
  assert.deepEqual(calls.map(x => x[0]).filter(x => x !== 'observe'), Array(2).fill(['baseline', 'seed', 'verify', 'delete-owned', 'verify-absence']).flat());
});

test('unknown seed and failed verification never trigger cleanup or mutation resend', async () => {
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  for (const bad of ['seed', 'verify']) {
    const calls = [];
    const io = async (op) => { calls.push(op); return op === bad ? { known: false, ok: false } : { known: true, ok: true }; };
    await assert.rejects(runStageContextRounds(io), /unknown/);
    assert.equal(calls.filter(x => x === bad).length, 1);
    assert.ok(!calls.includes('delete-owned'));
  }
});

test('unknown observation or cleanup stops immediately and never repeats mutations', async () => {
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  for (const failure of ['observe', 'delete-owned', 'verify-absence']) {
    const calls = [];
    await assert.rejects(runStageContextRounds(async (op) => {
      calls.push(op);
      return op === failure ? { known: false } : { known: true, ok: true };
    }), /unknown/);
    assert.equal(calls.at(-1), failure);
    assert.equal(calls.filter(x => x === 'seed').length, 1);
    assert.ok(calls.filter(x => x === 'delete-owned').length <= 1);
  }
});

test('generated phase/outcome/round table stops on every unknown without retry', async () => {
  const { readFileSync } = await import('node:fs');
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  const rows = readFileSync(new URL('./fs-ent-pipeline/fixtures/stage-context-rounds-pict.tsv', import.meta.url), 'utf8').trim().split('\n').slice(1);
  assert.equal(rows.length, 12);
  for (const row of rows) {
    const [phase, outcome, round] = row.split('\t');
    const calls = [];
    const run = () => runStageContextRounds(async (op, detail) => {
      calls.push([op, detail.round]);
      return op === phase && detail.round === Number(round) && outcome === 'unknown' ? { known: false } : { known: true, ok: true };
    });
    if (outcome === 'unknown') {
      await assert.rejects(run(), /unknown/);
      assert.deepEqual(calls.at(-1), [phase, Number(round)]);
      if (phase === 'seed' || phase === 'delete-owned') assert.equal(calls.filter(([op, n]) => op === phase && n === Number(round)).length, 1);
    } else {
      const result = await run(); assert.equal(result.observations + result.support, 32);
    }
  }
});
