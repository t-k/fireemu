import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate as flush } from 'node:timers/promises';
import { createWorldQueue, waitRequestTimeoutMs } from '../fireemu/testing-queue.mjs';

// A controllable operation: it records when it starts and finishes when the test says so.
// `cancelled` records that the queue rejected the call because an exclusive call cancelled it.
const CANCEL = Error('cancelled by an exclusive call');
function harness() {
  const queue = createWorldQueue();
  const ops = [];
  const reasons = new Set();
  const add = (kind, name = String(ops.length), reason) => {
    if (kind === 'exclusive') reasons.add(reason ?? CANCEL);
    const op = { kind, name, started: false, finished: false, cancelled: false };
    op.promise = queue[kind](signal => new Promise((resolve, reject) => {
      if (kind === 'waiting') op.signal = signal;
      op.started = true;
      op.finish = value => { op.finished = true; resolve(value); };
      op.fail = error => { op.finished = true; reject(error); };
    }), kind === 'exclusive' ? (reason ?? CANCEL) : undefined);
    op.promise.catch(error => { if (reasons.has(error)) op.cancelled = true; });
    ops.push(op);
    return op;
  };
  return { queue, ops, add };
}
const settleAll = async () => { for (let count = 0; count < 5; count++) await flush(); };
const startedNames = ops => ops.filter(op => op.started).map(op => op.name);

test('a waiting call does not delay a later ordered call: the awaitIdle and clock advance form', async () => {
  const { add, ops } = harness();
  const idle = add('waiting', 'awaitIdle');
  const advance = add('ordered', 'advance');
  await settleAll();
  assert.deepEqual(startedNames(ops), ['awaitIdle', 'advance'], 'both start at once');
  advance.finish('moved');
  await settleAll();
  idle.finish('idle');
  assert.deepEqual(await Promise.all([idle.promise, advance.promise]), ['idle', 'moved']);
});

test('ordered calls run one at a time in call order', async () => {
  const { add, ops } = harness();
  const [a, b, c] = ['a', 'b', 'c'].map(name => add('ordered', name));
  await settleAll();
  assert.deepEqual(startedNames(ops), ['a']);
  a.finish(); await settleAll();
  assert.deepEqual(startedNames(ops), ['a', 'b']);
  b.finish(); await settleAll();
  assert.deepEqual(startedNames(ops), ['a', 'b', 'c']);
  c.finish(); await settleAll();
});

test('a waiting call starts only after earlier ordered calls finish', async () => {
  const { add, ops } = harness();
  const move = add('ordered', 'move');
  add('waiting', 'idle');
  await settleAll();
  assert.deepEqual(startedNames(ops), ['move']);
  move.finish(); await settleAll();
  assert.deepEqual(startedNames(ops), ['move', 'idle']);
});

test('waiting calls do not order each other', async () => {
  const { add, ops } = harness();
  add('waiting', 'one'); add('waiting', 'two');
  await settleAll();
  assert.deepEqual(startedNames(ops), ['one', 'two']);
});

test('an exclusive call waits for earlier ordered calls and holds back every later call', async () => {
  const { add, ops } = harness();
  const move = add('ordered', 'move');
  const reset = add('exclusive', 'reset');
  const after = add('ordered', 'after');
  const afterWait = add('waiting', 'afterIdle');
  await settleAll();
  assert.deepEqual(startedNames(ops), ['move']);
  move.finish(); await settleAll();
  assert.deepEqual(startedNames(ops), ['move', 'reset']);
  reset.finish(); await settleAll();
  assert.deepEqual(startedNames(ops), ['move', 'reset', 'after']);
  after.finish(); await settleAll();
  assert.deepEqual(startedNames(ops), ['move', 'reset', 'after', 'afterIdle']);
  afterWait.finish(); await settleAll();
});

test('an exclusive call cancels running waiting calls with its reason and does not wait for them to be satisfied', { timeout: 10_000 }, async () => {
  const { add, ops } = harness();
  const idle = add('waiting', 'idle');
  await settleAll();
  assert.equal(idle.started, true);
  const reason = Error('the world was reset');
  const reset = add('exclusive', 'reset', reason);
  await settleAll();
  await assert.rejects(idle.promise, error => error === reason);
  assert.equal(idle.cancelled, true);
  assert.equal(idle.finished, false, 'the wait itself was left unsatisfied');
  assert.equal(reset.started, true, 'the exclusive call starts without anyone finishing the wait');
  reset.finish(); await settleAll();
});

test('a running wait is synchronously aborted by an exclusive call', async () => {
  const { add } = harness();
  const idle = add('waiting');
  await settleAll();
  assert.equal(idle.signal.aborted, false);
  const reason = Error('reset');
  const reset = add('exclusive', 'reset', reason);
  assert.equal(idle.signal.aborted, true);
  assert.equal(idle.signal.reason, reason);
  await assert.rejects(idle.promise, error => error === reason);
  await settleAll();
  assert.equal(reset.started, true);
  reset.finish();
});

test('a completed wait is not aborted by a later exclusive call', async () => {
  const { add } = harness();
  const idle = add('waiting');
  await settleAll();
  idle.finish();
  await idle.promise;
  await settleAll();
  const reset = add('exclusive');
  assert.equal(idle.signal.aborted, false);
  await settleAll();
  reset.finish();
});

test('a wait admitted after an exclusive call receives a fresh signal', async () => {
  const { add } = harness();
  const reset = add('exclusive');
  const idle = add('waiting');
  await settleAll();
  reset.finish();
  await settleAll();
  assert.equal(idle.signal.aborted, false);
  idle.finish();
});

test('a waiting call cancelled before it starts never starts', { timeout: 10_000 }, async () => {
  const { add, ops } = harness();
  const move = add('ordered', 'move');
  const idle = add('waiting', 'idle');
  const reason = Error('disposed');
  const dispose = add('exclusive', 'dispose', reason);
  await settleAll();
  await assert.rejects(idle.promise, error => error === reason);
  move.finish(); await settleAll();
  assert.equal(idle.started, false);
  assert.deepEqual(startedNames(ops), ['move', 'dispose']);
  dispose.finish(); await settleAll();
});

test('waiting calls admitted after an exclusive call are not cancelled by it', async () => {
  const { add, ops } = harness();
  const reset = add('exclusive', 'reset');
  const idle = add('waiting', 'idle');
  await settleAll();
  reset.finish(); await settleAll();
  assert.equal(idle.started, true);
  assert.equal(idle.cancelled, false);
  idle.finish('idle');
  assert.equal(await idle.promise, 'idle');
});

test('an exclusive call leaves ordered calls alone and still waits for them', async () => {
  const { add, ops } = harness();
  const move = add('ordered', 'move');
  const reset = add('exclusive', 'reset');
  await settleAll();
  assert.equal(move.cancelled, false);
  assert.equal(reset.started, false);
  move.finish(); await settleAll();
  assert.equal(reset.started, true);
  reset.finish();
});

test('a failed call does not stop later calls', async () => {
  const { add, ops } = harness();
  const first = add('ordered', 'first');
  const second = add('ordered', 'second');
  const reset = add('exclusive', 'reset');
  const later = add('waiting', 'later');
  await settleAll();
  first.fail(Error('first failed')); await settleAll();
  assert.ok(second.started);
  await assert.rejects(first.promise, /first failed/);
  second.fail(Error('second failed')); await settleAll();
  assert.ok(reset.started);
  reset.finish(); await settleAll();
  assert.ok(later.started);
  later.finish();
  await later.promise;
  assert.deepEqual(startedNames(ops), ['first', 'second', 'reset', 'later']);
});

test('settled covers exclusive and ordered calls admitted so far but not waiting calls', async () => {
  const { add, queue } = harness();
  const idle = add('waiting', 'idle');
  const move = add('ordered', 'move');
  let settled = false;
  queue.settled().then(() => { settled = true; });
  await settleAll();
  assert.equal(settled, false);
  move.finish(); await settleAll();
  assert.equal(settled, true);
  assert.equal(idle.finished, false);
});

// Reference model: the admission rules written out as predecessor sets (see WorldQueue.tla).
// Operations are admitted one at a time with progress in between, so waiting calls can be running
// or queued when an exclusive call arrives.
class Model {
  constructor() { this.ops = []; }
  admit(kind) {
    const index = this.ops.length;
    if (kind === 'exclusive') for (const op of this.ops) if (op.kind === 'waiting' && op.state !== 'done' && op.state !== 'cancelled') op.state = 'cancelled';
    this.ops.push({ kind, state: 'queued' });
    return index;
  }
  complete(index) { this.ops[index].state = 'done'; }
  isDone(op) { return op.state === 'done' || op.state === 'cancelled'; }
  preds(index) {
    const kind = this.ops[index].kind;
    return this.ops.slice(0, index).filter(op => kind === 'exclusive' || op.kind !== 'waiting');
  }
  startable() {
    // Eager: any queued call whose predecessors are done has started (or is running).
    let changed = true;
    while (changed) {
      changed = false;
      this.ops.forEach((op, index) => {
        if (op.state === 'queued' && this.preds(index).every(other => this.isDone(other))) { op.state = 'running'; changed = true; }
      });
    }
  }
  started() { return this.ops.flatMap((op, index) => op.state === 'running' || op.state === 'done' ? [index] : []); }
}

function prng(seed) {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 2 ** 32; };
}

test('random interleavings of admission and completion follow the admission rules and always complete', async () => {
  for (let seed = 1; seed <= 400; seed++) {
    const random = prng(seed);
    const { add, ops } = harness();
    const model = new Model();
    const total = 1 + Math.floor(random() * 8);
    let admitted = 0;
    for (let step = 0; step < 4 * total && (admitted < total || ops.some(op => !op.finished && !op.cancelled)); step++) {
      const choice = random();
      if (admitted < total && (choice < 0.45 || ops.every(op => op.finished || op.cancelled))) {
        const kind = ['ordered', 'waiting', 'exclusive'][Math.floor(random() * 3)];
        model.admit(kind);
        add(kind);
        admitted++;
      } else {
        const running = ops.flatMap((op, index) => op.started && !op.finished && !op.cancelled ? [index] : []);
        if (running.length) {
          const pick = running[Math.floor(random() * running.length)];
          if (random() < 0.2) ops[pick].fail(Error('x')); else ops[pick].finish();
          model.complete(pick);
        }
      }
      model.startable();
      await settleAll();
      for (const [index, op] of ops.entries()) if (op.cancelled && model.ops[index].state !== 'cancelled') assert.fail(`seed ${seed}: call ${index} cancelled without a later exclusive call`);
      // A call the model cancelled is rejected as cancelled.
      model.ops.forEach((modelOp, index) => { if (modelOp.state === 'cancelled') assert.ok(ops[index].cancelled, `seed ${seed}: cancelled call ${index} was not rejected`); });
      const live = model.started().filter(index => model.ops[index].state !== 'cancelled');
      assert.deepEqual(ops.flatMap((op, index) => op.started ? [index] : []).filter(index => model.ops[index].state !== 'cancelled'), live, `seed ${seed} step ${step}: ${ops.map(op => op.kind[0])}`);
    }
    // Drain: finish whatever still runs, in order, until every call has ended.
    for (let drain = 0; drain < 3 * total; drain++) {
      for (const [index, op] of ops.entries()) if (op.started && !op.finished && !op.cancelled) { op.finish(); model.complete(index); }
      model.startable();
      await settleAll();
    }
    assert.ok(ops.every(op => op.finished || op.cancelled), `seed ${seed}: every call ends: ${ops.map(op => `${op.kind[0]}${op.started ? 's' : ''}${op.finished ? 'f' : ''}`)}`);
  }
});

test('an awaitIdle request may take its wait budget plus five seconds', () => {
  assert.equal(waitRequestTimeoutMs({ timeoutSeconds: 20 }), 25_000);
  assert.equal(waitRequestTimeoutMs({}), 35_000, 'the daemon waits 30 s when no budget is given');
  assert.equal(waitRequestTimeoutMs(undefined), 35_000);
  assert.equal(waitRequestTimeoutMs({ timeoutSeconds: 0 }), 5_000);
  assert.equal(waitRequestTimeoutMs({ timeoutSeconds: 2.5 }), 7_500);
  assert.equal(waitRequestTimeoutMs({ timeoutSeconds: 10_000 }), 605_000, 'the daemon clamps the budget to 600 s');
  assert.equal(waitRequestTimeoutMs({ timeoutSeconds: -5 }), 5_000);
  for (const [timeoutSeconds, expected] of [[1.2345, 6235], [0.0001, 5001], [599.9999, 605000], [600.0001, 605000], [601, 605000], [5e-324, 5001], [0.1 + 0.2, 5301]]) assert.equal(waitRequestTimeoutMs({ timeoutSeconds }), expected);
  for (const timeoutSeconds of ['20', NaN, Infinity, null, {}]) assert.equal(waitRequestTimeoutMs({ timeoutSeconds }), 35_000, `${String(timeoutSeconds)} falls back to the daemon default`);
});

test('the wait request timeout follows the clamp rule for any budget', () => {
  const random = prng(7);
  const budgets = [0, 600];
  for (let count = 0; count < 2000; count++) {
    const scale = 10 ** (1 + count % 6);
    budgets.push(Math.round((random() - 0.2) * 1400 * scale) / scale);
  }
  for (const timeoutSeconds of budgets) {
    const r = waitRequestTimeoutMs({ timeoutSeconds });
    const budget = Math.min(Math.max(timeoutSeconds, 0), 600) * 1000;
    assert.ok(Number.isInteger(r), `${timeoutSeconds} s`);
    assert.ok(r >= 5000 && r <= 605000);
    // Compare the budget part alone: adding 5000 to a float such as 521729.00000000006 would round away the excess.
    assert.ok(r - 5000 >= budget && r - 5000 < budget + 1, `${timeoutSeconds} s gave ${r}`);
    assert.doesNotThrow(() => AbortSignal.timeout(r));
  }
});
