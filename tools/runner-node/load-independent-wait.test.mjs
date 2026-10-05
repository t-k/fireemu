// Tests of the load-independent wait helper, on a virtual clock: nothing here depends on how busy the
// machine is. The helper is what http-admission-runner and input-limits-runner wait with.
import assert from 'node:assert/strict';
import test from 'node:test';
import {STALL_MS, HARD_BACKSTOP_MS, childCpuTime, sampled, untilExit, waitUntil} from './load-independent-wait.mjs';

/** A virtual clock: sleep(ms) advances it, so a wait of any length takes no real time. */
function clock() {
  const c = {t: 0, sleeps: 0, now: () => c.t, sleep: async ms => {
    c.t += ms;
    // A wait that never ends must fail the test instead of spinning the event loop.
    if ((c.sleeps += 1) > 2_000_000) throw new Error('runaway wait');
  }};
  return c;
}

test('the named bounds are generous and shared', () => {
  assert.ok(STALL_MS >= 30_000);
  assert.ok(HARD_BACKSTOP_MS >= 10 * STALL_MS);
});

test('returns the truthy value as soon as the check passes', async () => {
  const c = clock();
  let n = 0;
  const value = await waitUntil({check: () => (++n === 3 ? 'ready' : false), label: 'x', ...c});
  assert.equal(value, 'ready');
  assert.equal(n, 3);
});

test('does not give up while progress keeps changing, however long the wait is', async () => {
  const c = clock();
  let progress = 0;
  const value = await waitUntil({
    check: () => c.t > 50 * STALL_MS, progress: () => (progress += 1), stallMs: STALL_MS, label: 'slow', ...c,
  });
  assert.equal(value, true);
  assert.ok(c.t > 50 * STALL_MS, 'it waited far longer than one stall window');
});

test('gives up after one stall window with no progress, naming the label and the window', async () => {
  const c = clock();
  await assert.rejects(
    waitUntil({check: () => false, progress: () => 7, stallMs: 1000, label: 'the child', ...c}),
    error => /the child/.test(error.message) && /1000 ms/.test(error.message),
  );
  assert.equal(c.t, 1000, 'it polls every 10 ms by default and gives up at the window');
});

test('a window restarts when progress changes after a pause', async () => {
  const c = clock();
  const value = await waitUntil({
    check: () => c.t >= 2500,
    progress: () => (c.t < 900 ? 1 : c.t < 1800 ? 2 : 3), // changes at 900 and 1800
    stallMs: 1000, label: 'staged', ...c,
  });
  assert.equal(value, true);
});

test('no progress function means the stall window is a plain deadline', async () => {
  const c = clock();
  await assert.rejects(waitUntil({check: () => false, stallMs: 500, label: 'plain', ...c}), /plain/);
});

test('failFast is consulted on every poll and its error wins over the stall', async () => {
  const c = clock();
  await assert.rejects(
    waitUntil({check: () => false, failFast: () => { if (c.t >= 40) throw new Error('child exited'); }, stallMs: 1000, label: 'z', ...c}),
    /child exited/,
  );
});

test('an async check and an async progress are awaited', async () => {
  const c = clock();
  let n = 0;
  const value = await waitUntil({check: async () => ++n >= 4, progress: async () => n, label: 'async', ...c});
  assert.equal(value, true);
});

test('untilExit returns the known result at once, and polls every 50 ms by default', async () => {
  const known = {code: 7, signal: null};
  assert.equal(await untilExit({end: Promise.resolve({code: 0}), result: () => known, label: 'known'}), known);
  const c = clock();
  await assert.rejects(
    untilExit({end: new Promise(() => {}), result: () => null, progress: () => 1, label: 'quiet', stallMs: 1000, ...c}),
    /quiet/,
  );
  assert.equal(c.t, 1000);
});

test('untilExit takes a resolved end whose result is not recorded yet, and passes on a rejected end', async () => {
  const c = clock();
  assert.deepEqual(await untilExit({end: Promise.resolve({code: 1}), result: () => null, label: 'late record', ...c}), {code: 1});
  await assert.rejects(
    untilExit({end: Promise.reject(new Error('spawn failed')), result: () => null, label: 'spawn', stallMs: 300, sleepMs: 10}),
    /spawn failed/,
  );
});

test('untilExit resolves with the exit, or rejects only after a stall', {timeout: 20_000}, async () => {
  const c = clock();
  let result = null;
  const end = new Promise(resolve => setTimeout(() => resolve((result = {code: 2, signal: null})), 20));
  assert.deepEqual(await untilExit({end, result: () => result, label: 'child', stallMs: 1000, sleepMs: 5}), {code: 2, signal: null});
  const never = new Promise(() => {});
  await assert.rejects(
    untilExit({end: never, result: () => null, progress: () => 1, label: 'stuck child', stallMs: 200, sleepMs: 10}),
    /stuck child/,
  );
  // While progress changes, the same child may take as long as it likes.
  let ticks = 0, done = null;
  const slow = new Promise(resolve => setTimeout(() => resolve((done = {code: 0, signal: null})), 400));
  assert.deepEqual(
    await untilExit({end: slow, result: () => done, progress: () => (ticks += 1), label: 'busy child', stallMs: 150, sleepMs: 10}),
    {code: 0, signal: null},
  );
  assert.ok(c.t === 0);
});

test('childCpuTime reads a running process and is null for one that is gone', async () => {
  assert.match(childCpuTime(process.pid), /^[\d:.-]+$/, 'only the time, without a header');
  assert.equal(childCpuTime(2 ** 22 + 12345), null);
  assert.equal(childCpuTime(0), null);
  assert.equal(childCpuTime(undefined), null);
  assert.equal(childCpuTime(-5), null);
});

test('sampled reads at most once per window and keeps the last value between reads', () => {
  let t = 0, reads = 0;
  const read = sampled(() => ++reads, 1000, () => t);
  assert.equal(read(), 1);
  t = 999; assert.equal(read(), 1);
  assert.equal(reads, 1);
  t = 1000; assert.equal(read(), 2);
  t = 1999; assert.equal(read(), 2);
  t = 2000; assert.equal(read(), 3);
  assert.equal(sampled(() => 'x')(), 'x', 'the default clock works');
  let u = 0, reads2 = 0;
  const byDefault = sampled(() => ++reads2, undefined, () => u);
  byDefault(); u = 999; byDefault();
  assert.equal(reads2, 1, 'the default window is one second');
  u = 1000; byDefault();
  assert.equal(reads2, 2);
});
