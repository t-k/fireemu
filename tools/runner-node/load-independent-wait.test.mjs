// Tests of the load-independent wait helper, on a virtual clock: nothing here depends on how busy the
// machine is. The helper is what http-admission-runner and input-limits-runner wait with.
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {
  STALL_MS, MAX_WAIT_MS, HARD_BACKSTOP_MS, childCpuTime, deadlineWithLag, quietStallMs, readText, sampled, untilExit, waitUntil,
} from './load-independent-wait.mjs';
import {MAX_INPUT_FRAME_WAIT_MS} from './protocol.mjs';

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
    check: () => c.t > 50 * STALL_MS, progress: () => (progress += 1), stallMs: STALL_MS, maxMs: 100 * STALL_MS, label: 'slow', ...c,
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

test('untilExit returns the known result at once, and polls every 50 ms by default', {timeout: 20_000}, async () => {
  const known = {code: 7, signal: null};
  assert.equal(await untilExit({end: Promise.resolve({code: 0}), result: () => known, label: 'known'}), known);
  const c = clock();
  await assert.rejects(
    untilExit({end: new Promise(() => {}), result: () => null, progress: () => 1, label: 'quiet', stallMs: 1000, ...c}),
    /quiet/,
  );
  assert.equal(c.t, 1000);
});

test('untilExit takes a resolved end whose result is not recorded yet, and passes on a rejected end', {timeout: 20_000}, async () => {
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
  const stuck = clock();
  await assert.rejects(
    untilExit({end: new Promise(() => {}), result: () => null, progress: () => 1, label: 'stuck child', stallMs: 200, sleepMs: 10, ...stuck}),
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

test('a wait that always shows progress still ends at the absolute ceiling, with a named error', {timeout: 20_000}, async () => {
  assert.ok(MAX_WAIT_MS >= 10 * STALL_MS && MAX_WAIT_MS < HARD_BACKSTOP_MS);
  const c = clock();
  let n = 0;
  await assert.rejects(
    waitUntil({check: () => false, progress: () => (n += 1), label: 'livelock', ...c}),
    error => /livelock/.test(error.message) && new RegExp(`still waiting after ${MAX_WAIT_MS} ms`).test(error.message),
  );
  assert.equal(c.t, MAX_WAIT_MS);
  const d = clock();
  await assert.rejects(waitUntil({check: () => false, progress: () => d.t, maxMs: 700, stallMs: 5000, label: 'short', ...d}), /still waiting after 700 ms/);
  assert.equal(d.t, 700);
  const e = clock();
  await assert.rejects(untilExit({end: new Promise(() => {}), result: () => null, progress: () => e.t, label: 'exit livelock', maxMs: 900, ...e}), /still waiting after 900 ms/);
});

// The designed quiet period: a child that is meant to say nothing and use no visible CPU for a whole
// product deadline, and then exits a few milliseconds after it. On Linux `ps` shows CPU time in whole
// seconds, so for such a child the stall window is the only thing that decides.
test('a wait that covers a designed quiet period needs a window longer than the period', {timeout: 20_000}, async () => {
  const exitAt = MAX_INPUT_FRAME_WAIT_MS + 3;
  const exit = {code: 2, signal: null};
  const run = (stallMs, c) => untilExit({
    end: new Promise(() => {}), result: () => (c.t >= exitAt ? exit : null), progress: () => Math.floor(c.t / 1000) * 0, label: 'header', stallMs, ...c,
  });
  // The race as it was: a window equal to the deadline gives up before the child exits.
  const same = clock();
  await assert.rejects(run(MAX_INPUT_FRAME_WAIT_MS, same), /no progress for 30000 ms/);
  assert.ok(same.t < exitAt, `gave up at ${same.t}, before the exit at ${exitAt}`);
  // With the window the helper computes for a quiet period, the exit is seen.
  const fixed = clock();
  assert.deepEqual(await run(quietStallMs(MAX_INPUT_FRAME_WAIT_MS), fixed), exit);
  assert.ok(fixed.t >= exitAt);
});

test('quietStallMs is the quiet period plus a margin, and is always longer than the period', () => {
  assert.equal(quietStallMs(30_000), 30_000 + STALL_MS);
  assert.equal(quietStallMs(30_000, 5_000), 35_000);
  assert.ok(quietStallMs(MAX_INPUT_FRAME_WAIT_MS) >= MAX_INPUT_FRAME_WAIT_MS + STALL_MS);
  assert.equal(quietStallMs(0), STALL_MS);
  assert.equal(quietStallMs(1000, 1), 1001, 'a margin of one millisecond is allowed');
  for (const bad of [-1, 1.5, NaN, '30000', undefined]) {
    assert.throws(() => quietStallMs(bad), {message: 'a quiet period is a non-negative integer of milliseconds'});
  }
  for (const bad of [0, -1, NaN, 1.5]) {
    assert.throws(() => quietStallMs(1000, bad), {message: 'the margin after a quiet period is a positive integer of milliseconds'});
  }
});

test('childCpuTime reads utime and stime from /proc/<pid>/stat when it exists, and falls back to ps', () => {
  // comm may hold spaces and parentheses; fields 14 and 15 are utime and stime in clock ticks.
  const stat = '4242 (node (a b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 7 5 0 0 20 0 1 0 12345 1 2 3\n';
  const calls = [];
  const readProc = path => { calls.push(path); return stat; };
  assert.equal(childCpuTime(4242, {readProc, ps: () => 'PS'}), '12');
  assert.deepEqual(calls, ['/proc/4242/stat']);
  assert.equal(childCpuTime(1, {readProc: () => { throw Object.assign(new Error('no proc'), {code: 'ENOENT'}); }, ps: () => '00:01.5'}), '00:01.5');
  assert.equal(childCpuTime(1, {readProc: () => 'garbage with no paren', ps: () => '00:02'}), '00:02');
  assert.equal(childCpuTime(1, {readProc: () => '1 a b c d e f g h i j k 7 5', ps: () => '00:02'}), '00:02', 'no (comm): not a stat line');
  assert.equal(childCpuTime(1, {readProc: () => ') S 1 1 1 0 -1 0 0 0 0 0 7 5', ps: () => '00:02'}), '00:02', 'no pid and comm in front');
  assert.equal(childCpuTime(1, {readProc: () => '1 (x) S 1 1 1 0 -1 0 0 0 0 0 7 x', ps: () => '00:05'}), '00:05', 'a bad stime');
  assert.equal(childCpuTime(1, {readProc: () => '1 (x) S 1 1 1 0 -1 0 0 0 0 0 x 5', ps: () => '00:06'}), '00:06', 'a bad utime');
  assert.equal(childCpuTime(1, {readProc: () => '1 (x) S 1 1 1 0 -1 0 0 0 0 0 7 5', ps: () => '00:07'}), '12', 'a minimal valid line');
  assert.equal(childCpuTime(1, {readProc: () => '1 (x) S 1 2', ps: () => '00:03'}), '00:03', 'a short stat line is not trusted');
  assert.equal(childCpuTime(1, {readProc: () => '1 (x) S 1 1 1 0 -1 0 0 0 0 0 a b 0', ps: () => '00:04'}), '00:04', 'non-numeric ticks are not trusted');
  assert.equal(childCpuTime(1, {readProc: () => { throw new Error('x'); }, ps: () => null}), null);
});

test('deadlineWithLag adds twice the worst event-loop stall, capped, and says when the machine is too loaded', () => {
  assert.deepEqual(deadlineWithLag(35_000, 0), {limit: 35_000, tooLoaded: false});
  assert.deepEqual(deadlineWithLag(35_000, 1500), {limit: 38_000, tooLoaded: false});
  assert.deepEqual(deadlineWithLag(35_000, 5000), {limit: 45_000, tooLoaded: false}, 'exactly the default cap, 10 s, is not over it');
  assert.deepEqual(deadlineWithLag(35_000, 5001), {limit: 45_000, tooLoaded: true}, 'over the cap the limit stops growing');
  assert.deepEqual(deadlineWithLag(35_000, 4999), {limit: 44_998, tooLoaded: false});
  assert.deepEqual(deadlineWithLag(35_000, 9000, 2000), {limit: 37_000, tooLoaded: true}, 'a lower cap');
  assert.deepEqual(deadlineWithLag(35_000, 1000, 2000), {limit: 37_000, tooLoaded: false}, 'exactly at the cap is not over it');
});

test('readText reads a file as UTF-8 text', () => {
  const text = readText(fileURLToPath(import.meta.url));
  assert.equal(typeof text, 'string');
  assert.ok(text.startsWith('// Tests of the load-independent wait helper'));
});
