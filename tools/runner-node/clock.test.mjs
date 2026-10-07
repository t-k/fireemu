import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const moduleUrl = new URL('./clock.mjs', import.meta.url).href;

function check(body, options = {}) {
  const script = `
    import assert from 'node:assert/strict';
    import timers from 'node:timers';
    import promises from 'node:timers/promises';
    const nativeDelay = promises.setTimeout;
    const NativeDate = Date;
    const { createRuntimeClock } = await import(${JSON.stringify(moduleUrl)});
    const clock = createRuntimeClock(${JSON.stringify({ date: 'virtual', timers: 'real', instantNanos: '1000000000', ...options })});
    clock.install();
    try { ${body} } finally { clock.restore(); }
    assert.equal(Date, NativeDate);
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
    encoding: 'utf8', timeout: 5000,
  });
  assert.equal(result.status, 0, result.stderr || String(result.error));
}

test('virtual Date preserves construction, parsing, prototype and subclass semantics', () => check(`
  assert.equal(Date.now(), 1000);
  assert.equal(new Date().getTime(), 1000);
  assert.equal(Date('ignored'), new NativeDate(1000).toString());
  assert.equal(new Date(0).getTime(), 0);
  assert.ok(Number.isNaN(new Date(undefined).getTime()));
  assert.equal(Date.parse('1970-01-01T00:00:01Z'), 1000);
  assert.equal(Date.UTC(1970, 0, 1), 0);
  assert.ok(new Date() instanceof Date);
  assert.ok(new NativeDate() instanceof Date);
  assert.equal(new Date().constructor, Date);
  assert.equal(new Date().constructor.now(), 1000);
  assert.equal(+new (new Date().constructor)(), 1000);
  class Child extends Date {}
  const child = new Child();
  assert.ok(child instanceof Child);
  assert.equal(child.getTime(), 1000);
`));

test('Date remains pinned across native waits and follows live updates after await', () => check(`
  const captured = new Date();
  await nativeDelay(4);
  assert.equal(Date.now(), 1000);
  clock.update({instantNanos:'2000000000'});
  await nativeDelay(1);
  assert.equal(Date.now(), 2000);
  assert.equal(captured.getTime(), 1000);
`));

test('negative and submillisecond epoch conversion floors consistently', () => check(`
  clock.update({instantNanos:'-1'});
  assert.equal(Date.now(), -1);
  clock.update({instantNanos:'999999'});
  assert.equal(Date.now(), 0);
  clock.update({instantNanos:'1000000'});
  assert.equal(Date.now(), 1);
`));

test('invalid Date range is refused without mutating clock or elapsed time', () => check(`
  assert.throws(() => clock.update({instantNanos:'8640000000000001000000'}), RangeError);
  assert.equal(Date.now(), 1000);
  assert.throws(() => clock.update({instantNanos:'01'}), TypeError);
`));

test('real Date and timers preserve the default runtime behavior', () => check(`
  assert.equal(Date, NativeDate);
  let called = false;
  setTimeout(() => {called = true}, 2);
  await nativeDelay(8);
  assert.ok(called);
`, {date:'real'}));

test('real timers run while virtual Date stays frozen', () => check(`
  const before = Date.now();
  await new Promise(resolve => setTimeout(resolve, 2));
  assert.equal(Date.now(), before);
`));

test('native Date does not constrain a Tasks-only logical clock', () => check(`
  clock.update({instantNanos:'9223372036854775807000000000'});
  assert.equal(Date, NativeDate);
`, {date:'real',instantNanos:'9223372036854775807000000000'}));

test('an aged virtual clock keeps native waits and timer deadlines deterministic', () => check(`
  const before=Date.now();
  await nativeDelay(2);
  assert.equal(Date.now(),before);
  let called=false;setTimeout(()=>{called=true},10);
  clock.update({instantNanos:'4000000000009999999',elapsedNanos:'100000000000009999999'});
  await clock.runDue();assert.equal(called,false);
  clock.update({instantNanos:'4000000000010000000',elapsedNanos:'100000000000010000000'});
  await clock.runDue();assert.equal(called,true);
`, {timers:'virtual',instantNanos:'4000000000000000000',elapsedNanos:'100000000000000000000'}));

test('virtual callback timers cover globals and named builtin imports', () => check(`
  const {setTimeout: importedTimeout} = await import('node:timers');
  const calls = [];
  setTimeout(() => calls.push(['global', Date.now()]), 10);
  timers.setTimeout(() => calls.push(['module', Date.now()]), 10);
  importedTimeout(() => calls.push(['named', Date.now()]), 10);
  await nativeDelay(15);
  assert.deepEqual(calls, []);
  clock.update({instantNanos:'1010000000'});
  assert.deepEqual(calls, []);
  assert.equal((await clock.runDue()).executed, 3);
  assert.deepEqual(calls, [['global',1010],['module',1010],['named',1010]]);
`, {timers:'virtual'}));

test('rewind does not consume or resurrect timers and fractional moves accumulate', () => check(`
  let calls = 0;
  setTimeout(() => calls++, 1);
  clock.update({instantNanos:'1000500000'});
  assert.equal((await clock.runDue()).executed, 0);
  clock.update({instantNanos:'0'});
  assert.equal((await clock.runDue()).executed, 0);
  clock.update({instantNanos:'500000'});
  assert.equal((await clock.runDue()).executed, 1);
  clock.update({instantNanos:'0'});
  clock.update({instantNanos:'2000000'});
  await clock.runDue();
  assert.equal(calls, 1);
`, {timers:'virtual'}));

test('absolute elapsed snapshots do not lose coalesced advancement and rewinds', () => check(`
  let calls = 0;
  setTimeout(() => calls++, 20);
  clock.update({instantNanos:'0', elapsedNanos:'20000000'});
  assert.equal((await clock.runDue()).executed, 1);
  clock.update({instantNanos:'0', elapsedNanos:'20000000'});
  assert.equal((await clock.runDue()).executed, 0);
  assert.equal(calls, 1);
`, {timers:'virtual',elapsedNanos:'0'}));

test('timer handles support cancellation, refresh, references and reactivation', () => check(`
  let calls = 0;
  const cancelled = setTimeout(() => calls += 100, 1);
  clearInterval(cancelled);
  const handle = setTimeout(() => calls++, 10);
  assert.equal(handle.hasRef(), true);
  assert.equal(handle.unref(), handle);
  assert.equal(handle.hasRef(), false);
  handle.ref();
  clock.update({instantNanos:'1005000000'});
  handle.refresh();
  clock.update({instantNanos:'1010000000'});
  assert.equal((await clock.runDue()).executed, 0);
  clock.update({instantNanos:'1015000000'});
  await clock.runDue();
  assert.equal(calls, 1);
  handle.refresh();
  clock.update({instantNanos:'1025000000'});
  await clock.runDue();
  assert.equal(calls, 2);
  clearTimeout(handle);
`, {timers:'virtual'}));

test('promise delays and intervals support named imports and AbortSignal', () => check(`
  const {setTimeout: delay, setInterval: interval} = await import('node:timers/promises');
  const aborter = new AbortController();
  const aborted = delay(50, undefined, {signal:aborter.signal});
  const rejection = assert.rejects(aborted, {name:'AbortError'});
  aborter.abort();
  await rejection;
  const timeout = delay(10, 'value');
  const ticks = interval(10, 'tick');
  const next = ticks.next();
  clock.update({instantNanos:'1010000000'});
  await clock.runDue();
  assert.equal(await timeout, 'value');
  assert.deepEqual(await next, {value:'tick',done:false});
  await ticks.return();
  assert.equal(clock.status().pending, 0);
`, {timers:'virtual'}));

test('timer drain is bounded, stable and does not advance the Date', () => check(`
  const calls = [];
  const interval = setInterval(() => calls.push('interval'), 1);
  setTimeout(() => calls.push('once'), 2);
  clock.update({instantNanos:'1100000000'});
  const first = await clock.runDue(3);
  assert.equal(first.executed, 3);
  assert.equal(first.due, 1);
  assert.deepEqual(calls, ['interval','interval','once']);
  assert.equal(Date.now(), 1100);
  assert.equal((await clock.runDue(2)).executed, 2);
  clearInterval(interval);
  assert.equal(clock.status().pending, 0);
  await assert.rejects(clock.runDue(0), RangeError);
`, {timers:'virtual'}));

test('virtual timers require virtual Date and reject invalid policy fields', () => {
  const script = `
    import assert from 'node:assert/strict';
    const {createRuntimeClock} = await import(${JSON.stringify(moduleUrl)});
    assert.throws(() => createRuntimeClock({date:'real',timers:'virtual'}), TypeError);
    assert.throws(() => createRuntimeClock({date:'invalid'}), TypeError);
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
});

test('timer callbacks yield to nested Promise continuations before the next timer', () => check(`
  const calls = [];
  setTimeout(async () => {
    await Promise.resolve();
    await Promise.resolve();
    calls.push('first');
    clearTimeout(second);
  }, 5);
  const second = setTimeout(() => calls.push('cancelled'), 10);
  clock.update({instantNanos:'1010000000'});
  await clock.runDue();
  assert.deepEqual(calls, ['first']);
`, {timers:'virtual'}));

test('promise timer imports can cancel later callbacks without awaiting application promises', () => check(`
  const {setTimeout: delay} = await import('node:timers/promises');
  const calls = [];
  delay(5).then(() => clearTimeout(cancelled));
  const cancelled = setTimeout(() => calls.push('cancelled'), 10);
  setTimeout(async () => { await delay(100); calls.push('future'); }, 5);
  clock.update({instantNanos:'1010000000'});
  await clock.runDue();
  assert.deepEqual(calls, []);
  assert.equal(clock.status().pending, 1);
`, {timers:'virtual'}));
