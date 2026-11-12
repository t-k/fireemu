import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createTestWorld } from '../fireemu/testing.mjs';

const binary = process.env.FIREEMU_TEST_BINARY;
const runFile = promisify(execFile);
const native = { skip: !binary, timeout: 60_000 };
const runner = new URL('../../tools/runner-node/index.mjs', import.meta.url).pathname;

// A Functions source whose task-queue function counts its deliveries and answers 200.
async function functionsFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fireemu-settle-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, 'functions');
  await mkdir(join(source, 'node_modules', 'express'), { recursive: true });
  await writeFile(join(source, 'package.json'), JSON.stringify({ main: 'index.cjs' }));
  await writeFile(join(source, 'node_modules', 'express', 'package.json'), JSON.stringify({ name: 'express', version: '5.0.0', main: 'index.cjs' }));
  await writeFile(join(source, 'node_modules', 'express', 'index.cjs'), `module.exports=function(){let handler;const app=(req,res)=>{let body='';req.on('data',c=>body+=c);req.on('end',()=>{req.body=JSON.parse(body||'{}');const p=req.url.split('?')[0].split('/');req.params={project:p[1],region:p[2],name:p[3]};req.get=name=>req.headers[name.toLowerCase()];res.status=code=>{res.statusCode=code;return res;};res.send=value=>res.end(String(value));res.json=value=>res.end(JSON.stringify(value));handler(req,res,()=>{});});};app.use=()=>{};app.all=(_path,fn)=>handler=fn;return app;};for(const name of ['json','text','urlencoded','raw'])module.exports[name]=()=>()=>{};`);
  await writeFile(join(source, 'index.cjs'), `
    let deliveries = 0;
    const api = async (req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ deliveries })); };
    api.__endpoint = { platform: 'gcfv2', httpsTrigger: {} };
    let fired = 0;
    const burst = async (req, res) => { for (let index = 0; index < 1500; index++) setTimeout(() => { fired++; }, 10); res.end('scheduled'); };
    burst.__endpoint = { platform: 'gcfv2', httpsTrigger: {} };
    const fires = async (req, res) => { res.end(String(fired)); };
    fires.__endpoint = { platform: 'gcfv2', httpsTrigger: {} };
    const slow = async (req, res) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500); deliveries++; res.statusCode = 200; res.end('slow'); };
    slow.__endpoint = { platform: 'gcfv2', taskQueueTrigger: { retryConfig: { maxAttempts: 1 }, rateLimits: { maxConcurrentDispatches: 1, maxDispatchesPerSecond: 100 } } };
    const task = async (req, res) => { deliveries++; res.statusCode = 200; res.end('ok'); };
    task.__endpoint = { platform: 'gcfv2', taskQueueTrigger: { retryConfig: { maxAttempts: 1 }, rateLimits: { maxConcurrentDispatches: 1, maxDispatchesPerSecond: 100 } } };
    module.exports = { api, task, slow, burst, fires };
  `);
  return { root, source };
}

async function worldWithTasks(t, extra = {}) {
  const { source } = await functionsFixture(t);
  const world = await createTestWorld({
    binaryPath: binary, projectId: 'demo-settle', clockStart: '2026-01-01T00:00:00Z', functionsSource: source,
    services: ['auth', 'functions'], clock: { timers: 'virtual' }, env: { ...process.env, NODE_PATH: '', FIREEMU_RUNNER_NODE: runner }, ...extra,
  });
  t.after(() => world.dispose());
  return world;
}

async function scheduleTask(world, name, delayMs, queue = 'task') {
  const now = Date.parse((await world.clock.get()).clock.clock);
  const response = await fetch(`${world.endpoints.tasks.url}/projects/${world.projectId}/locations/us-central1/queues/${queue}/tasks`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ task: { name, scheduleTime: new Date(now + delayMs).toISOString(), httpRequest: { url: '', body: Buffer.from('{}').toString('base64') } } }),
  });
  assert.equal(response.status, 200, await response.clone().text());
}
async function deliveries(world) {
  const response = await fetch(`${world.endpoints.functions.url}/${world.projectId}/us-central1/api`);
  return (await response.json()).deliveries;
}

test('awaitIdle and a clock advance issued together complete instead of waiting for each other', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const started = Date.now();
  const [idle, moved] = await Promise.all([
    world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 15 }),
    world.clock.advance(60_000),
  ]);
  assert.equal(idle.idle, true);
  assert.ok(Date.parse(moved.clock) > Date.parse('2026-01-01T00:00:00Z'));
  assert.ok(Date.now() - started < 12_000, 'finished well before the wait timeout');
  assert.equal(await deliveries(world), 1);
});

test('the same pair completes in the opposite call order', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const [moved, idle] = await Promise.all([
    world.clock.advance(60_000),
    world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 15 }),
  ]);
  assert.equal(idle.idle, true);
  assert.ok(moved.clock);
  assert.equal(await deliveries(world), 1);
});

test('a clock read is answered while an awaitIdle call is still waiting', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  let settled = false;
  const idle = world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 15 }).then(value => { settled = true; return value; });
  const session = await world.clock.get();
  assert.ok(session.clock.clock);
  assert.equal(settled, false, 'the wait is still pending');
  await world.clock.advance(60_000);
  assert.equal((await idle).idle, true);
});

test('advanceAndSettle moves the clock, drains due work and waits for idle in that order', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  assert.equal(await deliveries(world), 0);
  const result = await world.clock.advanceAndSettle(60_000);
  assert.equal(result.idle.idle, true);
  assert.equal(result.idle.scope, 'runnable');
  assert.equal(Date.parse(result.clock.clock), Date.parse('2026-01-01T00:01:00Z'));
  assert.ok(Array.isArray(result.timers.codebases));
  assert.equal(await deliveries(world), 1, 'the due task ran before the helper returned');
});

test('advanceAndSettle accepts the all scope, a duration object and skipping timers', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 30_000);
  const result = await world.clock.advanceAndSettle({ seconds: 30 }, { scope: 'all', timeoutSeconds: 15, runTimers: false });
  assert.equal(result.idle.scope, 'all');
  assert.equal(result.timers, undefined);
  assert.equal(await deliveries(world), 1);
});

test('advanceAndSettle in the runnable scope does not wait for work scheduled beyond the move', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'much-later', 3_600_000);
  const result = await world.clock.advanceAndSettle(1000);
  assert.equal(result.idle.idle, true);
  assert.equal(await deliveries(world), 0);
});

test('an awaitIdle started after advanceAndSettle does not delay later clock calls', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const settled = world.clock.advanceAndSettle(10, { scope: 'all', timeoutSeconds: 15 });
  const later = world.clock.advance(60_000);
  assert.ok((await later).clock);
  assert.equal((await settled).idle.idle, true);
});

test('advanceAndSettle rejects invalid options before calling the daemon', native, async t => {
  const world = await worldWithTasks(t);
  await assert.rejects(world.clock.advanceAndSettle(1, { scope: 'future' }), /scope must be all or runnable/);
  await assert.rejects(world.clock.advanceAndSettle(1, { timeoutSeconds: -1 }), /timeoutSeconds/);
  await assert.rejects(world.clock.advanceAndSettle(1, { timeoutSeconds: 601 }), /timeoutSeconds/);
  await assert.rejects(world.clock.advanceAndSettle(1, { runTimers: 'yes' }), /runTimers must be a boolean/);
  assert.equal((await world.clock.get()).clock.clock, '2026-01-01T00:00:00Z', 'no clock move happened');
});

test('a failed move is reported and the wait never starts', native, async t => {
  const world = await worldWithTasks(t);
  await assert.rejects(world.clock.advanceAndSettle({ seconds: -5 }), /control 400/);
});

test('reset aborts the pending awaitIdle request synchronously', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const realFetch = globalThis.fetch;
  let signal, recorded;
  const started = new Promise(resolve => { recorded = resolve; });
  t.mock.method(globalThis, 'fetch', (url, init) => {
    if (!String(url).endsWith(':awaitIdle')) return realFetch(url, init);
    signal = init.signal;
    recorded();
    return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
  });
  const idle = world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 30 });
  await started;
  await delay(200);
  assert.equal(signal.aborted, false);
  const reset = world.reset();
  assert.equal(signal.aborted, true);
  await assert.rejects(idle, /cancelled: the world was reset/);
  await reset;
});

test('dispose aborts the advanceAndSettle awaitIdle request synchronously', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const realFetch = globalThis.fetch;
  let signal, recorded;
  const started = new Promise(resolve => { recorded = resolve; });
  t.mock.method(globalThis, 'fetch', (url, init) => {
    if (!String(url).endsWith(':awaitIdle')) return realFetch(url, init);
    signal = init.signal;
    recorded();
    return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
  });
  const idle = world.clock.advanceAndSettle(10, { scope: 'all', timeoutSeconds: 30 });
  await started;
  await delay(200);
  assert.equal(signal.aborted, false);
  const dispose = world.dispose();
  assert.equal(signal.aborted, true);
  await assert.rejects(idle, /cancelled: the world was disposed/);
  await dispose;
});

test('a reset cancels a pending awaitIdle and the world keeps working afterwards', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const idle = world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 30 });
  const cancelled = assert.rejects(idle, /cancelled: the world was reset/);
  await delay(300); // the wait has reached the daemon
  const started = Date.now();
  await world.reset();
  await cancelled;
  assert.ok(Date.now() - started < 20_000, 'reset did not wait for the 30 second budget');
  assert.equal(world.generation, 2);
  assert.ok((await world.clock.get()).clock.clock);
});

test('a dispose behind a pending awaitIdle cancels it and disposes the world', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'later', 60_000);
  const idle = world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 30 });
  const cancelled = assert.rejects(idle, /cancelled: the world was disposed/);
  await delay(300);
  const started = Date.now();
  await world.dispose();
  await cancelled;
  assert.ok(Date.now() - started < 20_000, 'dispose did not wait for the 30 second budget');
  assert.throws(() => world.endpoints, /disposed/);
});

test('advanceAndSettle pending during dispose is cancelled', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'much-later', 3_600_000);
  const settled = world.clock.advanceAndSettle(10, { scope: 'all', timeoutSeconds: 30 });
  const cancelled = assert.rejects(settled, /cancelled: the world was disposed/);
  await delay(500);
  await world.dispose();
  await cancelled;
});

test('an awaitIdle wait is bounded by its own timeout rather than the request timeout', native, async t => {
  const world = await worldWithTasks(t, { requestTimeoutMs: 400 });
  await scheduleTask(world, 'later', 60_000);
  await assert.rejects(world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 2 }), error => error.status === 504);
});

test('ordinary control calls keep their request timeout', native, async t => {
  const world = await worldWithTasks(t, { requestTimeoutMs: 5000 });
  assert.ok((await world.control('GET', 'sessions/default')).session);
});

test('advanceAndSettle works in a world without Functions', native, async t => {
  const world = await createTestWorld({ binaryPath: binary, projectId: 'demo-settle-auth', services: ['auth'], env: { ...process.env, NODE_PATH: '' } });
  t.after(() => world.dispose());
  const result = await world.clock.advanceAndSettle(1000);
  assert.equal(result.idle.idle, true);
});

test('services without Functions skip the Functions snapshot and report what was copied', native, async t => {
  const { root, source } = await functionsFixture(t);
  await writeFile(join(source, 'index.cjs'), 'syntax error here (');
  await symlink(source, join(root, 'unused-link'), 'dir');
  const world = await createTestWorld({ binaryPath: binary, projectId: 'demo-skip', functionsSource: source, services: ['auth', 'firestore'], env: { ...process.env, NODE_PATH: '' } });
  t.after(() => world.dispose());
  const { initial, generations } = world.snapshotStats;
  assert.equal(initial.functions, 'skipped');
  assert.equal(initial.files, 1, 'only the generated configuration');
  assert.equal(generations.length, 1);
  assert.equal(generations[0].generation, 1);
  assert.equal(generations[0].files, 1);
  assert.deepEqual((await readdir(join(world.directory, 'baseline'))).filter(name => name.startsWith('functions-')), []);
  await world.reset();
  assert.deepEqual(world.snapshotStats.generations.map(entry => entry.generation), [1, 2]);
});

test('Functions worlds count the copied source and dependencies', native, async t => {
  const world = await worldWithTasks(t);
  const { initial, generations } = world.snapshotStats;
  assert.equal(initial.functions, 'included');
  assert.ok(initial.files >= 4 && initial.bytes > 0);
  assert.equal(generations[0].files, initial.files);
  for (const key of ['files', 'directories', 'symlinks', 'bytes', 'elapsedMs']) assert.ok(Number.isInteger(generations[0][key]), key);
  assert.ok(Object.isFrozen(world.snapshotStats) && Object.isFrozen(world.snapshotStats.initial));
});

test('FIREEMU_TEST_WORLD_STATS=1 logs each copy and nothing is logged otherwise', native, async t => {
  const { source } = await functionsFixture(t);
  const script = `
    import { createTestWorld } from ${JSON.stringify(new URL('../fireemu/testing.mjs', import.meta.url).href)};
    const world = await createTestWorld({ binaryPath: ${JSON.stringify(binary)}, functionsSource: ${JSON.stringify(source)}, services: ['auth', 'functions'], env: { ...process.env, NODE_PATH: '' } });
    await world.reset();
    await world.dispose();
  `;
  const base = { ...process.env, FIREEMU_RUNNER_NODE: runner };
  const quiet = await runFile(process.execPath, ['--input-type=module', '-e', script], { env: { ...base, FIREEMU_TEST_WORLD_STATS: '' }, timeout: 40_000 });
  assert.equal(quiet.stderr.includes('fireemu test world'), false);
  const loud = await runFile(process.execPath, ['--input-type=module', '-e', script], { env: { ...base, FIREEMU_TEST_WORLD_STATS: '1' }, timeout: 40_000 });
  const lines = loud.stderr.split('\n').filter(line => line.startsWith('fireemu test world'));
  assert.match(lines[0], /^fireemu test world initial: \d+ files, \d+ bytes, (copy|clone|mixed), \d+ ms$/);
  assert.match(lines[1], /^fireemu test world generation 1: \d+ files, \d+ bytes, (copy|clone|mixed), \d+ ms$/);
  assert.match(lines[2], /^fireemu test world generation 2: /);
  assert.equal(lines.length, 3);
});

test('advanceAndSettle skips the timer drain by default when timers are real, and drains them when asked', native, async t => {
  const { source } = await functionsFixture(t);
  const world = await createTestWorld({ binaryPath: binary, projectId: 'demo-settle-real', functionsSource: source, services: ['auth', 'functions'], env: { ...process.env, NODE_PATH: '', FIREEMU_RUNNER_NODE: runner } });
  t.after(() => world.dispose());
  const result = await world.clock.advanceAndSettle(1000);
  assert.equal(result.timers, undefined, 'real timers have nothing to drain');
  await assert.rejects(world.clock.advanceAndSettle(1000, { runTimers: true }), /virtual application timers are disabled/);
});

test('advanceAndSettle drains virtual timers by default', native, async t => {
  const world = await worldWithTasks(t);
  const result = await world.clock.advanceAndSettle(1000);
  assert.ok(Array.isArray(result.timers.codebases));
});

test('a failed move whose wait was cancelled by dispose leaves no unhandled rejection', native, async t => {
  const world = await worldWithTasks(t);
  const unhandled = [];
  const record = reason => unhandled.push(reason);
  process.on('unhandledRejection', record);
  t.after(() => process.off('unhandledRejection', record));
  const settled = world.clock.advanceAndSettle({ seconds: -5 });
  const outcome = assert.rejects(settled, /cancelled: the world was disposed/);
  await world.dispose();
  await outcome;
  await delay(100);
  assert.deepEqual(unhandled, []);
});

test('advanceAndSettle keeps draining virtual timers while a runner still reports due callbacks', native, async t => {
  const world = await worldWithTasks(t);
  const call = async name => (await fetch(`${world.endpoints.functions.url}/${world.projectId}/us-central1/${name}`)).text();
  assert.equal(await call('burst'), 'scheduled');
  const result = await world.clock.advanceAndSettle(1000);
  assert.equal(await call('fires'), '1500', 'one runDue batch is 1000 callbacks; the helper repeats it');
  assert.equal(result.timers.codebases[0].timers.due, 0);
});

test('a command started right after reset() sees the new generation', native, async t => {
  const world = await worldWithTasks(t);
  const reset = world.reset();
  const result = await world.run(process.execPath, ['-e', 'console.log(process.env.FIREEMU_TEST_WORLD_GENERATION)']);
  await reset;
  assert.equal(result.stdout.trim(), '2');
});

test('advanceAndSettle waits for running work for its default budget', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'slow-one', 1000, 'slow');
  const result = await world.clock.advanceAndSettle(1000);
  assert.equal(result.idle.idle, true, 'the 1.5 second task finished before the helper returned');
  assert.equal(await deliveries(world), 1);
});

test('advanceAndSettle sends its wait budget to the daemon', native, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'never', 3_600_000);
  const started = Date.now();
  await assert.rejects(world.clock.advanceAndSettle(1000, { scope: 'all', timeoutSeconds: 1 }), error => error.status === 504);
  assert.ok(Date.now() - started < 8000, 'the daemon gave up after the one second budget');
});

test('advanceAndSettle does not drain timers in a world without Functions even when the clock option asks for virtual timers', native, async t => {
  const world = await createTestWorld({ binaryPath: binary, projectId: 'demo-settle-novirt', services: ['auth'], clock: { timers: 'virtual' }, env: { ...process.env, NODE_PATH: '' } });
  t.after(() => world.dispose());
  const result = await world.clock.advanceAndSettle(1000);
  assert.equal(result.timers, undefined);
  assert.equal(result.idle.idle, true);
});

test('advanceAndSettle waits 20 seconds by default for work that never becomes idle', { ...native, timeout: 50_000 }, async t => {
  const world = await worldWithTasks(t);
  await scheduleTask(world, 'never', 3_600_000);
  const started = Date.now();
  await assert.rejects(world.clock.advanceAndSettle(1000, { scope: 'all' }), error => error.status === 504);
  const waited = Date.now() - started;
  assert.ok(waited >= 18_000 && waited < 30_000, `the default budget is 20 s, waited ${waited} ms`);
});

test('an awaitIdle request that the daemon never answers ends after its budget plus five seconds', { ...native, timeout: 40_000 }, async t => {
  const world = await worldWithTasks(t);
  const realFetch = globalThis.fetch;
  t.mock.method(globalThis, 'fetch', (url, init) => {
    if (!String(url).endsWith(':awaitIdle')) return realFetch(url, init);
    return new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true }));
  });
  const started = Date.now();
  await assert.rejects(world.control('POST', 'sessions/default:awaitIdle', { timeoutSeconds: 0 }), error => error.name === 'TimeoutError');
  const waited = Date.now() - started;
  assert.ok(waited >= 4500 && waited < 20_000, `waited ${waited} ms`);
});
