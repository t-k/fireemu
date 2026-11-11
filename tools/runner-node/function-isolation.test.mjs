// `--function <name>`: a runner dedicated to one function of a codebase (`functions.isolation = "function"`).
// The daemon fixes FUNCTION_TARGET, FUNCTION_SIGNATURE_TYPE and K_SERVICE at spawn, as a production instance
// has them from its start, so the runner must neither rewrite them per call nor serve another function. The
// codebase-shared runner (no flag) is exercised beside it to show what the dedicated runner removes: the
// identity of the call that started last, and a module cache both functions can see.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const encode = value => {
  const bytes = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${bytes.length}\n`), bytes]);
};
const invocation = (name, id, data = {}) => ({
  type: 'invoke', invocationId: id, function: name, entryPoint: name, trigger: 'schedule', event: { data },
});
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const shared = `
exports.cache = new Map();
`;
const entry = `
const { appendFileSync } = require('node:fs');
const shared = require('./shared.cjs');
const record = value => appendFileSync(__dirname + '/calls.jsonl', JSON.stringify(value) + '\\n');
const atImport = {
  target: process.env.FUNCTION_TARGET, service: process.env.K_SERVICE,
  signature: process.env.FUNCTION_SIGNATURE_TYPE, secret: process.env.ALPHA_SECRET ?? null,
  other: process.env.BETA_SECRET ?? null,
};
function handler(name) {
  const fn = async data => {
    record({ name, id: data.id, phase: 'start' });
    if (data.mode === 'remember') shared.cache.set('written-by', name);
    if (data.mode === 'log') console.log('hello from ' + name);
    if (data.mode === 'await') await delay(data.ms ?? 200);
    record({
      name, id: data.id, phase: 'end', service: process.env.K_SERVICE, target: process.env.FUNCTION_TARGET,
      signature: process.env.FUNCTION_SIGNATURE_TYPE, cached: shared.cache.get('written-by') ?? null,
      secret: process.env.ALPHA_SECRET ?? null, other: process.env.BETA_SECRET ?? null, atImport,
    });
  };
  fn.run = fn;
  fn.__endpoint = { platform: 'gcfv2', scheduleTrigger: { schedule: 'every 5 minutes' } };
  return fn;
}
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
module.exports = { alpha: handler('alpha'), beta: handler('beta') };
`;

async function codebase(t) {
  const dir = await mkdtemp(join(tmpdir(), 'fireemu-isolation-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ private: true, main: 'index.cjs' }));
  await writeFile(join(dir, 'shared.cjs'), shared);
  await writeFile(join(dir, 'index.cjs'), entry);
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

// One runner process, spawned the way the daemon spawns it: `target` adds `--function` and the identity the
// daemon computes from the discovered manifest.
async function start(t, dir, { target, env = {} } = {}) {
  const fixed = target === undefined ? {} : {
    K_SERVICE: target, FUNCTION_TARGET: target, FUNCTION_SIGNATURE_TYPE: 'http',
  };
  const argv = [runner, '--source', dir, ...(target === undefined ? [] : ['--function', target])];
  const child = spawn(process.execPath, argv, {
    env: { PATH: process.env.PATH, GCLOUD_PROJECT: 'demo-isolation', ...fixed, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const messages = [];
  let buffer = Buffer.alloc(0);
  let stderr = '';
  let exit = null;
  const exited = once(child, 'exit').then(([code, signal]) => (exit = { code, signal }));
  child.stdin.on('error', () => {});
  child.stderr.on('data', chunk => { if (stderr.length < 65536) stderr += chunk.toString(); });
  child.stdout.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const newline = buffer.indexOf(10);
      if (newline < 0) return;
      const length = Number(buffer.subarray(0, newline).toString('ascii'));
      if (buffer.length < newline + 1 + length) return;
      messages.push(JSON.parse(buffer.subarray(newline + 1, newline + 1 + length).toString('utf8')));
      buffer = buffer.subarray(newline + 1 + length);
    }
  });
  t.after(async () => {
    if (!exit) { child.kill('SIGKILL'); await exited; }
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
  });
  async function waitFor(predicate, label, timeout = 8000) {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      const value = predicate();
      if (value) return value;
      if (exit) throw new Error(`${label}: runner exited ${JSON.stringify(exit)}; ${stderr.slice(-400)}`);
      await delay(5);
    }
    throw new Error(`${label}: timeout; ${stderr.slice(-400)}`);
  }
  const runnerHandle = {
    child, messages, get stderr() { return stderr; },
    exited: () => Promise.race([exited, delay(8000).then(() => { throw new Error('runner did not exit'); })]),
    hello: () => waitFor(() => messages.find(m => m.type === 'hello'), 'hello'),
    send: message => child.stdin.write(encode(message)),
    result: id => waitFor(() => messages.find(m => m.type === 'result' && m.invocationId === id), `result ${id}`),
  };
  return runnerHandle;
}

async function calls(dir) {
  try {
    return (await readFile(join(dir, 'calls.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}
const ended = (all, name, id) => all.find(c => c.name === name && c.id === id && c.phase === 'end');

test('the codebase-shared runner reports the call that started last, and its functions share one module cache', async t => {
  const dir = await codebase(t);
  const shared = await start(t, dir);
  assert.equal((await shared.hello()).manifest.functions.length, 2);
  shared.send(invocation('alpha', 'a1', { id: 'a1', mode: 'await', ms: 250 }));
  await delay(60);
  shared.send(invocation('beta', 'b1', { id: 'b1', mode: 'remember' }));
  await shared.result('b1');
  await shared.result('a1');
  const all = await calls(dir);
  // The documented limit of one process serving a codebase: alpha reads the identity beta set while alpha awaited.
  assert.equal(ended(all, 'alpha', 'a1').service, 'beta');
  assert.equal(ended(all, 'alpha', 'a1').target, 'beta');
  // The module cache beta wrote is visible to alpha.
  assert.equal(ended(all, 'alpha', 'a1').cached, 'beta');
});

test('a dedicated runner keeps its function identity across an await while another function runs', async t => {
  const dir = await codebase(t);
  const alpha = await start(t, dir, { target: 'alpha' });
  const beta = await start(t, dir, { target: 'beta' });
  await alpha.hello(); await beta.hello();
  alpha.send(invocation('alpha', 'a1', { id: 'a1', mode: 'await', ms: 250 }));
  await delay(60);
  beta.send(invocation('beta', 'b1', { id: 'b1', mode: 'remember' }));
  await beta.result('b1');
  await alpha.result('a1');
  const all = await calls(dir);
  const a = ended(all, 'alpha', 'a1');
  assert.deepEqual([a.service, a.target, a.signature], ['alpha', 'alpha', 'http']);
  // Module-level state is per runner: what beta cached is not in alpha's module graph.
  assert.equal(a.cached, null);
  // The values were in place when the module was first imported, not first set by a call.
  assert.deepEqual(a.atImport.service, 'alpha');
  assert.deepEqual(a.atImport.target, 'alpha');
  assert.deepEqual(ended(all, 'beta', 'b1').cached, 'beta');
});

test('a dedicated runner announces and serves only its own function', async t => {
  const dir = await codebase(t);
  const alpha = await start(t, dir, { target: 'alpha' });
  const hello = await alpha.hello();
  assert.deepEqual(hello.manifest.functions.map(f => f.name), ['alpha']);
  alpha.send(invocation('beta', 'x1', { id: 'x1' }));
  const refused = await alpha.result('x1');
  assert.equal(refused.ok, false);
  assert.match(refused.error, /unknown function/);
  alpha.send(invocation('alpha', 'a1', { id: 'a1' }));
  assert.equal((await alpha.result('a1')).ok, true);
  assert.deepEqual((await calls(dir)).map(c => `${c.name}:${c.phase}`), ['alpha:start', 'alpha:end']);
});

test('a dedicated runner runs concurrent calls of its function side by side', async t => {
  const dir = await codebase(t);
  const alpha = await start(t, dir, { target: 'alpha' });
  await alpha.hello();
  alpha.send(invocation('alpha', 'a1', { id: 'a1', mode: 'await', ms: 600 }));
  alpha.send(invocation('alpha', 'a2', { id: 'a2', mode: 'await', ms: 600 }));
  let midway;
  for (const end = Date.now() + 8000; Date.now() < end;) {
    midway = await calls(dir);
    if (midway.filter(c => c.phase === 'start').length === 2) break;
    await delay(10);
  }
  assert.equal(midway.filter(c => c.phase === 'start').length, 2, 'both calls started');
  assert.equal(midway.filter(c => c.phase === 'end').length, 0, 'before either finished');
  await alpha.result('a1'); await alpha.result('a2');
});

test('a dedicated runner does not rewrite its identity variables for a call', async t => {
  const dir = await codebase(t);
  // A different value than the manifest names: the daemon decides it at spawn, the runner must not overwrite it.
  const alpha = await start(t, dir, { target: 'alpha', env: { K_SERVICE: 'fixed-at-spawn' } });
  await alpha.hello();
  alpha.send(invocation('alpha', 'a1', { id: 'a1' }));
  await alpha.result('a1');
  assert.equal(ended(await calls(dir), 'alpha', 'a1').service, 'fixed-at-spawn');
});

test('a dedicated runner sees the secrets placed in its environment at spawn, from the first line of user code', async t => {
  const dir = await codebase(t);
  const alpha = await start(t, dir, { target: 'alpha', env: { ALPHA_SECRET: 'only-alpha' } });
  await alpha.hello();
  alpha.send(invocation('alpha', 'a1', { id: 'a1' }));
  await alpha.result('a1');
  const a = ended(await calls(dir), 'alpha', 'a1');
  assert.equal(a.secret, 'only-alpha');
  assert.equal(a.atImport.secret, 'only-alpha');
  assert.equal(a.other, null);
});

test('a dedicated runner for a function the codebase does not export exits before it says hello', async t => {
  const dir = await codebase(t);
  const missing = await start(t, dir, { target: 'gamma' });
  const outcome = await missing.exited();
  assert.equal(outcome.code, 1);
  assert.equal(missing.messages.some(m => m.type === 'hello'), false);
  assert.match(missing.stderr, /gamma/);
});

test('a dedicated runner attributes its log lines to the function and the invocation', async t => {
  const dir = await codebase(t);
  const alpha = await start(t, dir, { target: 'alpha' });
  await alpha.hello();
  alpha.send(invocation('alpha', 'a1', { id: 'a1', mode: 'log' }));
  await alpha.result('a1');
  const line = alpha.messages.find(m => m.type === 'log' && String(m.message).includes('hello from alpha'));
  assert.ok(line, JSON.stringify(alpha.messages));
  assert.equal(line.functionName, 'alpha');
  assert.equal(line.invocationId, 'a1');
});
