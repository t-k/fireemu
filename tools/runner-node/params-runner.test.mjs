// The actual runner and IPC with a stand-in `firebase-functions/params`: parameters are resolved
// as they are declared and the hello reports what no value and no default can resolve.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));

// What `firebase-functions/params` is, as far as the runner relies on it: a shared array that
// every `define*` pushes to, parameters with a static `type` and an `options` object.
const paramsModule = String.raw`
const declaredParams = [];
class Param { constructor(name, options = {}) { this.name = name; this.options = options; } }
class StringParam extends Param { static type = 'string'; value() { return process.env[this.name] || ''; } }
class IntParam extends Param { static type = 'int'; value() { return parseInt(process.env[this.name] || '0', 10) || 0; } }
class SecretParam { static type = 'secret'; constructor(name, options = {}) { this.name = name; this.options = options; } }
const define = (Class) => (name, options) => { const p = new Class(name, options); declaredParams.push(p); return p; };
module.exports = { declaredParams, defineString: define(StringParam), defineInt: define(IntParam), defineSecret: define(SecretParam) };
`;

async function start(t, source, { env = {}, withParamsModule = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'fireemu-params-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ main: 'index.cjs', type: 'commonjs' }));
  if (withParamsModule) {
    const sdk = join(dir, 'node_modules/firebase-functions');
    await mkdir(sdk, { recursive: true });
    await writeFile(join(sdk, 'package.json'), JSON.stringify({ name: 'firebase-functions', version: '7.3.2', main: 'index.js', exports: { './params': './params.js' } }));
    await writeFile(join(sdk, 'index.js'), 'module.exports = {};');
    await writeFile(join(sdk, 'params.js'), paramsModule);
  }
  await writeFile(
    join(dir, 'index.cjs'),
    `exports.healthy = Object.assign(() => {}, { __endpoint: { platform: 'gcfv2', eventTrigger: { eventType: 'google.cloud.pubsub.topic.v1.messagePublished', eventFilters: { topic: 'projects/demo-params/topics/t' } } } });\n${source}`,
  );
  const childEnv = {
    PATH: process.env.PATH,
    HOME: dir,
    GCLOUD_PROJECT: 'demo-params',
    FIREBASE_CONFIG: '{"projectId":"demo-params"}',
    FIREEMU_RUNNER_SECRET: 'fixture-proxy',
    ...env,
  };
  const child = spawn(process.execPath, [runner, '--source', dir], { env: childEnv, stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  let pending = Buffer.alloc(0);
  const frames = [];
  const exited = once(child, 'exit');
  child.stdin.on('error', () => {});
  child.stderr.on('data', (b) => { if (stderr.length < 65536) stderr += b; });
  child.stdout.on('data', (b) => {
    pending = Buffer.concat([pending, b]);
    for (;;) {
      const nl = pending.indexOf(10);
      if (nl < 0) return;
      const n = Number(pending.subarray(0, nl).toString());
      if (pending.length < nl + 1 + n) return;
      frames.push(JSON.parse(pending.subarray(nl + 1, nl + 1 + n).toString()));
      pending = pending.subarray(nl + 1 + n);
    }
  });
  t.after(async () => {
    child.kill('SIGKILL');
    await exited;
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    await rm(dir, { recursive: true, force: true });
  });
  const end = performance.now() + 10000;
  for (;;) {
    const hello = frames.find((f) => f.type === 'hello');
    if (hello) return { hello, stderr: () => stderr };
    if (performance.now() > end) throw Error(`no hello: ${stderr}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

test('a declared default is in the environment as the parameter is declared, so a top-level read sees it', async (t) => {
  const f = await start(t, `
const { defineString, defineInt } = require('firebase-functions/params');
defineString('GREETING', { default: 'hello' });
defineInt('RETRIES', { default: 3 });
console.error('SEEN ' + JSON.stringify({ greeting: process.env.GREETING, retries: process.env.RETRIES }));
`);
  assert.deepEqual(f.hello.params, { missing: [], defaulted: [] });
  assert.match(f.stderr(), /SEEN \{"greeting":"hello","retries":"3"\}/);
});

test('a value from the environment wins over the default, and a parameter with neither is reported', async (t) => {
  const f = await start(
    t,
    `
const { defineString, defineInt, defineSecret } = require('firebase-functions/params');
defineString('FROM_DOTENV', { default: 'default' });
defineInt('NEEDS_VALUE');
defineSecret('A_SECRET');
console.error('SEEN ' + JSON.stringify({ fromDotenv: process.env.FROM_DOTENV, needs: process.env.NEEDS_VALUE ?? null }));
`,
    { env: { FROM_DOTENV: 'from the dotenv chain' } },
  );
  assert.deepEqual(f.hello.params.missing, [{ name: 'NEEDS_VALUE', type: 'int' }]);
  assert.match(f.stderr(), /SEEN \{"fromDotenv":"from the dotenv chain","needs":null\}/);
});

test('a codebase without firebase-functions/params declares nothing', async (t) => {
  const f = await start(t, '', { withParamsModule: false });
  assert.deepEqual(f.hello.params, { missing: [], defaulted: [] });
});
