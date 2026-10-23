import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { prepareLauncher } from './prepare-launcher.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const compiler = process.env.FIREEMU_TYPESCRIPT_PATH ?? join(root, 'ui/node_modules/.bin/tsc');
const consumer = `
import { createTestWorld, withTestWorld, type TestWorld, type TestWorldOptions } from 'fireemu/testing';
import { createControlClient } from 'fireemu/control';
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Check<T extends true> = T;
const env: Readonly<Record<string, string | undefined>> = { HOME: undefined };
const options = {
  services: ['auth', 'firestore', 'storage', 'functions', 'functions:worker', 'pubsub', 'database', 'appcheck'] as const,
  nodePathExcludes: ['firebase-admin'] as const, env: { ...env },
  binaryPath: '/binary', tempRoot: '/tmp', cwd: '/', firebaseJson: '/firebase.json',
  functionsSource: '/functions', import: '/export', projectId: 'demo-types', clockStart: '2026-01-01T00:00:00Z',
  config: { daemon: { authProject: 'demo-types' }, customExtension: true },
  clock: { date: 'virtual', timers: 'real', tasks: 'virtual' },
  hub: false, ui: true, seed: 1, startupTimeoutMs: 5000, shutdownTimeoutMs: 5000,
  requestTimeoutMs: 5000, signal: new AbortController().signal,
} satisfies TestWorldOptions;
const readonlyOptions: TestWorldOptions = options;
// @ts-expect-error service selections are readonly inputs
readonlyOptions.services?.push('auth');
const world = await createTestWorld(options);
await createTestWorld();
await createTestWorld({ config: '/fireemu.toml', services: ['database'] });
const id: string = world.id;
const generation: number = world.generation;
const projectId: string = world.projectId;
const directory: string = world.directory;
const ui: string | undefined = world.uiUrl;
const environment: string | undefined = world.environment.FIRESTORE_EMULATOR_HOST;
const controlUrl: string = world.endpoints.control.apiBaseUrl;
if (world.endpoints.firestore) {
  const host: string = world.endpoints.firestore.host;
  const port: number = world.endpoints.firestore.port;
  const url: string = world.endpoints.firestore.url;
}
type Reset = Check<Equal<ReturnType<TestWorld['reset']>, Promise<TestWorld>>>;
const reset: TestWorld = await world.reset();
const disposed: void = await world.dispose();
const sync = withTestWorld({}, w => w.projectId);
const asyncValue = withTestWorld({}, async w => ({ generation: w.generation }));
type Sync = Check<Equal<typeof sync, Promise<string>>>;
type Async = Check<Equal<typeof asyncValue, Promise<{ generation: number }>>>;
const result = await world.run('node', ['--version'] as const, { cwd: '/', env, stdio: 'pipe', signal: new AbortController().signal });
const code: number | null = result.code;
const signal: string | null = result.signal;
const stdout: string = result.stdout;
const stderr: string = result.stderr;
const clock = await world.clock.get();
const session: string = clock.session;
const edition: string = clock.edition;
const demo: boolean = clock.requireDemoPrefix;
const instant: string = clock.clock.clock;
const backwards: number = clock.clock.backwardsSets;
const state = await world.clock.set('2026-01-01T00:00:00Z', { allowBackwards: true });
const setInstant: string = state.clock;
await world.clock.advance(10);
await world.clock.advance({ seconds: 1 });
await world.clock.advance({ millis: 1 });
await world.clock.advance({ seconds: 1, millis: 2 });
await world.clock.advanceTo('2026-01-01T00:00:00Z');
const due = await world.clock.runDue(100);
if (due.codebases[0]) {
  const codebase: string = due.codebases[0].codebase;
  const executed: number = due.codebases[0].timers.executed;
  const pending: number = due.codebases[0].timers.pending;
  const dueCount: number = due.codebases[0].timers.due;
  const instantNanos: string = due.codebases[0].timers.instantNanos;
  const elapsedNanos: string = due.codebases[0].timers.elapsedNanos;
  // @ts-expect-error nanoseconds are decimal strings
  const numericNanos: number = due.codebases[0].timers.instantNanos;
}
const client = createControlClient({ origin: 'http://localhost:9000', token: 'capability' });
createControlClient({ apiBaseUrl: 'http://localhost:9000/v1/', token: 'capability', env, requestTimeoutMs: 10 });
createControlClient({ env });
createControlClient();
const response = await client.request('GET', 'sessions', undefined, { signal: new AbortController().signal });
type Response = Check<Equal<typeof response, unknown>>;
if (typeof response === 'object' && response !== null && 'session' in response && typeof response.session === 'string') {
  const narrowed: string = response.session;
}
const worldResponse = await world.control('POST', '/v1/sessions/default/clock:advance', { millis: 1 });
type WorldResponse = Check<Equal<typeof worldResponse, unknown>>;
// @ts-expect-error unknown response needs narrowing
response.session;
// @ts-expect-error world response also needs narrowing
worldResponse.clock;
// @ts-expect-error explicit endpoints cannot both be supplied
createControlClient({ origin: 'http://localhost', apiBaseUrl: 'http://localhost/v1/', token: 'x' });
// @ts-expect-error explicit origin requires an explicit token
createControlClient({ origin: 'http://localhost' });
// @ts-expect-error ambient token cannot authorize an explicit endpoint
createControlClient({ apiBaseUrl: 'http://localhost/v1/', env: { FIREEMU_CONTROL_TOKEN: 'x' } });
// @ts-expect-error unsupported product
createTestWorld({ services: ['hub'] });
// @ts-expect-error UI is not a product selection
createTestWorld({ services: ['ui'] });
// @ts-expect-error Eventarc is an endpoint, not a product selection
createTestWorld({ services: ['eventarc'] });
// @ts-expect-error Tasks is an endpoint, not a product selection
createTestWorld({ services: ['tasks'] });
// @ts-expect-error Logging is an endpoint, not a product selection
createTestWorld({ services: ['logging'] });
// @ts-expect-error Control is an endpoint, not a product selection
createTestWorld({ services: ['control'] });
// @ts-expect-error endpoint URLs are strings
createControlClient({ origin: 9000, token: 'x' });
// @ts-expect-error empty service selection
createTestWorld({ services: [] });
// @ts-expect-error unsupported option
createTestWorld({ imaginaryOption: true });
// @ts-expect-error config is an object or path
createTestWorld({ config: 1 });
// @ts-expect-error unsupported clock mode
createTestWorld({ clock: { timers: 'paused' } });
// @ts-expect-error unsupported stdio configuration
world.run('node', [], { stdio: 'ignore' });
// @ts-expect-error frozen world identity
world.id = 'changed';
// @ts-expect-error generation is a getter
world.generation = 2;
// @ts-expect-error frozen endpoint
world.endpoints.control.port = 1;
// @ts-expect-error frozen environment
world.environment.TEST = 'changed';
// @ts-expect-error frozen client
client.origin = 'http://other';
// @ts-expect-error frozen clock methods
world.clock.get = async () => clock;
// @ts-expect-error frozen lifecycle methods
world.reset = async () => world;
// @ts-expect-error frozen disposal method
world.dispose = async () => {};
// @ts-expect-error frozen command method
world.run = async () => result;
// @ts-expect-error UI is optional even when requested
const requiredUi: string = world.uiUrl;
// @ts-expect-error optional service endpoint
world.endpoints.auth.port;
// @ts-expect-error endpoints have no UI entry
world.endpoints.ui;
// @ts-expect-error environment is not exposed as env
world.env;
// @ts-expect-error world has no services property
world.services;
// @ts-expect-error world control has no per-call options
world.control('GET', '/v1', undefined, { signal: new AbortController().signal });
// @ts-expect-error due report has per-codebase timers, not flat fields
due.executed;
// @ts-expect-error withTestWorld requires options and a callback
withTestWorld(w => w.projectId);
`;

test('packed public subpaths type-check in isolated strict NodeNext and Bundler consumers', t => {
  const directory = mkdtempSync(join(tmpdir(), 'fireemu types 消費者 '));
  const artifactDirectory = process.env.FIREEMU_TYPES_ARTIFACT_DIR;
  const commands = [];
  const run = (command, args, options = {}) => {
    const record = { command, args, cwd: options.cwd ?? process.cwd() };
    commands.push(record);
    try {
      const result = execFileSync(command, args, { stdio: 'pipe', ...options });
      record.exit = 0;
      return result;
    } catch (error) {
      record.exit = error.status;
      record.stdout = error.stdout?.toString();
      record.stderr = error.stderr?.toString();
      throw error;
    }
  };
  try {
    prepareLauncher(root);
    const packed = JSON.parse(run('npm', ['pack', join(root, 'npm/fireemu'), '--json', '--pack-destination', directory], { encoding: 'utf8' }))[0];
    if (artifactDirectory) {
      mkdirSync(artifactDirectory, { recursive: true });
      copyFileSync(join(directory, packed.filename), join(artifactDirectory, packed.filename));
      writeFileSync(join(artifactDirectory, 'pack.json'), JSON.stringify(packed, null, 2));
      writeFileSync(join(artifactDirectory, 'consumer.mts'), consumer);
    }
    t.diagnostic(`packed tarball SHA256 ${createHash('sha256').update(readFileSync(join(directory, packed.filename))).digest('hex')}`);
    const files = new Set(packed.files.map(file => file.path));
    for (const name of ['testing.d.mts', 'control.d.mts']) assert(files.has(name), `tarball must contain ${name}`);
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
    run('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--omit=optional', join(directory, packed.filename)], { cwd: directory });
    const manifest = JSON.parse(readFileSync(join(directory, 'node_modules/fireemu/package.json'), 'utf8'));
    for (const name of ['testing', 'control']) {
      assert.equal(manifest.exports[`./${name}`].types, `./${name}.d.mts`);
      assert.equal(Object.keys(manifest.exports[`./${name}`])[0], 'types');
    }
    writeFileSync(join(directory, 'consumer.mts'), consumer);
    for (const [module, moduleResolution] of [['NodeNext', 'NodeNext'], ['ESNext', 'Bundler']]) {
      writeFileSync(join(directory, 'tsconfig.json'), JSON.stringify({ compilerOptions: { strict: true, noUncheckedIndexedAccess: true, skipLibCheck: false, noEmit: true, target: 'ES2022', lib: ['ES2022', 'DOM'], types: [], module, moduleResolution }, files: ['consumer.mts'] }));
      if (artifactDirectory) copyFileSync(join(directory, 'tsconfig.json'), join(artifactDirectory, `tsconfig.${moduleResolution}.json`));
      try { run(resolve(compiler), ['-p', join(directory, 'tsconfig.json')], { cwd: directory }); }
      catch (error) { throw new Error(`${moduleResolution} consumer failed:\n${error.stdout?.toString()}${error.stderr?.toString()}`, { cause: error }); }
    }
    run(process.execPath, ['--input-type=module', '-e', "import {createTestWorld,withTestWorld} from 'fireemu/testing'; import {createControlClient} from 'fireemu/control'; if (![createTestWorld,withTestWorld,createControlClient].every(f => typeof f === 'function')) throw Error('public ESM import failed');"], { cwd: directory });
  } finally {
    if (artifactDirectory) {
      mkdirSync(artifactDirectory, { recursive: true });
      writeFileSync(join(artifactDirectory, 'commands.json'), JSON.stringify(commands, null, 2));
    }
    rmSync(directory, { recursive: true, force: true });
  }
});
