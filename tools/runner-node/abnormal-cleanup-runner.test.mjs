// A daemon that is killed cannot reap its detached runner group. The runner must do that
// after its stdin pipe closes, without signaling an unrelated group.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const daemonSource = `
const {spawn} = require('node:child_process');
const {writeFileSync} = require('node:fs');
const child = spawn(process.argv[3], [process.argv[1], '--source', process.argv[2]], {
  detached: true, stdio: ['pipe', 'pipe', 'pipe'],
  env: {...process.env, GCLOUD_PROJECT: 'demo-abnormal-cleanup', FIREEMU_RUNNER: '1'}
});
child.on('error', error => process.send({error: error.message}));
child.on('exit', (code, signal) => process.send({runnerExited: true, code, signal}));
process.on('message', message => {
  if (message !== 'shutdown') return;
  const body = JSON.stringify({type: 'shutdown'});
  child.stdin.write(String(Buffer.byteLength(body)) + '\\n' + body);
});
writeFileSync(process.env.FIREEMU_RUNNER_MARKER, String(child.pid));
if (process.env.FIREEMU_PARTIAL_FRAME === '1') child.stdin.write('100\\n');
process.send({runnerPid: child.pid});
setInterval(() => {}, 1000);
`;
const userSource = `
const {spawn} = require('node:child_process');
const {writeFileSync} = require('node:fs');
const script = process.env.FIREEMU_RESIST_TERM === '1'
  ? "process.on('SIGTERM', () => {}); require('node:fs').writeFileSync(process.env.FIREEMU_CHILD_READY, '1'); setInterval(() => {}, 1000)"
  : 'setInterval(() => {}, 1000)';
const child = spawn(process.execPath, ['-e', script, '--', process.env.FIREEMU_CHILD_MARKER], {stdio: 'ignore'});
child.unref();
writeFileSync(process.env.FIREEMU_CHILD_MARKER, String(child.pid));
process.on('exit', () => {
  if (process.env.FIREEMU_HANG_ON_EXIT === '1') {
    writeFileSync(process.env.FIREEMU_EXIT_ENTERED, '1');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60_000);
  }
  writeFileSync(process.env.FIREEMU_RUNNER_EXIT, 'graceful');
});
if (process.env.FIREEMU_WRITE_AFTER_DEATH === '1') {
  setInterval(() => process.stderr.write('still running\\n'), 5);
}
const task = async () => {};
task.run = task;
task.__endpoint = {platform: 'gcfv2', scheduleTrigger: {schedule: 'every 5 minutes'}};
module.exports = {task};
`;
const slowUserSource = `
import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)', '--', process.env.FIREEMU_CHILD_MARKER], {stdio: 'ignore'});
child.unref();
writeFileSync(process.env.FIREEMU_CHILD_MARKER, String(child.pid));
await new Promise(resolve => setTimeout(resolve, 60_000));
`;
const fatalUserSource = `
const {spawn} = require('node:child_process');
const {writeFileSync} = require('node:fs');
const child = spawn(process.execPath, ['-e',
  "process.on('SIGTERM', () => {}); process.send('ready'); setInterval(() => {}, 1000)",
  '--', process.env.FIREEMU_CHILD_MARKER], {stdio: ['ignore', 'ignore', 'ignore', 'ipc']});
child.unref();
writeFileSync(process.env.FIREEMU_CHILD_MARKER, String(child.pid));
process.on('exit', () => writeFileSync(process.env.FIREEMU_RUNNER_EXIT, 'graceful'));
child.on('message', () => process.exit(7));
`;

function groupOf(pid) {
  try {
    const value = execFileSync('/bin/ps', ['-o', 'pgid=', '-p', String(pid)], {encoding: 'utf8', timeout: 1000}).trim();
    return /^\d+$/.test(value) ? Number(value) : null;
  } catch {
    return null;
  }
}

function alive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

function ownedMember(pid, group, token) {
  if (!pid || groupOf(pid) !== group) return false;
  try {
    const command = execFileSync('/bin/ps', ['-o', 'command=', '-p', String(pid)], {
      encoding: 'utf8', timeout: 1000
    });
    return command.includes(token);
  } catch {
    return false;
  }
}

function killOwnedGroup(group, members, token) {
  if (!group || group === groupOf(process.pid) ||
      !members.some(pid => ownedMember(pid, group, token))) return;
  try { process.kill(-group, 'SIGKILL'); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}

async function waitFor(predicate, label, timeout = 3000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error(`${label} did not complete within ${timeout} ms`);
}

async function checkAbnormalCleanup(t, nodeCommand, {
  slowDiscovery = false, resistant = false, writeAfterDeath = false,
  partialFrame = false, shutdownBeforeKill = false, hangOnExit = false,
  fatalExit = false
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fireemu-abnormal-cleanup-'));
  const marker = join(dir, 'child.pid');
  const readyMarker = join(dir, 'child.ready');
  const runnerMarker = join(dir, 'runner.pid');
  const runnerExitMarker = join(dir, 'runner-exit.txt');
  const exitEnteredMarker = join(dir, 'exit-entered.txt');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({private: true, main: slowDiscovery ? 'index.mjs' : 'index.cjs'}));
  writeFileSync(join(dir, slowDiscovery ? 'index.mjs' : 'index.cjs'),
    slowDiscovery ? slowUserSource : fatalExit ? fatalUserSource : userSource);
  const unrelated = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    detached: true, stdio: 'ignore'
  });
  unrelated.unref();
  const daemon = spawn(process.execPath, ['-e', daemonSource, runner, dir, nodeCommand], {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    env: {...process.env, FIREEMU_CHILD_MARKER: marker, FIREEMU_CHILD_READY: readyMarker,
      FIREEMU_RESIST_TERM: resistant ? '1' : '0', FIREEMU_RUNNER_MARKER: runnerMarker,
      FIREEMU_WRITE_AFTER_DEATH: writeAfterDeath ? '1' : '0',
      FIREEMU_PARTIAL_FRAME: partialFrame ? '1' : '0', FIREEMU_RUNNER_EXIT: runnerExitMarker,
      FIREEMU_HANG_ON_EXIT: hangOnExit ? '1' : '0', FIREEMU_EXIT_ENTERED: exitEnteredMarker}
  });
  const daemonExit = once(daemon, 'exit');
  const daemonMessages = [];
  daemon.on('message', message => daemonMessages.push(message));
  const noticePromise = once(daemon, 'message').then(([value]) => value);
  let runnerPid;
  let childPid;
  let ownedGroup;
  t.after(async () => {
    if (daemon.exitCode === null && daemon.signalCode === null) { daemon.kill('SIGKILL'); await daemonExit; }
    const recordedRunner = runnerPid ?? (existsSync(runnerMarker) ? Number(readFileSync(runnerMarker, 'utf8')) : null);
    const recordedChild = childPid ?? (existsSync(marker) ? Number(readFileSync(marker, 'utf8')) : null);
    const group = ownedGroup ?? (recordedRunner && ownedMember(recordedRunner, groupOf(recordedRunner), dir)
      ? groupOf(recordedRunner) : recordedChild && ownedMember(recordedChild, groupOf(recordedChild), dir)
        ? groupOf(recordedChild) : null);
    killOwnedGroup(group, [recordedRunner, recordedChild], dir);
    if (unrelated.exitCode === null && unrelated.signalCode === null) unrelated.kill('SIGKILL');
    rmSync(dir, {recursive: true, force: true});
  });
  let noticeTimer;
  let notice;
  try {
    notice = await Promise.race([
      noticePromise,
      new Promise((_, reject) => {
        noticeTimer = setTimeout(() => reject(new Error('daemon did not start runner')), 3000);
      })
    ]);
  } finally {
    clearTimeout(noticeTimer);
  }
  if (notice.error) throw new Error(notice.error);
  runnerPid = notice.runnerPid;
  assert.ok(Number.isInteger(runnerPid) && runnerPid > 1);
  childPid = await waitFor(() => existsSync(marker) && Number(readFileSync(marker, 'utf8')), 'user child');
  if (resistant) await waitFor(() => existsSync(readyMarker), 'SIGTERM handler');
  ownedGroup = fatalExit ? groupOf(childPid) : groupOf(runnerPid);
  assert.equal(groupOf(childPid), ownedGroup, 'the user child shares the runner group');
  assert.ok(ownedMember(fatalExit ? childPid : runnerPid, ownedGroup, dir),
    'group identity is tied to this fixture');
  assert.equal(groupOf(unrelated.pid), unrelated.pid, 'the unrelated process owns its own group');
  assert.notEqual(groupOf(process.pid), ownedGroup, 'the test is outside the runner group');
  if (shutdownBeforeKill) {
    daemon.send('shutdown');
    if (hangOnExit) await waitFor(() => existsSync(exitEnteredMarker), 'blocked runner exit');
    else {
      await waitFor(() => daemonMessages.find(message => message.runnerExited), 'runner shutdown');
      assert.equal(readFileSync(runnerExitMarker, 'utf8'), 'graceful');
    }
  }
  if (fatalExit) await waitFor(() => existsSync(runnerExitMarker), 'user exit handler');
  daemon.kill('SIGKILL');
  await daemonExit;
  await waitFor(() => !alive(runnerPid) && !alive(childPid), 'runner group cleanup', hangOnExit ? 5000 : 3000);
  runnerPid = null;
  childPid = null;
  ownedGroup = null;
  assert.ok(alive(unrelated.pid), 'an unrelated group must survive runner cleanup');
}

test('daemon SIGKILL closes runner stdin and reaps same-group user children', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath));

test('daemon SIGKILL during user-code discovery reaps children before hello', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {slowDiscovery: true}));

test('daemon SIGKILL reaps a same-group child that ignores SIGTERM', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {resistant: true}));

test('daemon SIGKILL during runner output failure reaps a SIGTERM-resistant child', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {resistant: true, writeAfterDeath: true}));

test('daemon SIGKILL after a partial input frame reaps a SIGTERM-resistant child', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {resistant: true, partialFrame: true}));

test('a shutdown frame reaps resistant children before daemon group cleanup', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {resistant: true, shutdownBeforeKill: true}));

test('a stalled exit after daemon SIGKILL is bounded by the owned-group helper', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {
  resistant: true, shutdownBeforeKill: true, hangOnExit: true
}));

test('a fatal user exit runs user exit handlers and reaps same-group children', {
  skip: process.platform === 'win32'
}, async t => checkAbnormalCleanup(t, process.execPath, {fatalExit: true}));

const voltaNode = process.env.FIREEMU_TEST_VOLTA_NODE;
test('Volta shim leader is an owned runner process group', {
  skip: process.platform === 'win32' || !voltaNode || !existsSync(voltaNode)
}, async t => checkAbnormalCleanup(t, voltaNode));

test('Volta shim cleanup escalates for a SIGTERM-resistant child', {
  skip: process.platform === 'win32' || !voltaNode || !existsSync(voltaNode)
}, async t => checkAbnormalCleanup(t, voltaNode, {resistant: true}));

test('a non-shim parent group is warned about and never signaled', {
  skip: process.platform === 'win32'
}, async t => {
  const dir = mkdtempSync(join(tmpdir(), 'fireemu-unowned-group-'));
  const marker = join(dir, 'child.pid');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({private: true, main: 'index.cjs'}));
  writeFileSync(join(dir, 'index.cjs'), userSource);
  const supervisorSource = `
const {spawn} = require('node:child_process');
const fakeCommandArgument = '/.volta/bin/node';
void fakeCommandArgument;
const runner = spawn(process.argv[1], [process.argv[2], '--source', process.argv[3]], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: {...process.env, GCLOUD_PROJECT: 'demo-unowned-group', FIREEMU_RUNNER: '1'}
});
let stderr = '';
runner.stderr.on('data', chunk => { stderr += chunk.toString(); });
runner.on('exit', (code, signal) => process.send({type: 'exit', code, signal, stderr}));
process.on('message', message => { if (message === 'close') runner.stdin.end(); });
process.send({type: 'ready', runnerPid: runner.pid});
setInterval(() => {}, 1000);
`;
  const supervisor = spawn(process.execPath, ['-e', supervisorSource, process.execPath, runner, dir], {
    detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], argv0: '/bogus/.volta/bin/node',
    env: {...process.env, FIREEMU_CHILD_MARKER: marker}
  });
  const notices = [];
  supervisor.on('message', message => notices.push(message));
  let childPid;
  t.after(() => {
    killOwnedGroup(supervisor.pid, [supervisor.pid, childPid], dir);
    rmSync(dir, {recursive: true, force: true});
  });
  const ready = await waitFor(() => notices.find(message => message.type === 'ready'), 'unowned runner');
  childPid = await waitFor(() => existsSync(marker) && Number(readFileSync(marker, 'utf8')), 'user child');
  assert.equal(groupOf(ready.runnerPid), supervisor.pid);
  assert.equal(groupOf(childPid), supervisor.pid);
  supervisor.send('close');
  const result = await waitFor(() => notices.find(message => message.type === 'exit'), 'runner EOF');
  assert.equal(result.code, 0);
  assert.match(result.stderr, /runner process group ownership is unverified/);
  assert.ok(alive(supervisor.pid), 'the unverified parent group survives');
  assert.ok(alive(childPid), 'the unverified group child survives');
});
