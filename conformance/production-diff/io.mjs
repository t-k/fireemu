import { constants, promises as fs } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { requireThat, sha256 } from './core.mjs';

export function cleanEnvironment(home) {
  // Never inherit NODE_OPTIONS, proxy/ADC/SDK variables, GIT_* overrides or credentials.
  return { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, TMPDIR: home,
    LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0' };
}
export const inside = (root, target) => {
  const r = relative(root, target);
  return r === '' || (!r.startsWith('..' + '/') && r !== '..' && !isAbsolute(r));
};

export async function readSource(root, name, maxBytes = 16 * 1024 * 1024) {
  requireThat(typeof name === 'string' && !isAbsolute(name) &&
    !name.split('/').some(s => !s || s === '.' || s === '..') && !name.includes('\\'), 'unsafe-source-path');
  root = await fs.realpath(root);
  let target = root;
  for (const part of name.split('/')) {
    target = join(target, part);
    requireThat(!(await fs.lstat(target)).isSymbolicLink(), 'source-symlink');
  }
  const handle = await fs.open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    requireThat(info.isFile() && info.size <= maxBytes, 'source-size-or-type');
    const data = await handle.readFile();
    requireThat(data.length <= maxBytes, 'source-too-large');
    return data;
  } finally { await handle.close(); }
}

export function git(root, args) {
  try {
    return execFileSync('git', ['--no-pager', '--literal-pathspecs', '-C', root, ...args], {
      env: cleanEnvironment('/nonexistent-fireemu-pilot-home'),
      stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024, timeout: 15000,
    });
  } catch { throw new Error('required-git-object-unavailable'); }
}
export function gitState(root) {
  return { head: git(root, ['rev-parse', 'HEAD']).toString().trim(),
    dirty: git(root, ['status', '--porcelain', '--untracked-files=normal']).length > 0 };
}

export async function newPrivateDirectory(path, repo) {
  requireThat(isAbsolute(path), 'absolute-output-directory-required');
  const parent = await fs.realpath(dirname(path));
  const target = join(parent, path.split('/').at(-1));
  const root = await fs.realpath(repo);
  requireThat(!inside(root, target) && !inside(target, root), 'output-must-be-outside-repository');
  await fs.mkdir(target, { mode: 0o700 }); // EEXIST is an error; do not reuse receipts.
  return target;
}

export async function publish(path, bytes) {
  const temp = `${path}.tmp-${randomBytes(8).toString('hex')}`;
  let handle;
  try {
    handle = await fs.open(temp, 'wx', 0o600);
    await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = null;
    await fs.link(temp, path); // Atomic no-replace publication on the same filesystem.
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}
export const publishJson = (path, value) => publish(path, JSON.stringify(value, null, 2) + '\n');

/** Own one POSIX process group. A timeout/log overflow never becomes an executed pass. */
export async function runProcess(command, args, { cwd, env, timeoutMs = 180000,
  maxLogBytes = 1024 * 1024 } = {}) {
  requireThat(process.platform !== 'win32', 'posix-supervision-required');
  return await new Promise(resolveResult => {
    const child = spawn(command, args, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let reason = null, bytes = 0, killTimer, settled = false;
    const chunks = [];
    const kill = signal => { if (child.pid) {
      try { process.kill(-child.pid, signal); } catch (e) { if (e.code !== 'ESRCH') reason ??= 'group-kill-failed'; }
    } };
    const stop = cause => {
      reason ??= cause; kill('SIGTERM');
      killTimer ??= setTimeout(() => kill('SIGKILL'), 2000);
    };
    const timer = setTimeout(() => stop('process-timeout'), timeoutMs);
    const interrupt = () => stop('interrupted');
    process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
    const finish = (code, signal) => {
      if (settled) return; settled = true;
      clearTimeout(timer); clearTimeout(killTimer);
      process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
      let residue = false;
      if (child.pid) { try { process.kill(-child.pid, 0); residue = true; } catch (e) {
        if (e.code !== 'ESRCH') residue = true;
      } }
      if (residue) { reason ??= 'remaining-process-group'; kill('SIGKILL'); }
      resolveResult({ code, signal, reason, pid: child.pid ?? null,
        state: residue ? 'unconfirmed' : 'stopped', log: Buffer.concat(chunks) });
    };
    child.once('error', () => { reason ??= 'spawn-failed'; finish(null, null); });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', bytesIn => {
      bytes += bytesIn.length;
      if (bytes <= maxLogBytes) chunks.push(bytesIn);
      else stop('process-log-limit');
    });
    child.once('close', finish);
  });
}

export async function snapshotBinary(path, destination) {
  const real = await fs.realpath(path);
  const h = await fs.open(real, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await h.stat();
    requireThat(info.isFile() && info.size > 4 && info.size < 1024 * 1024 * 1024, 'invalid-binary');
    const data = await h.readFile();
    const magic = data.subarray(0, 4).toString('hex');
    requireThat(['7f454c46', 'cffaedfe', 'cefaedfe', 'feedfacf', 'feedface', 'cafebabe', 'cafebabf']
      .includes(magic), 'native-binary-required');
    await publish(destination, data); await fs.chmod(destination, 0o700);
    return { sha256: sha256(data), bytes: data.length, platform: process.platform,
      sourceBinding: 'not-attested-build-receipt-required-for-final-acceptance' };
  } finally { await h.close(); }
}
