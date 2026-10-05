// Waiting that does not depend on how busy the machine is. A test that waits for a child process or
// a callback gives up only when the thing it waits for has made no observable progress for a whole
// stall window (more output, more events, more CPU time used by the child), not when a fixed wall
// clock bound runs out. A loaded machine slows progress down; it does not stop it.
//
// Shared by http-admission-runner.test.mjs and input-limits-runner.test.mjs.
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {setTimeout as delay} from 'node:timers/promises';

/** No progress at all for this long means the thing waited for is stuck (generous on purpose). */
export const STALL_MS = 30_000;
/** No single wait lasts longer than this, however much progress it shows (a livelock fails by name). */
export const MAX_WAIT_MS = 300_000;
/** The backstop passed as a node:test `timeout`: it only stops a hung run, never decides a verdict. */
export const HARD_BACKSTOP_MS = 600_000;

/**
 * The stall window for a wait that covers a quiet period the product is designed to have (an input
 * deadline, for example): the child says and shows nothing for `quietMs`, and may exit just after it,
 * so a window equal to the period would give up a few milliseconds before the child does.
 */
export function quietStallMs(quietMs, marginMs = STALL_MS) {
  if (!Number.isSafeInteger(quietMs) || quietMs < 0) throw new Error('a quiet period is a non-negative integer of milliseconds');
  if (!Number.isSafeInteger(marginMs) || marginMs <= 0) throw new Error('the margin after a quiet period is a positive integer of milliseconds');
  return quietMs + marginMs;
}

/**
 * An upper bound on a measured interval that allows for the worst event-loop stall (`lagMs`) of the
 * measuring process, twice over, but never for more than `capMs`. `tooLoaded` says the stall asked
 * for more than the cap, so the machine is too busy to judge the interval.
 */
export function deadlineWithLag(baseMs, lagMs, capMs = 10_000) {
  const wanted = 2 * lagMs;
  return {limit: baseMs + Math.min(wanted, capMs), tooLoaded: wanted > capMs};
}

function procCpuTicks(pid, readProc) {
  try {
    const text = readProc(`/proc/${pid}/stat`);
    // comm (field 2) may hold spaces and parentheses: the fields that follow start after the last ')'.
    const fields = text.slice(text.lastIndexOf(')') + 1).trim().split(/\s+/);
    const [utime, stime] = [fields[11], fields[12]];
    if (text.lastIndexOf(')') < 0 || !/^\d+$/.test(utime ?? '') || !/^\d+$/.test(stime ?? '')) return null;
    return String(Number(utime) + Number(stime));
  } catch {
    return null;
  }
}

function psCpuTime(pid) {
  const run = spawnSync('ps', ['-o', 'time=', '-p', String(pid)], {encoding: 'utf8', timeout: 5000});
  const text = run.status === 0 ? run.stdout.trim() : '';
  return text === '' ? null : text;
}

/**
 * CPU time a process has used: utime plus stime in clock ticks from /proc/<pid>/stat where that
 * exists (Linux, finer than a second), else what `ps` prints; null when it is gone or unreadable.
 */
export function childCpuTime(pid, {readProc = path => readFileSync(path, 'utf8'), ps = psCpuTime} = {}) {
  return procCpuTicks(pid, readProc) ?? ps(pid);
}

/** Wraps a cheap-to-call reader so the real read happens at most once per `everyMs`. */
export function sampled(read, everyMs = 1000, now = () => performance.now()) {
  let value = null;
  let at = Number.NEGATIVE_INFINITY;
  return () => {
    const t = now();
    if (t - at >= everyMs) {
      value = read();
      at = t;
    }
    return value;
  };
}

/**
 * Polls `check` until it returns a truthy value, which is returned. `progress` (optional) returns any
 * value that changes whenever the awaited thing advances; the wait fails only after `stallMs` with
 * the same value (with no `progress`, `stallMs` is a plain deadline). `failFast` may throw to stop at
 * once, for example when the child has exited. `now` and `sleep` are injectable for tests.
 */
export async function waitUntil({
  check, progress = () => null, failFast = () => {}, label, stallMs = STALL_MS, pollMs = 10,
  maxMs = MAX_WAIT_MS, now = () => performance.now(), sleep = delay,
}) {
  let last = await progress();
  const startedAt = now();
  let changedAt = startedAt;
  for (;;) {
    const value = await check();
    if (value) return value;
    failFast();
    const seen = await progress();
    const at = now();
    if (!Object.is(seen, last)) {
      last = seen;
      changedAt = at;
    } else if (at - changedAt >= stallMs) {
      throw new Error(`${label}: no progress for ${stallMs} ms`);
    }
    if (at - startedAt >= maxMs) throw new Error(`${label}: still waiting after ${maxMs} ms`);
    await sleep(pollMs);
  }
}

/**
 * Waits for a child's exit: `end` resolves with the exit and `result()` is it once known. Fails only
 * after `stallMs` without a change of `progress`.
 */
export async function untilExit({
  end, result, progress = () => null, label, stallMs = STALL_MS, sleepMs = 50,
  maxMs = MAX_WAIT_MS, now = () => performance.now(), sleep = delay,
}) {
  let exit = result();
  if (exit) return exit;
  let ended = false;
  end.then(() => { ended = true; }, () => { ended = true; });
  await waitUntil({check: () => ended || result(), progress, label: `${label} (waiting for exit)`, stallMs, pollMs: sleepMs, maxMs, now, sleep});
  return result() || end;
}
