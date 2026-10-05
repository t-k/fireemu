// Waiting that does not depend on how busy the machine is. A test that waits for a child process or
// a callback gives up only when the thing it waits for has made no observable progress for a whole
// stall window (more output, more events, more CPU time used by the child), not when a fixed wall
// clock bound runs out. A loaded machine slows progress down; it does not stop it.
//
// Shared by http-admission-runner.test.mjs and input-limits-runner.test.mjs.
import {spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';

/** No progress at all for this long means the thing waited for is stuck (generous on purpose). */
export const STALL_MS = 30_000;
/** The backstop passed as a node:test `timeout`: it only stops a hung run, never decides a verdict. */
export const HARD_BACKSTOP_MS = 600_000;

/** CPU time a process has used, as `ps` prints it, or null when it is gone or cannot be read. */
export function childCpuTime(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  const run = spawnSync('ps', ['-o', 'time=', '-p', String(pid)], {encoding: 'utf8', timeout: 5000});
  const text = run.status === 0 ? run.stdout.trim() : '';
  return text === '' ? null : text;
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
  now = () => performance.now(), sleep = delay,
}) {
  let last = await progress();
  let changedAt = now();
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
    await sleep(pollMs);
  }
}

/**
 * Waits for a child's exit: `end` resolves with the exit and `result()` is it once known. Fails only
 * after `stallMs` without a change of `progress`.
 */
export async function untilExit({end, result, progress = () => null, label, stallMs = STALL_MS, sleepMs = 50}) {
  let exit = result();
  if (exit) return exit;
  let ended = false;
  end.then(() => { ended = true; }, () => { ended = true; });
  await waitUntil({check: () => ended || result(), progress, label: `${label} (waiting for exit)`, stallMs, pollMs: sleepMs});
  return end;
}
