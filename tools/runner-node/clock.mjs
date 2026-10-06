// Opt-in application time. Native event-loop and lifecycle deadlines stay real.
import timers from 'node:timers';
import promises from 'node:timers/promises';
import { syncBuiltinESMExports } from 'node:module';
import { promisify } from 'node:util';

const NativeDate = Date;
const native = {
  setTimeout: timers.setTimeout, clearTimeout: timers.clearTimeout,
  setInterval: timers.setInterval, clearInterval: timers.clearInterval,
};
const nativePromises = { setTimeout: promises.setTimeout, setInterval: promises.setInterval };
const nanosPerMilli = 1_000_000n;
const dateLimit = 8_640_000_000_000_000n;
const maxDrain = 10_000;

function nanos(value, name) {
  if (typeof value !== 'string' || !/^(?:0|-?[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`invalid clock ${name}`);
  }
  return BigInt(value);
}

function milliseconds(instant) {
  const value = instant >= 0n ? instant / nanosPerMilli : (instant - nanosPerMilli + 1n) / nanosPerMilli;
  if (value < -dateLimit || value > dateLimit) throw new RangeError('clock outside JavaScript Date range');
  return Number(value);
}

function delay(value) {
  const number = Number(value ?? 1);
  return !Number.isFinite(number) || number < 1 || number > 2_147_483_647 ? 1 : Math.trunc(number);
}

function abortError(reason) {
  const error = new Error('The operation was aborted', {cause:reason});
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function options(value) {
  if (value === null || typeof value !== 'object') throw new TypeError('timer options must be an object');
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) throw new TypeError('invalid AbortSignal');
  if (value.ref !== undefined && typeof value.ref !== 'boolean') throw new TypeError('timer ref must be boolean');
  return value;
}

export function createRuntimeClock({date = 'real', timers: timerPolicy = 'real', instantNanos = '0', elapsedNanos = '0'} = {}) {
  if (!['real','virtual'].includes(date) || !['real','virtual'].includes(timerPolicy) ||
      (timerPolicy === 'virtual' && date !== 'virtual')) throw new TypeError('invalid runtime clock policy');
  let instant = nanos(instantNanos, 'instant');
  let epochMillis = milliseconds(instant);
  let elapsed = nanos(elapsedNanos, 'elapsed');
  if (elapsed < 0n) throw new RangeError('negative timer elapsed time');
  let installed = false;
  let sequence = 0;
  let draining = false;
  const queue = new Map();
  const handles = new Map();

  class Timer {
    constructor(callback, duration, args, repeat) {
      this.id = ++sequence;
      this.callback = callback;
      this.duration = BigInt(delay(duration)) * nanosPerMilli;
      this.args = args;
      this.repeat = repeat;
      this.referenced = true;
      this.cancelled = false;
      this.refresh();
    }
    refresh() {
      if (!this.cancelled) {
        this.deadline = elapsed + this.duration;
        this.order = ++sequence;
        queue.set(this.id, this);
        handles.set(this.id, this);
      }
      return this;
    }
    ref() { this.referenced = true; return this; }
    unref() { this.referenced = false; return this; }
    hasRef() { return this.referenced; }
    close() { cancel(this); return this; }
    [Symbol.toPrimitive]() { return this.id; }
    [Symbol.dispose]() { cancel(this); }
  }

  function schedule(callback, duration, args, repeat) {
    if (typeof callback !== 'function') throw new TypeError('timer callback must be a function');
    return new Timer(callback, duration, args, repeat);
  }

  function cancel(value) {
    const handle = value instanceof Timer ? value : handles.get(Number(value));
    if (!handle) return;
    handle.cancelled = true;
    queue.delete(handle.id);
    handles.delete(handle.id);
  }

  function promiseTimeout(duration, value, config = {}) {
    try { options(config); } catch (error) { return Promise.reject(error); }
    if (config.signal?.aborted) return Promise.reject(abortError(config.signal.reason));
    return new Promise((resolve, reject) => {
      const complete = () => {
        config.signal?.removeEventListener('abort', abort);
        resolve(value);
      };
      const handle = schedule(complete, duration, [], false);
      if (config.ref === false) handle.unref();
      const abort = () => {
        cancel(handle);
        config.signal.removeEventListener('abort', abort);
        reject(abortError(config.signal.reason));
      };
      config.signal?.addEventListener('abort', abort, {once:true});
    });
  }

  async function* promiseInterval(duration, value, config = {}) {
    options(config);
    if (config.signal?.aborted) throw abortError(config.signal.reason);
    let count = 0;
    let wake;
    let aborted = false;
    const handle = schedule(() => { count++; wake?.(); }, duration, [], true);
    if (config.ref === false) handle.unref();
    const abort = () => { aborted = true; cancel(handle); wake?.(); };
    config.signal?.addEventListener('abort', abort, {once:true});
    try {
      while (!aborted) {
        if (count === 0) await new Promise(resolve => {wake = resolve;});
        wake = undefined;
        if (aborted) break;
        count--;
        yield value;
      }
      throw abortError(config.signal.reason);
    } finally {
      cancel(handle);
      config.signal?.removeEventListener('abort', abort);
    }
  }

  const now = () => epochMillis;
  const VirtualDate = new Proxy(NativeDate, {
    apply() { return new NativeDate(epochMillis).toString(); },
    construct(target, args, newTarget) {
      return Reflect.construct(target, args.length === 0 ? [epochMillis] : args, newTarget);
    },
    get(target, key, receiver) {
      return key === 'now' ? now : Reflect.get(target, key, receiver);
    },
  });
  const virtual = {
    setTimeout: (callback, duration, ...args) => schedule(callback, duration, args, false),
    setInterval: (callback, duration, ...args) => schedule(callback, duration, args, true),
    clearTimeout: cancel, clearInterval: cancel,
  };
  Object.defineProperty(virtual.setTimeout, promisify.custom, {value:promiseTimeout});

  function status() {
    let due = 0;
    for (const handle of queue.values()) if (handle.deadline <= elapsed) due++;
    return {pending:queue.size, due, instantNanos:instant.toString(), elapsedNanos:elapsed.toString()};
  }

  return {
    install() {
      if (installed) return;
      installed = true;
      if (date === 'virtual') globalThis.Date = VirtualDate;
      if (timerPolicy === 'virtual') {
        Object.assign(globalThis, virtual);
        Object.assign(timers, virtual);
        promises.setTimeout = promiseTimeout;
        promises.setInterval = promiseInterval;
        syncBuiltinESMExports();
      }
    },
    restore() {
      if (!installed) return;
      installed = false;
      if (date === 'virtual') globalThis.Date = NativeDate;
      if (timerPolicy === 'virtual') {
        Object.assign(globalThis, native);
        Object.assign(timers, native);
        Object.assign(promises, nativePromises);
        syncBuiltinESMExports();
        queue.clear();
        handles.clear();
      }
    },
    update(value) {
      const next = nanos(value.instantNanos, 'instant');
      const nextMillis = milliseconds(next);
      const nextElapsed = value.elapsedNanos === undefined
        ? elapsed + (next > instant ? next - instant : 0n)
        : nanos(value.elapsedNanos, 'elapsed');
      if (nextElapsed < elapsed) throw new RangeError('timer elapsed time cannot rewind');
      instant = next;
      epochMillis = nextMillis;
      elapsed = nextElapsed;
      return status();
    },
    runDue(budget = 1000) {
      if (!Number.isSafeInteger(budget) || budget < 1 || budget > maxDrain) throw new RangeError('invalid timer drain budget');
      if (draining) throw new Error('timer drain is already running');
      draining = true;
      let executed = 0;
      try {
        while (executed < budget) {
          let next;
          for (const handle of queue.values()) {
            if (handle.deadline <= elapsed && (!next || handle.deadline < next.deadline ||
                (handle.deadline === next.deadline && handle.order < next.order))) next = handle;
          }
          if (!next) break;
          queue.delete(next.id);
          handles.delete(next.id);
          if (next.repeat) {
            next.deadline += next.duration;
            queue.set(next.id, next);
            handles.set(next.id, next);
          }
          executed++;
          Reflect.apply(next.callback, next, next.args);
        }
      } finally { draining = false; }
      return {executed,...status()};
    },
    status,
  };
}
