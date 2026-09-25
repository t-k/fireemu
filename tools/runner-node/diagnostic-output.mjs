// Bounded admission for direct stderr (and redirected user stdout) writes.
// The native Writable owns byte ordering and corking. Callback accounting adds
// backpressure even when a native write completes synchronously.
// This is not a process-wide sandbox: direct fd writes and replaced methods bypass it.
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';

const typedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const viewGetters = Object.fromEntries(['buffer', 'byteOffset', 'byteLength'].map(key =>
  [key, Object.getOwnPropertyDescriptor(typedPrototype, key).get]));
const dataViewGetters = Object.fromEntries(['buffer', 'byteOffset', 'byteLength'].map(key =>
  [key, Object.getOwnPropertyDescriptor(DataView.prototype, key).get]));
function viewData(chunk) {
  const getters = types.isDataView(chunk) ? dataViewGetters : viewGetters;
  return { buffer: getters.buffer.call(chunk), offset: getters.byteOffset.call(chunk),
    length: getters.byteLength.call(chunk) };
}

export const MAX_DIAGNOSTIC_BYTES = 8 * 1024 * 1024;
export const MAX_DIAGNOSTIC_WRITES = 1024;
export const MAX_DIAGNOSTIC_WAIT_MS = 30_000;
export const DIAGNOSTIC_FINISH_MS = 1_000;

export class DiagnosticOutputError extends Error {
  constructor(reason) {
    super(`runner diagnostic output failed (${reason})`);
    this.name = 'DiagnosticOutputError';
    this.code = 'ERR_FIREEMU_DIAGNOSTIC_OUTPUT';
  }
}

function limit(value, maximum, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`invalid diagnostic ${name}`);
  }
  return value;
}

export class DiagnosticWriter {
  #stream;
  #write;
  #emit;
  #highWaterMark;
  #needsDrain = false;
  #nativeBackpressure = false;
  #drainScheduled = false;
  #onError;
  #maxBytes;
  #maxWrites;
  #waitMs;
  #finishMs;
  #defaultEncoding = 'utf8';
  #pending = new Set();
  #bytes = 0;
  #failed = null;
  #closing = false;
  #closeAt = Infinity;
  #timer = null;
  #finishPromise;
  #finishResolve;

  constructor(stream, {
    onError,
    maxBytes = MAX_DIAGNOSTIC_BYTES,
    maxWrites = MAX_DIAGNOSTIC_WRITES,
    waitMs = MAX_DIAGNOSTIC_WAIT_MS,
    finishMs = DIAGNOSTIC_FINISH_MS,
  } = {}) {
    if (typeof stream?.write !== 'function' || typeof stream?.on !== 'function' ||
        typeof stream?.emit !== 'function' ||
        typeof onError !== 'function') throw new TypeError('diagnostic stream and onError required');
    this.#stream = stream;
    this.#write = stream.write.bind(stream);
    this.#emit = stream.emit.bind(stream);
    this.#onError = onError;
    this.#maxBytes = limit(maxBytes, MAX_DIAGNOSTIC_BYTES, 'bytes');
    this.#maxWrites = limit(maxWrites, MAX_DIAGNOSTIC_WRITES, 'writes');
    this.#waitMs = limit(waitMs, MAX_DIAGNOSTIC_WAIT_MS, 'wait');
    this.#finishMs = limit(finishMs, DIAGNOSTIC_FINISH_MS, 'finish wait');
    const nativeHighWaterMark = stream.writableHighWaterMark;
    this.#highWaterMark = Math.min(this.#maxBytes,
      Number.isSafeInteger(nativeHighWaterMark) && nativeHighWaterMark > 0
        ? nativeHighWaterMark : 64 * 1024);
    // Native drain can fire before write callbacks. Do not tell a producer to
    // resume while our callback reservations still fill the budget. Coalesce
    // it with logical backpressure and emit only after BOTH have cleared.
    stream.emit = (event, ...args) => {
      if (event !== 'drain') return this.#emit(event, ...args);
      this.#nativeBackpressure = false;
      this.#requestDrain();
      return (stream.listenerCount?.('drain') ?? 0) > 0;
    };
    // Retain the error listener after failure: an error event may follow its callback.
    stream.on('error', () => this.#fail('stream error'));
    stream.on('close', () => this.#fail('stream closed'));
    stream.on('finish', () => this.#fail('stream ended'));
  }

  get state() {
    return Object.freeze({ pendingBytes: this.#bytes, pendingWrites: this.#pending.size,
      failed: this.#failed !== null, closing: this.#closing });
  }

  setDefaultEncoding(encoding) {
    if (typeof encoding !== 'string' || !Buffer.isEncoding(encoding)) {
      throw new TypeError('invalid diagnostic encoding');
    }
    this.#defaultEncoding = encoding;
    return this;
  }

  write(chunk, encoding, callback) {
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (callback !== undefined && callback !== null && typeof callback !== 'function') {
      throw new TypeError('diagnostic write callback must be a function');
    }
    if (this.#failed || this.#closing) {
      if (callback) process.nextTick(callback, this.#failed ?? new DiagnosticOutputError('closing'));
      return false;
    }
    if (this.#expired()) { this.#fail('deadline'); return this.write(chunk, encoding, callback); }
    let size, selectedEncoding, view;
    if (typeof chunk === 'string') {
      selectedEncoding = encoding || this.#defaultEncoding;
      if (typeof selectedEncoding !== 'string' || !Buffer.isEncoding(selectedEncoding)) {
        throw new TypeError('invalid diagnostic encoding');
      }
      size = Buffer.byteLength(chunk, selectedEncoding);
    } else if (ArrayBuffer.isView(chunk)) {
      view = viewData(chunk);
      size = view.length;
    } else {
      throw new TypeError('diagnostic chunk must be a string or ArrayBuffer view');
    }
    // Include zero-length writes in the count: callbacks also retain memory.
    if (this.#pending.size >= this.#maxWrites || this.#bytes + size > this.#maxBytes) {
      this.#fail('pending limit');
      return this.write(chunk, encoding, callback);
    }
    if (this.#stream.destroyed || this.#stream.writableEnded) {
      this.#fail('stream unavailable');
      return this.write(chunk, encoding, callback);
    }
    // Copy views before native queuing; later caller mutation cannot change admitted bytes.
    // Strings are immutable. Encoding once also fixes accounting for hex/base64 inputs.
    const payload = typeof chunk === 'string' ? Buffer.from(chunk, selectedEncoding) :
      Buffer.from(new Uint8Array(view.buffer, view.offset, view.length));
    // Buffer.byteLength(base64/hex) can be conservative for malformed input. Charge
    // the bytes actually queued, after rejecting oversized allocation candidates above.
    size = payload.length;
    const entry = { size, at: performance.now(), callback };
    this.#pending.add(entry);
    this.#bytes += size;
    let accepted;
    try {
      accepted = this.#write(payload, error => {
        if (!this.#pending.has(entry)) return;
        if (error) { this.#fail('write callback'); return; }
        if (this.#expired()) { this.#fail('deadline'); return; }
        this.#settle(entry);
        this.#arm();
      });
    } catch {
      this.#fail('write');
      return false;
    }
    if (accepted !== true && accepted !== false) {
      this.#fail('write return');
      return false;
    }
    if (accepted === false) this.#nativeBackpressure = true;
    const pressured = accepted === false || this.#bytes >= this.#highWaterMark ||
      this.#pending.size >= this.#maxWrites;
    if (pressured) this.#needsDrain = true;
    this.#arm();
    this.#requestDrain();
    // Native false remains false. Native true may become false while completed
    // writes still have deferred callbacks; otherwise a cooperative producer
    // can exceed our limits before Node gets a turn to run those callbacks.
    // In either case the write was accepted and must not be resent.
    return this.#failed ? false : !pressured;
  }

  #settle(entry, error) {
    if (!this.#pending.delete(entry)) return;
    this.#bytes -= entry.size;
    // User callbacks cannot reenter or corrupt admission bookkeeping. Like Writable,
    // completion is asynchronous even with an inline write implementation in a test.
    if (entry.callback) process.nextTick(entry.callback, error);
    this.#requestDrain();
  }

  #requestDrain() {
    if (this.#failed || this.#closing || !this.#needsDrain || this.#nativeBackpressure ||
        this.#pending.size !== 0 || this.#drainScheduled) return;
    this.#drainScheduled = true;
    process.nextTick(() => {
      this.#drainScheduled = false;
      // A user write callback can enqueue new data before this notification.
      if (this.#failed || this.#closing || !this.#needsDrain || this.#nativeBackpressure ||
          this.#pending.size !== 0) return;
      this.#needsDrain = false;
      this.#emit('drain');
    });
  }

  #expired() {
    const oldest = this.#pending.values().next().value;
    if (!oldest) return false;
    const now = performance.now();
    return now >= oldest.at + this.#waitMs || now >= this.#closeAt;
  }

  #fail(reason) {
    if (this.#failed) return;
    this.#failed = new DiagnosticOutputError(reason);
    clearTimeout(this.#timer); this.#timer = null;
    for (const entry of this.#pending) this.#settle(entry, this.#failed);
    this.#finishResolve?.(false);
    // Never write a diagnostic about this failure back into the failed stderr.
    try { this.#onError(this.#failed); } catch { /* failure is already permanent */ }
  }

  #arm() {
    clearTimeout(this.#timer); this.#timer = null;
    if (this.#failed) return;
    const oldest = this.#pending.values().next().value;
    if (!oldest) { if (this.#closing) this.#finishResolve?.(true); return; }
    const remaining = Math.min(oldest.at + this.#waitMs, this.#closeAt) - performance.now();
    if (remaining <= 0) { this.#fail('deadline'); return; }
    this.#timer = setTimeout(() => this.#arm(), Math.max(1, Math.ceil(remaining)));
  }

  // Flush already-admitted writes only; do not close fd2 or wait for user callbacks/tasks.
  finish() {
    if (this.#finishPromise) return this.#finishPromise;
    this.#closing = true;
    this.#closeAt = performance.now() + this.#finishMs;
    this.#finishPromise = new Promise(resolve => { this.#finishResolve = resolve; });
    if (this.#failed) this.#finishResolve(false); else this.#arm();
    return this.#finishPromise;
  }
}

// Install before loading a user codebase. Keep the original stream object, fd,
// event listeners, cork/uncork and false-then-drain producer contract intact.
// Own pending callbacks can add backpressure; native true is not always returned.
export function installDiagnosticOutput(stream, options) {
  const writer = new DiagnosticWriter(stream, options);
  const setEncoding = stream.setDefaultEncoding?.bind(stream);
  stream.write = writer.write.bind(writer);
  if (setEncoding) stream.setDefaultEncoding = encoding => {
    // Validate with the native API too; preserve its chaining return value.
    const result = setEncoding(encoding);
    writer.setDefaultEncoding(encoding);
    return result;
  };
  return writer;
}
