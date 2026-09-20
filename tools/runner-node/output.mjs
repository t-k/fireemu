// A bounded, ordered writer for the runner's private stdout protocol channel.
// Limits are local resource policies, not Firebase quotas. They count encoded
// pending frames (including the stream's in-flight write), not process-wide RSS.
import { performance } from 'node:perf_hooks';
import { MAX_FRAME_BYTES } from './protocol.mjs';

export const MAX_PENDING_BYTES = 32 * 1024 * 1024;
export const MAX_PENDING_FRAMES = 1024;
export const MAX_OUTPUT_WAIT_MS = 30_000;
export const OUTPUT_FINISH_MS = 1_000;

export class OutputError extends Error {
  constructor(reason) {
    super(`runner output failed (${reason})`);
    this.name = 'OutputError';
  }
}

function limit(value, maximum, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`invalid output ${name}`);
  }
  return value;
}

export class FrameWriter {
  #stream;
  #write;
  #onError;
  #maxBytes;
  #maxFrames;
  #waitMs;
  #finishMs;
  #queue = [];
  #current = null;
  #bytes = 0;
  #frames = 0;
  #blocked = false;
  #blockedAt = 0;
  #writing = false;
  #encoding = false;
  #failed = false;
  #closing = false;
  #closeAt = Infinity;
  #finishPromise;
  #finishResolve;
  #timer = null;

  constructor(stream, {
    onError,
    maxBytes = MAX_PENDING_BYTES,
    maxFrames = MAX_PENDING_FRAMES,
    waitMs = MAX_OUTPUT_WAIT_MS,
    finishMs = OUTPUT_FINISH_MS,
  } = {}) {
    if (typeof stream?.write !== 'function' || typeof stream?.on !== 'function' ||
        typeof onError !== 'function') throw new TypeError('output stream and onError required');
    this.#stream = stream;
    // Capture before index.mjs redirects user stdout writes to stderr.
    this.#write = stream.write.bind(stream);
    this.#onError = onError;
    this.#maxBytes = limit(maxBytes, MAX_PENDING_BYTES, 'bytes');
    this.#maxFrames = limit(maxFrames, MAX_PENDING_FRAMES, 'frames');
    this.#waitMs = limit(waitMs, MAX_OUTPUT_WAIT_MS, 'wait');
    this.#finishMs = limit(finishMs, OUTPUT_FINISH_MS, 'finish wait');
    stream.on('drain', () => {
      if (this.#failed) return;
      this.#blocked = false;
      this.#pump();
    });
    // Keep the error listener after failure: a write callback can fail before
    // the stream emits 'error'. Neither event may become an unhandled error.
    stream.on('error', () => this.#fail('stream error'));
    stream.on('close', () => this.#fail('stream closed'));
    stream.on('finish', () => this.#fail('stream ended'));
  }

  get state() {
    return Object.freeze({ pendingBytes: this.#bytes, pendingFrames: this.#frames,
      backpressured: this.#blocked, failed: this.#failed, closing: this.#closing });
  }

  // true means admitted to the bounded queue, NOT delivered to the daemon.
  send(message) {
    if (this.#failed || this.#closing) return false;
    if (this.#encoding) return this.#fail('reentrant serialization');
    if (this.#frames >= this.#maxFrames) return this.#fail('frame queue limit');
    let payload;
    this.#encoding = true;
    try {
      const text = JSON.stringify(message);
      if (typeof text !== 'string' || text[0] !== '{' || text.at(-1) !== '}') {
        return this.#fail('message object');
      }
      const length = Buffer.byteLength(text, 'utf8');
      if (length > MAX_FRAME_BYTES) return this.#fail('frame too large');
      const prefix = `${length}\n`;
      const size = Buffer.byteLength(prefix) + length;
      if (this.#bytes + size > this.#maxBytes) return this.#fail('byte queue limit');
      // One private Buffer/write per complete frame; never publish a length for
      // a payload that fails size/serialization checks or replay a false write.
      payload = Buffer.from(prefix + text, 'utf8');
    } catch {
      return this.#fail('serialization');
    } finally {
      this.#encoding = false;
    }
    if (this.#failed) return false;
    this.#queue.push({ payload, size: payload.length, at: performance.now() });
    this.#bytes += payload.length;
    this.#frames += 1;
    this.#pump();
    return !this.#failed;
  }

  // Flush only already-admitted output on ordinary EOF/explicit shutdown.
  // Does not wait for user callbacks, end process.stdout, or cancel side effects.
  finish() {
    if (this.#finishPromise) return this.#finishPromise;
    this.#closing = true;
    this.#closeAt = performance.now() + this.#finishMs;
    this.#finishPromise = new Promise(resolve => { this.#finishResolve = resolve; });
    if (this.#failed) this.#finishResolve(false);
    else this.#pump();
    return this.#finishPromise;
  }

  #fail(reason) {
    if (this.#failed) return false;
    this.#failed = true;
    clearTimeout(this.#timer);
    this.#timer = null;
    this.#queue = [];
    this.#current = null;
    this.#bytes = 0;
    this.#frames = 0;
    this.#finishResolve?.(false);
    // No raw payload or arbitrary error getters/stringification in diagnostics.
    try { this.#onError(new OutputError(reason)); } catch { /* already failed */ }
    return false;
  }

  #arm() {
    clearTimeout(this.#timer);
    this.#timer = null;
    if (this.#failed) return;
    const oldest = this.#current ?? this.#queue[0];
    if (!oldest && !this.#blocked) {
      if (this.#closing) this.#finishResolve?.(true);
      return;
    }
    // Enqueues/drain/progress never renew the oldest frame's residence time.
    let due = oldest ? oldest.at + this.#waitMs : Infinity;
    if (this.#blocked) due = Math.min(due, this.#blockedAt + this.#waitMs);
    due = Math.min(due, this.#closeAt);
    const remaining = due - performance.now();
    if (remaining <= 0) { this.#fail('deadline'); return; }
    this.#timer = setTimeout(() => this.#arm(), Math.max(1, Math.ceil(remaining)));
    // Intentionally referenced: pending output must not disappear on empty EOF.
  }

  #pump() {
    if (this.#failed || this.#writing) return;
    if (this.#stream.destroyed || this.#stream.writableEnded) {
      this.#fail('stream unavailable'); return;
    }
    const pending = this.#current ?? this.#queue[0];
    if (pending && (performance.now() >= pending.at + this.#waitMs ||
                    performance.now() >= this.#closeAt)) {
      this.#fail('deadline'); return;
    }
    this.#writing = true;
    try {
      while (!this.#failed && !this.#current && !this.#blocked && this.#queue.length) {
        const entry = this.#queue.shift();
        this.#current = entry;
        let returned;
        try {
          returned = this.#write(entry.payload, error => {
            if (this.#failed) return;
            if (error) { this.#fail('write callback'); return; }
            if (performance.now() >= entry.at + this.#waitMs ||
                performance.now() >= this.#closeAt) { this.#fail('deadline'); return; }
            if (this.#current !== entry) { this.#fail('write callback order'); return; }
            this.#current = null;
            this.#bytes -= entry.size;
            this.#frames -= 1;
            this.#pump();
          });
        } catch {
          this.#fail('write'); break;
        }
        if (returned !== true && returned !== false) { this.#fail('write return'); break; }
        if (returned === false) {
          this.#blocked = true;
          this.#blockedAt = entry.at;
        }
      }
    } finally {
      this.#writing = false;
    }
    this.#arm();
  }
}
