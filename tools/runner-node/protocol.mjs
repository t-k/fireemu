// Runtime -> runner: canonical decimal byte length, LF, UTF-8 JSON object.
// Keep the byte cap in sync with fireemu-adapter-functions/src/protocol.rs.
// This is a trusted local pipe, not an authentication or arbitrary-code sandbox.
import { TextDecoder } from 'node:util';
import { performance } from 'node:perf_hooks';
import { setTimeout, clearTimeout } from 'node:timers';

export const MAX_FRAME_BYTES = 16 * 1024 * 1024;
// Local pipe safety policies, not Firebase invocation deadlines or quotas.
export const MAX_INPUT_FRAME_WAIT_MS = 30_000;
export const MAX_ACTIVE_INVOCATIONS = 4096;
export const MAX_ACTIVE_INVOCATION_BYTES = 64 * 1024 * 1024;
const MAX_HEADER_BYTES = String(MAX_FRAME_BYTES).length;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export class ProtocolError extends Error {
  constructor(reason) {
    // Fixed diagnostics only: JSON.parse errors can include user payload bytes.
    super(`invalid runner frame (${reason})`);
    this.name = 'ProtocolError';
  }
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function text(value) {
  return typeof value === 'string' && value.length > 0;
}

function decodeMessage(payload) {
  let message;
  try {
    message = JSON.parse(decoder.decode(payload));
  } catch {
    throw new ProtocolError('UTF-8 or JSON');
  }
  if (!object(message)) throw new ProtocolError('message object');
  if (message.type === 'shutdown') return message;
  if (message.type !== 'invoke' || !text(message.invocationId) ||
      !text(message.function) || !text(message.trigger) || !object(message.event) ||
      (message.entryPoint !== undefined && !text(message.entryPoint))) {
    throw new ProtocolError('message fields');
  }
  return message;
}

// At most one capped body allocation is retained. Chunking never causes repeated
// concatenation of the growing body, and an over-limit header fails before that
// allocation. Handlers run only after a complete frame has been decoded.
export class FrameDecoder {
  #onFrame;
  #length = 0;
  #digits = 0;
  #body = null;
  #offset = 0;
  #ended = false;
  #failed = false;
  #now;
  #waitMs;
  #lastTime = null;
  #deadline = null;

  constructor(onFrame, { frameWaitMs = MAX_INPUT_FRAME_WAIT_MS,
    now = () => performance.now() } = {}) {
    if (typeof onFrame !== 'function' || typeof now !== 'function') {
      throw new TypeError('onFrame and now must be functions');
    }
    if (!Number.isSafeInteger(frameWaitMs) || frameWaitMs < 1 ||
        frameWaitMs > MAX_INPUT_FRAME_WAIT_MS) throw new TypeError('invalid input frame wait');
    this.#onFrame = onFrame;
    this.#waitMs = frameWaitMs;
    this.#now = now;
  }

  #time() {
    let value;
    try { value = this.#now(); } catch { throw new ProtocolError('input clock'); }
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 ||
        (this.#lastTime !== null && value < this.#lastTime)) {
      throw new ProtocolError('input clock');
    }
    this.#lastTime = value;
    return value;
  }

  #check(now = this.#time()) {
    if (this.#deadline !== null && now >= this.#deadline) {
      throw new ProtocolError('input frame deadline');
    }
  }

  #fail(error) {
    this.#failed = true;
    this.#body = null;
    this.#deadline = null;
    throw error;
  }

  // Null when between frames. Partial headers and bodies share one deadline,
  // measured from the first observed byte, never renewed by progress.
  remainingTime() {
    if (this.#failed) throw new ProtocolError('closed');
    if (this.#ended || this.#deadline === null) return null;
    try {
      const now = this.#time();
      this.#check(now);
      return this.#deadline - now;
    } catch (error) { return this.#fail(error); }
  }

  push(chunk) {
    if (this.#failed) throw new ProtocolError('closed');
    if (this.#ended) return;
    try {
      if (!Buffer.isBuffer(chunk)) throw new ProtocolError('non-byte input');
      if (chunk.length === 0) { this.remainingTime(); return; }
      // All bytes in a coalesced chunk arrived together. A slow synchronous
      // onFrame must not give its trailing frame a fresh receive-time budget.
      const receivedAt = this.#time();
      this.#check(receivedAt);
      let at = 0;
      while (at < chunk.length && !this.#ended) {
        if (this.#deadline === null) {
          this.#deadline = receivedAt + this.#waitMs;
          if (!Number.isFinite(this.#deadline) || this.#deadline <= receivedAt) {
            throw new ProtocolError('input clock');
          }
        }
        this.#check();
        if (this.#body === null) {
          const byte = chunk[at++];
          if (byte === 10) {
            if (this.#digits === 0) throw new ProtocolError('empty length');
            this.#body = Buffer.allocUnsafe(this.#length);
          } else {
            if (byte < 48 || byte > 57 || (this.#digits === 0 && byte === 48)) {
              throw new ProtocolError('decimal length');
            }
            this.#digits += 1;
            this.#length = this.#length * 10 + byte - 48;
            if (this.#digits > MAX_HEADER_BYTES || this.#length > MAX_FRAME_BYTES) {
              throw new ProtocolError('frame too large');
            }
          }
        } else {
          const count = Math.min(chunk.length - at, this.#length - this.#offset);
          chunk.copy(this.#body, this.#offset, at, at + count);
          at += count;
          this.#offset += count;
          if (this.#offset !== this.#length) continue;
          const message = decodeMessage(this.#body);
          // Timers can run late. Check after decoding, before any user callback,
          // so a late final chunk cannot race the timer into successful dispatch.
          this.#check();
          const payloadBytes = this.#length;
          this.#body = null;
          this.#offset = 0;
          this.#length = 0;
          this.#digits = 0;
          this.#deadline = null;
          // Byte accounting is the actual received payload length, not a
          // caller-supplied field or a second JSON serialization.
          if (this.#onFrame(message, payloadBytes) === false) this.#ended = true;
        }
      }
    } catch (error) { this.#fail(error); }
  }

  end() {
    if (this.#failed) throw new ProtocolError('closed');
    if (this.#ended) return;
    this.#ended = true;
    if (this.#digits !== 0 || this.#body !== null) {
      this.#fail(new ProtocolError('truncated'));
    }
  }
}

// Keep the active callback and environment-queue inputs bounded independently
// of the output queue. A lease releases once, including on callback rejection.
// Counts measure encoded input payload bytes, not V8 heap size or retained user
// references after a callback returns. HTTP callbacks are not part of this pipe.
export class InvocationBudget {
  #active = new Map();
  #bytes = 0;
  #failed = false;
  #maxCount;
  #maxBytes;

  constructor({ maxCount = MAX_ACTIVE_INVOCATIONS,
    maxBytes = MAX_ACTIVE_INVOCATION_BYTES } = {}) {
    if (!Number.isSafeInteger(maxCount) || maxCount < 1 || maxCount > MAX_ACTIVE_INVOCATIONS ||
        !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_ACTIVE_INVOCATION_BYTES) {
      throw new TypeError('invalid invocation limits');
    }
    this.#maxCount = maxCount;
    this.#maxBytes = maxBytes;
  }

  get state() {
    return Object.freeze({ count: this.#active.size, payloadBytes: this.#bytes, failed: this.#failed });
  }

  #fail(reason) {
    this.#failed = true;
    throw new ProtocolError(reason);
  }

  reserve(id, payloadBytes) {
    if (this.#failed) throw new ProtocolError('closed');
    if (!text(id) || !Number.isSafeInteger(payloadBytes) || payloadBytes < 1 ||
        payloadBytes > MAX_FRAME_BYTES) this.#fail('invocation accounting');
    if (this.#active.has(id)) this.#fail('duplicate active invocation');
    if (this.#active.size >= this.#maxCount) this.#fail('active invocation count');
    if (this.#bytes + payloadBytes > this.#maxBytes) this.#fail('active invocation bytes');
    const ticket = { payloadBytes };
    this.#active.set(id, ticket);
    this.#bytes += payloadBytes;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      // An old lease cannot release a later invocation that reuses the ID.
      if (this.#active.get(id) !== ticket) return;
      this.#active.delete(id);
      this.#bytes -= payloadBytes;
    };
  }
}

export function readFrames(input, onFrame, onEnd, onError, options = {}) {
  let stopped = false;
  let timer = null;
  const disarm = () => { clearTimeout(timer); timer = null; };
  const pause = () => { try { input.pause(); } catch { /* already stopped */ } };
  const stop = error => {
    if (stopped) return;
    stopped = true;
    disarm();
    pause();
    // No parser message (or raw bytes) may widen this fixed diagnostic.
    onError(error instanceof ProtocolError ? error : new ProtocolError('dispatch'));
  };
  const frames = new FrameDecoder((message, payloadBytes) => {
    const keepReading = onFrame(message, payloadBytes);
    if (keepReading === false) {
      stopped = true;
      disarm();
      pause();
    }
    return keepReading;
  }, options);
  const arm = () => {
    disarm();
    if (stopped) return;
    let remaining;
    try { remaining = frames.remainingTime(); } catch (error) { stop(error); return; }
    if (remaining === null) return; // Idle runner and in-flight user work have no frame timer.
    timer = setTimeout(arm, Math.max(1, Math.ceil(remaining)));
    // Referenced while a partial frame is held; never refresh from the latest byte.
  };
  input.on('data', chunk => {
    if (stopped) return;
    try { frames.push(chunk); } catch (error) { stop(error); return; }
    arm();
  });
  input.on('end', () => {
    if (stopped) return;
    try { frames.end(); } catch (error) { stop(error); return; }
    stopped = true;
    disarm();
    onEnd();
  });
  input.on('error', () => stop(new ProtocolError('input stream')));
  // A close without end is not a clean EOF (for example, a destroyed pipe).
  input.on('close', () => {
    if (!stopped) stop(new ProtocolError('input closed'));
  });
}
