// Local receiver limits, not deployment concurrency or Firebase quotas. The
// byte count is reserved decoded-body capacity, not heap/RSS or user retention.
import { timingSafeEqual } from 'node:crypto';

export const HTTP_ADMISSION_LIMITS = Object.freeze({
  requests: 1024,
  bytes: 64 * 1024 * 1024,
  bodyBytes: 32 * 1024 * 1024,
});

function positiveLimit(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function secretMatches(presented, expected) {
  if (typeof presented !== 'string') return false;
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function rejection(response, status, message) {
  // Do not read an unauthenticated/rejected body to keep the connection alive.
  // This also prevents a subsequent pipelined request reusing unread bytes.
  if (response.destroyed || response.writableEnded) return;
  response.statusCode = status;
  response.shouldKeepAlive = false;
  response.setHeader('Connection', 'close');
  response.setHeader('Content-Type', 'text/plain; charset=utf-8');
  response.end(message);
}

function reservedBodyBytes(headers, limit) {
  const length = headers['content-length'];
  const transfer = headers['transfer-encoding'];
  const encoding = headers['content-encoding'];
  if (length !== undefined && (typeof length !== 'string' || !/^[0-9]+$/.test(length))) {
    throw Object.assign(new Error('invalid content length'), { status: 400 });
  }
  if (length !== undefined && transfer !== undefined) {
    throw Object.assign(new Error('ambiguous content length'), { status: 400 });
  }
  const size = length === undefined ? undefined : Number(length);
  if (size !== undefined && (!Number.isSafeInteger(size) || size > limit)) {
    throw Object.assign(new Error('request body too large'), { status: 413 });
  }
  // Compressed Content-Length is NOT a bound on the decoded parser buffer.
  // Likewise reserve the parser's full limit for an unknown chunked length.
  if ((encoding !== undefined && encoding !== 'identity') || transfer !== undefined) return limit;
  // Node's HTTP/1 parser does not infer an EOF-delimited request body.
  return size ?? 0;
}

export function createHttpAdmission({ secret, isStopping = () => false, limits = HTTP_ADMISSION_LIMITS }) {
  if (typeof secret !== 'string' || typeof isStopping !== 'function' ||
      !positiveLimit(limits.requests) || !positiveLimit(limits.bytes) ||
      !positiveLimit(limits.bodyBytes) || limits.bodyBytes > limits.bytes) {
    throw new TypeError('invalid HTTP admission configuration');
  }
  // Copy configuration: a caller cannot replenish capacity by mutating limits.
  const maximum = Object.freeze({ ...limits });
  const leases = new WeakMap();
  let requests = 0, bytes = 0;

  function refresh(lease) {
    if (lease.response.destroyed || lease.response.writableFinished) lease.terminal = true;
    if (lease.released || !lease.terminal || lease.held) return;
    lease.released = true;
    requests -= 1;
    bytes -= lease.bytes;
    lease.response.removeListener('finish', lease.settle);
    lease.response.removeListener('close', lease.settle);
    lease.response.removeListener('error', lease.settle);
  }

  return Object.freeze({
    // Runs on Node's request/checkContinue event, before ANY Express parser.
    handle(request, response, next, expectContinue = false) {
      if (isStopping()) { rejection(response, 503, 'runner is shutting down'); return; }
      if (!secret) { rejection(response, 500, 'FIREEMU_RUNNER_SECRET is required'); return; }
      if (!secretMatches(request.headers['x-fireemu-runner-secret'], secret)) {
        rejection(response, 403, 'not the fireemu proxy'); return;
      }
      if (leases.has(request)) { rejection(response, 400, 'duplicate request dispatch'); return; }
      let reserved;
      try { reserved = reservedBodyBytes(request.headers, maximum.bodyBytes); }
      catch (error) { rejection(response, error.status, error.message); return; }
      if (requests >= maximum.requests || bytes + reserved > maximum.bytes) {
        rejection(response, 503, 'runner HTTP capacity exhausted'); return;
      }
      requests += 1; bytes += reserved;
      const lease = { response, bytes: reserved, terminal: false, held: false, released: false, begun: false };
      lease.settle = () => { lease.terminal = true; refresh(lease); };
      leases.set(request, lease);
      response.once('finish', lease.settle);
      response.once('close', lease.settle);
      response.once('error', lease.settle);
      refresh(lease);
      if (lease.released) return;
      // Never expose the proxy capability to parsers or user callbacks.
      delete request.headers['x-fireemu-runner-secret'];
      if (Array.isArray(request.rawHeaders)) {
        for (let i = request.rawHeaders.length - 2; i >= 0; i -= 2) {
          if (request.rawHeaders[i].toLowerCase() === 'x-fireemu-runner-secret') request.rawHeaders.splice(i, 2);
        }
      }
      try {
        if (expectContinue) response.writeContinue();
        next(request, response);
      } catch {
        if (response.headersSent) response.destroy();
        else rejection(response, 500, 'internal error');
      }
    },

    // Express calls verify on its decoded Buffer before JSON/text processing.
    // For compressed/chunked input, unused reserved capacity is returned here.
    verify(request, _response, body) {
      const lease = leases.get(request);
      if (!lease || lease.released || lease.begun || !Buffer.isBuffer(body) ||
          body.length > lease.bytes || body.length > maximum.bodyBytes) {
        throw Object.assign(new Error('unadmitted request body'), { status: 413, statusCode: 413 });
      }
      bytes -= lease.bytes - body.length;
      lease.bytes = body.length;
    },

    // Pin before environment-queue insertion. Client disconnect must NOT return
    // the slot while that queue or a running user Promise still retains input.
    begin(request) {
      const lease = leases.get(request);
      if (!lease) return null;
      refresh(lease);
      if (lease.released || lease.begun || lease.response.writableEnded) return null;
      lease.begun = true; lease.held = true;
      let completed = false;
      return () => {
        if (completed) return;
        completed = true; lease.held = false; refresh(lease);
      };
    },

    snapshot() { return Object.freeze({ requests, bytes }); },
  });
}
