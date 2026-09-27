const localUrl = value => /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}(?:\/|$)/.test(value);
const urlOf = input => typeof input === 'string' ? input : input?.url ?? String(input);

/** Instrument the pinned Node SDK transports before importing Firebase. */
export const installNodeWireGuard = ({ http2, globals, budget, phase,
  allowUrl = localUrl }) => {
  if (typeof http2?.connect !== 'function' || typeof globals?.fetch !== 'function' ||
      typeof budget?.claim !== 'function' || typeof phase !== 'function' ||
      typeof allowUrl !== 'function') throw new Error('invalid Node wire guard inputs');
  const originalConnect = http2.connect;
  const originalFetch = globals.fetch;
  const sessions = new Map();
  let closed = false;
  http2.connect = function guardedConnect(authority, ...options) {
    if (closed || !allowUrl(urlOf(authority))) throw new Error('wire destination refused');
    const session = originalConnect.call(this, authority, ...options);
    if (!sessions.has(session)) {
      const request = session.request;
      session.request = function guardedRequest(...args) {
        if (closed) throw new Error('wire guard closed');
        budget.claim(phase(), 'grpc');
        return request.apply(this, args);
      };
      sessions.set(session, request);
    }
    return session;
  };
  globals.fetch = function guardedFetch(input, ...options) {
    if (closed || !allowUrl(urlOf(input))) {
      return Promise.reject(new Error('wire destination refused'));
    }
    try {
      budget.claim(phase(), 'auth');
    } catch (error) {
      return Promise.reject(error);
    }
    return originalFetch.call(this, input, ...options);
  };
  return Object.freeze({
    close() {
      if (closed) return;
      closed = true;
      http2.connect = originalConnect;
      globals.fetch = originalFetch;
      for (const [session, request] of sessions) session.request = request;
    },
  });
};
