const owners = new WeakMap();
const urlOf = (input) => (typeof input === "string" ? input : (input?.url ?? String(input)));
const localUrl = (value) => {
  const url = new URL(value);
  return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
};

/** Guard only injected http2 session requests and fetch, not every Node outbound path. */
export const installNodeWireGuard = ({ http2, globals, budget, phase, allowUrl = localUrl }) => {
  if (
    typeof http2?.connect !== "function" ||
    typeof globals?.fetch !== "function" ||
    typeof budget?.claim !== "function" ||
    typeof phase !== "function" ||
    typeof allowUrl !== "function"
  )
    throw new Error("invalid Node wire guard inputs");
  const originalConnect = http2.connect;
  const originalFetch = globals.fetch;
  const sessions = new Map();
  const hooks = [];
  const failures = { closed: 0, destination: 0, claim: 0, ownership: 0 };
  let closed = false;
  const refuse = (kind, error) => {
    failures[kind]++;
    throw error;
  };
  const owned = (target, key) => owners.get(target)?.get(key);
  const available = (target, key) => {
    if (owned(target, key)) throw new Error("wire hook ownership refused");
  };
  // Check both top-level owners before touching either hook.
  available(http2, "connect");
  available(globals, "fetch");

  const inheritedDescriptor = (target, key) => {
    for (let owner = Object.getPrototypeOf(target); owner; owner = Object.getPrototypeOf(owner)) {
      const descriptor = Object.getOwnPropertyDescriptor(owner, key);
      if (descriptor) return { owner, descriptor };
    }
    return null;
  };
  const installHook = (target, key, original, wrapper) => {
    if (closed) throw new Error("wire guard closed");
    available(target, key);
    if (target[key] !== original) throw new Error("wire hook ownership refused");
    const hook = {
      target,
      key,
      original,
      wrapper,
      hadOwn: Object.hasOwn(target, key),
      installed: false,
      inherited: Object.hasOwn(target, key) ? null : inheritedDescriptor(target, key),
    };
    hooks.push(hook);
    if (!owners.has(target)) owners.set(target, new Map());
    owners.get(target).set(key, hook);
    try {
      target[key] = wrapper;
      if (closed) throw new Error("wire guard closed");
      const installed = target[key];
      if (closed) throw new Error("wire guard closed");
      if (owned(target, key) !== hook || installed !== wrapper)
        throw new Error("wire hook installation refused");
      hook.installed = true;
      return hook;
    } catch (error) {
      try {
        restoreHook(hook);
      } catch (rollbackError) {
        throw new AggregateError(
          [error, rollbackError],
          "wire hook installation and rollback failed",
        );
      } finally {
        hooks.splice(hooks.indexOf(hook), 1);
      }
      throw error;
    }
  };
  const restoreHook = (hook) => {
    const { target, key, original, wrapper, hadOwn } = hook;
    try {
      if (target[key] === wrapper) {
        if (hadOwn) target[key] = original;
        else if (Object.hasOwn(target, key)) delete target[key];
        else {
          const current = inheritedDescriptor(target, key);
          if (
            current?.owner !== hook.inherited?.owner ||
            current?.descriptor.get !== hook.inherited?.descriptor.get ||
            current?.descriptor.set !== hook.inherited?.descriptor.set
          ) {
            failures.ownership++;
            return;
          }
          target[key] = original;
        }
        if (target[key] !== original) throw new Error("wire hook restoration refused");
      } else if (hook.installed) {
        failures.ownership++;
      }
    } finally {
      if (owned(target, key) === hook) owners.get(target).delete(key);
    }
  };
  const active = (target, key, wrapper) => {
    if (closed) refuse("closed", new Error("wire guard closed"));
    const current = target[key];
    if (closed) refuse("closed", new Error("wire guard closed"));
    if (owned(target, key)?.wrapper !== wrapper || current !== wrapper) {
      refuse("ownership", new Error("wire hook ownership refused"));
    }
  };
  const destination = (input) => {
    try {
      const value = urlOf(input);
      const url = new URL(value);
      const port = Number(url.port || (url.protocol === "http:" ? 80 : 443));
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        !Number.isInteger(port) ||
        port < 1 ||
        port > 65535 ||
        allowUrl(value) !== true
      ) {
        throw new Error("wire destination refused");
      }
    } catch {
      refuse("destination", new Error("wire destination refused"));
    }
  };
  const claim = (transport) => {
    try {
      budget.claim(phase(), transport);
    } catch (error) {
      refuse("claim", error);
    }
  };
  const guardedConnect = function (authority, ...options) {
    active(http2, "connect", guardedConnect);
    destination(authority);
    active(http2, "connect", guardedConnect);
    const session = originalConnect.call(this, authority, ...options);
    active(http2, "connect", guardedConnect);
    if (!sessions.has(session)) {
      try {
        if (typeof session?.request !== "function") throw new Error("invalid wire session request");
        const request = session.request;
        const guardedRequest = function (...args) {
          active(session, "request", guardedRequest);
          claim("grpc");
          active(session, "request", guardedRequest);
          return request.apply(this, args);
        };
        sessions.set(session, installHook(session, "request", request, guardedRequest));
      } catch (error) {
        refuse(closed ? "closed" : "ownership", error);
      }
    } else {
      active(session, "request", sessions.get(session).wrapper);
    }
    return session;
  };
  const guardedFetch = function (input, ...options) {
    try {
      active(globals, "fetch", guardedFetch);
      destination(input);
      active(globals, "fetch", guardedFetch);
      claim("auth");
      active(globals, "fetch", guardedFetch);
    } catch (error) {
      return Promise.reject(error);
    }
    return originalFetch.call(this, input, ...options);
  };
  const restore = () => {
    const errors = [];
    for (const hook of hooks.toReversed()) {
      try {
        restoreHook(hook);
      } catch (error) {
        failures.ownership++;
        errors.push(error);
      }
    }
    if (errors.length) throw new AggregateError(errors, "wire hook restoration failed");
  };
  try {
    installHook(http2, "connect", originalConnect, guardedConnect);
    installHook(globals, "fetch", originalFetch, guardedFetch);
  } catch (error) {
    closed = true;
    try {
      restore();
    } catch (rollbackError) {
      throw new AggregateError(
        [error, rollbackError],
        "wire guard installation and rollback failed",
      );
    }
    throw error;
  }
  return Object.freeze({
    close() {
      if (closed) return;
      closed = true;
      restore();
    },
    snapshot() {
      return { closed, failures: { ...failures } };
    },
  });
};
