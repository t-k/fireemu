// The daemon sets this marker only for strict-profile dispatches and removes caller-supplied copies.
// The runner removes it before the function sees the request. Only the SDK's first read is hidden,
// so the handler and its timers continue to see "true".
import { AsyncLocalStorage } from "node:async_hooks";

export const TASK_IDENTITY_HEADER = "x-fireemu-task-identity";
const scope = new AsyncLocalStorage();
const installed = new WeakSet();

export function takeTaskIdentityMarker(req) {
  const marker = req.headers?.[TASK_IDENTITY_HEADER];
  if (req.headers) delete req.headers[TASK_IDENTITY_HEADER];
  if (Array.isArray(req.rawHeaders)) {
    const kept = [];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      if (String(req.rawHeaders[i]).toLowerCase() !== TASK_IDENTITY_HEADER) {
        kept.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
      }
    }
    req.rawHeaders = kept;
  }
  return marker === "1";
}

export function runWithTaskAuth(run) {
  return scope.run({ hideNext: true }, run);
}

export function installTaskAuthEnvironment(target = process) {
  if (installed.has(target)) return;
  const real = target.env;
  target.env = new Proxy(real, {
    get: (env, prop) => {
      const store = scope.getStore();
      if (prop === "FUNCTIONS_EMULATOR" && store?.hideNext) {
        store.hideNext = false;
        return undefined;
      }
      return env[prop];
    },
    // Writes go to the real environment by plain assignment: the real `process.env` refuses a descriptor-based write.
    set: (env, prop, value) => {
      env[prop] = value;
      return true;
    },
    deleteProperty: (env, prop) => delete env[prop],
    defineProperty: (env, prop, descriptor) => {
      if ("value" in descriptor) env[prop] = descriptor.value;
      return true;
    },
  });
  installed.add(target);
}
