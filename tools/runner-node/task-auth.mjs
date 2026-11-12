// The identity token Cloud Tasks delivers to a task queue function, and the `request.auth` the SDK builds from it.
//
// firebase-functions builds a task's `auth` only when `process.env.FUNCTIONS_EMULATOR` is unset (common/providers/tasks.js),
// and the runner sets it for the whole process because the rest of the SDK needs it. So that a handler sees `request.auth` as in
// production, the runner hides that one variable from a task dispatch that carries the emulator's identity token, and only
// from the code that dispatch runs (an AsyncLocalStorage scope), never from another function sharing the process.
import { AsyncLocalStorage } from "node:async_hooks";

const HIDDEN = "FUNCTIONS_EMULATOR";
const scope = new AsyncLocalStorage();
const installed = new WeakSet();

/** Whether the request has `Authorization: Bearer` and a token of three dot-separated segments. */
export function hasTaskIdentityToken(headers) {
  const value = headers?.authorization;
  if (typeof value !== "string") return false;
  const match = /^Bearer ([^\s.]+\.[^\s.]+\.[^\s.]*)$/.exec(value);
  return match !== null;
}

/** Whether the current execution is inside a task dispatch that carries the identity token. */
export function inTaskAuthScope() {
  return scope.getStore()?.taskAuth === true;
}

/** Runs `run` with `FUNCTIONS_EMULATOR` hidden from `process.env` for it and everything it awaits. */
export function runWithTaskAuth(run) {
  return scope.run({ taskAuth: true }, run);
}

/**
 * Replaces `target.env` with a view that hides `FUNCTIONS_EMULATOR` inside a task auth scope and is the real
 * environment everywhere else (reads, writes, deletes and enumeration all go to it).
 */
export function installTaskAuthEnvironment(target = process) {
  if (installed.has(target)) return;
  const real = target.env;
  const hidden = (prop) => prop === HIDDEN && inTaskAuthScope();
  target.env = new Proxy(real, {
    get: (env, prop) => (hidden(prop) ? undefined : env[prop]),
    has: (env, prop) => !hidden(prop) && prop in env,
    getOwnPropertyDescriptor: (env, prop) =>
      hidden(prop) ? undefined : Reflect.getOwnPropertyDescriptor(env, prop),
    ownKeys: (env) => Reflect.ownKeys(env).filter((key) => !hidden(key)),
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
