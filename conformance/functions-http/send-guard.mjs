// The production send guard. Every byte this directory's clients send to a real service leaves through the
// functions below, and every one of them checks the launch script's flag (FIREEMU_PRODUCTION_SEND=1) at the
// moment of sending: `guardedFetch` for fetch, `guardedRequest` and `guardedModules` for node:http(s), and the
// real Firebase CLI's spawn in production.mjs (`assertProductionSend`). A loopback URL is never refused.
//
// There is no allowance by object identity. A client takes a replacement transport only through an explicit
// parameter (`send`, `modules`), which replaces the egress entirely: the replacement is a test double that
// cannot send, and a replacement that is the real node:http(s) request is refused (`assertNotNativeRequest`).
// Nothing reads `globalThis.fetch` at send time, so replacing it changes nothing. `send-guard.test.mjs` also
// scans every production source of this directory for a direct network call outside this file.
//
// Why: on 2026-11-11 a mutation pass reached the real Identity Toolkit through a mutant that skipped the test
// double, created two sandbox users and appended 31 rows to the sandbox ledger.

import http from "node:http";
import https from "node:https";
import { realpathSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";

export const SEND_FLAG = "FIREEMU_PRODUCTION_SEND";
/** Set by the mutation harness: the one directory the private paths may be in while it runs. */
export const MUTATION_WORK = "FIREEMU_MUTATION_WORK";

/** Throws unless the launch script's flag is set (`env` is injectable so the positive path is testable). */
export function assertProductionSend(what, env = process.env) {
  if (env[SEND_FLAG] !== "1")
    throw new Error(`${what}: refused; ${SEND_FLAG}=1 is set by a launch script only`);
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

/** Whether a host name is this machine. */
export const isLoopbackHost = (hostname) => LOOPBACK.has(String(hostname ?? ""));

/** Whether a URL names this machine (a local fireemu or a test server). */
export function isLoopbackUrl(url) {
  try {
    return isLoopbackHost(new URL(String(url)).hostname);
  } catch {
    return false;
  }
}

const nativeFetch = globalThis.fetch;

/** `fetch`, refused for a non-loopback URL unless the flag is set. The one place this directory calls fetch. */
export async function guardedFetch(url, init) {
  if (!isLoopbackUrl(url)) assertProductionSend(`fetch ${new URL(String(url)).host}`);
  return nativeFetch(url, init);
}

/** `http(s).request`, refused for a non-loopback host unless the flag is set. */
export function guardedRequest(protocol, options, callback) {
  const host = options?.hostname ?? options?.host;
  if (!isLoopbackHost(host)) assertProductionSend(`request ${host}`);
  return (protocol === "https:" ? https : http).request(options, callback);
}

/** The modules a transport uses by default: the real agents, a request that checks the flag. */
export const guardedModules = Object.freeze({
  "https:": Object.freeze({
    Agent: https.Agent,
    request: (options, callback) => guardedRequest("https:", options, callback),
  }),
  "http:": Object.freeze({
    Agent: http.Agent,
    request: (options, callback) => guardedRequest("http:", options, callback),
  }),
});

/** A replacement for the modules must not be the real request function: that would send without the check. */
export function assertNotNativeRequest(modules) {
  for (const [protocol, module] of Object.entries(modules)) {
    if (module?.request === http.request || module?.request === https.request)
      throw new Error(
        `${protocol} modules: the real node:http(s) request is refused as a replacement`,
      );
    if (typeof module?.request !== "function" || typeof module?.Agent !== "function")
      throw new Error(`${protocol} modules need an Agent and a request`);
  }
}

/**
 * While the mutation harness runs (FIREEMU_MUTATION_WORK set), a private path must be inside the work copy.
 * The root of the work copy is the one place a mutant can find (an empty directory).
 */
export function assertPrivatePathAllowed(path, env = process.env) {
  const work = env[MUTATION_WORK];
  if (!work) return;
  // The real path of the nearest existing ancestor, with the rest appended: a file that does not exist yet
  // (a private file a mutant looks for) under a symlinked directory is still judged by where it would be.
  const real = (value) => {
    const absolute = resolve(value);
    for (let current = absolute, rest = ""; ;) {
      try {
        return resolve(realpathSync(current), rest);
      } catch {
        const parent = dirname(current);
        if (parent === current) return absolute;
        rest = join(basename(current), rest);
        current = parent;
      }
    }
  };
  const root = real(work);
  const target = real(String(path));
  if (target !== root && !target.startsWith(`${root}${sep}`))
    throw new Error(
      "a private path outside the mutation work copy is refused while the harness runs",
    );
}
