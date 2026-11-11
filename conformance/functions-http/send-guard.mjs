// The production send guard. Every client of this directory that can reach a real service (the REST control,
// the ADC refresh, the Auth sign-up, the Firebase CLI, the invocation transport, the default `fetch`) goes
// through it and refuses unless the launch script set FIREEMU_PRODUCTION_SEND=1. No test sets it: a test
// that needs a client replaces `fetch` (or the module) with its own, and a loopback URL is never refused.
//
// Why: on 2026-11-11 a mutation pass reached the real Identity Toolkit through a mutant that skipped the test
// double, created two sandbox users and appended 31 rows to the sandbox ledger. A mutant (or a test) must not
// be able to reach production by falling back to the real client.

export const SEND_FLAG = "FIREEMU_PRODUCTION_SEND";

/** Throws unless the launch script's flag is set (`env` is injectable so the positive path is testable). */
export function assertProductionSend(what, env = process.env) {
  if (env[SEND_FLAG] !== "1")
    throw new Error(`${what}: refused; ${SEND_FLAG}=1 is set by a launch script only`);
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

/** Whether a URL names this machine (a local fireemu or a test server). */
export function isLoopbackUrl(url) {
  try {
    return LOOPBACK.has(new URL(String(url)).hostname);
  } catch {
    return false;
  }
}

const nativeFetch = globalThis.fetch;

/**
 * `fetch`, refused for a non-loopback URL unless the flag is set. A `fetch` a test replaced on `globalThis`
 * after this module loaded is used as it is: it cannot reach a network.
 */
export async function guardedFetch(url, init) {
  const current = globalThis.fetch;
  if (current === nativeFetch && !isLoopbackUrl(url)) {
    assertProductionSend(`fetch ${new URL(String(url)).host}`);
  }
  return current(url, init);
}
