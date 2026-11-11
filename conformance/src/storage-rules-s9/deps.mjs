// Real dependencies of the Storage Rules observation: the network and the credentials. Kept apart
// from observe.mjs so the tests never touch a credential.

import { Buffer } from "node:buffer";

import { PROJECT, REQUEST_TIMEOUT_MS } from "./plan.mjs";

/** fetch with no redirect following; status, lower-case headers and the exact body bytes. */
export async function fetchNet({ method, url, headers, body, timeoutMs = REQUEST_TIMEOUT_MS }) {
  const init = { method, headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) };
  if (body !== undefined) init.body = body;
  const response = await fetch(url, init);
  const bytes = Buffer.from(await response.arrayBuffer());
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: bytes,
  };
}

const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Production: the owner's user ADC access token (read by the launch script, never by this
 * module's callers) with the quota project header, and the project lock lease around every request.
 * `token` is a function that returns the current token (it may mint a fresh one when the first is
 * old); `accessToken` is the fixed token it replaces. `net` is the transport (tests replace it).
 *
 * A GET whose transport fails does not mark the lease failed: a read leaves nothing behind that a
 * retained lock would protect, and the wire already records it as an unknown read. A failed write
 * still does.
 */
export function createProductionDeps({ accessToken, token = null, lease, net = fetchNet }) {
  return {
    adminHeaders: () => ({
      authorization: `Bearer ${token ? token() : accessToken}`,
      "x-goog-user-project": PROJECT,
    }),
    net: async (request) => {
      await lease.verifyHeld();
      if (request.method !== "GET") return lease.dispatch(() => net(request));
      let failure = null;
      const answer = await lease.dispatch(async () => {
        try {
          return await net(request);
        } catch (error) {
          failure = error;
          return null;
        }
      });
      if (failure !== null) throw failure;
      return answer;
    },
    now: () => Date.now(),
    sleep: realSleep,
  };
}

/** Local dry run against fireemu or the official emulator: the emulators' owner credential `owner`. */
export function createLocalDeps() {
  return {
    adminHeaders: () => ({ authorization: "Bearer owner" }),
    net: fetchNet,
    now: () => Date.now(),
    sleep: realSleep,
  };
}
