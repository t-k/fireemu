// Real dependencies of the Storage Rules observation: the network and the credentials. Kept apart
// from observe.mjs so the tests never touch a credential.

import { Buffer } from "node:buffer";

import { PROJECT, REQUEST_TIMEOUT_MS } from "./plan.mjs";

// The launch flag. Nothing in this recorder reaches a host outside loopback, and no credential is
// read, until a launch has armed it: the launch script exports FIREEMU_STORAGE_RULES_LAUNCH=<family>
// and the three commands that send (record-production, readback, recover) call `armSending` with
// their own family. A test run, a mutation run or a stray import never has the flag, so it cannot
// send even when the machine holds credentials (2026-11-11: a mutation pass of another lane reached
// production through a work copy).
export const LAUNCH_FLAG = "FIREEMU_STORAGE_RULES_LAUNCH";
let armedFamily = null;

/** Arms production sending for one family; the flag must be exactly the family's id. */
export function armSending(env, family) {
  if (typeof family !== "string" || family === "" || env?.[LAUNCH_FLAG] !== family)
    throw new Error(`production sending needs ${LAUNCH_FLAG}=${family}`);
  armedFamily = family;
}

export const isArmed = () => armedFamily !== null;

/** Disarms (tests only). */
export function disarmSending() {
  armedFamily = null;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** fetch with no redirect following; status, lower-case headers and the exact body bytes. A host outside loopback needs the launch flag. */
export async function fetchNet({ method, url, headers, body, timeoutMs = REQUEST_TIMEOUT_MS }) {
  if (!LOOPBACK_HOSTS.has(new URL(url).hostname) && !isArmed())
    throw new Error(`refusing to send to ${new URL(url).hostname} without ${LAUNCH_FLAG}`);
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
