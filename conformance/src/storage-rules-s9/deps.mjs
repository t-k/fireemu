// Real dependencies of the Storage Rules observation: the network and the credentials. Kept apart
// from observe.mjs so the tests never touch a credential.

import { Buffer } from "node:buffer";

import { PROJECT, REQUEST_TIMEOUT_MS } from "./plan.mjs";

// The launch flag. Nothing in this recorder reaches a host outside loopback, and no credential is
// read, unless the real process environment holds FIREEMU_STORAGE_RULES_LAUNCH=<family>, which only
// the launch script exports. The flag is read from `process.env` every time a client is about to
// send or to read a credential: it is never cached, never armed by an option, and never taken from
// an object a caller passes. A test run, a mutation run or a stray import has no flag, so it cannot
// send even when the machine holds credentials (2026-11-11: a mutation pass of another lane reached
// production through a work copy).
export const LAUNCH_FLAG = "FIREEMU_STORAGE_RULES_LAUNCH";
export const LAUNCH_FAMILIES = ["s9", "case"];

/** Throws unless the process environment holds the flag, for `family` when one is named, else for any known family. */
export function requireLaunch(family) {
  const value = process.env[LAUNCH_FLAG];
  const ok =
    family === undefined
      ? LAUNCH_FAMILIES.includes(value)
      : LAUNCH_FAMILIES.includes(family) && value === family;
  if (!ok)
    throw new Error(
      `production sending needs ${LAUNCH_FLAG}${family === undefined ? "" : `=${family}`}`,
    );
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** fetch with no redirect following; status, lower-case headers and the exact body bytes. A host outside loopback needs the launch flag. */
export async function fetchNet({ method, url, headers, body, timeoutMs = REQUEST_TIMEOUT_MS }) {
  if (!LOOPBACK_HOSTS.has(new URL(url).hostname)) requireLaunch();
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
 * old); `accessToken` is the fixed token it replaces. The transport is always `fetchNet`, which
 * checks the launch flag itself.
 *
 * A GET whose transport fails does not mark the lease failed: a read leaves nothing behind that a
 * retained lock would protect, and the wire already records it as an unknown read. A failed write
 * still does.
 */
export function createProductionDeps({ accessToken, token = null, lease }) {
  return leasedDeps({ accessToken, token, lease, net: fetchNet });
}

/** The same deps over a transport the caller supplies: for rehearsals against a fake world only. */
export function createRehearsalDeps({ accessToken, token = null, lease, net }) {
  return leasedDeps({ accessToken, token, lease, net });
}

function leasedDeps({ accessToken, token, lease, net }) {
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
