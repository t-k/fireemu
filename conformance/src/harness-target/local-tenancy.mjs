// Multi-tenancy on the local target, prepared from outside the recorded harness.
//
// The strict profile refuses tenant management while `multiTenant.allowTenants` is off, as
// production does. The recorded sessions switch it on only for the production target, and their
// files are bound to the recorded rows by the harness digest (../harness-registry.mjs), so the
// local switch is set here, by the local runner, before the corpus runs and undone after it. This
// file is not a digest input. It sends the requests the recorded session sends to production
// (a config read, the config update with the mask `multiTenant.allowTenants`, a read back) and
// nothing else, and only to a loopback origin of a local target.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { sourceTokens } from "../harness-registry.mjs";

/** What a run that switched multi-tenancy on and off reports, for the comparison's evidence. */
export const EXPECTED_ACTIONS = [
  "multiTenant.allowTenants false -> true (read back)",
  "multiTenant.allowTenants restored to false (read back)",
];

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const PROJECT_ID = /^[a-z0-9][a-z0-9-]*$/;

/** The digest of a helper source: its tokens, so a comment edit does not change it. */
export const setupDigestOf = (text) =>
  createHash("sha256")
    .update(JSON.stringify(sourceTokens(text)))
    .digest("hex");

/** Digest of this helper's tokens: it goes into the comparison's evidence beside the actions. */
export const localSetupDigest = () =>
  setupDigestOf(readFileSync(fileURLToPath(import.meta.url), "utf8"));

/** The auth emulator's origin, or a reason the setup refuses to send anything. */
function loopbackOrigin(ctx) {
  if (ctx?.target?.kind !== "local") throw new Error("only a local target is prepared here");
  if (typeof ctx.project !== "string" || !PROJECT_ID.test(ctx.project))
    throw new Error(`the project id ${JSON.stringify(ctx.project)} is not a plain project id`);
  const given = ctx.target.authOrigin;
  let url;
  try {
    url = new URL(given);
  } catch {
    throw new Error(`the auth origin ${JSON.stringify(given)} is not an origin`);
  }
  // The origin must be exactly what was given: no credentials, path, query or fragment.
  const plain =
    url.protocol === "http:" &&
    LOOPBACK_HOSTS.has(url.hostname) &&
    url.origin === String(given).replace(/\/$/, "");
  if (!plain) throw new Error(`the auth origin ${given} is not a loopback http origin`);
  return url.origin;
}

/**
 * Runs `run` with multi-tenancy on, and restores it afterwards whatever `run` does. Returns
 * `{ value, actions, digest }`: `actions` lists what was changed and read back (empty when it was
 * on already).
 */
export async function withLocalMultiTenancy(
  ctx,
  run,
  { fetchImpl = fetch, timeoutMs = 30_000 } = {},
) {
  const origin = loopbackOrigin(ctx);
  const config = `${origin}/identitytoolkit.googleapis.com/admin/v2/projects/${ctx.project}/config`;
  const call = async (method, allowTenants) => {
    const init = {
      method,
      headers: { authorization: "Bearer owner" },
      signal: AbortSignal.timeout(timeoutMs),
    };
    let url = config;
    if (method === "PATCH") {
      url = `${config}?updateMask=multiTenant.allowTenants`;
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify({ multiTenant: { allowTenants } });
    }
    const response = await fetchImpl(url, init);
    const json = await response.json().catch(() => null);
    if (response.status !== 200) throw new Error(`local config ${method}: HTTP ${response.status}`);
    return json;
  };
  const isOn = async () => (await call("GET"))?.multiTenant?.allowTenants === true;

  const actions = [];
  let changed = false;
  let value;
  let runError;
  try {
    if (!(await isOn())) {
      // Recorded before the change, so a failure after it still restores the flag.
      changed = true;
      await call("PATCH", true);
      if (!(await isOn())) throw new Error("multiTenant.allowTenants did not read back as enabled");
      actions.push(EXPECTED_ACTIONS[0]);
    }
    value = await run();
  } catch (error) {
    runError = error;
  }
  let restoreError;
  if (changed) {
    try {
      await call("PATCH", false);
      if (await isOn()) throw new Error("multiTenant.allowTenants did not read back as restored");
      actions.push(EXPECTED_ACTIONS[1]);
    } catch (error) {
      restoreError = error;
    }
  }
  if (runError && restoreError)
    throw new Error(`${runError.message}; and the restore failed: ${restoreError.message}`, {
      cause: runError,
    });
  if (runError) throw runError;
  if (restoreError) throw restoreError;
  return { value, actions, digest: localSetupDigest() };
}
