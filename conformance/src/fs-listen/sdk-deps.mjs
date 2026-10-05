// The effects of the Node SDK recording: the catalog adapter's dependencies (createDeps, which
// binds the real SDK) with the band and the transaction groups of sdk-deps-core.mjs applied.

import { createHash } from "node:crypto";

import { createDeps } from "../../../tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs";
import { inBand, queryConstraints, wrapDeps } from "./sdk-deps-core.mjs";

export { inBand, queryConstraints };

/** Ranks of one run: 1000 + 100 * (a million-way hash of the run id), so runs rarely overlap. */
export function bandOf(run) {
  const digest = createHash("sha256").update(String(run)).digest();
  return 1000 + (digest.readUInt32BE(0) % 1_000_000) * 100;
}

/**
 * Dependencies over the real SDK (`sdk`, the firebase modules) and `clients`
 * ({ name: { db, auth, app, account } }).
 */
export function makeDeps({ sdk, clients, base, revoke = null }) {
  return wrapDeps(createDeps(sdk, clients, { revoke }), { sdk, clients, base });
}
