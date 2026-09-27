// Installs the SDK driver's wire guard before any Firebase module is evaluated: the SDK may take
// `fetch` and `http2.connect` when its module loads, so this module is imported first.

import { createHash } from "node:crypto";

import { createWireLedger, installWireGuard, PRODUCTION_HOSTS } from "./sdk-wire.mjs";

const started = Date.now();
export const emit = (event) =>
  process.stdout.write(`${JSON.stringify({ t: Date.now() - started, ...event })}\n`);
export const sha256 = (text) => createHash("sha256").update(text).digest("hex");
export const config = JSON.parse(process.env.AFC_SDK_CONFIG ?? "{}");
export const local = config.mode === "local";
/** Which uid each ID token (by hash) belonged to, as the SDK obtained them. */
export const tokenOwner = new Map();

installWireGuard(
  createWireLedger({
    hosts: local ? ["127.0.0.1", "localhost"] : PRODUCTION_HOSTS,
    cap: config.wireCap ?? 400,
    onRecord: ({ n, host, path, bearer }) =>
      emit({
        event: "wire",
        n,
        host,
        path,
        principal: bearer === null ? null : (tokenOwner.get(bearer) ?? "unknown"),
      }),
    // A refused request marks the rows of this client as the harness's limit, not behavior.
    onRefuse: ({ host, path, reason }) => emit({ event: "wire-refused", host, path, reason }),
  }),
);
