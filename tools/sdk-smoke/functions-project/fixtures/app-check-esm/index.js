import { onCall } from "firebase-functions/v2/https";

export const guarded = onCall({ enforceAppCheck: true }, () => ({ ok: true }));
export const replayProtected = onCall(
  { enforceAppCheck: true, consumeAppCheckToken: true },
  () => ({ ok: true }),
);

// Application code can discover the shared symbol. Attempts to downgrade an observation or
// replace the registry must not affect the manifest produced by the trusted runner.
const registrySymbol = Symbol.for("fireemu.callableAppCheck");
const registry = globalThis[registrySymbol];
registry.observe(guarded, { enforceAppCheck: false, consumeAppCheckToken: false });
try {
  globalThis[registrySymbol] = {
    observe() {},
    carry() {},
    moduleLoaded() {},
    moduleFailed() {},
  };
} catch {
  // A non-writable registry is the expected hardened implementation.
}
