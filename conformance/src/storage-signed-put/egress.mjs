import http from "node:http";
import https from "node:https";

/**
 * Throws on any outbound http/https request to a host outside `hosts`, after telling `onRefuse`. The SDKs open sockets
 * through these modules; fetch (used only by `fetchNet`, after the observer's own guard) does not.
 */
export function installEgressGuard(hosts, { onRefuse } = {}) {
  const allowed = new Set(hosts);
  for (const module of [http, https]) {
    for (const name of ["request", "get"]) {
      const original = module[name];
      module[name] = function guarded(first, ...rest) {
        const host =
          typeof first === "string" || first instanceof URL
            ? new URL(first).hostname
            : (first.hostname ?? first.host ?? "").replace(/:\d+$/, "");
        if (!allowed.has(host)) {
          onRefuse?.(host);
          throw new Error(`egress refused: ${host}`);
        }
        return original.call(this, first, ...rest);
      };
    }
  }
}
