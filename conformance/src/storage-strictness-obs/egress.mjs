import http from "node:http";
import https from "node:https";
import { classifyRequest, GuardError } from "./guard.mjs";

// No SDK or alternate HTTP path is allowed. The captured fetch is reachable only after classification.
export function installEgressGuard() {
  const saved = [];
  const refuse = () => {
    throw new GuardError("unguarded network request refused");
  };
  for (const module of [http, https])
    for (const key of ["request", "get"]) {
      saved.push([module, key, module[key]]);
      module[key] = refuse;
    }
  saved.push([globalThis, "fetch", globalThis.fetch]);
  globalThis.fetch = refuse;
  return () => {
    for (const [object, key, value] of saved) object[key] = value;
  };
}

export function fetchNet(target, fetchImpl = globalThis.fetch) {
  return async (request, { signal, location }) => {
    classifyRequest(target, request, location);
    const response = await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "manual",
      signal,
    });
    // Reading the body is inside the same timeout as receiving the headers.
    const headers = Object.fromEntries(response.headers.entries());
    try {
      return { status: response.status, headers, body: Buffer.from(await response.arrayBuffer()) };
    } catch {
      return { status: response.status, headers, body: null };
    }
  };
}
