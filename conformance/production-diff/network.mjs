// Defense in depth for the pinned Node recorder, not an OS sandbox for arbitrary code.
import net from "node:net";
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { TextDecoder } from "node:util";
import { requireThat } from "./core.mjs";

export function localOrigin(host) {
  requireThat(/^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(host ?? ""), "owned-loopback-required");
  const port = Number(host.split(":")[1]);
  requireThat(port <= 65535, "invalid-port");
  return `http://${host}`;
}
export function assertUrl(value, origin) {
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new Error("invalid-network-url");
  }
  requireThat(
    u.origin === origin &&
      u.hostname === "127.0.0.1" &&
      u.protocol === "http:" &&
      !u.username &&
      !u.password &&
      !u.hash,
    "network-outside-owned-origin",
  );
  return u;
}

export function installNetworkGuard(origin = null) {
  const deny = () => {
    throw new Error("offline-operation-denied");
  };
  const connect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    let a = args;
    if (Array.isArray(a[0])) a = a[0];
    let options =
      typeof a[0] === "object" && a[0] !== null
        ? a[0]
        : { port: a[0], host: typeof a[1] === "string" ? a[1] : "localhost" };
    requireThat(
      origin &&
        !options.path &&
        options.host === "127.0.0.1" &&
        Number(options.port) === Number(new URL(origin).port),
      "network-outside-owned-origin",
    );
    return Reflect.apply(connect, this, args);
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (input, init = {}) => {
    requireThat(origin, "offline-operation-denied");
    assertUrl(typeof input === "string" || input instanceof URL ? input : input.url, origin);
    return realFetch(input, { ...init, redirect: "error" });
  };
  // No legacy path needs these APIs. fetch's undici connection is constrained above.
  for (const module of [http, https]) for (const key of ["request", "get"]) module[key] = deny;
  for (const key of ["lookup", "resolve", "resolve4", "resolve6", "lookupService", "reverse"]) {
    dns[key] = deny;
    if (dns.promises[key]) dns.promises[key] = deny;
  }
  for (const key of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"])
    childProcess[key] = deny;
  syncBuiltinESMExports();
  return globalThis.fetch;
}

export async function boundedText(response, maxBytes = 2 * 1024 * 1024, signal) {
  signal?.throwIfAborted();
  const chunks = [];
  let size = 0;
  if (response.body) {
    const reader = response.body.getReader();
    // Do not rely only on fetch's abort forwarding after headers have arrived. Cancel
    // the locked reader directly so even a continuously streaming body reaches EOF.
    // Cancellation of the underlying source need not finish before we report failure.
    const cancel = () => {
      void reader.cancel().catch(() => {});
    };
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      for (;;) {
        signal?.throwIfAborted();
        const { done, value } = await reader.read();
        signal?.throwIfAborted();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) {
          cancel();
          throw new Error("response-too-large");
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      signal?.removeEventListener("abort", cancel);
      reader.releaseLock();
    }
  }
  // Evidence must not silently turn malformed wire bytes into U+FFFD. Preserve a BOM
  // rather than removing it: callers still decide whether that text is valid JSON.
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
  } catch {
    throw new Error("response-invalid-utf8");
  }
}
