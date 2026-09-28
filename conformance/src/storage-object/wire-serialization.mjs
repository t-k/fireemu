import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";
import { types } from "node:util";

const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteLength",
).get;

const FRAMING_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "accept-encoding",
  "upgrade",
  "expect",
  "trailer",
]);

export function loopbackHttpOrigin(value) {
  try {
    const url = new URL(value);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      throw new Error();
    return url.origin;
  } catch {
    throw new Error("invalid wire request origin");
  }
}

/** Deterministic HTTP/1.1 plaintext, with no implicit framing headers or unresolved body. */
export function serializeLocalHttpRequest(value, init, origins) {
  try {
    return serializeBoundedHttpRequest(value, init, origins.map(loopbackHttpOrigin));
  } catch {
    throw new Error("invalid wire request");
  }
}

/** Factories supply already validated bare origins to the shared plaintext framing implementation. */
export function serializeBoundedHttpRequest(value, init, allowed) {
  try {
    const url = new URL(value);
    const method = init.method ?? "GET";
    if (
      !allowed.includes(url.origin) ||
      url.username ||
      url.password ||
      url.hash ||
      !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method) ||
      !/^[\x21-\x7e]{1,8192}$/.test(url.pathname + url.search)
    )
      throw new Error();
    let body;
    if (init.body === undefined) body = Buffer.alloc(0);
    else if (typeof init.body === "string") {
      if (Buffer.byteLength(init.body) > MAX_RESPONSE_BODY_BYTES) throw new Error();
      body = Buffer.from(init.body);
    } else if (!types.isProxy(init.body) && Buffer.isBuffer(init.body)) {
      if (
        Object.getPrototypeOf(init.body) !== Buffer.prototype ||
        ["length", "byteLength", "byteOffset", "buffer"].some((key) =>
          Object.hasOwn(init.body, key),
        )
      )
        throw new Error();
      const length = typedArrayByteLength.call(init.body);
      if (length > MAX_RESPONSE_BODY_BYTES) throw new Error();
      body = Buffer.alloc(length);
      Uint8Array.prototype.set.call(body, init.body);
    } else throw new Error();
    const headers = [
      "Host",
      url.host,
      "Connection",
      "close",
      "Content-Length",
      String(body.length),
      "Accept-Encoding",
      "identity",
    ];
    const seen = new Set();
    if (
      init.headers !== undefined &&
      (init.headers === null || typeof init.headers !== "object" || Array.isArray(init.headers))
    )
      throw new Error();
    for (const [name, descriptor] of Object.entries(
      Object.getOwnPropertyDescriptors(init.headers ?? {}),
    )) {
      const key = name.toLowerCase();
      if (
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        !/^[!#$%&'*+.^_`|~A-Za-z0-9-]+$/.test(name) ||
        typeof descriptor.value !== "string" ||
        !/^[\x20-\x7e]*$/.test(descriptor.value) ||
        (FRAMING_HEADERS.has(key) &&
          !(key === "content-length" && descriptor.value === String(body.length))) ||
        seen.has(key)
      )
        throw new Error();
      seen.add(key);
      if (key === "content-length") continue;
      headers.push(name, descriptor.value);
    }
    let head = `${method} ${url.pathname}${url.search} HTTP/1.1\r\n`;
    for (let i = 0; i < headers.length; i += 2) head += `${headers[i]}: ${headers[i + 1]}\r\n`;
    head += "\r\n";
    if (Buffer.byteLength(head) > 16 * 1024) throw new Error();
    return { url, method, headers, body, wire: Buffer.concat([Buffer.from(head), body]) };
  } catch {
    throw new Error("invalid wire request");
  }
}
