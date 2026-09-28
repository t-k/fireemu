// The network guard of an SDK driver process (AUTH-FS-CROSS stage 2): only the allowed hosts are
// reached, every request counts against a cap, and each request is recorded with its host, path
// and the SHA-256 of its bearer, so a row can say which principal's token a write or a commit
// carried without the token ever being stored.

import { createHash } from "node:crypto";
import http2 from "node:http2";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The Google hosts a production driver may reach. */
export const PRODUCTION_HOSTS = [
  "firestore.googleapis.com",
  "identitytoolkit.googleapis.com",
  "securetoken.googleapis.com",
];

/** The bearer of an authorization value, hashed (`null`: none). */
export const bearerHash = (value) => {
  const text = Array.isArray(value) ? value[0] : value;
  if (typeof text !== "string" || !text) return null;
  const match = /^Bearer (.+)$/i.exec(text);
  return match ? sha256(match[1]) : sha256(text);
};

/**
 * A request ledger: `admit(host, path, authorization)` refuses a host outside `hosts` or a request
 * past `cap`, and records the rest. The first refusal closes the ledger: every later request and
 * connection is refused at once, and `onRefuse` hears only that first one (host, path and reason,
 * never the bearer). An SDK retries a refused request immediately, so a ledger that stayed open
 * would let it open connections without end.
 */
export function createWireLedger({ hosts, cap, onRecord = () => {}, onRefuse = () => {} }) {
  const allowed = new Set(hosts);
  const records = [];
  let closed = false;
  const refuse = (host, path, reason) => {
    if (!closed) {
      closed = true;
      onRefuse({ host, path, reason });
    }
    throw new Error(`wire: ${reason}`);
  };
  return {
    records,
    closed: () => closed,
    /** Refuses a new connection once the ledger is closed. */
    connect(host) {
      if (closed) refuse(host, "", "the client is closed after a refused request");
    },
    admit(host, path, authorization) {
      if (closed) refuse(host, path, "the client is closed after a refused request");
      if (!allowed.has(host)) refuse(host, path, `${host} is not an allowed host`);
      if (records.length >= cap) refuse(host, path, `request cap ${cap} reached`);
      const record = { n: records.length + 1, host, path, bearer: bearerHash(authorization) };
      records.push(record);
      onRecord(record);
      return record;
    },
  };
}

const hostOf = (authority) => new URL(`https://${authority.replace(/^https?:\/\//, "")}`).hostname;

/**
 * Routes `fetch` and every HTTP/2 session through `ledger` for the life of the process. Returns a
 * function that restores both. A refused request throws before anything is sent.
 */
export function installWireGuard(ledger, { fetchImpl = globalThis.fetch } = {}) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const requestHeaders = input instanceof Request ? input.headers : undefined;
    const headers = new Headers(init.headers ?? requestHeaders ?? {});
    ledger.admit(url.hostname, url.pathname, headers.get("authorization"));
    return fetchImpl(input, init);
  };
  const originalConnect = http2.connect;
  http2.connect = function connect(authority, ...rest) {
    const host = hostOf(String(authority));
    // No connection is opened for a client whose ledger is closed.
    ledger.connect(host);
    const session = originalConnect.call(this, authority, ...rest);
    const request = session.request.bind(session);
    session.request = (headers = {}, options) => {
      ledger.admit(host, headers[":path"] ?? "", headers.authorization);
      return request(headers, options);
    };
    return session;
  };
  return () => {
    globalThis.fetch = originalFetch;
    http2.connect = originalConnect;
  };
}
