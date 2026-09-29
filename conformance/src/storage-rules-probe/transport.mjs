// A copy of storage-rules/http-transport.mjs for stage 2d, narrowed to eight exact routes, each with its exact query string: the owner's token refresh
// and identity, and the six probe reads (the Rulesets list, the missing object's metadata and media, the two `:test` calls and the missing document).
// No origin is allowed as a whole, so a request outside these routes is refused before it is counted. Diff it against the original: the route table,
// the target check and the export name differ.
const RULES = "https://firebaserules.googleapis.com";
const GCS = "https://storage.googleapis.com";
const OBJECT_PATH = /^\/storage\/v1\/b\/[a-z0-9][a-z0-9._-]{2,221}\/o\/STORAGE-RULES%2Fprobe-2d%2Fabsent-object\.bin$/;
const EXACT_ROUTES = [
  { method: "POST", origin: "https://oauth2.googleapis.com", path: /^\/token$/, search: "" },
  { method: "GET", origin: "https://www.googleapis.com", path: /^\/oauth2\/v2\/userinfo$/, search: "" },
  { method: "GET", origin: RULES, path: /^\/v1\/projects\/fireemu-oracle-query\/rulesets$/, search: "?pageSize=100" },
  { method: "GET", origin: GCS, path: OBJECT_PATH, search: "" },
  { method: "GET", origin: GCS, path: OBJECT_PATH, search: "?alt=media" },
  { method: "POST", origin: RULES, path: /^\/v1\/projects\/fireemu-oracle-query:test$/, search: "" },
  { method: "GET", origin: "https://firestore.googleapis.com", path: /^\/v1\/projects\/fireemu-oracle-query\/databases\/\(default\)\/documents\/STORAGE-RULES\/probe-2d-absent-document$/, search: "" },
];
// An empty query (a bare `?`) is not the route without one: `url.search` is "" for both, so the text of the URL decides.
const exactRoute = (url, method) => EXACT_ROUTES.some((route) => route.method === method && route.origin === url.origin && route.search === url.search && (route.search !== "" || !url.href.includes("?")) && route.path.test(url.pathname));
export const ROUTE_COUNT = EXACT_ROUTES.length;
const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_HEADER_BYTES = 32 * 1024;
const TIMEOUT_MS = 30000;
const inputRefusal = () => Object.assign(new Error("invalid HTTP transport input"), { notSent: true });
const forbiddenHeaders = new Set(["host", "connection", "content-length", "transfer-encoding", "proxy-authorization", "proxy-connection", "upgrade", "expect", "accept-encoding"]);
const nativeLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "length").get;

function record(value, keys) {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("invalid HTTP transport input");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error("invalid HTTP transport input");
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error("invalid HTTP transport input");
  }
}

function copyBody(value) {
  if (value === null) return null;
  if (!Buffer.isBuffer(value) || Object.getPrototypeOf(value) !== Buffer.prototype) throw new Error("invalid HTTP transport input");
  const size = nativeLength.call(value);
  if (size > MAX_REQUEST_BYTES) throw new Error("invalid HTTP transport input");
  const keys = Reflect.ownKeys(value);
  if (keys.length !== size || keys.some((key, index) => key !== String(index))) throw new Error("invalid HTTP transport input");
  const body = Buffer.alloc(size);
  Uint8Array.prototype.set.call(body, value);
  return body;
}

function prepare(spec) {
  record(spec, ["url", "method", "headers", "body"]);
  const body = copyBody(spec.body);
  if (typeof spec.url !== "string" || spec.url.length > 16384 || !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(spec.method)) throw new Error("invalid HTTP transport input");
  let url;
  try { url = new URL(spec.url); } catch { throw new Error("invalid HTTP transport input"); }
  if (
    url.href !== spec.url || url.username || url.password || url.hash || url.protocol !== "https:" || url.port ||
    !exactRoute(url, spec.method) ||
    (body !== null && ["GET", "DELETE"].includes(spec.method))
  ) throw new Error("invalid HTTP transport input");
  if (!spec.headers || typeof spec.headers !== "object") throw new Error("invalid HTTP transport input");
  const keys = Reflect.ownKeys(spec.headers);
  record(spec.headers, keys);
  const headers = {};
  let headerBytes = 0;
  for (const key of keys) {
    const value = spec.headers[key];
    if (typeof key !== "string" || !/^[a-z0-9-]{1,64}$/.test(key) || forbiddenHeaders.has(key) || typeof value !== "string" || !/^[\x20-\x7e]*$/.test(value)) throw new Error("invalid HTTP transport input");
    headerBytes += key.length + value.length + 4;
    if (headerBytes > MAX_HEADER_BYTES) throw new Error("invalid HTTP transport input");
    headers[key] = value;
  }
  headers["accept-encoding"] = "identity";
  if (body !== null || ["POST", "PUT", "PATCH"].includes(spec.method)) headers["content-length"] = String(body?.length ?? 0);
  if (Object.entries(headers).reduce((total, [key, value]) => total + key.length + value.length + 4, 0) > MAX_HEADER_BYTES) throw new Error("invalid HTTP transport input");
  return { url, method: spec.method, headers, body };
}

/** One injected https.request attempt. Scope, credentials and counted admission belong to the caller. */
export function createProbeHttpsTransport(options) {
  record(options, ["requestImpl"]);
  const { requestImpl } = options;
  if (typeof requestImpl !== "function") throw new Error("invalid HTTP transport input");
  return Object.freeze({
    /** The transport's own input check, with nothing sent: a caller runs it before a request is counted. */
    validate(spec) {
      try { prepare(spec); } catch { throw inputRefusal(); }
    },
    async send(spec) {
      let prepared;
      try { prepared = prepare(spec); } catch { throw inputRefusal(); }
      const { url, method, headers, body } = prepared;
      const startedAtMs = Date.now();
      return new Promise((resolve, reject) => {
        let request;
        let response;
        let settled = false;
        let size = 0;
        const chunks = [];
        const timer = setTimeout(() => fail("HTTP transport timed out"), TIMEOUT_MS);

        function fail(message = "HTTP transport failed") {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          try { response?.destroy(); } catch {}
          try { request?.destroy(); } catch {}
          reject(new Error(message));
        }

        try {
          request = requestImpl(url, { method, headers, agent: false, rejectUnauthorized: true, maxHeaderSize: MAX_HEADER_BYTES }, (incoming) => {
            response = incoming;
            incoming.on("error", () => fail());
            incoming.once("aborted", () => fail());
            incoming.once("close", () => { if (!settled) fail(); });
            if (settled) { try { incoming.destroy(); } catch {} return; }
            const rawHeaders = incoming.rawHeaders;
            if (!Number.isInteger(incoming.statusCode) || incoming.statusCode < 100 || incoming.statusCode > 599 || !Array.isArray(rawHeaders) || rawHeaders.length % 2 || rawHeaders.some((value) => typeof value !== "string") || rawHeaders.reduce((total, value) => total + Buffer.byteLength(value) + 2, 0) > MAX_HEADER_BYTES) return fail();
            const capturedHeaders = Object.freeze([...rawHeaders]);
            incoming.on("data", (chunk) => {
              if (settled) return;
              if (!Buffer.isBuffer(chunk)) return fail();
              size += chunk.length;
              if (size > MAX_RESPONSE_BYTES) return fail("HTTP response exceeds bound");
              chunks.push(Buffer.from(chunk));
            });
            incoming.once("end", () => {
              if (settled) return;
              if (incoming.complete !== true) return fail();
              settled = true;
              clearTimeout(timer);
              resolve(Object.freeze({ status: incoming.statusCode, rawHeaders: capturedHeaders, bytes: Buffer.concat(chunks, size), startedAtMs, finishedAtMs: Date.now() }));
            });
          });
          request.on("error", () => fail());
          request.once("close", () => { if (!settled) fail(); });
          if (settled) { try { request.destroy(); } catch {} return; }
          request.end(body ?? undefined);
        } catch { fail(); }
      });
    },
  });
}
