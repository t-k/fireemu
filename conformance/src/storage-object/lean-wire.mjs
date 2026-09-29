// The wire of a lean STORAGE-OBJECT production run.
//
// The sender and the recipe replays run in their local mode, against placeholder loopback
// origins. This wire is where a request becomes a real one, so it alone decides the destination:
// a closed table of routes for one bucket, one run prefix and one project, nothing else. It swaps
// the real credentials in (the senders only ever hold placeholders), hashes secrets before a
// capture is written, spaces writes to one object, never follows a redirect, never retries, and
// halts on a capture failure or an oversize response.
//
// Every call counts as one attempt, sent or refused, because the request counter has already
// counted it. `realRequests` counts what actually went out, including the two reads behind the
// Rules answer.

import { createHash } from "node:crypto";

export const LEAN_PLACEHOLDER_ADMIN = "Bearer owner";
export const LEAN_PLACEHOLDER_API_KEY = "storage-object-local-key";

const REAL = Object.freeze({
  firebase: "https://firebasestorage.googleapis.com",
  gcs: "https://storage.googleapis.com",
  identity: "https://identitytoolkit.googleapis.com",
  token: "https://securetoken.googleapis.com",
});
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const BUCKET = /^[a-z0-9][a-z0-9._-]{2,220}[a-z0-9]$/;
const PROJECT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const PREFIX = /^storage-object\/[a-z0-9]{8,64}\/$/;
const API_KEY = /^[A-Za-z0-9_-]{20,}$/;
const SECRET_JSON_KEYS = new Set(["refreshToken", "refresh_token", "access_token"]);
const REWRITTEN_HEADERS = ["location", "x-goog-upload-url"];

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const hashed = (value) => `sha256:${sha256(value)}`;

function loopbackOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("invalid placeholder origin");
  }
  // `origin` drops any userinfo, path, query and fragment, so equality with the input also proves
  // there were none.
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.origin !== value
  )
    throw new Error("placeholder origins are bare loopback HTTP origins");
  return url.origin;
}

const hasDotSegment = (text) => /(^|\/)(\.|%2e){1,2}(?=\/|\?|#|$)/i.test(text);

function objectName(segment) {
  let decoded;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    throw new Error("route has an undecodable object name");
  }
  if (decoded.split("/").some((part) => part === "." || part === "..") || /[\0\r\n]/.test(decoded))
    throw new Error("route has an unsafe object name");
  return decoded;
}

/**
 * The real request for a sender request, or an error. `scope` is { bucket, projectId, prefix }.
 * Returns { real: URL, kind, mutation, name } where `name` is the object a write acts on.
 */
function storageRoute(url, method, scope) {
  const { bucket, prefix } = scope;
  const inRun = (name) => name.startsWith(prefix) && name.length > prefix.length;
  const segments = url.pathname.split("/");
  // segments[0] is empty: "/v0/b/<bucket>/o/<name>" -> ["", "v0", "b", bucket, "o", name]
  let host;
  let index;
  if (segments[1] === "v0" && segments[2] === "b") {
    host = REAL.firebase;
    index = 3;
  } else if (segments[1] === "storage" && segments[2] === "v1" && segments[3] === "b") {
    host = REAL.gcs;
    index = 4;
  } else if (
    segments[1] === "upload" &&
    segments[2] === "storage" &&
    segments[3] === "v1" &&
    segments[4] === "b"
  ) {
    host = REAL.gcs;
    index = 5;
  } else throw new Error("route is not a Storage route of this run");
  const upload = segments[1] === "upload";
  if (segments[index] !== bucket || segments[index + 1] !== "o")
    throw new Error("route names another bucket or resource");
  const rest = segments.slice(index + 2);
  const write = method !== "GET";
  const finish = (name, extra = {}) => ({
    real: new URL(`${host}${url.pathname}${url.search}`),
    kind: "storage",
    mutation: write,
    name,
    ...extra,
  });

  if (rest.length === 0) {
    // The collection: a list, an upload, or a resumable continuation.
    if (upload) {
      const name = url.searchParams.get("name");
      if (!["POST", "PUT"].includes(method) || name === null || !inRun(objectName(name)))
        throw new Error("upload needs an owned object name");
      return finish(objectName(name));
    }
    if (method === "GET") {
      if (!url.searchParams.get("prefix")?.startsWith(prefix))
        throw new Error("a list must stay inside the run prefix");
      return finish(undefined);
    }
    if (host === REAL.firebase && ["POST", "PUT"].includes(method)) {
      const name = url.searchParams.get("name");
      if (name === null || !inRun(objectName(name)))
        throw new Error("upload needs an owned object name");
      return finish(objectName(name));
    }
    throw new Error("method is not allowed on the collection");
  }
  if (upload) throw new Error("upload routes have no object path");
  const name = objectName(rest[0]);
  if (!inRun(name)) throw new Error("object is outside the run prefix");
  if (rest.length === 1) {
    if (!["GET", "PUT", "PATCH", "DELETE", "POST"].includes(method))
      throw new Error("method is not allowed on an object");
    if (method === "POST" && host === REAL.gcs) throw new Error("GCS object POST is not a route");
    return finish(name);
  }
  if (
    host === REAL.gcs &&
    method === "POST" &&
    rest.length === 5 &&
    ["copyTo", "rewriteTo"].includes(rest[1]) &&
    rest[2] === "b" &&
    rest[3] === bucket &&
    rest[4] === "o"
  )
    throw new Error("malformed copy route");
  if (
    host === REAL.gcs &&
    method === "POST" &&
    rest.length === 6 &&
    ["copyTo", "rewriteTo"].includes(rest[1]) &&
    rest[2] === "b" &&
    rest[3] === bucket &&
    rest[4] === "o"
  ) {
    const destination = objectName(rest[5]);
    if (!inRun(destination)) throw new Error("copy destination is outside the run prefix");
    return finish(destination);
  }
  throw new Error("route is not in the table");
}

function authRoute(url, method, scope) {
  if (method !== "POST" && method !== "GET") throw new Error("auth method is not allowed");
  const { pathname } = url;
  const identity = "/identitytoolkit.googleapis.com/v1/";
  const token = "/securetoken.googleapis.com/v1/";
  if (pathname.startsWith(identity)) {
    const rest = pathname.slice(identity.length);
    const account = /^accounts:(signUp|signInWithPassword|lookup|delete)$/;
    const project = new RegExp(`^projects/${scope.projectId}/accounts:(lookup|delete)$`);
    if (!account.test(rest) && !project.test(rest))
      throw new Error("auth route is not in the table");
    return {
      real: new URL(`${REAL.identity}/v1/${rest}${url.search}`),
      kind: "auth",
      mutation: false,
      name: undefined,
    };
  }
  if (pathname === `${token}token`)
    return {
      real: new URL(`${REAL.token}/v1/token${url.search}`),
      kind: "auth",
      mutation: false,
      name: undefined,
    };
  throw new Error("auth route is not in the table");
}

/** Hash the secret members of a JSON body; other bodies are kept as they are. */
function sanitizedJson(bytes) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    return bytes;
  }
  const walk = (node) => {
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object")
      return Object.fromEntries(
        Object.entries(node).map(([key, child]) => [
          key,
          SECRET_JSON_KEYS.has(key) && typeof child === "string" ? hashed(child) : walk(child),
        ]),
      );
    return node;
  };
  return Buffer.from(JSON.stringify(walk(value)));
}

function scrub(text, secrets) {
  let out = String(text);
  for (const secret of secrets) if (secret) out = out.split(secret).join(hashed(secret));
  return out;
}

/** Create the wire. See the file comment; every collaborator is supplied. */
export function createLeanWire({
  bucket,
  projectId,
  prefix,
  origins,
  adminToken,
  authApiKey,
  readRules,
  fetchImpl,
  capture,
  pacer,
  timeoutMs = 30_000,
} = {}) {
  if (
    typeof bucket !== "string" ||
    !BUCKET.test(bucket) ||
    typeof projectId !== "string" ||
    !PROJECT.test(projectId) ||
    typeof prefix !== "string" ||
    !PREFIX.test(prefix) ||
    typeof adminToken !== "function" ||
    typeof authApiKey !== "string" ||
    !API_KEY.test(authApiKey) ||
    typeof readRules !== "function" ||
    typeof fetchImpl !== "function" ||
    typeof capture !== "function" ||
    typeof pacer?.dispatch !== "function" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 60_000
  )
    throw new Error("invalid lean wire configuration");
  const placeholders = {
    storage: loopbackOrigin(origins?.storage),
    auth: loopbackOrigin(origins?.auth),
    control: loopbackOrigin(origins?.control),
  };
  if (new Set(Object.values(placeholders)).size !== 3)
    throw new Error("the three placeholder origins are distinct");
  const scope = Object.freeze({ bucket, projectId, prefix });

  let attempts = 0;
  let realRequests = 0;
  let active = false;
  let halted = false;
  let closed = false;

  const record = async (entry) => {
    try {
      await capture(entry);
    } catch {
      halted = true;
      throw new Error("LEAN_WIRE_CAPTURE_FAILED");
    }
  };

  function resolve(href, method) {
    if (
      hasDotSegment(
        String(href)
          .split("?")[0]
          .replace(/^[a-z]+:\/\/[^/]*/i, ""),
      )
    )
      throw new Error("route has a dot segment");
    const url = new URL(href);
    if (url.username || url.password || url.hash)
      throw new Error("route has credentials or a fragment");
    if (url.origin === placeholders.storage) return storageRoute(url, method, scope);
    if (url.origin === placeholders.auth) return authRoute(url, method, scope);
    if (url.origin === placeholders.control) {
      if (method === "GET" && url.pathname === "/v1/storage/rules" && !url.search)
        return { kind: "control", mutation: false, name: undefined };
      throw new Error("control route is not in the table");
    }
    throw new Error("origin is not a placeholder of this run");
  }

  async function requestHeaders(init) {
    const headers = new Headers(init.headers ?? {});
    const secrets = [];
    let admin = false;
    if (headers.get("authorization") === LEAN_PLACEHOLDER_ADMIN) {
      let token;
      try {
        token = await adminToken();
      } catch {
        // The provider's own message may quote what it failed to obtain.
        throw new Error("owner access token is unavailable");
      }
      if (typeof token !== "string" || !/^[^\s]{20,}$/.test(token))
        throw new Error("owner access token is unavailable");
      headers.set("authorization", `Bearer ${token}`);
      secrets.push(token);
      admin = true;
    }
    headers.delete("x-goog-user-project");
    if (admin) headers.set("x-goog-user-project", projectId);
    return { headers, secrets };
  }

  function realUrl(route, secrets) {
    const target = route.real;
    if (target.searchParams.get("key") === LEAN_PLACEHOLDER_API_KEY) {
      target.searchParams.set("key", authApiKey);
      secrets.push(authApiKey);
    }
    return target;
  }

  function capturedHeaders(headers, secrets) {
    const out = {};
    for (const [key, value] of headers.entries()) {
      out[key] =
        key === "authorization"
          ? value.replace(/^(\S+)\s+(.*)$/, (_, scheme, rest) => `${scheme} ${hashed(rest)}`)
          : scrub(value, secrets);
    }
    return out;
  }

  const giveBack = (headers) => {
    const out = new Headers(headers);
    for (const name of REWRITTEN_HEADERS) {
      const value = out.get(name);
      if (value === null) continue;
      out.set(
        name,
        value.replace(REAL.gcs, placeholders.storage).replace(REAL.firebase, placeholders.storage),
      );
    }
    return out;
  };

  async function send(route, init, sequence) {
    const { headers, secrets } = await requestHeaders(init);
    const target = realUrl(route, secrets);
    const body = init.body === undefined || init.body === null ? null : Buffer.from(init.body);
    const request = {
      method: init.method,
      url: scrub(target.href, secrets),
      headers: capturedHeaders(headers, secrets),
      bodyBytes: body?.length ?? 0,
      ...(body ? { bodySha256: sha256(body) } : {}),
    };
    const attempt = async () => {
      realRequests++;
      return fetchImpl(target.href, {
        method: init.method,
        headers,
        ...(body ? { body } : {}),
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
    };
    let response;
    let bytes;
    try {
      response =
        route.name === undefined || !route.mutation
          ? await attempt()
          : await pacer.dispatch(route.name, attempt);
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (error) {
      await record({
        sequence,
        at: new Date().toISOString(),
        request,
        error: scrub(error?.message ?? error, secrets),
      });
      throw error;
    }
    if (bytes.length > MAX_RESPONSE_BYTES) {
      halted = true;
      await record({
        sequence,
        at: new Date().toISOString(),
        request,
        error: "response over the cap",
      }).catch(() => {});
      throw new Error("LEAN_WIRE_RESPONSE_CAP_EXCEEDED");
    }
    const contentType = response.headers.get("content-type") ?? "";
    const kept = contentType.includes("json") ? sanitizedJson(bytes) : bytes;
    await record({
      sequence,
      at: new Date().toISOString(),
      request,
      response: {
        status: response.status,
        headers: Object.fromEntries(
          [...response.headers.entries()].map(([key, value]) => [key, scrub(value, secrets)]),
        ),
        bodyBase64: kept.toString("base64"),
        bodySha256: sha256(bytes),
        bodyBytes: bytes.length,
        ...(kept === bytes ? {} : { sanitized: true }),
      },
    });
    return new Response([204, 205, 304].includes(response.status) ? null : bytes, {
      status: response.status,
      statusText: response.statusText,
      headers: giveBack(response.headers),
    });
  }

  return {
    async fetch(href, init = {}) {
      attempts++;
      if (closed || halted) throw new Error("LEAN_WIRE_UNAVAILABLE");
      if (active) throw new Error("LEAN_WIRE_BUSY");
      active = true;
      try {
        const method = String(init.method ?? "GET").toUpperCase();
        const route = resolve(href, method);
        const sequence = attempts;
        if (route.kind === "control") {
          const rules = await readRules();
          realRequests += Number.isSafeInteger(rules?.requests) ? rules.requests : 0;
          if (typeof rules?.source !== "string") throw new Error("Rules read failed");
          return Response.json({ loaded: true, targeted: false, source: rules.source });
        }
        return await send(route, { ...init, method }, sequence);
      } finally {
        active = false;
      }
    },
    snapshot: () =>
      Object.freeze({
        attempts,
        realRequests,
        active: false,
        busy: active,
        halted,
        closed,
        readAfterHaltBytes: 0,
      }),
    async close() {
      closed = true;
    },
  };
}
