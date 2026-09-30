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

/** A path segment names an object once: decode it once, and never again. */
function decodeSegment(segment) {
  try {
    return decodeURIComponent(segment);
  } catch {
    throw new Error("route has an undecodable object name");
  }
}

/**
 * The checks a decoded object name must pass. A line feed is allowed: `errors/object-name` sends
 * one on purpose, and the prefix rule already keeps it inside the run's own names.
 */
function checkName(name) {
  if (name.split("/").some((part) => part === "." || part === "..") || name.includes("\0"))
    throw new Error("route has an unsafe object name");
  return name;
}

const pathName = (segment) => checkName(decodeSegment(segment));

/** `URLSearchParams` has decoded the value once; it is the name as it is, so it is not decoded again. */
function queryName(url) {
  const values = url.searchParams.getAll("name");
  if (values.length !== 1) throw new Error("route needs exactly one object name");
  return checkName(values[0]);
}

/** Query parameters that change which resource or which project a request acts on. */
function checkQuery(url) {
  for (const key of url.searchParams.keys()) {
    if (key.toLowerCase() === "userproject") throw new Error("route names a billing project");
  }
  if (url.searchParams.getAll("prefix").length > 1)
    throw new Error("route has more than one prefix");
}

/**
 * The real request for a sender request, or an error. `scope` is { bucket, projectId, prefix }.
 * Returns { real: URL, kind, mutation, name } where `name` is the object a write acts on.
 */
function storageRoute(url, method, scope) {
  const { bucket, prefix } = scope;
  checkQuery(url);
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
      // POST starts an upload, PUT continues or probes a resumable session, DELETE cancels one.
      const allowed =
        method === "DELETE" ? url.searchParams.has("upload_id") : ["POST", "PUT"].includes(method);
      const name = queryName(url);
      if (!allowed || !inRun(name)) throw new Error("upload needs an owned object name");
      return finish(name);
    }
    if (method === "GET") {
      if (!url.searchParams.get("prefix")?.startsWith(prefix))
        throw new Error("a list must stay inside the run prefix");
      return finish(undefined);
    }
    if (host === REAL.firebase && ["POST", "PUT"].includes(method)) {
      const name = queryName(url);
      if (!inRun(name)) throw new Error("upload needs an owned object name");
      return finish(name);
    }
    throw new Error("method is not allowed on the collection");
  }
  if (upload) throw new Error("upload routes have no object path");
  const name = pathName(rest[0]);
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
    const destination = pathName(rest[5]);
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

function sanitizedBase64(text, secrets) {
  const bytes = Buffer.from(text, "base64");
  // Text that is not canonical base64 is not a body; scrub it as text.
  if (bytes.toString("base64") !== text) return scrub(text, secrets);
  let kept = sanitizedJson(bytes);
  if (secrets.some((secret) => secret && kept.includes(secret)))
    kept = Buffer.from(scrub(kept.toString("utf8"), secrets));
  return kept.toString("base64");
}

/**
 * A copy of a record with the secrets taken out: secret JSON members hashed, known secrets
 * scrubbed from every string, and the base64 body of a response treated the same way. What a
 * record holds is written to disk, so every record goes through this before it is.
 */
export function sanitizeRecord(value, secrets = []) {
  const walk = (node) => {
    if (typeof node === "string") return scrub(node, secrets);
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      return Object.fromEntries(
        Object.entries(node).map(([key, child]) => [
          key,
          SECRET_JSON_KEYS.has(key) && typeof child === "string"
            ? hashed(child)
            : key.toLowerCase().endsWith("base64") && typeof child === "string"
              ? sanitizedBase64(child, secrets)
              : walk(child),
        ]),
      );
    }
    return node;
  };
  return walk(value);
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
  // What a caller must not go on after: transports that failed, and throttled (429) or failed (5xx)
  // answers. A recipe that fails without either may be followed by the next recipe.
  let transportFailures = 0;
  let throttled = 0;
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
      if (typeof token !== "string" || !/^[A-Za-z0-9._~+/=-]{20,}$/.test(token))
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
      // Only a value that starts with a real host is one of ours; a look-alike inside a longer
      // URL is left alone.
      const real = [REAL.gcs, REAL.firebase].find((host) => value.startsWith(host));
      if (real !== undefined) out.set(name, `${placeholders.storage}${value.slice(real.length)}`);
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
      transportFailures++;
      await record({
        sequence,
        at: new Date().toISOString(),
        request,
        error: scrub(error?.message ?? error, secrets),
      });
      throw error;
    }
    if (response.status === 429 || response.status >= 500) throttled++;
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
    const textual = /json|text|xml|urlencoded/i.test(contentType);
    const holdsSecret = secrets.some((secret) => secret && bytes.includes(secret));
    if (holdsSecret && !textual) {
      // A secret inside bytes that are not text cannot be taken out of them: stop.
      halted = true;
      await record({
        sequence,
        at: new Date().toISOString(),
        request,
        error: "response holds a known secret",
      }).catch(() => {});
      throw new Error("LEAN_WIRE_SECRET_IN_RESPONSE");
    }
    let kept = bytes;
    if (contentType.includes("json")) kept = sanitizedJson(kept);
    if (holdsSecret) kept = Buffer.from(scrub(kept.toString("utf8"), secrets));
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
        let route;
        try {
          route = resolve(href, method);
        } catch (error) {
          // Nothing was sent: the route table refused this request. A caller that may go on after
          // a refusal (and only after one) tells it from any other failure by this mark.
          error.routeRefused = true;
          throw error;
        }
        const sequence = attempts;
        if (route.kind === "control") {
          // Each real request is counted where it is made, so a read that fails is counted too.
          const rules = await readRules({
            countRequest: () => {
              realRequests++;
            },
          });
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
        transportFailures,
        throttled,
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
