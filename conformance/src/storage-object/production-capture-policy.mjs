import { createHash } from "node:crypto";
import {
  sanitizeStorageCaptureBody,
  parseCaptureJsonSpans,
  captureStringIsWellFormed,
} from "./production-capture-body.mjs";

const ORIGINS = new Set([
  "https://firebasestorage.googleapis.com",
  "https://storage.googleapis.com",
  "https://identitytoolkit.googleapis.com",
  "https://securetoken.googleapis.com",
  "https://oauth2.googleapis.com",
  "https://firebaserules.googleapis.com",
  "https://apikeys.googleapis.com",
  "https://cloudresourcemanager.googleapis.com",
]);
const CREDENTIAL_ORIGINS = new Set([
  "https://identitytoolkit.googleapis.com",
  "https://securetoken.googleapis.com",
  "https://oauth2.googleapis.com",
]);
const SECRET_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "location",
  "x-goog-upload-url",
  "x-goog-upload-control-url",
  "x-guploader-uploadid",
  "x-firebase-appcheck",
  "x-firebase-storage-download-tokens",
]);
const PUBLIC_HEADERS = new Set([
  "accept",
  "accept-encoding",
  "host",
  "connection",
  "date",
  "server",
  "content-type",
  "content-length",
  "content-range",
  "content-encoding",
  "content-disposition",
  "cache-control",
  "expires",
  "last-modified",
  "etag",
  "vary",
  "transfer-encoding",
  "range",
  "user-agent",
  "x-goog-user-project",
  "x-goog-hash",
  "x-goog-generation",
  "x-goog-metageneration",
  "x-goog-storage-class",
  "x-goog-stored-content-length",
  "x-goog-stored-content-encoding",
  "x-goog-upload-protocol",
  "x-goog-upload-command",
  "x-goog-upload-offset",
  "x-goog-upload-header-content-length",
  "x-goog-upload-header-content-type",
  "x-goog-upload-status",
  "x-goog-upload-size-received",
  "x-content-type-options",
]);
const SECRET_QUERY = new Set([
  "key",
  "access_token",
  "token",
  "upload_id",
  "pageToken",
  "rewriteToken",
]);
const PUBLIC_QUERY = new Set([
  "alt",
  "name",
  "prefix",
  "delimiter",
  "maxResults",
  "startOffset",
  "endOffset",
  "matchGlob",
  "includeTrailingDelimiter",
  "includeFoldersAsPrefixes",
  "projection",
  "uploadType",
  "ifGenerationMatch",
  "ifGenerationNotMatch",
  "ifMetagenerationMatch",
  "ifMetagenerationNotMatch",
  "ifSourceGenerationMatch",
  "ifSourceGenerationNotMatch",
  "ifSourceMetagenerationMatch",
  "ifSourceMetagenerationNotMatch",
  "sourceGeneration",
  "maxBytesRewrittenPerCall",
]);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const commitment = (value) => {
  const bytes = Buffer.isBuffer(value)
    ? value
    : Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return { byteLength: bytes.length, sha256: digest(bytes) };
};
const CREDENTIAL_FORM =
  /1\/\/|GOCSPX-|AMf-v|AIza[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:Bearer|Firebase) [A-Za-z0-9._~+/-]+/;

function strictPairs(encoded) {
  if (!encoded) return [];
  const seen = new Set();
  return encoded.split("&").map((pair) => {
    const split = pair.indexOf("=");
    const decode = (value) => decodeURIComponent(value.replace(/\+/g, " "));
    const key = decode(split < 0 ? pair : pair.slice(0, split));
    const value = decode(split < 0 ? "" : pair.slice(split + 1));
    if (
      !key ||
      seen.has(key) ||
      !captureStringIsWellFormed(key) ||
      !captureStringIsWellFormed(value)
    )
      throw new Error("invalid encoded pairs");
    seen.add(key);
    return [key, value];
  });
}

function typedSchema(url, direction) {
  if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token")
    return direction === "request"
      ? {
          form: true,
          fields: {
            grant_type: "refresh-grant",
            client_id: "string",
            client_secret: "string",
            refresh_token: "string",
          },
        }
      : {
          fields: {
            access_token: "string",
            id_token: "string",
            token_type: "bearer",
            expires_in: "number",
            scope: "string",
          },
        };
  if (url.origin === "https://securetoken.googleapis.com" && url.pathname === "/v1/token")
    return direction === "request"
      ? { form: true, fields: { grant_type: "refresh-grant", refresh_token: "string" } }
      : {
          fields: {
            access_token: "string",
            id_token: "string",
            refresh_token: "string",
            token_type: "bearer",
            expires_in: "digits",
            user_id: "string",
            project_id: "string",
          },
        };
  if (url.origin !== "https://identitytoolkit.googleapis.com") return null;
  if (["/v1/accounts:signUp", "/v1/accounts:signInWithPassword"].includes(url.pathname))
    return direction === "request"
      ? { fields: { email: "string", password: "string", returnSecureToken: "boolean" } }
      : {
          fields: {
            kind: "string",
            localId: "uid",
            email: "email",
            idToken: "string",
            refreshToken: "string",
            expiresIn: "digits",
          },
        };
  if (url.pathname === "/v1/accounts:lookup")
    return direction === "response"
      ? { fields: { kind: "string", users: "accounts" } }
      : {
          fields: {
            idToken: "string",
            localId: "strings",
            email: "strings",
            targetProjectId: "string",
          },
        };
  return null;
}

function typedObservation(body, headers, unsafe, { url, direction, expectedEmails }) {
  try {
    const schema = typedSchema(url, direction);
    if (!schema) return commitment(body);
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
    const contentTypes = headers
      .filter(([name]) => name.toLowerCase() === "content-type")
      .map(([, value]) => value);
    let value;
    if (schema.form) {
      if (contentTypes.length !== 1 || contentTypes[0] !== "application/x-www-form-urlencoded")
        return commitment(body);
      value = Object.fromEntries(strictPairs(text));
    } else {
      if (
        contentTypes.length > 1 ||
        (contentTypes.length &&
          ![
            "application/json",
            "application/json; charset=UTF-8",
            "application/json; charset=utf-8",
          ].includes(contentTypes[0]))
      )
        return commitment(body);
      parseCaptureJsonSpans(text);
      value = JSON.parse(text);
    }
    const accountFields = {
      localId: "uid",
      email: "email",
      emailVerified: "boolean",
      disabled: "boolean",
      validSince: "digits",
      createdAt: "digits",
      lastLoginAt: "digits",
    };
    const record = (node, fields) => {
      if (node === null || typeof node !== "object" || Array.isArray(node))
        throw new Error("unknown observation shape");
      if (
        Object.hasOwn(node, "localId") &&
        fields.localId === "uid" &&
        (!Object.hasOwn(node, "email") || !expectedEmails.includes(node.email))
      )
        throw new Error("unbound account identity");
      const result = Object.create(null);
      for (const [key, child] of Object.entries(node)) {
        if (!Object.hasOwn(fields, key)) throw new Error("unknown observation field");
        result[key] = project(child, fields[key]);
      }
      return result;
    };
    const project = (node, shape) => {
      if (shape === "accounts") {
        if (!Array.isArray(node)) throw new Error("unknown account array");
        return node.map((child) => record(child, accountFields));
      }
      if (shape === "strings") {
        if (!Array.isArray(node)) throw new Error("unknown string array");
        return node.map((child) => project(child, "string"));
      }
      if (shape === "boolean" && typeof node === "boolean") return node;
      if (shape === "number" && Number.isSafeInteger(node) && node >= 0 && node <= 86400)
        return node;
      if (typeof node !== "string" || !captureStringIsWellFormed(node))
        throw new Error("unknown observation leaf");
      if (shape === "string") return commitment(node);
      if (shape === "uid" && !unsafe(node) && /^[A-Za-z0-9_-]{1,128}$/.test(node)) return node;
      if (shape === "email" && !unsafe(node) && expectedEmails.includes(node)) return node;
      if (shape === "digits" && /^[0-9]{1,20}$/.test(node)) return commitment(node);
      if (shape === "bearer" && ["Bearer", "bearer"].includes(node)) return node;
      if (shape === "refresh-grant" && node === "refresh_token") return node;
      throw new Error("unknown observation value");
    };
    return record(value, schema.fields);
  } catch {
    return commitment(body);
  }
}

function rawPathAllowed(url, bucket, names) {
  if (url.origin === "https://oauth2.googleapis.com")
    return ["/token", "/tokeninfo"].includes(url.pathname);
  if (url.origin === "https://securetoken.googleapis.com") return url.pathname === "/v1/token";
  if (url.origin === "https://identitytoolkit.googleapis.com")
    return [
      "/v1/accounts:signUp",
      "/v1/accounts:signInWithPassword",
      "/v1/accounts:lookup",
      "/v1/accounts:delete",
    ].includes(url.pathname);
  if (typeof bucket !== "string" || !bucket || !Array.isArray(names)) return false;
  const roots =
    url.origin === "https://storage.googleapis.com"
      ? [`/storage/v1/b/${bucket}/o`, `/upload/storage/v1/b/${bucket}/o`]
      : url.origin === "https://firebasestorage.googleapis.com"
        ? [`/v0/b/${bucket}/o`]
        : [];
  for (const root of roots) {
    if (url.pathname === root) return true;
    if (
      url.pathname.startsWith(`${root}/`) &&
      names.includes(decodeURIComponent(url.pathname.slice(root.length + 1)))
    )
      return true;
  }
  return false;
}

function rawQueryValueAllowed(key, value, names) {
  if (key === "alt") return ["media", "json"].includes(value);
  if (key === "name") return names.includes(value);
  if (key === "prefix") return value.endsWith("/") && names.some((name) => name.startsWith(value));
  if (key === "uploadType") return ["media", "multipart", "resumable"].includes(value);
  return false;
}

function rawHeaderValueAllowed(key, value, { url, body, complete }) {
  if (key === "content-type")
    return [
      "application/json",
      "application/json; charset=UTF-8",
      "application/json; charset=utf-8",
      "application/octet-stream",
      "text/plain",
      "text/plain; charset=UTF-8",
      "text/plain; charset=utf-8",
      "application/x-www-form-urlencoded",
    ].includes(value);
  if (key === "content-length") return complete && value === String(body.length);
  if (key === "host") return value === url.host;
  if (key === "connection") return value === "close";
  if (key === "accept-encoding" || key === "content-encoding") return value === "identity";
  if (key === "accept")
    return ["*/*", "application/json", "application/octet-stream"].includes(value);
  return false;
}

/** This returns persistence copies only. Live validation must use the original in-memory bytes. */
export function sanitizeProductionCapture({
  url: value,
  direction,
  headers,
  body,
  complete,
  knownSecrets = [],
  approvedBodySha256 = [],
  expectedObjectNames = [],
  expectedBucket,
  expectedEmails = [],
  bodyKind = "json",
}) {
  try {
    if (
      typeof value !== "string" ||
      !captureStringIsWellFormed(value) ||
      !Array.isArray(expectedEmails) ||
      expectedEmails.some(
        (email) => typeof email !== "string" || !captureStringIsWellFormed(email),
      ) ||
      !["request", "response"].includes(direction) ||
      !Array.isArray(headers) ||
      headers.length > 256 ||
      headers.some(
        (pair) =>
          !Array.isArray(pair) ||
          pair.length !== 2 ||
          typeof pair[0] !== "string" ||
          typeof pair[1] !== "string" ||
          !captureStringIsWellFormed(pair[1]) ||
          !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(pair[0]) ||
          pair[1].length > 16384 ||
          /[\r\n]/.test(pair[1]),
      )
    )
      throw new Error("invalid capture shape");
    const url = new URL(value);
    if (!ORIGINS.has(url.origin) || url.username || url.password || url.hash)
      throw new Error("invalid capture origin");
    const captured = sanitizeStorageCaptureBody(body, {
      knownSecrets,
      approvedBodySha256,
      complete,
      expectedObjectNames,
      expectedBucket,
      bodyKind,
    });
    const forms = knownSecrets.flatMap((secret) => [
      secret,
      encodeURIComponent(secret),
      new URLSearchParams({ v: secret }).toString().slice(2),
      Buffer.from(secret).toString("base64"),
      JSON.stringify(secret).slice(1, -1),
    ]);
    const unsafe = (text) =>
      CREDENTIAL_FORM.test(text) || forms.some((secret) => text.includes(secret));
    let path = url.pathname;
    try {
      if (
        !rawPathAllowed(url, expectedBucket, expectedObjectNames) ||
        unsafe(decodeURIComponent(path))
      )
        path = commitment(path);
    } catch {
      path = commitment(path);
    }
    let query;
    try {
      query = strictPairs(url.search.slice(1)).map(([key, child]) => [
        PUBLIC_QUERY.has(key) || SECRET_QUERY.has(key) ? key : commitment(key),
        SECRET_QUERY.has(key) ||
        !PUBLIC_QUERY.has(key) ||
        unsafe(child) ||
        !rawQueryValueAllowed(key, child, expectedObjectNames)
          ? commitment(child)
          : child,
      ]);
    } catch {
      query = commitment(url.search);
    }
    const replacedHeaders = [];
    const savedHeaders = headers.map(([name, child], index) => {
      const key = name.toLowerCase();
      const known = PUBLIC_HEADERS.has(key) || SECRET_HEADERS.has(key);
      if (
        !known ||
        SECRET_HEADERS.has(key) ||
        unsafe(child) ||
        !rawHeaderValueAllowed(key, child, { url, body, complete })
      ) {
        replacedHeaders.push(
          known ? `/headers/${index}/${name}` : { index, name: commitment(name) },
        );
        return [known ? name : commitment(name), commitment(child)];
      }
      return [name, child];
    });
    const credentialExchange =
      CREDENTIAL_ORIGINS.has(url.origin) ||
      url.origin === "https://apikeys.googleapis.com" ||
      url.searchParams.has("key") ||
      url.searchParams.has("access_token");
    const mode = credentialExchange || !complete ? "COMMITMENT_ONLY" : captured.mode;
    return {
      ...captured,
      mode,
      body: mode === "COMMITMENT_ONLY" ? null : captured.body,
      url: { origin: url.origin, pathname: path, query, original: commitment(value) },
      headers: savedHeaders,
      replacedHeaders,
      observation:
        mode === "COMMITMENT_ONLY" && complete
          ? typedObservation(body, headers, unsafe, { url, direction, expectedEmails })
          : null,
    };
  } catch {
    throw new Error("invalid production capture");
  }
}
