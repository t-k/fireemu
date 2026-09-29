import { types } from "node:util";
import {
  isProductionSecretRegistry,
  registerProductionSecretBatch,
} from "./production-secret-registry.mjs";
import { parseCaptureJsonSpans } from "./production-capture-body.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

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
const SECRET_FIELDS = new Set([
  "downloadTokens",
  "firebaseStorageDownloadTokens",
  "nextPageToken",
  "rewriteToken",
  "upload_id",
  "uploadId",
  "delete_token",
  "deleteToken",
  "access_token",
  "accessToken",
  "id_token",
  "idToken",
  "refresh_token",
  "refreshToken",
  "password",
  "passwordHash",
  "rawPassword",
  "salt",
  "signerKey",
  "saltSeparator",
  "username",
  "client_secret",
  "clientSecret",
  "private_key",
  "privateKey",
  "keyString",
  "apiKey",
  "oauthAccessToken",
  "oauthIdToken",
  "temporaryProof",
  "pendingToken",
  "sessionInfo",
  "mfaPendingCredential",
]);
const SECRET_QUERY = new Set([
  "key",
  "access_token",
  "token",
  "delete_token",
  "upload_id",
  "pageToken",
  "rewriteToken",
]);
const URI_FIELDS = new Set(["sessionUri", "sessionURI", "sessionUrl", "uploadUrl"]);
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
const URI_HEADERS = new Set(["location", "x-goog-upload-url", "x-goog-upload-control-url"]);
const CSV_FIELDS = new Set(["downloadTokens", "firebaseStorageDownloadTokens"]);
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteLength",
).get;
const unavailable = () => new Error("SECRET_DISCOVERY_UNAVAILABLE");

function plainRecord(value, keys) {
  if (!value || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype)
    throw unavailable();
  if (Reflect.ownKeys(value).length !== keys.length) throw unavailable();
  return Object.fromEntries(
    keys.map((key) => {
      const d = Object.getOwnPropertyDescriptor(value, key);
      if (!d?.enumerable || !Object.hasOwn(d, "value")) throw unavailable();
      return [key, d.value];
    }),
  );
}
function arrayCopy(value, maximum) {
  if (
    types.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw unavailable();
  return Array.from({ length: value.length }, (_, index) => {
    const d = Object.getOwnPropertyDescriptor(value, String(index));
    if (!d?.enumerable || !Object.hasOwn(d, "value")) throw unavailable();
    return d.value;
  });
}
function strictPairs(text) {
  if (!text) return [];
  const seen = new Set();
  return text.split("&").map((pair) => {
    const offset = pair.indexOf("="),
      decode = (value) => decodeURIComponent(value.replaceAll("+", " "));
    const key = decode(offset < 0 ? pair : pair.slice(0, offset)),
      value = decode(offset < 0 ? "" : pair.slice(offset + 1));
    if (!key || seen.has(key) || !key.isWellFormed() || !value.isWellFormed()) throw unavailable();
    seen.add(key);
    return [key, value];
  });
}

/** Discovery never approves a schema or exposes values; projection must follow it before any writer. */
export function discoverProductionCaptureSecrets(registry, supplied) {
  if (!isProductionSecretRegistry(registry)) throw new Error("invalid task secret registry");
  try {
    // Validate original identity/readiness before invoking any capture property or parsing bytes.
    registry.openScan();
    const input = plainRecord(supplied, [
      "url",
      "direction",
      "headers",
      "body",
      "complete",
      "bodyKind",
    ]);
    if (
      typeof input.url !== "string" ||
      !input.url.isWellFormed() ||
      input.url.length > 32768 ||
      !["request", "response"].includes(input.direction) ||
      input.complete !== true ||
      !["json", "media"].includes(input.bodyKind)
    )
      throw unavailable();
    const url = new URL(input.url);
    if (!ORIGINS.has(url.origin) || url.username || url.password || url.hash) throw unavailable();
    const headers = arrayCopy(input.headers, 256).map((pair) => {
      const copy = arrayCopy(pair, 2);
      if (
        copy.length !== 2 ||
        typeof copy[0] !== "string" ||
        typeof copy[1] !== "string" ||
        !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(copy[0]) ||
        !copy[1].isWellFormed() ||
        copy[1].length > 16384 ||
        /[\r\n]/.test(copy[1])
      )
        throw unavailable();
      return copy;
    });
    if (
      types.isProxy(input.body) ||
      !Buffer.isBuffer(input.body) ||
      Object.getPrototypeOf(input.body) !== Buffer.prototype
    )
      throw unavailable();
    const length = byteLength.call(input.body);
    if (length > MAX_RESPONSE_BODY_BYTES) throw unavailable();
    const body = Buffer.alloc(length);
    Uint8Array.prototype.set.call(body, input.body);
    const values = new Set();
    function learn(value) {
      if (typeof value !== "string" || value.length > 8192 || !value.isWellFormed())
        throw unavailable();
      if (!value || values.has(value)) return;
      if (values.size >= 64) throw unavailable();
      values.add(value);
    }
    function csv(value) {
      learn(value);
      for (const part of value.split(",")) {
        learn(part);
        learn(part.trim());
      }
    }
    function encodedKey(value) {
      learn(value);
      const bytes = Buffer.from(value, "base64"),
        standard = bytes.toString("base64"),
        encodedUrl = bytes.toString("base64url");
      const forms = [
        standard,
        standard.replace(/=+$/, ""),
        encodedUrl,
        encodedUrl + "=".repeat((4 - (encodedUrl.length % 4)) % 4),
      ];
      if (!forms.includes(value)) throw unavailable();
      for (const form of forms) learn(form);
      let decoded;
      try {
        decoded = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        return;
      }
      learn(decoded);
    }
    function uri(value) {
      learn(value);
      const parsed = new URL(value);
      for (const [key, child] of strictPairs(parsed.search.slice(1)))
        if (SECRET_QUERY.has(key)) learn(child);
    }
    for (const [key, value] of strictPairs(url.search.slice(1)))
      if (SECRET_QUERY.has(key)) learn(value);
    for (const [name, value] of headers) {
      const key = name.toLowerCase();
      if (!SECRET_HEADERS.has(key)) continue;
      learn(value);
      if (["authorization", "proxy-authorization"].includes(key)) {
        const token = /^(?:Bearer|Firebase) +([\x21-\x7e]+)$/i.exec(value)?.[1];
        if (!token) throw unavailable();
        learn(token);
      }
      if (URI_HEADERS.has(key)) uri(value);
      if (key === "x-firebase-storage-download-tokens") csv(value);
      if (["cookie", "set-cookie"].includes(key)) {
        const cookies = key === "cookie" ? value.split(";") : [value.split(";")[0]];
        for (const cookie of cookies) {
          const offset = cookie.indexOf("=");
          if (offset < 1) throw unavailable();
          learn(cookie.slice(offset + 1).trim());
        }
      }
    }
    let bodyForm = "EMPTY";
    if (body.length && input.bodyKind === "media") bodyForm = "OPAQUE";
    else if (body.length) {
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
      const form =
        input.direction === "request" &&
        ((url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token") ||
          (url.origin === "https://securetoken.googleapis.com" && url.pathname === "/v1/token"));
      if (form) {
        const contentTypes = headers
          .filter(([key]) => key.toLowerCase() === "content-type")
          .map(([, value]) => value);
        if (
          contentTypes.length !== 1 ||
          ![
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded;charset=UTF-8",
            "application/x-www-form-urlencoded; charset=UTF-8",
          ].includes(contentTypes[0])
        )
          throw unavailable();
        for (const [key, value] of strictPairs(text)) if (SECRET_FIELDS.has(key)) learn(value);
        bodyForm = "FORM";
      } else if (text === "OK") bodyForm = "SESSION_ACK";
      else {
        const root = parseCaptureJsonSpans(text);
        const walk = (node) => {
          if (node.type === "array") {
            for (const child of node.entries) walk(child);
            return;
          }
          if (node.type !== "object") return;
          for (const [key, child] of node.entries) {
            if (SECRET_FIELDS.has(key) || URI_FIELDS.has(key)) {
              for (const value of child.type === "array" ? child.entries : [child]) {
                if (value.type !== "string") throw unavailable();
                if (URI_FIELDS.has(key)) uri(value.value);
                else if (CSV_FIELDS.has(key)) csv(value.value);
                else if (["signerKey", "saltSeparator"].includes(key)) encodedKey(value.value);
                else learn(value.value);
              }
            } else walk(child);
          }
        };
        walk(root);
        bodyForm = "JSON";
      }
    }
    registerProductionSecretBatch(registry, [...values]);
    return Object.freeze({ available: true, discoveredValues: values.size, bodyForm });
  } catch {
    registry.close();
    return Object.freeze({
      available: false,
      discoveredValues: 0,
      bodyForm: null,
      reason: "SECRET_DISCOVERY_UNAVAILABLE",
    });
  }
}
