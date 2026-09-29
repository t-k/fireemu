import { createHash } from "node:crypto";

// Removes bearer material from anything that may be saved: response bytes, response headers and free text such as a
// target or an error message. Bytes are read as Latin-1, so every offset maps one to one onto the original. A span
// records where a secret was and a salted digest of it, never the value.
const MAX_BYTES = 2 * 1024 * 1024;
const SECRET_FIELDS = "downloadTokens|firebaseStorageDownloadTokens|idToken|id_token|refreshToken|refresh_token|access_token|accessToken|passwordHash|salt|keyString|sessionInfo|password|secret|apiKey|api_key|token|privateKey|private_key|client_secret";
const URL_PARAMETERS = "token|key|upload_id|access_token|id_token|refresh_token|sig|signature|X-Goog-Signature|X-Goog-Credential|X-Amz-Signature|X-Amz-Credential";
const HEADER_NAMES = new Set(["authorization", "proxy-authorization", "cookie", "set-cookie", "x-goog-upload-url", "x-goog-api-key", "x-firebase-appcheck", "x-goog-iam-authorization-token"]);
// Each pattern yields spans; `group` selects the secret part of a match, and the first pattern to reach a byte wins after merging.
const PATTERNS = [
  { kind: "session-url", re: /https?:\/\/[^\s"'<>\\]*[?&]upload_id=[^\s"'<>\\]*/gi, group: 0 },
  { kind: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, group: 0 },
  { kind: "json-field", re: new RegExp(`"(?:${SECRET_FIELDS})"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`, "gi"), group: 1 },
  { kind: "url-parameter", re: new RegExp(`(?:[?&]|\\\\u0026|&amp;)(?:${URL_PARAMETERS})=([^&"'\\s<>\\\\]+)`, "gi"), group: 1 },
  { kind: "assignment", re: /(?:^|[\s,;([{])(?:token|access_token|id_token|refresh_token|password|secret|api[_-]?key|upload_id|downloadTokens)\s*[=:]\s*([^\s,;&"'<>)\]}]+)/gi, group: 1 },
  { kind: "jwt", re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, group: 0 },
  { kind: "google-api-key", re: /AIza[0-9A-Za-z_-]{35}/g, group: 0 },
  { kind: "oauth-access-token", re: /ya29\.[0-9A-Za-z_-]{10,}/g, group: 0 },
  { kind: "oauth-refresh-token", re: /1\/\/[0-9A-Za-z_-]{20,}/g, group: 0 },
  { kind: "bearer", re: /Bearer\s+([A-Za-z0-9._~+/=-]{8,})/gi, group: 1 },
];
const bad = () => { throw new Error("invalid redaction input"); };

function findSpans(text) {
  const found = [];
  for (const { kind, re, group } of PATTERNS) {
    re.lastIndex = 0;
    for (const match of text.matchAll(re)) {
      const value = match[group];
      if (typeof value !== "string" || value.length === 0) continue;
      // The secret is the whole match or the capture at its end.
      found.push({ kind, start: group === 0 ? match.index : match.index + match[0].lastIndexOf(value), length: value.length, priority: found.length });
    }
  }
  found.sort((a, b) => a.start - b.start || b.length - a.length || a.priority - b.priority);
  const merged = [];
  for (const span of found) {
    const last = merged.at(-1);
    if (last && span.start < last.start + last.length) {
      const end = Math.max(last.start + last.length, span.start + span.length);
      last.length = end - last.start;
    } else merged.push({ ...span });
  }
  return merged;
}

export function createRedactor(options) {
  if (!options || typeof options !== "object" || Array.isArray(options) || Object.getPrototypeOf(options) !== Object.prototype || Reflect.ownKeys(options).length !== 1 || !Object.hasOwn(options, "digestSalt")) throw new Error("invalid redactor options");
  const field = Object.getOwnPropertyDescriptor(options, "digestSalt");
  if (!field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "string" || !/^[0-9a-f]{64}$/.test(field.value)) throw new Error("invalid redactor options");
  const salt = field.value;
  const digest = (...parts) => createHash("sha256").update([salt, ...parts].join("\0")).digest("hex");

  function redactString(text) {
    const spans = findSpans(text);
    let out = ""; let cursor = 0;
    const described = spans.map((span) => {
      out += text.slice(cursor, span.start) + `<redacted:${span.kind}>`;
      cursor = span.start + span.length;
      return Object.freeze({ kind: span.kind, start: span.start, length: span.length, valueSha256: digest(span.kind, text.slice(span.start, span.start + span.length)) });
    });
    return { text: out + text.slice(cursor), spans: described };
  }

  return Object.freeze({
    bytes(input) {
      if (!Buffer.isBuffer(input) || Object.getPrototypeOf(input) !== Buffer.prototype || input.length > MAX_BYTES) bad();
      const original = input.toString("latin1");
      const { text, spans } = redactString(original);
      return Object.freeze({ bytes: Buffer.from(text, "latin1"), spans: Object.freeze(spans), originalSha256: digest(original) });
    },
    headers(rawHeaders) {
      if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0 || rawHeaders.some((entry) => typeof entry !== "string")) bad();
      const out = [];
      for (let index = 0; index < rawHeaders.length; index += 2) {
        const name = rawHeaders[index];
        out.push(name, HEADER_NAMES.has(name.toLowerCase()) ? "<redacted:header>" : redactString(rawHeaders[index + 1]).text);
      }
      return Object.freeze(out);
    },
    text(input) {
      if (typeof input !== "string") bad();
      return redactString(input).text;
    },
  });
}
