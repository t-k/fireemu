import { createHash } from "node:crypto";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const digest = (value) => createHash("sha256").update(value).digest("hex");
export const captureStringIsWellFormed = (value) => Buffer.from(value).toString("utf8") === value;
const wellFormed = captureStringIsWellFormed;

export function captureSecretForms(value) {
  if (typeof value !== "string" || !wellFormed(value)) throw new Error("invalid capture secret");
  if (!value) return [];
  const encoded = encodeURIComponent(value),
    form = new URLSearchParams({ v: value }).toString().slice(2);
  return [
    ...new Set([
      value,
      encoded,
      encoded.replace(/%[a-fA-F0-9]{2}/g, (part) => part.toLowerCase()),
      form,
      form.replace(/%[a-fA-F0-9]{2}/g, (part) => part.toLowerCase()),
      Buffer.from(value).toString("base64"),
      JSON.stringify(value).slice(1, -1),
    ]),
  ];
}

/** Inspect bounded plain, percent/form and embedded Base64 copies before persistence. */
export function captureHasSecretCopy(text, forms) {
  const percent = (value) =>
    value.replace(/(?:%[a-fA-F0-9]{2})+/g, (part) => {
      try {
        return decodeURIComponent(part);
      } catch {
        return part;
      }
    });
  const candidates = new Set([text, percent(text), percent(text.replaceAll("+", "%20"))]);
  const contains = (value) => forms.some((secret) => value.includes(secret));
  for (const value of candidates) {
    if (contains(value)) return true;
    for (const pattern of [/[A-Za-z0-9+/]{4,}={0,2}/g, /[A-Za-z0-9_-]{4,}/g]) {
      for (const [segment] of value.matchAll(pattern)) {
        for (let offset = 0; offset < 4 && segment.length - offset >= 4; offset++) {
          const encoded = segment.slice(offset),
            bytes = Buffer.from(encoded, "base64");
          // Prefix/suffix alphabet characters can make the enclosing run noncanonical.
          // Its decoded complete bytes still contain a canonical embedded capability.
          const decoded = bytes.toString("utf8");
          if (
            contains(decoded) ||
            contains(percent(decoded)) ||
            contains(percent(decoded.replaceAll("+", "%20")))
          )
            return true;
        }
      }
    }
  }
  return false;
}
// Unknown response fields, including unsupported optional Storage features, remain commitments.
const SCHEMAS = {
  object: {
    kind: "object-kind",
    name: "owned-name",
    id: "object-id",
    bucket: "owned-bucket",
    generation: "unsigned-string",
    metageneration: "unsigned-string",
    size: "unsigned-string",
    contentType: "text",
    cacheControl: "text",
    contentDisposition: "text",
    contentEncoding: "text",
    contentLanguage: "text",
    storageClass: "text",
    timeCreated: "text",
    updated: "text",
    timeDeleted: "text",
    customTime: "text",
    md5Hash: "text",
    crc32c: "text",
    etag: "text",
    selfLink: "url",
    mediaLink: "url",
    componentCount: "unsigned-integer",
    kmsKeyName: "text",
    temporaryHold: "boolean",
    eventBasedHold: "boolean",
    retentionExpirationTime: "text",
    metadata: "metadata",
    downloadTokens: "download-tokens",
  },
  list: {
    kind: "list-kind",
    items: "object-array",
    prefixes: "prefix-array",
    nextPageToken: "capability",
  },
  rewrite: {
    kind: "rewrite-kind",
    done: "boolean",
    totalBytesRewritten: "unsigned-string",
    objectSize: "unsigned-string",
    rewriteToken: "capability",
    resource: "object",
  },
  metadata: {
    marker: "marker",
    remove: "remove-marker",
    preconditionMarker: "precondition-marker",
    firebaseStorageDownloadTokens: "capability",
  },
  "error-wrapper": { error: "error" },
  error: { code: "unsigned-integer", message: "message", errors: "error-array" },
  "error-detail": {
    reason: "reason",
    domain: "domain",
    message: "message",
    location: "location",
    locationType: "location-type",
  },
};
const MARKERS = new Set([
  "cross-dialect-updated",
  "first",
  "second",
  "before-overwrite",
  "missing-observation",
  "multipart-observation",
  "copy-source",
  "rewrite-override",
  "gcs-resumable",
]);
const SAFE_MESSAGES = new Set(["Not Found", "Forbidden", "Unauthorized", "Bad Request"]);
const CREDENTIAL_FORM =
  /1\/\/|GOCSPX-|AMf-v|AIza[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:Bearer|Firebase) [A-Za-z0-9._~+/-]+/;

function valueCommitment(value) {
  const bytes = Buffer.from(value);
  return {
    byteLength: bytes.length,
    codePointLength: [...value].length,
    sha256: digest(bytes),
    characterClasses: {
      uppercase: /[A-Z]/.test(value),
      lowercase: /[a-z]/.test(value),
      digit: /[0-9]/.test(value),
      asciiPunctuation: /[\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]/.test(value),
      whitespace: /\s/.test(value),
      nonAscii: bytes.length !== value.length,
    },
  };
}

// JSON.parse validates syntax first; this bounded tree retains the original value spans.
export function parseCaptureJsonSpans(text) {
  JSON.parse(text);
  let offset = 0;
  let count = 0;
  const whitespace = () => {
    while (/[\x20\t\r\n]/.test(text[offset] ?? "x")) offset++;
  };
  const string = () => {
    const start = offset++;
    while (text[offset] !== '"') {
      if (text[offset] === "\\") offset++;
      offset++;
    }
    offset++;
    const value = JSON.parse(text.slice(start, offset));
    if (!wellFormed(value)) throw new Error("invalid JSON Unicode");
    return { start, end: offset, value, type: "string" };
  };
  const node = (depth = 0) => {
    if (++count > 65536 || depth > 64) throw new Error("bounded JSON shape exceeded");
    whitespace();
    const start = offset;
    if (text[offset] === '"') return string();
    if (text[offset] === "{") {
      offset++;
      whitespace();
      const entries = [];
      const keys = new Set();
      while (text[offset] !== "}") {
        const key = string().value;
        if (keys.has(key)) throw new Error("duplicate JSON key");
        keys.add(key);
        whitespace();
        offset++;
        entries.push([key, node(depth + 1)]);
        whitespace();
        if (text[offset] === ",") {
          offset++;
          whitespace();
        }
      }
      offset++;
      return { type: "object", start, end: offset, entries };
    }
    if (text[offset] === "[") {
      offset++;
      whitespace();
      const entries = [];
      while (text[offset] !== "]") {
        entries.push(node(depth + 1));
        whitespace();
        if (text[offset] === ",") {
          offset++;
          whitespace();
        }
      }
      offset++;
      return { type: "array", start, end: offset, entries };
    }
    while (offset < text.length && !/[\x20\t\r\n,}\]]/.test(text[offset])) offset++;
    return { type: "primitive", start, end: offset, value: JSON.parse(text.slice(start, offset)) };
  };
  return node();
}

function capabilityPath(path) {
  return (
    /^\/(?:downloadTokens|nextPageToken|rewriteToken)$/.test(path) ||
    /^\/(?:resource\/|items\/[0-9]+\/)?(?:downloadTokens|metadata\/firebaseStorageDownloadTokens)$/.test(
      path,
    )
  );
}

function safeStorageUrl(value, expectedBucket, names, unsafe) {
  try {
    const url = new URL(value);
    if (
      !["https://storage.googleapis.com", "https://www.googleapis.com"].includes(url.origin) ||
      url.username ||
      url.password ||
      url.hash ||
      !expectedBucket ||
      unsafe(decodeURIComponent(url.pathname))
    )
      return false;
    const base = `/storage/v1/b/${encodeURIComponent(expectedBucket)}/o/`;
    const prefix = url.pathname.startsWith(`/download${base}`) ? `/download${base}` : base;
    if (
      !url.pathname.startsWith(prefix) ||
      !names.has(decodeURIComponent(url.pathname.slice(prefix.length)))
    )
      return false;
    const seen = new Set();
    for (const [key, child] of url.searchParams) {
      if (seen.has(key) || unsafe(child)) return false;
      seen.add(key);
      if (key === "alt" ? child !== "media" : key !== "generation" || !/^[0-9]{1,20}$/.test(child))
        return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Preserve nonsecret Storage bytes and fixed capability structure; unknown shapes retain only hashes. */
export function sanitizeStorageCaptureBody(
  bytes,
  {
    knownSecrets = [],
    contextSecrets = [],
    approvedBodySha256 = [],
    complete = true,
    bodyKind = "json",
    expectedObjectNames = [],
    expectedBucket,
  } = {},
) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length > MAX_RESPONSE_BODY_BYTES ||
    [knownSecrets, contextSecrets].some(
      (secrets) =>
        !Array.isArray(secrets) ||
        secrets.length > 64 ||
        secrets.some(
          (value) =>
            typeof value !== "string" ||
            value.length === 0 ||
            value.length > 262144 ||
            !wellFormed(value),
        ),
    ) ||
    !Array.isArray(approvedBodySha256) ||
    approvedBodySha256.some((value) => !/^[a-f0-9]{64}$/.test(value)) ||
    typeof complete !== "boolean" ||
    !["json", "media"].includes(bodyKind) ||
    !Array.isArray(expectedObjectNames) ||
    expectedObjectNames.some((name) => typeof name !== "string" || !name) ||
    (expectedBucket !== undefined && (typeof expectedBucket !== "string" || !expectedBucket))
  )
    throw new Error("invalid capture body configuration");
  const base = {
    originalByteLength: bytes.length,
    originalSha256: digest(bytes),
    mode: "COMMITMENT_ONLY",
    body: null,
    replacedFields: [],
  };
  if (!complete) return base;
  const secretForms = [...knownSecrets, ...contextSecrets].flatMap(captureSecretForms);
  const unsafe = (text) => CREDENTIAL_FORM.test(text) || captureHasSecretCopy(text, secretForms);
  if (bytes.length === 0 && bodyKind === "json")
    return { ...base, mode: "RAW_BODY", body: Buffer.from(bytes) };
  if (
    bodyKind === "media" &&
    approvedBodySha256.includes(base.originalSha256) &&
    !/^[{["]/.test(bytes.toString("utf8").trimStart()) &&
    !unsafe(bytes.toString("utf8"))
  )
    return { ...base, mode: "RAW_BODY", body: Buffer.from(bytes) };
  if (bodyKind === "media") return base;
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const root = parseCaptureJsonSpans(text);
    if (root.type !== "object") return base;
    const replacements = [];
    const discoveredCapabilities = new Set(),
      publicStrings = [];
    const learnCapability = (value) => {
      if (!value || discoveredCapabilities.has(value)) return;
      if (value.length > 8192 || discoveredCapabilities.size >= 64)
        throw new Error("capability discovery bound exceeded");
      discoveredCapabilities.add(value);
      secretForms.push(...captureSecretForms(value));
    };
    const names = new Set(expectedObjectNames);
    const prefixes = new Set(
      expectedObjectNames.flatMap((name) =>
        name
          .split("/")
          .slice(0, -1)
          .map(
            (_, index) =>
              `${name
                .split("/")
                .slice(0, index + 1)
                .join("/")}/`,
          ),
      ),
    );
    const walk = (node, path, shape) => {
      if (shape === "capability" || shape === "download-tokens") {
        if (!capabilityPath(path)) throw new Error("unknown capability path");
        const tokens = node.type === "array" && shape === "download-tokens" ? node.entries : [node];
        for (const [index, token] of tokens.entries()) {
          if (token.type !== "string" || !wellFormed(token.value))
            throw new Error("unknown capability shape");
          learnCapability(token.value);
          if (path.endsWith("/metadata/firebaseStorageDownloadTokens"))
            for (const part of token.value.split(",")) learnCapability(part);
          const tokenPath = node.type === "array" ? `${path}/${index}` : path;
          const observation = valueCommitment(token.value);
          replacements.push({ start: token.start, end: token.end, path: tokenPath, observation });
        }
        return;
      }
      if (Object.hasOwn(SCHEMAS, shape)) {
        if (node.type !== "object") throw new Error("unknown JSON shape");
        for (const [key, child] of node.entries) {
          if (!Object.hasOwn(SCHEMAS[shape], key)) throw new Error("unknown JSON field");
          walk(child, `${path}/${key}`, SCHEMAS[shape][key]);
        }
        return;
      }
      if (["object-array", "prefix-array", "error-array"].includes(shape)) {
        if (node.type !== "array") throw new Error("unknown JSON shape");
        const childShape = {
          "object-array": "object",
          "prefix-array": "prefix",
          "error-array": "error-detail",
        }[shape];
        for (const [index, child] of node.entries.entries())
          walk(child, `${path}/${index}`, childShape);
        return;
      }
      const value = node.value;
      if (shape === "boolean") {
        if (typeof value !== "boolean") throw new Error("unknown leaf type");
        return;
      }
      if (shape === "unsigned-integer") {
        if (!Number.isSafeInteger(value) || value < 0) throw new Error("unknown leaf type");
        return;
      }
      if (shape === "remove-marker" && value === null) return;
      if (node.type !== "string" || !wellFormed(value) || unsafe(value))
        throw new Error("secret or unknown string value");
      publicStrings.push(value);
      const valid = {
        text: () => true,
        url: () => safeStorageUrl(value, expectedBucket, names, unsafe),
        "owned-name": () => names.has(value),
        "owned-bucket": () => value === expectedBucket,
        "object-id": () =>
          expectedBucket &&
          [...names].some((name) => {
            const prefix = `${expectedBucket}/${name}/`;
            return value.startsWith(prefix) && /^[0-9]+$/.test(value.slice(prefix.length));
          }),
        prefix: () => prefixes.has(value),
        "unsigned-string": () => /^[0-9]{1,20}$/.test(value),
        "object-kind": () => value === "storage#object",
        "list-kind": () => value === "storage#objects",
        "rewrite-kind": () => value === "storage#rewriteResponse",
        marker: () => MARKERS.has(value),
        "remove-marker": () => value === "present",
        "precondition-marker": () => ["advanced", "subject-update"].includes(value),
        message: () => SAFE_MESSAGES.has(value),
        reason: () =>
          [
            "notFound",
            "forbidden",
            "required",
            "invalid",
            "conditionNotMet",
            "badRequest",
            "authError",
          ].includes(value),
        domain: () => ["global", "usageLimits"].includes(value),
        location: () =>
          ["name", "ifGenerationMatch", "ifMetagenerationMatch", "alt"].includes(value),
        "location-type": () => ["parameter", "header"].includes(value),
      };
      if (!valid[shape]?.()) throw new Error("unknown leaf value");
    };
    const keys = new Set(root.entries.map(([key]) => key));
    const kind = root.entries.find(([key]) => key === "kind")?.[1]?.value;
    const rootShape = keys.has("error")
      ? "error-wrapper"
      : keys.has("items") ||
          keys.has("prefixes") ||
          keys.has("nextPageToken") ||
          kind === "storage#objects"
        ? "list"
        : keys.has("resource") ||
            keys.has("rewriteToken") ||
            keys.has("done") ||
            keys.has("totalBytesRewritten") ||
            keys.has("objectSize") ||
            kind === "storage#rewriteResponse"
          ? "rewrite"
          : "object";
    walk(root, "", rootShape);
    if (publicStrings.some(unsafe)) return base;
    let offset = 0;
    const parts = [];
    for (const replacement of replacements) {
      parts.push(text.slice(offset, replacement.start), JSON.stringify(replacement.observation));
      offset = replacement.end;
    }
    parts.push(text.slice(offset));
    const saved = parts.join("");
    if (unsafe(saved)) return base;
    return {
      ...base,
      mode: replacements.length ? "CAPABILITY_FIELDS_REPLACED" : "RAW_BODY",
      body: Buffer.from(saved),
      replacedFields: replacements.map(({ path, observation }) =>
        Object.assign({ path }, observation),
      ),
    };
  } catch {
    return base;
  }
}
