// Normalization of documented nondeterminism, and nothing else.
//
// Every rule here erases a value that both a correct oracle and a correct fireemu are
// free to choose differently on two runs of the same corpus: wall-clock instants, generated
// identifiers, credentials, host:port pairs and object generations. Statuses, error codes,
// error messages, payload shapes, listener sequences and Rules decisions are never touched --
// those are exactly what the suite compares.
//
// The rules are deliberately conservative: a placeholder replaces the whole value only when
// the value's *shape* has already been checked by the pattern that matched it, so a scenario
// still fails when a timestamp turns into a number or an id changes length.

/** Ordering that is documented as unspecified, applied by a scenario that opts in. */
export const sortStrings = (xs) => xs.toSorted((a, b) => (a < b ? -1 : a > b ? 1 : 0));

const RULES = [
  // RFC 3339 instants, with or without sub-second precision and with a numeric offset.
  [/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/, "<timestamp>"],
  // Firestore auto ids and Auth local ids are both 20 URL-safe characters.
  [/^[A-Za-z0-9]{20}$/, "<auto-id>"],
  // JWTs: ID tokens, refresh tokens and App Check tokens.
  [/^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, "<jwt>"],
  // Storage download tokens and OOB codes are opaque and regenerated per run.
  [/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, "<uuid>"],
  // Object generations are microsecond-derived decimal strings.
  [/^1[0-9]{15,18}$/, "<generation>"],
];

// The one nondeterministic substring that appears inside otherwise-compared messages: the
// two sides bind different ports on purpose, and both echo their own address back in some
// errors. Identifiers do not need a rule here because the corpus derives every document id,
// email address and object name from its scenario id rather than from a clock or a counter.
const HOST_PORT = /\b(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}\b/g;

/** Replaces the nondeterministic substrings inside a message that is otherwise compared. */
export function normalizeText(text) {
  return text.replace(HOST_PORT, "<host>");
}

/**
 * Normalizes one recorded value. Object keys are sorted so that a fixture never depends on
 * property insertion order, which neither SDK guarantees.
 */
export function normalize(value, path = "") {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") {
    for (const [pattern, placeholder] of RULES) {
      if (pattern.test(value)) return placeholder;
    }
    return normalizeText(value);
  }
  if (Array.isArray(value)) return value.map((v, i) => normalize(v, `${path}[${i}]`));
  if (value instanceof Date) return "<timestamp>";
  if (typeof value === "object") {
    // Firestore Timestamp / GeoPoint / DocumentReference and their client twins.
    const ctor = value.constructor?.name;
    if (ctor === "Timestamp") return "<timestamp>";
    if (ctor === "GeoPoint") return { geoPoint: [value.latitude, value.longitude] };
    if (ctor === "DocumentReference") return { ref: value.path ?? String(value) };
    if (Buffer.isBuffer(value)) return { bytesLength: value.length };
    if (value instanceof Uint8Array) return { bytesLength: value.length };
    const out = {};
    for (const key of Object.keys(value).toSorted()) {
      out[key] = normalize(value[key], path ? `${path}.${key}` : key);
    }
    return out;
  }
  return String(value);
}

/**
 * The comparable shape of a thrown SDK error. Codes and messages are the point of the
 * comparison, so only their embedded hosts and nonces are normalized.
 */
export function normalizeError(error) {
  const raw = error ?? {};
  const out = {
    thrown: true,
    // `code` is numeric on gRPC (firebase-admin) and a string on the web SDKs.
    code: raw.code === undefined ? null : normalizeText(String(raw.code)),
    message: raw.message === undefined ? null : normalizeText(String(raw.message)),
  };
  if (raw.status !== undefined) out.status = normalizeText(String(raw.status));
  // grpc-js exposes the decoded status text separately from Error.message. Keep both: the
  // wire trailer comparison must not accidentally treat a changed `details` value as noise.
  if (raw.details !== undefined) out.details = normalizeText(String(raw.details));
  if (raw.metadata?.getMap && raw.metadata?.get) {
    const trailers = [];
    for (const key of Object.keys(raw.metadata.getMap()).toSorted()) {
      const lower = key.toLowerCase();
      // grpc-js synthesizes this transport timestamp for each response. It is not an error
      // contract and would make every recorded fixture expire immediately.
      if (lower === "date") continue;
      for (const value of raw.metadata.get(key)) {
        if (lower.endsWith("-bin")) {
          const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
          trailers.push({ key: lower, kind: "binary", valueBase64: bytes.toString("base64") });
        } else {
          trailers.push({ key: lower, kind: "ascii", value: normalizeText(String(value)) });
        }
      }
    }
    out.trailers = trailers;
  }
  if (raw.customData?.serverResponse !== undefined) {
    out.serverResponse = normalizeText(String(raw.customData.serverResponse));
  }
  return out;
}
