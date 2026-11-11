// Normalization of documented nondeterminism, and nothing else.
//
// Every rule here erases a value that both a correct oracle and a correct fireemu are
// free to choose differently on two runs of the same corpus: wall-clock instants, generated
// identifiers, credentials and object generations. Statuses, error codes, error messages,
// payload shapes, listener sequences and Rules decisions are never touched -- those are
// exactly what the suite compares.
//
// A value is generated because of what the field *means*, not because of how its characters
// look, so a rule applies only at a path the scenario declared (`generated`). A string a
// scenario wrote itself -- a 20-character user id, an RFC 3339 literal in a document field, a
// key name that happens to be 20 letters long -- is compared exactly even when its shape
// equals a generated one. Even at a declared path the shape is still checked, so a scenario
// still fails when a timestamp turns into a number or an id changes length.

/** Ordering that is documented as unspecified, applied by a scenario that opts in. */
export const sortStrings = (xs) => xs.toSorted((a, b) => (a < b ? -1 : a > b ? 1 : 0));

/** The kinds of generated value a scenario can declare, each with the shape it must have. */
const GENERATED = {
  // RFC 3339 instants, with or without sub-second precision and with a numeric offset. A
  // Date or an SDK Timestamp at a declared path is an instant too.
  timestamp: {
    pattern: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/,
    placeholder: "<timestamp>",
  },
  // Firestore auto ids and Auth local ids are both 20 URL-safe characters.
  "auto-id": { pattern: /^[A-Za-z0-9]{20}$/, placeholder: "<auto-id>" },
  // JWTs: ID tokens, refresh tokens and App Check tokens.
  jwt: { pattern: /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, placeholder: "<jwt>" },
  // Storage download tokens and OOB codes are opaque and regenerated per run.
  uuid: {
    pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    placeholder: "<uuid>",
  },
  // Object generations are microsecond-derived decimal strings.
  generation: { pattern: /^1[0-9]{15,18}$/, placeholder: "<generation>" },
};

/** The declarable kinds, for scenarios and tests. */
export const GENERATED_KINDS = Object.keys(GENERATED);

const INDEX = Symbol("array element");
const ANY_KEY = Symbol("any key");

/**
 * Parses declared paths. `generated` maps a path to a kind:
 *
 *   ""                  the recorded value itself
 *   "data.at"           key `at` of key `data`
 *   "body[].readTime"   key `readTime` of every element of the array at key `body`
 *   "*.id"              key `id` of any key
 *
 * Array elements count as one `[]` step whatever their index. A key that contains a dot or
 * brackets cannot be named, which is deliberate: such a key is user data.
 */
export function compileGenerated(generated = {}) {
  const rules = [];
  for (const [path, kind] of Object.entries(generated)) {
    if (!Object.hasOwn(GENERATED, kind)) {
      throw new Error(
        `generated path ${JSON.stringify(path)}: unknown kind ${JSON.stringify(kind)}`,
      );
    }
    const tokens = [];
    if (path !== "") {
      for (const [position, part] of path.split(".").entries()) {
        const match = /^([^[\]]*)((?:\[\])*)$/.exec(part);
        // An empty key is only allowed as the very first segment, in front of brackets ("[].id").
        if (!match || (match[1] === "" && (match[2] === "" || position > 0))) {
          throw new Error(
            `generated path ${JSON.stringify(path)}: bad segment ${JSON.stringify(part)}`,
          );
        }
        if (match[1] !== "") tokens.push(match[1] === "*" ? ANY_KEY : match[1]);
        for (let i = 0; i < match[2].length / 2; i += 1) tokens.push(INDEX);
      }
    }
    rules.push({ tokens, kind });
  }
  return rules;
}

function declaredKind(rules, location) {
  for (const { tokens, kind } of rules) {
    if (tokens.length !== location.length) continue;
    const same = tokens.every(
      (t, i) => t === location[i] || (t === ANY_KEY && typeof location[i] === "string"),
    );
    if (same) return kind;
  }
  return null;
}

// The one nondeterministic substring that appears inside otherwise-compared messages: the
// two sides bind different ports on purpose, and both echo their own address back in some
// errors. Identifiers do not need a rule here because the corpus derives every document id,
// email address and object name from its scenario id rather than from a clock or a counter.
const HOST_PORT = /\b(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}\b/g;

/** Replaces the nondeterministic substrings inside a message that is otherwise compared. */
export function normalizeText(text) {
  return text.replace(HOST_PORT, "<host>");
}

/** Replaces `value` at a declared generated path, or returns it unchanged when its shape is wrong. */
function generatedPlaceholder(kind, value) {
  const { pattern, placeholder } = GENERATED[kind];
  if (typeof value === "string") return pattern.test(value) ? placeholder : undefined;
  if (kind === "timestamp" && (value instanceof Date || value?.constructor?.name === "Timestamp")) {
    return placeholder;
  }
  return undefined;
}

/** The comparable form of an instant nobody declared generated: exact, to the nanosecond. */
function exactInstant(value) {
  if (value instanceof Date) {
    return { date: Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString() };
  }
  return {
    timestamp: {
      seconds: Number(value.seconds),
      nanoseconds: Number(value.nanoseconds),
    },
  };
}

/**
 * Normalizes one recorded value. Object keys are sorted so that a fixture never depends on
 * property insertion order, which neither SDK guarantees.
 *
 * `generated` declares, by path, the fields whose value the server or the SDK generates (see
 * `compileGenerated`); only there is a value of the declared shape replaced by its placeholder.
 * Everything else is recorded exactly: no string is replaced because of its shape.
 */
export function normalize(value, { generated } = {}) {
  return walk(value, compileGenerated(generated), []);
}

function walk(value, rules, location) {
  if (value === null || value === undefined) return null;
  const kind = declaredKind(rules, location);
  if (kind !== null) {
    const placeholder = generatedPlaceholder(kind, value);
    if (placeholder !== undefined) return placeholder;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return normalizeText(value);
  if (Array.isArray(value)) return value.map((v) => walk(v, rules, [...location, INDEX]));
  if (value instanceof Date) return exactInstant(value);
  if (typeof value === "object") {
    // Firestore Timestamp / GeoPoint / DocumentReference and their client twins.
    const ctor = value.constructor?.name;
    if (ctor === "Timestamp") return exactInstant(value);
    if (ctor === "GeoPoint") return { geoPoint: [value.latitude, value.longitude] };
    if (ctor === "DocumentReference") return { ref: value.path ?? String(value) };
    if (Buffer.isBuffer(value)) return { bytesLength: value.length };
    if (value instanceof Uint8Array) return { bytesLength: value.length };
    const out = {};
    for (const key of Object.keys(value).toSorted()) {
      out[key] = walk(value[key], rules, [...location, key]);
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
