// Pure helpers that turn one observation into comparable leaves. Nothing here decides what is
// volatile: E8 of the frozen closure says a field is volatile only when the two production passes
// show it varying, so this module only replaces the resource names and ids the operation itself
// declared (its matchKey) and the project by role placeholders, and then lists every path.

/** Listing members printed only in the production stdout capture mode (record-schema.md). */
export const PRODUCTION_ONLY_PATHS = [
  ["event", "context", "contextKeys"],
  ["event", "context", "contextExtras"],
  ["event", "eventKeys"],
  ["event", "extensionAttributes"],
];

const lastSegment = (value) => value.slice(value.lastIndexOf("/") + 1);

function requireRole(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`placeholder role ${label} must be a non-empty string`);
  }
  return value;
}

/**
 * Role placeholders derived from an operation's matchKey and the project, as [source, token] pairs.
 * Longest source first (ties by source text) so a longer name is replaced before a name inside it.
 */
export function placeholderTable({ matchKey, project }) {
  if (!matchKey || typeof matchKey !== "object") throw new TypeError("matchKey is required");
  const roles = [];
  if (Array.isArray(matchKey.values)) {
    matchKey.values.forEach((value, index) =>
      roles.push([requireRole(value, `values[${index}]`), `<key.values[${index}]>`]),
    );
  } else {
    const value = requireRole(matchKey.value, "value");
    roles.push([value, "<key.value>"]);
    const encoded = encodeURIComponent(value);
    if (encoded !== value) roles.push([encoded, "<key.value|uri>"]);
    if (matchKey.kind === "firestore" || matchKey.kind === "storage") {
      const id = lastSegment(value);
      if (id !== value && id.length > 0) roles.push([id, "<key.id>"]);
    }
  }
  if (matchKey.bucket != null) roles.push([requireRole(matchKey.bucket, "bucket"), "<key.bucket>"]);
  roles.push([requireRole(project, "project"), "<project>"]);
  const seen = new Set();
  const unique = roles.filter(([source]) => !seen.has(source) && seen.add(source));
  return unique.sort(([a], [b]) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function replacer(table) {
  if (table.length === 0) return (text) => text;
  const tokens = new Map(table);
  const pattern = new RegExp(table.map(([source]) => escapeRegExp(source)).join("|"), "g");
  return (text) => text.replace(pattern, (match) => tokens.get(match));
}

/** Deep copy with every placeholder source replaced, in string values and object keys, in one pass. */
export function applyPlaceholders(value, table) {
  const replace = replacer(table);
  const walk = (node) => {
    if (typeof node === "string") return replace(node);
    if (Array.isArray(node)) return node.map(walk);
    if (node !== null && typeof node === "object") {
      const out = {};
      for (const [key, child] of Object.entries(node)) out[replace(key)] = walk(child);
      return out;
    }
    return node;
  };
  return walk(value);
}

const pathText = (segments) => `$${segments.map((segment) => `.${segment}`).join("")}`;

function listingNames(value) {
  if (Array.isArray(value)) return value.map(String).sort();
  if (value !== null && typeof value === "object") return Object.keys(value).sort();
  return [];
}

/**
 * Remove the production-only listing members from a frame (copy) and return their member names.
 * Only names are kept: the listing values can hold trace ids, which never leave the private record.
 */
export function splitProductionOnly(frame) {
  const copy = structuredClone(frame);
  const listing = {};
  for (const segments of PRODUCTION_ONLY_PATHS) {
    let parent = copy;
    for (const segment of segments.slice(0, -1)) {
      parent = parent !== null && typeof parent === "object" ? parent[segment] : undefined;
    }
    const last = segments.at(-1);
    if (parent !== null && typeof parent === "object" && !Array.isArray(parent) && last in parent) {
      listing[pathText(segments)] = listingNames(parent[last]);
      delete parent[last];
    }
  }
  return {
    frame: copy,
    listing: Object.fromEntries(Object.entries(listing).sort(([a], [b]) => (a < b ? -1 : 1))),
  };
}

const plainKey = /^[A-Za-z_][A-Za-z0-9_]*$/;
const childPath = (parent, key) =>
  plainKey.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`;

function leafType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/** Every path of a JSON value with its type; objects keep member order, arrays their length. */
export function flatten(value) {
  const leaves = new Map();
  const walk = (node, path) => {
    const type = leafType(node);
    if (type === "object") {
      const keys = Object.keys(node);
      leaves.set(path, { type, keys });
      for (const key of keys) walk(node[key], childPath(path, key));
    } else if (type === "array") {
      leaves.set(path, { type, length: node.length });
      node.forEach((child, index) => walk(child, `${path}[${index}]`));
    } else if (["string", "number", "boolean", "null"].includes(type)) {
      leaves.set(path, { type, value: node });
    } else {
      throw new TypeError(`not a JSON value at ${path}`);
    }
  };
  walk(value, "$");
  return leaves;
}

const timestampPattern =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:-\d+)?$/i;

/** The format of a primitive: what a mask must never hide (kind, length, precision, zone). */
export function formatOf(value) {
  if (value === null) return { kind: "null" };
  if (typeof value === "boolean") return { kind: "boolean" };
  if (typeof value === "number") return { kind: Number.isInteger(value) ? "integer" : "fraction" };
  const timestamp = timestampPattern.exec(value);
  if (timestamp) {
    return {
      kind: "timestamp",
      length: value.length,
      fractionDigits: timestamp[1]?.length ?? 0,
      zone: timestamp[2],
    };
  }
  if (/^\d+$/.test(value)) return { kind: "decimal", length: value.length };
  if (uuidPattern.test(value)) return { kind: "uuid", length: value.length };
  return { kind: "text", length: value.length };
}
