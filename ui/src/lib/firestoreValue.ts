import { err, ok, type Result } from "neverthrow";

/** A Firestore REST value (`google.firestore.v1.Value` in JSON). */
export type FsValue =
  | { nullValue: null }
  | { booleanValue: boolean }
  | { integerValue: string }
  | { doubleValue: number | "NaN" | "Infinity" | "-Infinity" }
  | { stringValue: string }
  | { timestampValue: string }
  | { geoPointValue: { latitude: number; longitude: number } }
  | { referenceValue: string }
  | { bytesValue: string }
  | { arrayValue: { values?: FsValue[] } }
  | { mapValue: { fields?: Record<string, FsValue> } };

export type FsDocument = {
  name: string;
  fields?: Record<string, FsValue>;
  createTime?: string;
  updateTime?: string;
};

/** The types the editor offers. */
export type FieldType =
  | "string"
  | "number"
  | "boolean"
  | "null"
  | "timestamp"
  | "geopoint"
  | "reference"
  | "array"
  | "map"
  | "bytes";

export const FIELD_TYPES: FieldType[] = [
  "string",
  "number",
  "boolean",
  "null",
  "timestamp",
  "geopoint",
  "reference",
  "array",
  "map",
  "bytes",
];

export type NumberKind = "integer" | "double";

/** One editable field, including the immutable wire value captured when editing began. */
export type EditableField = {
  name: string;
  type: FieldType;
  text: string;
  original?: FsValue | undefined;
  dirty?: boolean;
  numberKind?: NumberKind | undefined;
};

/** The type of a REST value. */
export const typeOf = (v: FsValue): FieldType => {
  if ("nullValue" in v) return "null";
  if ("booleanValue" in v) return "boolean";
  if ("integerValue" in v || "doubleValue" in v) return "number";
  if ("stringValue" in v) return "string";
  if ("timestampValue" in v) return "timestamp";
  if ("geoPointValue" in v) return "geopoint";
  if ("referenceValue" in v) return "reference";
  if ("bytesValue" in v) return "bytes";
  if ("arrayValue" in v) return "array";
  return "map";
};

/** A REST value as plain JSON (for JSON views of arrays and maps). */
export const toPlain = (v: FsValue): unknown => {
  if ("nullValue" in v) return null;
  if ("booleanValue" in v) return v.booleanValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("stringValue" in v) return v.stringValue;
  if ("timestampValue" in v) return v.timestampValue;
  if ("geoPointValue" in v) return v.geoPointValue;
  if ("referenceValue" in v) return v.referenceValue;
  if ("bytesValue" in v) return v.bytesValue;
  if ("arrayValue" in v) return (v.arrayValue.values ?? []).map(toPlain);
  return Object.fromEntries(
    Object.entries(v.mapValue.fields ?? {}).map(([k, x]) => [k, toPlain(x)]),
  );
};

/** A one-line rendering of a REST value for lists. */
export const summarize = (v: FsValue): string => {
  if ("stringValue" in v) return JSON.stringify(v.stringValue);
  if ("nullValue" in v) return "null";
  if ("booleanValue" in v) return String(v.booleanValue);
  if ("integerValue" in v) return v.integerValue;
  if ("doubleValue" in v) return String(v.doubleValue);
  if ("timestampValue" in v) return v.timestampValue;
  if ("geoPointValue" in v) return `[${v.geoPointValue.latitude}, ${v.geoPointValue.longitude}]`;
  if ("referenceValue" in v)
    return v.referenceValue.replace(/^projects\/[^/]+\/databases\/[^/]+\/documents\//, "");
  if ("bytesValue" in v) return `bytes(${v.bytesValue.length})`;
  if ("arrayValue" in v) return JSON.stringify((v.arrayValue.values ?? []).map(toPlain));
  return JSON.stringify(toPlain(v));
};

/** The editor text of a REST value (what the user sees in the input). */
export const toText = (v: FsValue): string => {
  if ("stringValue" in v) return v.stringValue;
  if ("nullValue" in v) return "";
  if ("booleanValue" in v) return String(v.booleanValue);
  if ("integerValue" in v) return v.integerValue;
  if ("doubleValue" in v) return String(v.doubleValue);
  if ("timestampValue" in v) return v.timestampValue;
  if ("geoPointValue" in v) return `${v.geoPointValue.latitude}, ${v.geoPointValue.longitude}`;
  if ("referenceValue" in v) return v.referenceValue;
  if ("bytesValue" in v) return v.bytesValue;
  if ("arrayValue" in v) return JSON.stringify(v.arrayValue.values ?? [], null, 2);
  return JSON.stringify(v.mapValue.fields ?? {}, null, 2);
};

/** The editable fields of a document. */
export const toEditable = (fields: Record<string, FsValue> | undefined): EditableField[] =>
  Object.entries(fields ?? {}).map(([name, v]) => ({
    name,
    type: typeOf(v),
    text: toText(v),
    original: v,
    dirty: false,
    numberKind: "integerValue" in v ? "integer" : "doubleValue" in v ? "double" : undefined,
  }));

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

const isFsValue = (x: unknown): x is FsValue => {
  if (!x || typeof x !== "object" || Array.isArray(x)) return false;
  const keys = Object.keys(x);
  if (keys.length !== 1) return false;
  const key = keys[0] ?? "";
  const value = x as Record<string, unknown>;
  switch (key) {
    case "nullValue":
      return value[key] === null;
    case "booleanValue":
      return typeof value[key] === "boolean";
    case "integerValue":
      return typeof value[key] === "string" && /^[+-]?\d+$/.test(value[key]);
    case "doubleValue":
      return (
        (typeof value[key] === "number" && Number.isFinite(value[key])) ||
        value[key] === "NaN" ||
        value[key] === "Infinity" ||
        value[key] === "-Infinity"
      );
    case "stringValue":
    case "timestampValue":
    case "referenceValue":
    case "bytesValue":
      return typeof value[key] === "string";
    case "geoPointValue": {
      const point = value[key];
      return (
        !!point &&
        typeof point === "object" &&
        !Array.isArray(point) &&
        typeof (point as Record<string, unknown>).latitude === "number" &&
        typeof (point as Record<string, unknown>).longitude === "number"
      );
    }
    case "arrayValue": {
      const array = value[key];
      if (!array || typeof array !== "object" || Array.isArray(array)) return false;
      const values = (array as Record<string, unknown>).values;
      return values === undefined || (Array.isArray(values) && values.every(isFsValue));
    }
    case "mapValue": {
      const map = value[key];
      if (!map || typeof map !== "object" || Array.isArray(map)) return false;
      const fields = (map as Record<string, unknown>).fields;
      return (
        fields === undefined ||
        (!!fields &&
          typeof fields === "object" &&
          !Array.isArray(fields) &&
          Object.values(fields).every(isFsValue))
      );
    }
    default:
      return false;
  }
};

/** The REST value a document path refers to (relative paths are resolved under `documentsRoot`). */
const referenceValue = (text: string, documentsRoot: string): Result<FsValue, string> => {
  const path = text.trim();
  if (!path) return err("a document path is required");
  const full = path.startsWith("projects/") ? path : `${documentsRoot}/${path}`;
  const rel = full.slice(full.indexOf("/documents/") + "/documents/".length);
  const segments = rel.split("/");
  if (segments.length % 2 !== 0 || segments.some((s) => s.length === 0)) {
    return err("a document path has an even number of non-empty segments");
  }
  return ok({ referenceValue: full });
};

/** Parses one editable field into a REST value. */
export const parseField = (
  type: FieldType,
  text: string,
  documentsRoot: string,
  numberKind?: NumberKind,
): Result<FsValue, string> => {
  switch (type) {
    case "string":
      return ok({ stringValue: text });
    case "null":
      return ok({ nullValue: null });
    case "boolean": {
      const v = text.trim().toLowerCase();
      if (v === "true") return ok({ booleanValue: true });
      if (v === "false") return ok({ booleanValue: false });
      return err("true or false");
    }
    case "number": {
      const v = text.trim();
      if (numberKind === "double" && ["NaN", "Infinity", "-Infinity"].includes(v)) {
        return ok({ doubleValue: v as "NaN" | "Infinity" | "-Infinity" });
      }
      if (numberKind !== "double" && /^[+-]?\d+$/.test(v)) {
        const n = BigInt(v);
        if (n > 9223372036854775807n || n < -9223372036854775808n) {
          return err("integer out of the 64-bit range");
        }
        return ok({ integerValue: n.toString() });
      }
      const n = Number(v);
      if (v === "" || !Number.isFinite(n)) return err("integer, decimal, NaN, or Infinity");
      return ok({ doubleValue: n });
    }
    case "timestamp": {
      const v = text.trim();
      if (!RFC3339.test(v) || Number.isNaN(Date.parse(v))) return err("RFC 3339 timestamp");
      return ok({ timestampValue: v });
    }
    case "geopoint": {
      const parts = text.split(",").map((s) => s.trim());
      if (parts.length !== 2) return err("latitude, longitude");
      const [lat, lng] = parts.map(Number);
      if (lat === undefined || lng === undefined || Number.isNaN(lat) || Number.isNaN(lng)) {
        return err("latitude, longitude");
      }
      if (lat < -90 || lat > 90 || lng < -180 || lng > 180)
        return err("latitude in -90..90, longitude in -180..180");
      return ok({ geoPointValue: { latitude: lat, longitude: lng } });
    }
    case "reference":
      return referenceValue(text, documentsRoot);
    case "bytes": {
      const v = text.replace(/\s+/g, "");
      if (!BASE64.test(v) || v.length % 4 !== 0) return err("base64");
      return ok({ bytesValue: v });
    }
    case "array": {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text || "[]");
      } catch (e) {
        return err(e instanceof Error ? e.message : "invalid JSON");
      }
      if (!Array.isArray(parsed) || !parsed.every(isFsValue)) {
        return err('a JSON array of Firestore values, for example [{"stringValue": "a"}]');
      }
      return ok({ arrayValue: { values: parsed } });
    }
    case "map": {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text || "{}");
      } catch (e) {
        return err(e instanceof Error ? e.message : "invalid JSON");
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return err('a JSON object of Firestore values, for example {"k": {"stringValue": "v"}}');
      }
      const entries = Object.entries(parsed as Record<string, unknown>);
      if (!entries.every(([, v]) => isFsValue(v))) {
        return err('every map entry must be a Firestore value, for example {"stringValue": "v"}');
      }
      return ok({ mapValue: { fields: Object.fromEntries(entries) as Record<string, FsValue> } });
    }
  }
};

/** Whether a field name is acceptable (non-empty, no control characters, no dots). */
export const validFieldName = (name: string): boolean =>
  name.length > 0 && name.length <= 1500 && !/[ -]/.test(name);

/**
 * Parses the editor's fields into a document body. Errors name the field; duplicate and
 * empty names are refused.
 */
export const parseFields = (
  fields: EditableField[],
  documentsRoot: string,
): Result<Record<string, FsValue>, { field: string; message: string }> => {
  const seen = new Set<string>();
  const entries: [string, FsValue][] = [];
  for (const f of fields) {
    if (!validFieldName(f.name)) {
      return err({ field: f.name, message: "a field needs a name without control characters" });
    }
    if (seen.has(f.name)) {
      return err({ field: f.name, message: "declared twice" });
    }
    seen.add(f.name);
    if (f.original !== undefined && f.dirty !== true && typeOf(f.original) === f.type) {
      entries.push([f.name, f.original]);
      continue;
    }
    const value = parseField(f.type, f.text, documentsRoot, f.numberKind);
    if (value.isErr()) {
      return err({ field: f.name, message: value.error });
    }
    entries.push([f.name, value.value]);
  }
  const out: Record<string, FsValue> = {};
  for (const [name, value] of entries) {
    Object.defineProperty(out, name, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return ok(out);
};

/** The default text for a type when the user switches to it. */
export const defaultText = (type: FieldType): string => {
  switch (type) {
    case "boolean":
      return "true";
    case "number":
      return "0";
    case "timestamp":
      return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    case "geopoint":
      return "0, 0";
    case "array":
      return "[]";
    case "map":
      return "{}";
    default:
      return "";
  }
};

/** The relative path (`users/alice`) of a document resource name. */
export const relativePath = (name: string): string => {
  const at = name.indexOf("/documents/");
  return at < 0 ? name : name.slice(at + "/documents/".length);
};

/** The last segment of a path. */
export const lastSegment = (path: string): string => {
  const segments = path.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? "";
};

/** The parent path (`""` for a root collection). */
export const parentPath = (path: string): string => {
  const segments = path.split("/").filter(Boolean);
  segments.pop();
  return segments.join("/");
};

/** Whether a relative path names a document (even number of segments). */
export const isDocumentPath = (path: string): boolean => {
  const n = path.split("/").filter(Boolean).length;
  return n > 0 && n % 2 === 0;
};
