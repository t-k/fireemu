import { err, ok, type Result } from "neverthrow";
import { parseField, type FieldType, type FsValue } from "./firestoreValue";

export const QUERY_TYPES = [
  "string",
  "integer",
  "double",
  "boolean",
  "null",
  "timestamp",
  "geopoint",
  "reference",
  "array",
  "map",
  "bytes",
] as const;
export type QueryValueType = (typeof QUERY_TYPES)[number];
export const QUERY_OPERATORS = [
  "EQUAL",
  "NOT_EQUAL",
  "LESS_THAN",
  "LESS_THAN_OR_EQUAL",
  "GREATER_THAN",
  "GREATER_THAN_OR_EQUAL",
  "ARRAY_CONTAINS",
  "IN",
  "ARRAY_CONTAINS_ANY",
  "NOT_IN",
] as const;
export type QueryOperator = (typeof QUERY_OPERATORS)[number];
export type QueryFilter = { field: string; op: QueryOperator; type: QueryValueType; text: string };
export type QueryOrder = { field: string; direction: "ASCENDING" | "DESCENDING" };
export type QueryDraft = {
  version: 1;
  mode: "AND" | "OR";
  filters: QueryFilter[];
  orders: QueryOrder[];
  limit: string;
};
export type CompiledQuery = { path: string; body: { structuredQuery: Record<string, unknown> } };

export const defaultQuery = (): QueryDraft => ({
  version: 1,
  mode: "AND",
  filters: [],
  orders: [],
  limit: "50",
});
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

/** Validate typed JSON recursively without converting int64 strings through Number. */
export const normalizeQueryValue = (
  value: unknown,
  root: string,
  depth = 0,
): Result<FsValue, string> => {
  if (depth > 32 || !object(value) || Object.keys(value).length !== 1)
    return err("one typed Firestore REST value is required (maximum depth 32)");
  const [key] = Object.keys(value);
  const raw = key === undefined ? undefined : value[key];
  if (
    key === "arrayValue" &&
    object(raw) &&
    (raw.values === undefined || Array.isArray(raw.values))
  ) {
    const values: FsValue[] = [];
    for (const item of (raw.values ?? []) as unknown[]) {
      const parsed = normalizeQueryValue(item, root, depth + 1);
      if (parsed.isErr()) return parsed;
      values.push(parsed.value);
    }
    return ok({ arrayValue: { values } });
  }
  if (key === "mapValue" && object(raw) && (raw.fields === undefined || object(raw.fields))) {
    const entries: [string, FsValue][] = [];
    for (const [name, item] of Object.entries(raw.fields ?? {})) {
      const parsed = normalizeQueryValue(item, root, depth + 1);
      if (parsed.isErr()) return parsed;
      entries.push([name, parsed.value]);
    }
    return ok({ mapValue: { fields: Object.fromEntries(entries) } });
  }
  if (key === "nullValue" && raw === null) return ok({ nullValue: null });
  if (key === "booleanValue" && typeof raw === "boolean") return ok({ booleanValue: raw });
  if (
    key === "geoPointValue" &&
    object(raw) &&
    typeof raw.latitude === "number" &&
    typeof raw.longitude === "number" &&
    Number.isFinite(raw.latitude) &&
    Number.isFinite(raw.longitude)
  )
    return parseField("geopoint", `${raw.latitude},${raw.longitude}`, root);
  const types: Record<string, QueryValueType> = {
    stringValue: "string",
    integerValue: "integer",
    doubleValue: "double",
    timestampValue: "timestamp",
    referenceValue: "reference",
    bytesValue: "bytes",
  };
  const type = key === undefined || !Object.hasOwn(types, key) ? undefined : types[key];
  if (type && (typeof raw === "string" || (type === "double" && typeof raw === "number")))
    return parseQueryValue(type, String(raw), root);
  return err("invalid typed Firestore REST value");
};

export const parseQueryValue = (
  type: QueryValueType,
  text: string,
  root: string,
): Result<FsValue, string> => {
  if (type === "integer") {
    if (!/^[+-]?\d+$/.test(text.trim())) return err("an integer is required");
    return parseField("number", text, root, "integer");
  }
  if (type === "double") {
    if (
      !["NaN", "Infinity", "-Infinity"].includes(text.trim()) &&
      !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(text.trim())
    )
      return err("a double is required");
    return parseField("number", text, root, "double");
  }
  if (type === "reference") {
    const full = text.trim().startsWith("projects/") ? text.trim() : `${root}/${text.trim()}`;
    if (!/^projects\/[^/]+\/databases\/[^/]+\/documents\/.+/.test(full))
      return err("a document reference is required");
    return parseField("reference", full, root);
  }
  if (type === "array" || type === "map") {
    let value: unknown;
    try {
      value = JSON.parse(text || (type === "array" ? "[]" : "{}")) as unknown;
    } catch {
      return err("valid typed REST JSON is required");
    }
    if (type === "array" && !Array.isArray(value))
      return err("a JSON array of typed REST values is required");
    if (type === "map" && !object(value))
      return err("a JSON object of typed REST values is required");
    return normalizeQueryValue(
      type === "array" ? { arrayValue: { values: value } } : { mapValue: { fields: value } },
      root,
    );
  }
  return parseField(type as FieldType, text, root);
};

/** Only encoding constraints are local; Firestore remains the query semantic authority. */
export const compileQuery = (
  root: string,
  collection: string,
  draft: QueryDraft,
): Result<CompiledQuery, string> => {
  const segments = collection.split("/");
  if (segments.length % 2 !== 1 || segments.some((segment) => !segment))
    return err("select a collection path with nonempty segments");
  if (!/^\d+$/.test(draft.limit) || Number(draft.limit) < 1 || Number(draft.limit) > 1000)
    return err("the result limit must be an integer from 1 through 1000");
  if (draft.filters.length > 20 || draft.orders.length > 20)
    return err("at most 20 conditions and 20 order fields are supported");
  const filters: unknown[] = [];
  for (const row of draft.filters) {
    if (!QUERY_OPERATORS.includes(row.op) || !QUERY_TYPES.includes(row.type))
      return err("unsupported condition operator or value type");
    if (!row.field.trim()) return err("a condition field path is required");
    const parsed = parseQueryValue(row.type, row.text, root);
    if (parsed.isErr()) return err(`${row.field}: ${parsed.error}`);
    const value = parsed.value;
    const candidates = row.op === "IN" || row.op === "NOT_IN" || row.op === "ARRAY_CONTAINS_ANY";
    if (candidates && (!("arrayValue" in value) || !value.arrayValue.values?.length))
      return err(`${row.op} requires a nonempty array of typed candidate values`);
    if (
      row.field.trim() === "__name__" &&
      (candidates
        ? !("arrayValue" in value) ||
          !value.arrayValue.values?.every((item) => "referenceValue" in item)
        : !("referenceValue" in value))
    )
      return err("__name__ requires document references");
    const unary =
      "nullValue" in value
        ? "NULL"
        : "doubleValue" in value && value.doubleValue === "NaN"
          ? "NAN"
          : null;
    if (unary !== null) {
      if (row.op !== "EQUAL" && row.op !== "NOT_EQUAL")
        return err("null and NaN require equality or inequality");
      filters.push({
        unaryFilter: {
          field: { fieldPath: row.field.trim() },
          op: `IS_${row.op === "NOT_EQUAL" ? "NOT_" : ""}${unary}`,
        },
      });
    } else
      filters.push({ fieldFilter: { field: { fieldPath: row.field.trim() }, op: row.op, value } });
  }
  for (const order of draft.orders)
    if (!order.field.trim()) return err("an order field path is required");
  const parent = segments.slice(0, -1).map(encodeURIComponent).join("/");
  return ok({
    path: `firestore/v1/${root.split("/").map(encodeURIComponent).join("/")}${parent ? `/${parent}` : ""}:runQuery`,
    body: {
      structuredQuery: {
        from: [{ collectionId: segments.at(-1) }],
        ...(filters.length === 0
          ? {}
          : {
              where:
                filters.length === 1
                  ? filters[0]
                  : { compositeFilter: { op: draft.mode, filters } },
            }),
        ...(draft.orders.length === 0
          ? {}
          : {
              orderBy: draft.orders.map((row) => ({
                field: { fieldPath: row.field.trim() },
                direction: row.direction,
              })),
            }),
        limit: Number(draft.limit),
      },
    },
  });
};

export const encodeSharedQuery = (draft: QueryDraft): string => JSON.stringify(draft);
export const decodeSharedQuery = (text: string): Result<QueryDraft, string> => {
  if (new TextEncoder().encode(text).length > 32768) return err("shared query exceeds 32 KiB");
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return err("invalid shared query JSON");
  }
  if (
    !object(value) ||
    value.version !== 1 ||
    typeof value.mode !== "string" ||
    !["AND", "OR"].includes(value.mode) ||
    typeof value.limit !== "string" ||
    !Array.isArray(value.filters) ||
    !Array.isArray(value.orders) ||
    value.filters.length > 20 ||
    value.orders.length > 20
  )
    return err("invalid shared query definition");
  if (
    !value.filters.every(
      (row) =>
        object(row) &&
        typeof row.field === "string" &&
        typeof row.text === "string" &&
        QUERY_OPERATORS.includes(row.op as QueryOperator) &&
        QUERY_TYPES.includes(row.type as QueryValueType),
    )
  )
    return err("invalid shared query condition");
  if (
    !value.orders.every(
      (row) =>
        object(row) &&
        typeof row.field === "string" &&
        typeof row.direction === "string" &&
        ["ASCENDING", "DESCENDING"].includes(row.direction),
    )
  )
    return err("invalid shared query order");
  return ok({
    version: 1,
    mode: value.mode as "AND" | "OR",
    filters: (value.filters as QueryFilter[]).map(({ field, op, type, text }) => ({
      field,
      op,
      type,
      text,
    })),
    orders: (value.orders as QueryOrder[]).map(({ field, direction }) => ({ field, direction })),
    limit: value.limit,
  });
};
