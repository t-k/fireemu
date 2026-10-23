import { err, ok, ResultAsync, type Result } from "neverthrow";
import { controlToken } from "../config";
import { normalizeQueryValue, type CompiledQuery } from "../lib/firestoreQuery";
import type { FsDocument, FsValue } from "../lib/firestoreValue";
import { parseApiError, type ApiError } from "./client";

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const hasError = (value: unknown): boolean => object(value) && "error" in value;
const errorFrom = (status: number, body: unknown): ApiError => {
  if (Array.isArray(body)) {
    const errors = body.filter(hasError).map((item) => parseApiError(status, item));
    if (errors.length)
      return { ...errors[0]!, message: errors.map((item) => item.message).join("\n") };
  }
  if (typeof body === "string") return { status, message: body || `HTTP ${status}` };
  return parseApiError(status, body);
};

/** runQuery errors are arrays; this transport retains their real HTTP and RPC failures. */
const queryRequest = (
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): ResultAsync<unknown, ApiError> =>
  ResultAsync.fromPromise(
    (async (): Promise<Result<unknown, ApiError>> => {
      const token = controlToken();
      const response = await fetch(`/ui/api/${path}`, {
        method,
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        ...(signal ? { signal } : {}),
      });
      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        parsed = text;
      }
      if (!response.ok || hasError(parsed) || (Array.isArray(parsed) && parsed.some(hasError)))
        return err(errorFrom(response.status, parsed));
      return ok(parsed);
    })(),
    (error): ApiError => ({
      status: 0,
      message: error instanceof Error ? error.message : String(error),
    }),
  ).andThen((result) => result);

export type QueryResults = {
  rows: Record<string, unknown>[];
  documents: FsDocument[];
  metadata: Record<string, unknown>[];
};
const malformed = (message: string): Result<never, ApiError> =>
  err({ status: 0, code: "INVALID_RESPONSE", message: `Malformed query response: ${message}` });

export const parseQueryResults = (body: unknown): Result<QueryResults, ApiError> => {
  if (!Array.isArray(body)) return malformed("expected an array of stream rows");
  const rows: Record<string, unknown>[] = [];
  const documents: FsDocument[] = [];
  const metadata: Record<string, unknown>[] = [];
  for (const row of body) {
    if (!object(row)) return malformed("expected an object stream row");
    rows.push(row);
    if (row.document !== undefined) {
      const document = row.document;
      if (
        !object(document) ||
        typeof document.name !== "string" ||
        !/^projects\/[^/]+\/databases\/[^/]+\/documents\/.+/.test(document.name)
      )
        return malformed("document has no valid name");
      const fields: [string, FsValue][] = [];
      if (document.fields !== undefined) {
        if (!object(document.fields)) return malformed("document fields must be typed values");
        const root = document.name.split("/documents/")[0] + "/documents";
        for (const [field, value] of Object.entries(document.fields)) {
          const checked = normalizeQueryValue(value, root);
          if (checked.isErr()) return malformed(`${field}: ${checked.error}`);
          fields.push([field, checked.value]);
        }
      }
      if (
        (document.createTime !== undefined && typeof document.createTime !== "string") ||
        (document.updateTime !== undefined && typeof document.updateTime !== "string")
      )
        return malformed("document timestamps must be strings");
      documents.push({
        name: document.name,
        ...(document.fields === undefined ? {} : { fields: Object.fromEntries(fields) }),
        ...(typeof document.createTime === "string" ? { createTime: document.createTime } : {}),
        ...(typeof document.updateTime === "string" ? { updateTime: document.updateTime } : {}),
      });
    } else {
      if (
        !(
          typeof row.readTime === "string" ||
          typeof row.skippedResults === "number" ||
          typeof row.transaction === "string" ||
          object(row.explainMetrics)
        )
      )
        return malformed("unrecognized metadata-only row");
      metadata.push(row);
    }
  }
  return ok({ rows, documents, metadata });
};

export const runQuery = (
  query: CompiledQuery,
  signal?: AbortSignal,
): ResultAsync<QueryResults, ApiError> =>
  queryRequest("POST", query.path, query.body, signal).andThen(parseQueryResults);

export type MissingIndex = {
  project: string;
  database: string;
  name: string;
  index: unknown;
  message: string;
};
export type MissingIndexReports = {
  missingIndexes: MissingIndex[];
  indexesJson: Record<string, unknown>;
  truncated: boolean;
  dropped: number;
};

/** Never reads the global report or clears records; selected database filtering is explicit. */
export const loadMissingIndexes = (
  session: string,
  root: string,
  signal?: AbortSignal,
): ResultAsync<MissingIndexReports, ApiError> =>
  queryRequest(
    "GET",
    `control/v1/sessions/${encodeURIComponent(session)}/firestore/missingIndexes`,
    undefined,
    signal,
  ).andThen((body) => {
    if (
      !object(body) ||
      !Array.isArray(body.missingIndexes) ||
      typeof body.truncated !== "boolean" ||
      typeof body.dropped !== "number" ||
      !Number.isSafeInteger(body.dropped) ||
      body.dropped < 0 ||
      !object(body.indexesJson)
    )
      return malformed("invalid missing-index report");
    const entries: MissingIndex[] = [];
    for (const item of body.missingIndexes) {
      if (
        !object(item) ||
        typeof item.project !== "string" ||
        typeof item.database !== "string" ||
        typeof item.name !== "string" ||
        typeof item.message !== "string" ||
        !("index" in item)
      )
        return malformed("invalid missing-index entry");
      if (item.name === root.replace(/\/documents$/, ""))
        entries.push({
          project: item.project,
          database: item.database,
          name: item.name,
          message: item.message,
          index: item.index,
        });
    }
    const name = root.replace(/\/documents$/, "");
    return ok({
      missingIndexes: entries,
      indexesJson: Object.hasOwn(body.indexesJson, name) ? { [name]: body.indexesJson[name] } : {},
      truncated: body.truncated,
      dropped: body.dropped,
    });
  });
