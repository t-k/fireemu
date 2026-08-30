import { err, ok, ResultAsync, type Result } from "neverthrow";
import { request, type ApiError, type Json } from "./client";
import type { FsDocument, FsValue } from "../lib/firestoreValue";

/** `projects/{p}/databases/{d}/documents`. */
export const documentsRoot = (project: string, database: string): string =>
  `projects/${project}/databases/${database}/documents`;

const encodePath = (path: string): string =>
  path
    .split("/")
    .map((s) => encodeURIComponent(s))
    .join("/");

const url = (root: string, path: string): string =>
  `firestore/v1/${root}${path ? `/${encodePath(path)}` : ""}`;

export type DocumentPage = { documents?: FsDocument[]; nextPageToken?: string };

/** The collection IDs under `parent` (`""` for the root). */
export const listCollectionIds = (
  root: string,
  parent: string,
): ResultAsync<{ collectionIds?: string[]; nextPageToken?: string }, ApiError> =>
  request("POST", `${url(root, parent)}:listCollectionIds`, { pageSize: 300 });

/** One page of documents of a collection (missing documents included). */
export const listDocuments = (
  root: string,
  collection: string,
  pageToken?: string,
): ResultAsync<DocumentPage, ApiError> => {
  const params = new URLSearchParams({ pageSize: "50", showMissing: "true" });
  if (pageToken) {
    params.set("pageToken", pageToken);
  }
  return request<DocumentPage>("GET", `${url(root, collection)}?${params.toString()}`);
};

export const getDocument = (root: string, path: string): ResultAsync<FsDocument, ApiError> =>
  request<FsDocument>("GET", url(root, path));

/** Replaces the whole document (creates it when missing). */
export const setDocument = (
  root: string,
  path: string,
  fields: Record<string, FsValue>,
): ResultAsync<FsDocument, ApiError> => request<FsDocument>("PATCH", url(root, path), { fields });

/** Creates a document in `collection` (`documentId` empty: a generated ID). */
export const createDocument = (
  root: string,
  collection: string,
  documentId: string,
  fields: Record<string, FsValue>,
): ResultAsync<FsDocument, ApiError> => {
  const query = documentId ? `?documentId=${encodeURIComponent(documentId)}` : "";
  return request<FsDocument>("POST", `${url(root, collection)}${query}`, { fields });
};

export const deleteDocument = (root: string, path: string): ResultAsync<Json, ApiError> =>
  request("DELETE", url(root, path));

const commitDeletes = (root: string, names: string[]): ResultAsync<Json, ApiError> =>
  request("POST", `firestore/v1/${root}:commit`, {
    writes: names.map((name) => ({ delete: name })),
  });

const chunk = <T>(items: T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
};

const exists = (d: FsDocument): boolean => d.createTime !== undefined || d.fields !== undefined;

/**
 * Deletes every document of a collection and, recursively, their subcollections, in
 * commits of at most 100 deletes. Resolves to the number of documents deleted.
 */
export const deleteCollection = (
  root: string,
  collection: string,
  onProgress?: (deleted: number) => void,
): ResultAsync<number, ApiError> => {
  let deleted = 0;
  const walk = async (path: string): Promise<ApiError | null> => {
    let pageToken: string | undefined;
    do {
      const page = await listDocuments(root, path, pageToken);
      if (page.isErr()) {
        return page.error;
      }
      const docs = page.value.documents ?? [];
      for (const d of docs) {
        const rel = d.name.slice(d.name.indexOf("/documents/") + "/documents/".length);
        const subs = await listCollectionIds(root, rel);
        if (subs.isErr()) {
          return subs.error;
        }
        for (const id of subs.value.collectionIds ?? []) {
          const failure = await walk(`${rel}/${id}`);
          if (failure) {
            return failure;
          }
        }
      }
      const names = docs.filter(exists).map((d) => d.name);
      for (const group of chunk(names, 100)) {
        const r = await commitDeletes(root, group);
        if (r.isErr()) {
          return r.error;
        }
        deleted += group.length;
        onProgress?.(deleted);
      }
      pageToken = page.value.nextPageToken;
    } while (pageToken);
    return null;
  };
  const run = async (): Promise<Result<number, ApiError>> => {
    const failure = await walk(collection);
    return failure ? err(failure) : ok(deleted);
  };
  return ResultAsync.fromSafePromise(run()).andThen((r) => r);
};
