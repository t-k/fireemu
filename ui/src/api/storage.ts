import type { ResultAsync } from "neverthrow";
import { request, requestBytes, type ApiError, type Json } from "./client";

export type BucketInfo = { name: string; project: string; default: boolean };

export type ObjectInfo = {
  name: string;
  bucket: string;
  size: string;
  contentType: string;
  generation: string;
  metageneration: string;
  timeCreated: string;
  updated: string;
  md5Hash?: string;
  crc32c?: string;
  etag?: string;
  metadata?: Record<string, string>;
};

export type ObjectPage = { items?: ObjectInfo[]; prefixes?: string[]; nextPageToken?: string };

const bucketUrl = (bucket: string): string => `storage/storage/v1/b/${encodeURIComponent(bucket)}`;

export const listBuckets = (project: string): ResultAsync<{ buckets: BucketInfo[] }, ApiError> =>
  request("GET", `storage/buckets?project=${encodeURIComponent(project)}`);

/** One page of objects directly under `prefix` (folders come back as `prefixes`). */
export const listObjects = (
  bucket: string,
  prefix: string,
  pageToken?: string,
): ResultAsync<ObjectPage, ApiError> => {
  const params = new URLSearchParams({ delimiter: "/", maxResults: "100" });
  if (prefix) {
    params.set("prefix", prefix);
  }
  if (pageToken) {
    params.set("pageToken", pageToken);
  }
  return request<ObjectPage>("GET", `${bucketUrl(bucket)}/o?${params.toString()}`);
};

export const getObject = (bucket: string, name: string): ResultAsync<ObjectInfo, ApiError> =>
  request<ObjectInfo>("GET", `${bucketUrl(bucket)}/o/${encodeURIComponent(name)}`);

export const deleteObject = (bucket: string, name: string): ResultAsync<Json, ApiError> =>
  request("DELETE", `${bucketUrl(bucket)}/o/${encodeURIComponent(name)}`);

export const uploadObject = (
  bucket: string,
  name: string,
  file: File,
): ResultAsync<ObjectInfo, ApiError> => {
  const params = new URLSearchParams({ uploadType: "media", name });
  return request<ObjectInfo>(
    "POST",
    `storage/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?${params.toString()}`,
    undefined,
    { headers: { "content-type": file.type || "application/octet-stream" }, raw: file },
  );
};

export const downloadObject = (
  bucket: string,
  name: string,
): ResultAsync<{ blob: Blob; contentType: string }, ApiError> =>
  requestBytes(
    `storage/download/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(name)}?alt=media`,
  );
