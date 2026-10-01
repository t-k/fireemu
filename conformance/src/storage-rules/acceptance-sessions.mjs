import { decimal, isObject, jsonBody, result, secretResult, single, unexpected } from "./acceptance-core.mjs";

// Firebase Storage object-token creation and the resumable upload protocol. The session URL and the download token are
// bearer capabilities: they come back only in a non-enumerable secret, never in a fact.
const SESSION_ORIGIN = "https://firebasestorage.googleapis.com";
const SESSION_KEYS = ["name", "upload_id", "upload_protocol", "uploadType"];
const MAX_RECEIVED = 4;

function bucketOf(row, prefix) {
  const match = new RegExp(`^${prefix}/b/([^/]+)/o(?:/|$)`).exec(row.request.path ?? "");
  return match ? match[1] : null;
}

function sessionUrl(text, bucket, objectName) {
  let url;
  try { url = new URL(text); } catch { return false; }
  if (url.origin !== SESSION_ORIGIN || url.protocol !== "https:" || url.username || url.password || url.hash || url.port || url.pathname !== `/v0/b/${bucket}/o` || url.href !== text) return false;
  const seen = new Map();
  for (const [key, value] of url.searchParams) { if (seen.has(key) || !SESSION_KEYS.includes(key)) return false; seen.set(key, value); }
  return seen.get("name") === objectName && seen.get("upload_protocol") === "resumable" && /^[A-Za-z0-9._-]{8,256}$/.test(seen.get("upload_id") ?? "");
}

export const SESSION_CLASSIFIERS = {
  "firebase-create-token": (row, response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    const bucket = bucketOf(row, "/v0");
    if (isObject(body) && bucket !== null && body.name === row.request.objectName && body.bucket === bucket && decimal(body.generation) && decimal(body.metageneration) && typeof body.downloadTokens === "string" && body.downloadTokens !== "") {
      return secretResult("firebase-create-token", "accepted", { status: 200, generation: body.generation, metageneration: body.metageneration, hasDownloadToken: true }, { downloadTokens: body.downloadTokens });
    }
    return unexpected("firebase-create-token", response);
  },
  "session-start": (row, response) => {
    const url = single(response.headers, "x-goog-upload-url");
    const status = single(response.headers, "x-goog-upload-status");
    const bucket = bucketOf(row, "/v0");
    if (response.status === 200 && status === "active" && typeof url === "string" && bucket !== null && sessionUrl(url, bucket, row.request.objectName)) {
      return secretResult("session-start", "accepted", { status: 200, uploadStatus: "active" }, { sessionUrl: url });
    }
    return unexpected("session-start", response);
  },
  "session-command": (row, response) => {
    const command = row.request.headers?.["x-goog-upload-command"];
    const status = single(response.headers, "x-goog-upload-status");
    if (response.status !== 200 || response.bytes.length !== 0) return unexpected("session-command", response);
    if (command === "query") {
      const received = single(response.headers, "x-goog-upload-size-received");
      if ((status === "active" || status === "final") && typeof received === "string" && /^(?:0|[1-9]\d{0,3})$/.test(received) && Number(received) <= MAX_RECEIVED) {
        return result("session-command", status, { status: 200, uploadStatus: status, sizeReceived: Number(received) });
      }
    }
    if (command === "cancel" && (status === undefined || status === "cancelled")) return result("session-command", "acknowledged", { status: 200 });
    return unexpected("session-command", response);
  },
};
