// Current local-only wire receipt. Raw body bytes stay in the owned private directory.
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
let serial = 0;
export const HTTP_CONTRACT = "bounded-http-v1";

export async function receiveHttp(
  input,
  options,
  { origin, privateDirectory, maxBytes = 2 * 1024 * 1024 },
) {
  const target = new URL(input);
  if (
    target.origin !== origin ||
    target.protocol !== "http:" ||
    target.hostname !== "127.0.0.1" ||
    Number(target.port) < 1024 ||
    target.username ||
    target.password
  ) {
    throw new Error("request escapes owned origin");
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 2 * 1024 * 1024)
    throw new Error("invalid wire limit");
  const signal = AbortSignal.any([options.signal, AbortSignal.timeout(5000)].filter(Boolean));
  let response,
    failure = null,
    receivedBytes = 0,
    storedBytes = 0;
  const chunks = [];
  try {
    response = await fetch(input, { ...options, signal, redirect: "error" });
    const reader = response.body?.getReader();
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        receivedBytes += value.byteLength;
        const kept = value.subarray(0, Math.max(0, maxBytes - storedBytes));
        chunks.push(kept);
        storedBytes += kept.byteLength;
        if (receivedBytes > maxBytes) {
          failure = "size-limit";
          await reader.cancel();
          break;
        }
      }
    }
  } catch {
    failure ??= signal.aborted
      ? signal.reason?.name === "TimeoutError"
        ? "timeout"
        : "aborted"
      : response
        ? "body-interrupted"
        : "connection-failure";
  }
  const bytes = Buffer.concat(chunks, storedBytes);
  let body,
    bodyKind = "unavailable";
  if (failure === null) {
    bodyKind = bytes.length === 0 ? "empty" : "non-json";
    if (bytes.length) {
      try {
        body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        bodyKind = "json";
      } catch {
        /* Preserve non-JSON as received bytes, not a network failure. */
      }
    }
  }
  await mkdir(privateDirectory, { recursive: true, mode: 0o700 });
  const privateFile = `body-${++serial}.bin`;
  await writeFile(join(privateDirectory, privateFile), bytes, { mode: 0o600, flag: "wx" });
  const contentType = response?.headers.get("content-type") ?? "";
  return {
    http: {
      contract: HTTP_CONTRACT,
      status: response?.status ?? null,
      contentType: contentType.slice(0, 512),
      contentTypeTruncated: contentType.length > 512,
      bodyKind,
      receivedBytes,
      retainedBytes: storedBytes,
      bodySha256: createHash("sha256").update(bytes).digest("hex"),
      digestScope: failure === null ? "full" : "prefix",
      complete: failure === null,
      failure,
      truncated: failure !== null,
    },
    body,
    privateFile,
  };
}
