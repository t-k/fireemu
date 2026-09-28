import {
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  openSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";

export function writePrivateBytes(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (!written) throw new Error("private wire capture write failed");
    offset += written;
  }
}

export function writePrivateExclusive(path, bytes) {
  const fd = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writePrivateBytes(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function privateCaptureDirectory(directory) {
  const stat = lstatSync(directory);
  if (
    !stat.isDirectory() ||
    (stat.mode & 0o777) !== 0o700 ||
    (typeof process.getuid === "function" && stat.uid !== process.getuid())
  )
    throw new Error("invalid private wire capture directory");
  return realpathSync(directory);
}

/** Private binary captures must be created before dispatch, with bounded synchronous response writes. */
export function createPrivateWireAttempt({ directory, sequence, request, metadata }) {
  let responseFd;
  try {
    const parent = privateCaptureDirectory(directory);
    if (
      !Number.isSafeInteger(sequence) ||
      sequence < 1 ||
      sequence > 999999 ||
      !Buffer.isBuffer(request)
    )
      throw new Error("invalid private wire capture");
    const stem = String(sequence).padStart(6, "0");
    const files = Object.freeze({
      request: join(parent, `${stem}-request.bin`),
      response: join(parent, `${stem}-response.bin`),
      intent: join(parent, `${stem}-intent.json`),
      result: join(parent, `${stem}-result.json`),
    });
    writePrivateExclusive(files.request, request);
    writePrivateExclusive(
      files.intent,
      Buffer.from(`${JSON.stringify({ sequence, ...metadata })}\n`),
    );
    responseFd = openSync(
      files.response,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    let closed = false;
    return Object.freeze({
      files,
      appendResponse(bytes) {
        if (closed) throw new Error("private wire capture is closed");
        try {
          if (!Buffer.isBuffer(bytes)) throw new Error("invalid private wire capture");
          writePrivateBytes(responseFd, bytes);
        } catch {
          throw new Error("private wire capture write failed");
        }
      },
      finish(receipt) {
        if (closed) throw new Error("private wire capture is closed");
        closed = true;
        try {
          fsyncSync(responseFd);
        } finally {
          closeSync(responseFd);
        }
        try {
          writePrivateExclusive(files.result, Buffer.from(`${JSON.stringify(receipt)}\n`));
        } catch {
          throw new Error("private wire capture receipt failed");
        }
      },
    });
  } catch {
    if (responseFd !== undefined) closeSync(responseFd);
    throw new Error("private wire capture creation failed");
  }
}
