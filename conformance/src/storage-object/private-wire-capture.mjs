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

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset);
    if (!written) throw new Error("private wire capture write failed");
    offset += written;
  }
}

function writeExclusive(path, bytes) {
  const fd = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeAll(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Private binary captures must be created before dispatch, with bounded synchronous response writes. */
export function createPrivateWireAttempt({ directory, sequence, request, metadata }) {
  let responseFd;
  try {
    const stat = lstatSync(directory);
    if (
      !stat.isDirectory() ||
      (stat.mode & 0o777) !== 0o700 ||
      (typeof process.getuid === "function" && stat.uid !== process.getuid()) ||
      !Number.isSafeInteger(sequence) ||
      sequence < 1 ||
      sequence > 999999 ||
      !Buffer.isBuffer(request)
    )
      throw new Error("invalid private wire capture");
    const parent = realpathSync(directory);
    const stem = String(sequence).padStart(6, "0");
    const files = Object.freeze({
      request: join(parent, `${stem}-request.bin`),
      response: join(parent, `${stem}-response.bin`),
      intent: join(parent, `${stem}-intent.json`),
      result: join(parent, `${stem}-result.json`),
    });
    writeExclusive(files.request, request);
    writeExclusive(files.intent, Buffer.from(`${JSON.stringify({ sequence, ...metadata })}\n`));
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
          writeAll(responseFd, bytes);
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
          writeExclusive(files.result, Buffer.from(`${JSON.stringify(receipt)}\n`));
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
