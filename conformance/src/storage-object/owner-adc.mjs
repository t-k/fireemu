import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute } from "node:path";
import { types } from "node:util";
import { parseCaptureJsonSpans } from "./production-capture-body.mjs";

const MAX_ADC_BYTES = 64 * 1024;
const INPUT_KEYS = ["path", "expectedSha256", "expectedClientId", "expectedQuotaProjectId"];
const ADC_KEYS = new Set([
  "type",
  "client_id",
  "client_secret",
  "refresh_token",
  "quota_project_id",
  "universe_domain",
  "account",
]);
const ascii = (value, maximum) =>
  typeof value === "string" && value.length <= maximum && /^[\x21-\x7e]+$/.test(value);

function pinnedInput(input) {
  if (
    !input ||
    types.isProxy(input) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(input)) ||
    Reflect.ownKeys(input).length !== INPUT_KEYS.length
  )
    throw new Error();
  const copy = {};
  for (const key of INPUT_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error();
    copy[key] = descriptor.value;
  }
  if (
    typeof copy.path !== "string" ||
    !isAbsolute(copy.path) ||
    copy.path.length > 4096 ||
    copy.path.includes("\0") ||
    typeof copy.expectedSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(copy.expectedSha256) ||
    !ascii(copy.expectedClientId, 512) ||
    typeof copy.expectedQuotaProjectId !== "string" ||
    !/^[a-z][a-z0-9-]{4,29}$/.test(copy.expectedQuotaProjectId)
  )
    throw new Error();
  return copy;
}

/** Read the pinned authorized_user file once without a snapshot. Only the receipt is serializable. */
export function readProductionOwnerAdc(input) {
  let descriptor,
    bytes,
    result,
    failed = false;
  try {
    const pinned = pinnedInput(input);
    if (!Number.isSafeInteger(constants.O_NOFOLLOW)) throw new Error();
    descriptor = openSync(
      pinned.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const before = fstatSync(descriptor, { bigint: true });
    if (
      !before.isFile() ||
      before.uid !== BigInt(process.getuid()) ||
      (before.mode & 0o077n) !== 0n ||
      before.size < 1n ||
      before.size > BigInt(MAX_ADC_BYTES)
    )
      throw new Error();
    bytes = Buffer.alloc(MAX_ADC_BYTES + 1);
    let count = 0;
    while (count < bytes.length) {
      const read = readSync(descriptor, bytes, count, bytes.length - count, null);
      if (read === 0) break;
      count += read;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (
      count !== Number(before.size) ||
      ["dev", "ino", "mode", "uid", "size", "mtimeNs", "ctimeNs"].some(
        (key) => before[key] !== after[key],
      )
    )
      throw new Error();
    const original = bytes.subarray(0, count);
    const sha256 = createHash("sha256").update(original).digest("hex");
    if (sha256 !== pinned.expectedSha256) throw new Error();
    const text = original.toString("utf8");
    if (!Buffer.from(text).equals(original)) throw new Error();
    if (parseCaptureJsonSpans(text).type !== "object") throw new Error();
    const adc = JSON.parse(text);
    if (
      Object.keys(adc).some((key) => !ADC_KEYS.has(key)) ||
      adc.type !== "authorized_user" ||
      adc.client_id !== pinned.expectedClientId ||
      !ascii(adc.client_secret, 1024) ||
      !ascii(adc.refresh_token, 8192) ||
      (Object.hasOwn(adc, "quota_project_id") &&
        adc.quota_project_id !== pinned.expectedQuotaProjectId) ||
      (Object.hasOwn(adc, "universe_domain") && adc.universe_domain !== "googleapis.com") ||
      (Object.hasOwn(adc, "account") &&
        (typeof adc.account !== "string" || adc.account.length > 512))
    )
      throw new Error();
    let disposed = false;
    result = Object.freeze({
      receipt: Object.freeze({
        sha256,
        type: "authorized_user",
        clientId: adc.client_id,
        quotaProjectId: adc.quota_project_id ?? null,
      }),
      exchangeBody() {
        if (disposed) throw new Error("owner ADC is unavailable");
        return Buffer.from(
          new URLSearchParams({
            grant_type: "refresh_token",
            client_id: adc.client_id,
            client_secret: adc.client_secret,
            refresh_token: adc.refresh_token,
          }).toString(),
        );
      },
      dispose() {
        adc.client_secret = "";
        adc.refresh_token = "";
        disposed = true;
      },
    });
  } catch {
    failed = true;
  } finally {
    bytes?.fill(0);
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        failed = true;
      }
    }
  }
  if (failed) throw new Error("owner ADC is unavailable");
  return result;
}
