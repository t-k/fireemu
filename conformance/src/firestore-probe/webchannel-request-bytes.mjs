import { normalizeRecordedResponse } from "./production-normalization.mjs";

export const WEBCHANNEL_PATH =
  "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8&RID=1&SID=missing-fireemu-byte-probe&AID=0";

export function makeWebChannelFormBody(targetBytes) {
  if (![10_485_760, 10_485_761].includes(targetBytes)) {
    throw new Error("unsupported WebChannel byte target");
  }
  const prefix = "count=0&pad=";
  const body = prefix + "a".repeat(targetBytes - Buffer.byteLength(prefix));
  if (Buffer.byteLength(body) !== targetBytes) throw new Error("WebChannel body size differs");
  return body;
}

export function projectWebChannelResponse(status, text) {
  const message = normalizeRecordedResponse(text.slice(0, 400), {
    project: "fireemu-oracle-sbx",
    recordProject: "demo-firestore-probe",
    scope: "error",
  });
  if (status >= 200 && status < 300) {
    return { status, code: "OK", body: message };
  }
  let error;
  try {
    error = JSON.parse(text).error;
  } catch {
    // WebChannel may answer with a framed or plain-text transport error.
  }
  return {
    status,
    code: typeof error?.status === "string" ? error.status : "WEBCHANNEL_HTTP",
    message: error?.message
      ? normalizeRecordedResponse(String(error.message).slice(0, 400), {
          project: "fireemu-oracle-sbx",
          recordProject: "demo-firestore-probe",
          scope: "error",
        })
      : message,
  };
}
