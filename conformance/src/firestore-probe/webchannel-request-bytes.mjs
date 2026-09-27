import { normalizeRecordedResponse } from "./production-normalization.mjs";

export const WEBCHANNEL_PATH =
  "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8&RID=1&SID=missing-fireemu-byte-probe&AID=0";

const CHANNEL =
  "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8";
const SESSION = "SID={{handshake.sid}}&AID=0&gsessionid={{handshake.gsessionid}}";
const CONTROL_BODY_BYTES = 13;
/**
 * The bracket recording's pair at the REST Commit bound, then the follow-up's ladder above it:
 * 12 MiB and the exact pairs at 16 MiB and 32 MiB.
 */
export const WEBCHANNEL_SESSION_SIZES = Object.freeze([
  11_534_336, 11_534_337, 12_582_912, 16_777_216, 16_777_217, 33_554_432, 33_554_433,
]);
const FORM_BODY_SIZES = new Set([
  CONTROL_BODY_BYTES,
  10_485_760,
  10_485_761,
  ...WEBCHANNEL_SESSION_SIZES,
]);

/**
 * One valid WebChannel session per size: open it, send a small control message, send the
 * measured form body, and terminate it. The SID and session header are captured at run time
 * and substituted into the later paths; they are never recorded.
 */
export function webchannelSessionProgram(size) {
  if (!WEBCHANNEL_SESSION_SIZES.includes(size)) {
    throw new Error("unsupported WebChannel session size");
  }
  return {
    id: `writes/limits/webchannel-request-bytes/${size}`,
    area: "writes",
    steps: [
      {
        id: "handshake",
        method: "POST",
        path: `${CHANNEL}&RID=1&CVER=22&X-HTTP-Session-Id=gsessionid`,
        webchannelSession: "handshake",
      },
      {
        id: "control",
        method: "POST",
        path: `${CHANNEL}&RID=2&${SESSION}`,
        webchannelSession: "control",
        webchannelBodyBytes: CONTROL_BODY_BYTES,
      },
      {
        id: "boundary",
        method: "POST",
        path: `${CHANNEL}&RID=3&${SESSION}`,
        webchannelSession: "boundary",
        webchannelBodyBytes: size,
      },
      {
        id: "terminate",
        method: "GET",
        path: `${CHANNEL}&RID=4&${SESSION}&TYPE=terminate`,
        webchannelSession: "terminate",
      },
    ],
  };
}

/** The opening request carries the Write stream's first message: the database only. */
export function makeWebChannelHandshakeBody() {
  const data = encodeURIComponent(
    JSON.stringify({ database: "projects/fireemu-oracle-sbx/databases/(default)" }),
  )
    .replaceAll("(", "%28")
    .replaceAll(")", "%29");
  return `count=1&ofs=0&req0___data__=${data}`;
}

/** The first length-prefixed chunk; the length counts UTF-16 code units. */
function parseFrame(text) {
  const match = /^(\d+)\n/.exec(text);
  if (!match) return undefined;
  const length = Number(match[1]);
  const payload = text.slice(match[0].length, match[0].length + length);
  if (payload.length !== length) return undefined;
  try {
    return JSON.parse(payload);
  } catch {
    return undefined;
  }
}

/** The SID from the opening frame and the session header; null when the session did not open. */
export function parseWebChannelOpening(status, sessionHeader, text) {
  if (status !== 200) return null;
  if (typeof sessionHeader !== "string" || !/^[A-Za-z0-9_-]{4,256}$/.test(sessionHeader)) {
    return null;
  }
  const frame = parseFrame(text);
  const data = Array.isArray(frame) && frame[0]?.[0] === 0 ? frame[0][1] : undefined;
  const sid = data?.[1];
  if (data?.[0] !== "c" || typeof sid !== "string" || !/^[A-Za-z0-9_-]{12,256}$/.test(sid)) {
    return null;
  }
  return { sid, gsessionid: sessionHeader };
}

/**
 * `[backchannelAttached, lastArrayId, pendingBytes]`. The last value counts bytes waiting on the
 * back channel, which this probe never opens, so any non-negative count is an acknowledgement.
 */
function isForwardAck(text) {
  const value = parseFrame(text);
  return (
    Array.isArray(value) &&
    value.length === 3 &&
    [0, 1].includes(value[0]) &&
    [value[1], value[2]].every((count) => Number.isSafeInteger(count) && count >= 0)
  );
}

function redactSession(text, session) {
  let out = text;
  for (const value of [session?.sid, session?.gsessionid]) {
    if (typeof value === "string" && value.length > 0) out = out.split(value).join("<session>");
  }
  return out;
}

/** A session step recorded by shape; a refusal keeps its message without session identifiers. */
export function projectWebChannelSessionStep(kind, status, text, session) {
  if (!["handshake", "control", "boundary", "terminate"].includes(kind)) {
    throw new Error("unsupported WebChannel session step");
  }
  if (status >= 200 && status < 300) {
    if (kind === "handshake") {
      return { status, code: "OK", body: session ? "session-opened" : "unparsed-opening" };
    }
    if (kind === "terminate") return { status, code: "OK", body: "session-terminated" };
    return {
      status,
      code: "OK",
      body: isForwardAck(text) ? "forward-ack" : "unexpected-forward-answer",
    };
  }
  return projectWebChannelResponse(status, redactSession(text, session));
}

export function makeWebChannelFormBody(targetBytes) {
  if (!FORM_BODY_SIZES.has(targetBytes)) {
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
