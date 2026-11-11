// Classifies one REST answer. A status below 200, a 3xx, a 5xx, a transport timeout, a cancelled call
// and an unreadable body are all unknown (lane guide section 5); a complete 2xx or a listed error with
// its matching body is known. The latency class separates a cached 404 (11-51 ms recorded) from a
// forwarded one (147 ms or more recorded).

import { normalizeOutcome } from "../pubsub-production/outcome.mjs";

export const FAST_MS = 60;
export const SLOW_MS = 120;

export function latencyClass(headersMs) {
  if (!Number.isFinite(headersMs) || headersMs < 0) return "unknown";
  if (headersMs <= FAST_MS) return "fast";
  if (headersMs >= SLOW_MS) return "slow";
  return "ambiguous";
}

/**
 * @param {{status?:number, bodyText?:string, failure?:string, headersMs?:number}} raw
 * @returns {{kind:'ok'|'error'|'unknown', status:number|null, code:string|null, body:any, latency:string}}
 */
export function classify(raw) {
  const latency = latencyClass(raw.headersMs);
  const unknown = (status = null) => ({ kind: "unknown", status, code: null, body: null, latency });
  if (raw.failure || !Number.isInteger(raw.status)) return unknown();
  let body;
  try {
    body = raw.bodyText === "" || raw.bodyText === undefined ? {} : JSON.parse(raw.bodyText);
  } catch {
    return unknown(raw.status);
  }
  if (raw.status < 200 || raw.status >= 300) {
    const code = body?.error?.status ?? null;
    const outcome = normalizeOutcome({ ok: false, code, status: raw.status, body });
    if (outcome.unknown) return unknown(raw.status);
    return { kind: "error", status: raw.status, code, body, latency };
  }
  const outcome = normalizeOutcome({ ok: true, code: "OK", status: raw.status, body });
  if (outcome.unknown || "done" in body) return unknown(raw.status);
  return { kind: "ok", status: raw.status, code: "OK", body, latency };
}
