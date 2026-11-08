// The guarded transport of the Storage Rules observation: every request is classified, counted
// against the budget and journaled before it leaves the process. A mutating call whose answer is
// unknown throws and is never retried; a read may be recorded as unknown and the run goes on.

import { Buffer } from "node:buffer";

import { classifyRequest, isUnknownStatus } from "./guard.mjs";
import { REQUEST_TIMEOUT_MS } from "./plan.mjs";

export class UnknownAnswer extends Error {
  constructor(label, status) {
    super(`unknown answer: ${label} (${Number.isInteger(status) ? status : "transport"})`);
    this.label = label;
    this.status = Number.isInteger(status) ? status : Number.NaN;
  }
}

export function createWire({ target, state, budget, deps, out }) {
  const unknownLabels = [];
  const unknownReads = [];

  /**
   * @param {string} label journal label
   * @param {{method: string, url: string, headers?: object, body?: Uint8Array}} request
   * @param {{admin?: boolean, read?: boolean}} [options] `admin`: add the owner headers; `read`:
   *   an unknown answer is returned (with `unknown: true`) instead of thrown
   */
  async function wire(label, request, { admin = false, read = false } = {}) {
    const headers = { ...(admin ? deps.adminHeaders() : {}), ...request.headers };
    const kind = classifyRequest(target, { ...request, headers }, state);
    const n = budget.take();
    out.journal({
      phase: "before",
      n,
      label,
      kind,
      method: request.method,
      url: request.url,
      headers: request.headers ?? {},
      bodyBytes: request.body?.length ?? 0,
    });
    let res;
    try {
      res = await deps.net({
        method: request.method,
        url: request.url,
        headers,
        body: request.body,
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch {
      out.journal({ phase: "unknown", n, label, reason: "transport" });
      if (!read) {
        unknownLabels.push(label);
        throw new UnknownAnswer(label, Number.NaN);
      }
      unknownReads.push(label);
      return { status: Number.NaN, headers: {}, body: Buffer.alloc(0), unknown: true, kind };
    }
    const body = Buffer.from(res.body ?? []);
    out.journal({
      phase: "after",
      n,
      label,
      status: res.status,
      headers: res.headers,
      bodyBytes: body.length,
      bodyBase64: body.toString("base64"),
    });
    if (isUnknownStatus(res.status)) {
      if (!read) {
        unknownLabels.push(label);
        throw new UnknownAnswer(label, res.status);
      }
      unknownReads.push(label);
      return { status: res.status, headers: res.headers ?? {}, body, unknown: true, kind };
    }
    return { status: res.status, headers: res.headers ?? {}, body, unknown: false, kind };
  }

  return { wire, unknownLabels, unknownReads };
}
