// The guarded transport of the signed PUT observer: every request, raw or made by an SDK, is
// classified, counted against the budget and journaled before it leaves the process; an unknown
// answer (the shared rule) is never retried and throws.

import { Buffer } from "node:buffer";

import { classifyRequest, isUnknownStatus, redactSignedUrl } from "./guard.mjs";
import { REQUEST_TIMEOUT_MS } from "./plan.mjs";

export class UnknownAnswer extends Error {
  constructor(label, status) {
    super(`unknown answer: ${label} (${Number.isInteger(status) ? status : "transport"})`);
    this.label = label;
    this.status = Number.isInteger(status) ? status : Number.NaN;
  }
}

export function createWire({ target, prefix, budget, deps, out }) {
  const unknownLabels = [];

  async function wire(label, request, { admin = false, context = {} } = {}) {
    // The guard sees the headers that will actually be sent, credentials included.
    const headers = { ...(admin ? deps.adminHeaders() : {}), ...request.headers };
    const kind = classifyRequest(target, { ...request, headers }, prefix);
    const n = budget.take();
    out.journal({
      phase: "before",
      n,
      label,
      kind,
      method: request.method,
      url: redactSignedUrl(request.url),
      headers: request.headers ?? {},
      bodyBytes: request.body?.length ?? 0,
      ...context,
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
      unknownLabels.push(label);
      throw new UnknownAnswer(label, Number.NaN);
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
      unknownLabels.push(label);
      throw new UnknownAnswer(label, res.status);
    }
    return { status: res.status, headers: res.headers ?? {}, body };
  }

  // The SDK's own request (signBlob) passes the same guard and budget.
  const meter = {
    request(label, request) {
      classifyRequest(target, request, prefix);
      const n = budget.take();
      out.journal({
        phase: "sdk-before",
        n,
        label,
        method: request.method,
        url: redactSignedUrl(request.url),
      });
    },
    after(label, status) {
      out.journal({ phase: "sdk-after", label, status });
      if (isUnknownStatus(status)) {
        unknownLabels.push(label);
        throw new UnknownAnswer(label, status);
      }
    },
  };

  return { wire, meter, unknownLabels };
}
