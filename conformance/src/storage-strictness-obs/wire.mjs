import { closeSync, fsyncSync, openSync, writeSync } from "node:fs";
import {
  classifyRequest,
  GuardError,
  isUnknownStatus,
  RequestBudget,
  SEND_FLAG,
} from "./guard.mjs";
import { fetchNet } from "./egress.mjs";

export function redactHeaders(headers, secrets = []) {
  return Object.fromEntries(
    [...new Headers(headers).entries()].map(([key, value]) => [
      key,
      key === "authorization" || key === "proxy-authorization"
        ? "<redacted>"
        : secrets
            .filter(Boolean)
            .reduce((text, secret) => text.replaceAll(secret, "<redacted>"), value)
            .replace(/AIza[\w-]{20,}|-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*/g, "<redacted>"),
    ]),
  );
}

export function openJournal(path) {
  const fd = openSync(path, "wx", 0o600);
  return {
    append(entry) {
      const bytes = Buffer.from(`${JSON.stringify(entry)}\n`);
      let offset = 0;
      while (offset < bytes.length) offset += writeSync(fd, bytes, offset, bytes.length - offset);
      fsyncSync(fd);
    },
    close() {
      closeSync(fd);
    },
  };
}

export function createProductionClient(target, { send, token, fetchImpl, env = process.env } = {}) {
  if (!send || env[SEND_FLAG] !== "launch-script" || target.local)
    throw new GuardError("production send flag required");
  if (typeof token !== "string" || !token || /\s/.test(token))
    throw new GuardError("invalid bearer");
  const net = fetchNet(target, fetchImpl);
  return async (...args) => {
    if (env[SEND_FLAG] !== "launch-script") throw new GuardError("production send flag required");
    return net(...args);
  };
}

export function createWire({
  target,
  net,
  journal,
  token = "fake-owner",
  now = Date.now,
  budget = new RequestBudget(),
  deadline = now() + 15 * 60_000,
}) {
  const unknownDeletes = new Set();
  const entries = [];
  const secrets = [token, `Bearer ${token}`, "Firebase not-a-jwt", "not-a-jwt"];
  const append = (entry) => {
    journal.append(entry);
    entries.push(entry);
  };
  async function wire(planned, location = "US") {
    const headers = { ...planned.headers };
    if (planned.auth === "malformed") headers.authorization = "Firebase not-a-jwt";
    else if (!target.local && planned.auth !== "none") headers.authorization = `Bearer ${token}`;
    const request = { ...planned, headers };
    const checked = classifyRequest(target, request, location);
    if (checked.action === "delete" && unknownDeletes.has(checked.resource))
      throw new GuardError("unknown DELETE cannot be resent");
    const remaining = deadline - now();
    if (remaining <= 0) throw new GuardError("whole-run deadline exhausted");
    const n = budget.take();
    const startedAt = now();
    const timeoutMs = Math.min(checked.case === "W1" ? 60_000 : 30_000, remaining);
    const base = {
      n,
      case: checked.case,
      method: request.method,
      url: request.url,
      requestHeaders: redactHeaders(headers, secrets),
      action: checked.action,
      resource: checked.resource,
      startedAt,
      timeoutMs,
    };
    append({
      phase: "before",
      ...base,
      requestBodyBytes: Buffer.byteLength(request.body ?? ""),
      requestBodyBase64: Buffer.from(request.body ?? "").toString("base64"),
    });
    const controller = new AbortController();
    let timer;
    let answer;
    try {
      const expiry = new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("timeout"));
        }, timeoutMs);
      });
      const response = await Promise.race([
        Promise.resolve().then(() => net(request, { signal: controller.signal, location })),
        expiry,
      ]);
      if (!response) throw new Error("no response");
      const unreadable = response.body == null;
      const body = unreadable ? Buffer.alloc(0) : Buffer.from(response.body);
      const rawHeaders = Object.fromEntries(new Headers(response.headers).entries());
      const responseHeaders = redactHeaders(rawHeaders, secrets);
      // Never persist echoed credentials. Withholding makes the answer unknown, never a fixture.
      const withheld =
        secrets.some((secret) => secret && body.includes(Buffer.from(secret))) ||
        /AIza[\w-]{20,}|-----BEGIN [^-]*PRIVATE KEY-----/.test(body.toString("utf8"));
      const headersRedacted = JSON.stringify(rawHeaders) !== JSON.stringify(responseHeaders);
      answer = {
        status: response.status,
        headers: responseHeaders,
        body: withheld ? Buffer.alloc(0) : body,
        bodyBytes: unreadable ? null : body.length,
        unknown: isUnknownStatus(response.status) || withheld || headersRedacted || unreadable,
        withheld,
        headersRedacted,
        unreadable,
      };
      if (
        checked.action === "read" &&
        response.status >= 200 &&
        response.status < 300 &&
        !answer.unknown
      ) {
        const match = /^\/storage\/v1\/b\/([^/]+)(?:\/o\/(.+))?$/.exec(checked.resource);
        try {
          const value = JSON.parse(body.toString("utf8"));
          answer.showsResource = match[2]
            ? value.bucket === match[1] && value.name === decodeURIComponent(match[2])
            : value.name === match[1];
        } catch {
          answer.showsResource =
            Boolean(match?.[2]) &&
            body.equals(Buffer.from("fire")) &&
            (new URL(request.url).searchParams.get("alt") === "media" || checked.case === "A9");
        }
      }
    } catch {
      answer = {
        status: null,
        headers: {},
        body: Buffer.alloc(0),
        bodyBytes: 0,
        unknown: true,
        failure: "transport, timeout, cancelled call or unreadable body",
      };
    } finally {
      clearTimeout(timer);
    }
    if (checked.action === "delete" && answer.unknown) unknownDeletes.add(checked.resource);
    const { body, ...stored } = answer;
    append({
      phase: "after",
      ...base,
      ...stored,
      bodyBase64: body.toString("base64"),
      endedAt: now(),
      durationMs: now() - startedAt,
    });
    return answer;
  }
  return { wire, append, entries, budget, unknownDeletes, deadline, now };
}
