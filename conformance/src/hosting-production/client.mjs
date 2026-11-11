// The edge client of the Hosting observation: one request with a literal request target, no
// redirect following, no automatic decompression, no retry, bounded body and a deadline. It never
// resolves a name the caller did not pass and sends no header the caller did not name except `host`
// and `connection: close`. Answers are plain data for `shapeRow`.
import http from "node:http";
import https from "node:https";

export const DEFAULT_TIMEOUT_MS = 30_000;
export const MAX_BODY_BYTES = 262_144;

/**
 * @param {object} request { host, port?, secure?, method, target, headers?, body? }
 * @param {object} options { timeoutMs, maxBodyBytes }
 * @returns {Promise<object>} { outcome: "answered", status, httpVersion, headers: [[name, value]],
 *   body: Buffer, elapsedMs } or { outcome: "unknown", reason, elapsedMs }
 */
export function edgeRequest(
  request,
  { timeoutMs = DEFAULT_TIMEOUT_MS, maxBodyBytes = MAX_BODY_BYTES } = {},
) {
  const started = Date.now();
  const transport = request.secure === false ? http : https;
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      resolve({ ...value, elapsedMs: Date.now() - started });
    };
    const unknown = (reason) => done({ outcome: "unknown", reason });
    let req;
    try {
      req = transport.request(
        {
          host: request.host,
          port: request.port,
          path: request.target,
          method: request.method,
          headers: { ...request.headers, connection: "close" },
          agent: false,
          timeout: timeoutMs,
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on("data", (chunk) => {
            size += chunk.length;
            if (size > maxBodyBytes) {
              req.destroy();
              unknown("body-too-large");
            } else chunks.push(chunk);
          });
          res.on("aborted", () => unknown("aborted"));
          res.on("error", (error) => unknown(error.code ?? "response-error"));
          res.on("end", () => {
            const body = Buffer.concat(chunks);
            const length = res.headers["content-length"];
            const mustHaveBody = request.method !== "HEAD" && ![204, 304].includes(res.statusCode);
            if (
              mustHaveBody &&
              length !== undefined &&
              !res.headers["content-encoding"] &&
              Number(length) !== body.length
            ) {
              unknown("content-length-mismatch");
              return;
            }
            const pairs = [];
            for (let i = 0; i < res.rawHeaders.length; i += 2) {
              pairs.push([res.rawHeaders[i], res.rawHeaders[i + 1]]);
            }
            done({
              outcome: "answered",
              status: res.statusCode,
              httpVersion: res.httpVersion,
              headers: pairs,
              body,
            });
          });
        },
      );
    } catch (error) {
      unknown(error.code ?? "request-refused");
      return;
    }
    req.on("timeout", () => {
      req.destroy();
      unknown("timeout");
    });
    req.on("error", (error) => unknown(error.code ?? "request-error"));
    req.end(request.body);
  });
}
