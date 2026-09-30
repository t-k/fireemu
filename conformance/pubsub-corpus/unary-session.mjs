// Raw same-source unary recorder; production admission and resource ownership belong to its guarded executor.
import { createHash } from "node:crypto";
import { buildGrpc, buildRest, METHODS } from "./wire-methods.mjs";
function snapshot(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array)
    throw new Error("canonical JSON input required; byte fields use base64 strings");
  if (Array.isArray(value)) return Object.freeze(value.map(snapshot));
  if (value && typeof value === "object") {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value)))
      throw new Error("plain canonical input required");
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, member]) => [key, snapshot(member)])),
    );
  }
  if (["function", "symbol", "bigint"].includes(typeof value))
    throw new Error("plain canonical input required");
  return value;
}
function rawBytes(bytes, credential) {
  if (credential && bytes.includes(Buffer.from(credential)))
    throw new Error("credential reflection refused");
  return {
    bodyBase64: bytes.toString("base64"),
    bodyBytes: bytes.length,
    bodySha256: createHash("sha256").update(bytes).digest("hex"),
  };
}
async function responseBytes(response, limit) {
  const chunks = [];
  let size = 0;
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error("response byte bound exceeded");
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, size);
}
function metadataValues(metadata, credential) {
  if (
    credential &&
    Object.values(metadata ?? {})
      .flat()
      .some((value) =>
        Buffer.isBuffer(value) || value instanceof Uint8Array
          ? Buffer.from(value).includes(Buffer.from(credential))
          : String(value).includes(credential),
      )
  )
    throw new Error("credential reflection refused");
  return Object.fromEntries(
    Object.entries(metadata ?? {}).map(([key, values]) => [
      key,
      (Array.isArray(values) ? values : [values]).map((value) =>
        Buffer.isBuffer(value) || value instanceof Uint8Array
          ? { base64: Buffer.from(value).toString("base64") }
          : String(value),
      ),
    ]),
  );
}
const nativeReasons = new Set([
  "deadline",
  "abort",
  "close",
  "stream-error",
  "stream-close",
  "session-error",
  "session-close",
  "session-goaway",
  "response-bound",
  "header-bound",
  "protocol",
  "invalid-status",
  "invalid-headers",
  "extra-headers",
]);
function nativeWire(wire, credential, bodyLimit, headerLimit) {
  if (wire === undefined) return undefined;
  const headers = wire.headers,
    trailers = wire.trailers;
  const additional = wire.additionalHeaders ?? [];
  if (!Array.isArray(additional)) throw new Error("bounded raw native wire required");
  const blocks = [headers, trailers, ...additional];
  if (
    !blocks.every(
      (raw) =>
        Array.isArray(raw) &&
        raw.length % 2 === 0 &&
        raw.every((value) => typeof value === "string"),
    ) ||
    typeof wire.dataBase64 !== "string"
  )
    throw new Error("bounded raw native wire required");
  if (blocks.flat().reduce((size, value) => size + Buffer.byteLength(value), 0) > headerLimit)
    throw new Error("native header bound exceeded");
  for (const raw of blocks)
    for (let i = 0; i < raw.length; i += 2)
      if (raw[i].endsWith("-bin"))
        for (const value of raw[i + 1].split(","))
          rawBytes(Buffer.from(value.trim(), "base64"), credential);
  const bytes = Buffer.from(wire.dataBase64, "base64");
  if (bytes.toString("base64") !== wire.dataBase64 || bytes.length > bodyLimit + 5)
    throw new Error("native frame capture bound exceeded");
  return {
    headers: headers.slice(),
    trailers: trailers.slice(),
    ...(additional.length ? { additionalHeaders: additional.map((raw) => raw.slice()) } : {}),
    data: rawBytes(bytes, credential),
    ...(wire.truncated === true ? { truncated: true } : {}),
  };
}
export function createUnarySession({
  target,
  maxRequests,
  maxResponseBytes,
  maxWireHeaderBytes = maxResponseBytes,
  wallMs,
  requestMs,
  persist,
  guard,
  codec,
  sendRest = (request) => fetch(request.url, request),
  sendGrpc,
  clock = Date.now,
}) {
  target = snapshot(target);
  if (!target || !["local", "production"].includes(target.kind) || typeof persist !== "function")
    throw new Error("explicit target and durable receipt sink required");
  for (const value of [maxRequests, maxResponseBytes, maxWireHeaderBytes, wallMs, requestMs])
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new Error("finite positive bounds required");
  if (target.kind === "production" && typeof guard !== "function")
    throw new Error("production admission guard required");
  const endpoint = new URL(target.restEndpoint);
  if (
    (target.kind === "production" && endpoint.origin !== "https://pubsub.googleapis.com") ||
    (target.kind === "local" &&
      (endpoint.protocol !== "http:" ||
        !["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname)))
  )
    throw new Error("target kind and broker endpoint disagree");
  if (
    target.accessToken !== undefined &&
    (typeof target.accessToken !== "string" ||
      !target.accessToken ||
      /[\r\n]/.test(target.accessToken))
  )
    throw new Error("invalid transport credential");
  const started = clock(),
    identities = new Set();
  let attempted = 0,
    completed = 0,
    halted = false;
  function protectedRecord(row) {
    if (target.accessToken && JSON.stringify(row).includes(target.accessToken))
      throw new Error("credential cannot enter receipt storage");
    return persist(row);
  }
  async function check(step, transport) {
    if (halted) throw new Error("uncertain or non-durable run is halted");
    if (!step || !/^[a-z0-9][a-z0-9._-]*$/.test(step.id) || identities.has(step.id))
      throw new Error("unique receipt identity required");
    if (!METHODS[step.method] || METHODS[step.method].requestStream)
      throw new Error("unary broker operation required");
    if (attempted >= maxRequests || clock() - started >= wallMs)
      throw new Error("unary run bound exceeded");
    await guard?.(step, transport);
  }
  function metadata(step, built) {
    const result = built.routing ? { "x-goog-request-params": built.routing } : {};
    if (target.accessToken) result.authorization = `Bearer ${target.accessToken}`;
    if (target.quotaProject) result["x-goog-user-project"] = target.quotaProject;
    return result;
  }
  async function record(step, transport, built, dispatch) {
    await check(step, transport);
    const before = {
      id: step.id,
      operation: step.method,
      transport,
      state: "before-send",
      mutation: METHODS[step.method].http.verb !== "GET",
      ...(transport === "rest"
        ? {
            request: {
              method: built.method,
              url: built.url,
              ...(built.body !== undefined ? { body: built.body } : {}),
            },
          }
        : {
            request: {
              path: built.path,
              requestType: built.requestType,
              responseType: built.responseType,
              bodyBase64: built.requestBytes.toString("base64"),
              routing: built.routing,
            },
          }),
    };
    try {
      await protectedRecord(before);
    } catch {
      halted = true;
      throw new Error("reservation was not durable");
    }
    identities.add(step.id);
    attempted++;
    let response;
    try {
      // Recheck live admission for the immutable wire input after the durable reservation.
      await guard?.(step, transport);
      const remaining = wallMs - (clock() - started);
      if (remaining <= 0) throw new Error("wall budget expired before dispatch");
      response = await dispatch(Math.min(requestMs, remaining));
      if (response.transportUncertain) {
        halted = true;
        await protectedRecord({
          id: step.id,
          transport,
          state: "transport-uncertain",
          ...response,
        });
        return { outcome: "transport-uncertain", ...response };
      }
      await protectedRecord({ id: step.id, transport, state: "response-persisted", ...response });
      completed++;
    } catch {
      halted = true;
      await protectedRecord({ id: step.id, transport, state: "transport-uncertain" });
      return { outcome: "transport-uncertain" };
    }
    return { outcome: "recorded", ...response };
  }
  async function rest(step) {
    const built = buildRest(step, target.restEndpoint);
    return record(step, "rest", built, async (timeout) => {
      const headers = metadata(step, {});
      if (built.body !== undefined) headers["content-type"] = "application/json";
      const response = await sendRest({
        ...built,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(timeout),
      });
      const bytes = await responseBytes(response, maxResponseBytes);
      return {
        status: response.status,
        contentType: response.headers.get("content-type"),
        ...rawBytes(bytes, target.accessToken),
      };
    });
  }
  async function grpc(step) {
    const built = buildGrpc(step);
    if (typeof codec?.serialize !== "function" || typeof sendGrpc !== "function")
      throw new Error("native codec and transport required");
    built.requestBytes = Buffer.from(codec.serialize(built.requestType, step.request));
    rawBytes(built.requestBytes, target.accessToken);
    return record(step, "grpc", built, async (timeout) => {
      const response = await sendGrpc({
        path: built.path,
        requestBytes: built.requestBytes,
        metadata: metadata(step, built),
        deadline: new Date(clock() + timeout),
        signal: AbortSignal.timeout(timeout),
      });
      const available = response.responseBytes !== undefined;
      const bytes = available ? Buffer.from(response.responseBytes) : undefined;
      if (available && bytes.length > maxResponseBytes)
        throw new Error("bounded native response required");
      const wire = nativeWire(
        response.wire,
        target.accessToken,
        maxResponseBytes,
        maxWireHeaderBytes,
      );
      const validStatus =
        Number.isInteger(response.status?.code) &&
        response.status.code >= 0 &&
        response.status.code <= 16;
      const confirmed =
        validStatus &&
        !response.interruption &&
        !response.reason &&
        ((response.statusOrigin === "peer-trailers" && wire && !wire.truncated) ||
          (response.statusOrigin === "successful-response" &&
            response.status.code === 0 &&
            available));
      return {
        responseType: built.responseType,
        responseBytesAvailable: available,
        ...(available ? rawBytes(bytes, target.accessToken) : {}),
        ...(wire ? { nativeWire: wire } : {}),
        ...(nativeReasons.has(response.reason) ? { nativeReason: response.reason } : {}),
        statusOrigin: confirmed ? response.statusOrigin : "unverified",
        ...(!confirmed ? { transportUncertain: true } : {}),
        ...(Number.isInteger(response.callbackCode) ? { callbackCode: response.callbackCode } : {}),
        ...(response.interruption === "deadline" ? { interruption: "deadline" } : {}),
        ...(validStatus
          ? {
              grpcStatus: {
                code: response.status.code,
                details: response.status.details ?? "",
                metadata: metadataValues(response.status.metadata, target.accessToken),
              },
            }
          : {}),
      };
    });
  }
  let active = false;
  function exclusive(operation) {
    return async (step) => {
      if (active) throw new Error("concurrent sends are forbidden in the bounded unary recorder");
      active = true;
      try {
        return await operation(snapshot(step));
      } finally {
        active = false;
      }
    };
  }
  return {
    rest: exclusive(rest),
    grpc: exclusive(grpc),
    counts: () => ({ attempted, completed, unknown: attempted - completed }),
  };
}
