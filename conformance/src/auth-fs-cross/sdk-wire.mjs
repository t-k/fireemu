// The network guard of an SDK driver process (AUTH-FS-CROSS stage 2): only the allowed hosts are
// reached, every request counts against a cap, and each request is recorded with its host, path
// and the SHA-256 of its bearer, so a row can say which principal's token a write or a commit
// carried without the token ever being stored.

import { createHash } from "node:crypto";
import http2 from "node:http2";
import net from "node:net";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The Google hosts a production driver may reach. */
export const PRODUCTION_HOSTS = [
  "firestore.googleapis.com",
  "identitytoolkit.googleapis.com",
  "securetoken.googleapis.com",
];

/** The bearer of an authorization value, hashed (`null`: none). */
export const bearerHash = (value) => {
  const text = Array.isArray(value) ? value[0] : value;
  if (typeof text !== "string" || !text) return null;
  const match = /^Bearer (.+)$/i.exec(text);
  return match ? sha256(match[1]) : sha256(text);
};

/**
 * A request ledger: `admit(host, path, authorization)` refuses a host outside `hosts` or a request
 * past `cap`, and records the rest. The first refusal closes the ledger: every later request and
 * connection is refused at once, and `onRefuse` hears only that first one (host, path and reason,
 * never the bearer). An SDK retries a refused request immediately, so a ledger that stayed open
 * would let it open connections without end.
 */
export function createWireLedger({
  hosts,
  cap,
  connectionCap = Infinity,
  onRecord = () => {},
  onConnection = () => {},
  onRefuse = () => {},
}) {
  const allowed = new Set(hosts);
  const records = [];
  let connections = 0;
  let closed = false;
  const refuse = (host, path, reason) => {
    if (!closed) {
      closed = true;
      onRefuse({ host, path, reason });
    }
    throw new Error(`wire: ${reason}`);
  };
  return {
    records,
    closed: () => closed,
    connections: () => connections,
    /** Refuses a new connection once the ledger is closed. */
    connect(host) {
      if (closed) refuse(host, "", "the client is closed after a refused request");
    },
    /**
     * Counts one socket connection, whatever opens it, and refuses the one past `connectionCap`
     * (which closes the ledger): a retry loop that opens connections without sending requests is
     * stopped too.
     */
    connection(host) {
      if (closed) refuse(host, "", "the client is closed after a refused request");
      if (connections >= connectionCap) refuse(host, "", `connection cap ${connectionCap} reached`);
      connections += 1;
      onConnection({ n: connections, host });
    },
    admit(host, path, authorization) {
      if (closed) refuse(host, path, "the client is closed after a refused request");
      if (!allowed.has(host)) refuse(host, path, `${host} is not an allowed host`);
      if (records.length >= cap) refuse(host, path, `request cap ${cap} reached`);
      const record = { n: records.length + 1, host, path, bearer: bearerHash(authorization) };
      records.push(record);
      onRecord(record);
      return record;
    },
  };
}

const hostOf = (authority) => new URL(`https://${authority.replace(/^https?:\/\//, "")}`).hostname;

/**
 * Routes `fetch` and every HTTP/2 session through `ledger` for the life of the process. Returns a
 * function that restores both. A refused request throws before anything is sent.
 */
export function installWireGuard(
  ledger,
  { fetchImpl = globalThis.fetch, onTransaction, decodeGrpc, beforeTransaction } = {},
) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    let effective, requestBody;
    if (beforeTransaction) {
      effective = new Request(input instanceof Request ? input.clone() : input, init);
      requestBody = await effective.clone().text();
      if (Buffer.byteLength(requestBody) > TRANSACTION_BODY_LIMIT)
        throw new Error("transaction admission body is capped");
      effective = new Request(effective, { method: effective.method, body: requestBody });
    }
    const url = new URL(
      effective?.url ?? (typeof input === "string" || input instanceof URL ? input : input.url),
    );
    const requestHeaders = input instanceof Request ? input.headers : undefined;
    const headers = new Headers(effective?.headers ?? init.headers ?? requestHeaders ?? {});
    const record = ledger.admit(url.hostname, url.pathname, headers.get("authorization"));
    const method = transactionMethod(url.pathname);
    if (beforeTransaction) {
      if (!method) throw new Error("transaction admission requires a transaction RPC");
      await beforeTransaction({ method, request: JSON.parse(requestBody), record });
    }
    const response = effective ? await fetchImpl(effective) : await fetchImpl(input, init);
    if (onTransaction && method) {
      try {
        requestBody ??=
          init.body ?? (input instanceof Request ? await input.clone().text() : undefined);
        const body = await boundedResponse(response.clone());
        onTransaction({
          n: record.n,
          ...transactionWireEvidence(method, requestBody, body, response.status),
        });
      } catch {
        onTransaction({ n: record.n, method, complete: false, reason: "capture-failed" });
      }
    }
    return response;
  };
  const originalConnect = http2.connect;
  http2.connect = function connect(authority, ...rest) {
    const host = hostOf(String(authority));
    ledger.connect(host);
    const session = originalConnect.call(this, authority, ...rest);
    const request = session.request.bind(session);
    session.request = (headers = {}, options) => {
      const record = ledger.admit(host, headers[":path"] ?? "", headers.authorization);
      const method = transactionMethod(headers[":path"] ?? "");
      if (beforeTransaction && (!method || !decodeGrpc || !onTransaction))
        throw new Error("transaction admission requires decoded transaction capture");
      const stream = request(headers, options);
      if (onTransaction && decodeGrpc && method) {
        const sent = [],
          received = [];
        let sentBytes = 0,
          receivedBytes = 0,
          status,
          code;
        const collect = (chunks, chunk, encoding, outbound) => {
          const bytes =
            beforeTransaction && outbound
              ? Buffer.from(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding))
              : Buffer.isBuffer(chunk)
                ? chunk
                : Buffer.from(chunk, encoding);
          if (outbound) sentBytes += bytes.length;
          else receivedBytes += bytes.length;
          if ((outbound ? sentBytes : receivedBytes) <= TRANSACTION_BODY_LIMIT) chunks.push(bytes);
          return bytes;
        };
        const write = stream.write.bind(stream),
          end = stream.end.bind(stream);
        const pendingWrites = [];
        let admissionStarted = false;
        stream.write = (chunk, ...args) => {
          if (admissionStarted) throw new Error("transaction payload already ended");
          const snapshot = collect(
            sent,
            chunk,
            typeof args[0] === "string" ? args[0] : undefined,
            true,
          );
          if (beforeTransaction) {
            if (sentBytes > TRANSACTION_BODY_LIMIT) {
              stream.destroy(new Error("transaction admission body capped"));
              return false;
            }
            pendingWrites.push([snapshot, ...args]);
            return true;
          }
          return write(chunk, ...args);
        };
        stream.end = (chunk, ...args) => {
          if (chunk != null && typeof chunk !== "function") {
            const snapshot = collect(
              sent,
              chunk,
              typeof args[0] === "string" ? args[0] : undefined,
              true,
            );
            if (beforeTransaction) chunk = snapshot;
          }
          if (beforeTransaction) {
            if (admissionStarted) throw new Error("transaction payload already ended");
            admissionStarted = true;
            Promise.resolve()
              .then(async () => {
                if (sentBytes > TRANSACTION_BODY_LIMIT)
                  throw new Error("transaction admission body capped");
                const requestBody = decodeGrpc(method, Buffer.concat(sent), false);
                await beforeTransaction({ method, request: requestBody, record });
                if (stream.destroyed) throw new Error("transaction stream closed before admission");
                for (const queued of pendingWrites) write(...queued);
                end(chunk, ...args);
              })
              .catch(() => stream.destroy(new Error("transaction admission refused")));
            return stream;
          }
          return end(chunk, ...args);
        };
        stream.on("response", (h) => {
          status = Number(h[":status"]);
          code = h["grpc-status"];
        });
        stream.on("trailers", (h) => {
          code = h["grpc-status"];
        });
        stream.on("data", (chunk) => collect(received, chunk, undefined, false));
        let emitted = false;
        const finish = () => {
          if (emitted) return;
          emitted = true;
          try {
            if (
              sentBytes > TRANSACTION_BODY_LIMIT ||
              receivedBytes > TRANSACTION_BODY_LIMIT ||
              code === undefined
            )
              throw new Error("cap-or-missing-status");
            const req = decodeGrpc(method, Buffer.concat(sent), false);
            const res =
              code !== undefined && Number(code) !== 0
                ? { error: { code: Number(code) } }
                : decodeGrpc(method, Buffer.concat(received), true);
            onTransaction({
              n: record.n,
              ...transactionWireEvidence(
                method,
                req,
                res,
                status,
                code === undefined ? undefined : Number(code),
              ),
            });
          } catch {
            onTransaction({ n: record.n, method, complete: false, reason: "capture-failed" });
          }
        };
        stream.on("end", finish);
        stream.on("error", finish);
        stream.on("aborted", finish);
      }
      return stream;
    };
    return session;
  };
  return () => {
    globalThis.fetch = originalFetch;
    http2.connect = originalConnect;
  };
}

export const TRANSACTION_BODY_LIMIT = 65_536;

/** Only optimistic transaction RPCs are observed; query strings are never retained. */
export function transactionMethod(path) {
  if (/^\/google\.firestore\.v1\.Firestore\/(BatchGetDocuments|Commit)$/.test(path))
    return path.split("/").at(-1);
  const match = /^\/v1\/projects\/[^/]+\/databases\/[^/]+\/documents:(batchGet|commit)$/.exec(path);
  return match ? (match[1] === "batchGet" ? "BatchGetDocuments" : "Commit") : null;
}

/** Whitelisted evidence excludes headers, tokens, URL parameters and arbitrary document fields. */
export function transactionWireEvidence(method, request, response, status, grpcCode) {
  if (!["BatchGetDocuments", "Commit"].includes(method)) return null;
  try {
    const parse = (value) => {
      if (typeof value === "string") {
        if (Buffer.byteLength(value) > TRANSACTION_BODY_LIMIT) throw new Error("cap");
        return JSON.parse(value);
      }
      if (!value || typeof value !== "object") throw new Error("missing");
      return value;
    };
    const req = parse(request),
      res = parse(response);
    const timestamp = (value) =>
      typeof value === "string"
        ? value
        : value && typeof value === "object"
          ? { seconds: String(value.seconds ?? 0), nanos: Number(value.nanos ?? 0) }
          : null;
    const document = (value) => ({
      name: value?.name ?? null,
      updateTime: timestamp(value?.updateTime),
    });
    const writes = (req.writes ?? []).map((w) => ({
      update: w.update ? document(w.update) : null,
      currentDocument: w.currentDocument
        ? {
            ...(w.currentDocument.updateTime
              ? { updateTime: timestamp(w.currentDocument.updateTime) }
              : {}),
            ...(typeof w.currentDocument.exists === "boolean"
              ? { exists: w.currentDocument.exists }
              : {}),
          }
        : null,
    }));
    const shapedRequest =
      method === "Commit"
        ? { writes, transactionPresent: Boolean(req.transaction) }
        : {
            documents: (req.documents ?? []).filter((v) => typeof v === "string"),
            transactionPresent: Boolean(req.transaction || req.newTransaction),
          };
    const shapedResponse = res.error
      ? { error: { code: res.error.code ?? null, status: res.error.status ?? null } }
      : method === "BatchGetDocuments"
        ? {
            documents: (Array.isArray(res) ? res : [res]).map((row) =>
              row.found ? document(row.found) : { missing: row.missing ?? null },
            ),
          }
        : {
            writeResults: (res.writeResults ?? []).map((w) => ({
              updateTime: timestamp(w.updateTime),
            })),
            commitTime: timestamp(res.commitTime),
          };
    const known =
      (status >= 200 && status < 300 && (grpcCode === undefined || Number.isInteger(grpcCode))) ||
      (status >= 400 && status < 500 && Boolean(res.error));
    const shape =
      method === "Commit"
        ? writes.length > 0 &&
          (Boolean(res.error?.code) ||
            (Boolean(shapedResponse.commitTime) &&
              shapedResponse.writeResults.length === writes.length))
        : shapedRequest.documents.length > 0 && shapedResponse.documents?.length > 0;
    return {
      method,
      status,
      ...(grpcCode === undefined ? {} : { grpcCode }),
      request: shapedRequest,
      response: shapedResponse,
      complete: Boolean(known && shape),
    };
  } catch {
    return { method, status, complete: false, reason: "missing-malformed-or-capped-body" };
  }
}

/** Bounds the cloned response without consuming or replacing the SDK's response. */
async function boundedResponse(response) {
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      let timer;
      const { done, value } = await Promise.race([
        reader.read(),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("capture timeout")), 2000);
        }),
      ]).finally(() => clearTimeout(timer));
      if (done) break;
      bytes += value.byteLength;
      if (bytes > TRANSACTION_BODY_LIMIT) throw new Error("cap");
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    reader.cancel().catch(() => {});
  }
}

/** The host a `net.Socket#connect` call is for. */
function socketHost(args) {
  // `net.connect` hands `connect` its arguments already normalized, as one array.
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  if (first && typeof first === "object" && !Array.isArray(first))
    return String(first.host ?? first.path ?? "localhost");
  if (typeof args[1] === "string") return args[1];
  return typeof first === "string" ? first : "localhost";
}

/**
 * Counts every socket connection of the process through `ledger.connection` (HTTP/2, fetch and
 * anything else open sockets through `net.Socket#connect`). A refused connection is destroyed
 * before it connects. Returns a function that restores the original.
 */
export function installSocketGuard(ledger) {
  const original = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function connect(...args) {
    try {
      ledger.connection(socketHost(args));
    } catch (error) {
      process.nextTick(() => this.destroy(error));
      return this;
    }
    return original.apply(this, args);
  };
  return () => {
    net.Socket.prototype.connect = original;
  };
}

/** Fixed S5b dispatches use the driver's existing command pipe for parent acknowledgments. */
export function createS5bAdmission(config, emit) {
  const admitted = config.s5bAdmission;
  if (
    config.mode !== "production" ||
    config.web?.projectId !== "fireemu-oracle-query" ||
    !admitted ||
    Object.keys(admitted).sort().join(",") !== "authorized,nonce,ownerId,probe,transport" ||
    admitted.authorized !== true ||
    !/^[a-f0-9]{32}$/.test(admitted.nonce) ||
    !/^[a-f0-9]{32}$/.test(admitted.ownerId) ||
    !["node", "browser"].includes(admitted.transport) ||
    typeof admitted.probe !== "boolean" ||
    config.wireCap !== (admitted.probe ? 1 : 6) ||
    config.connectionCap !== 20
  )
    throw new Error("S5b fixed production admission differs");
  const database = "projects/fireemu-oracle-query/databases/(default)";
  const prefix = `${database}/documents/conf_txn/s5b_${admitted.nonce}_${admitted.transport}_`;
  const names = new Set(
    admitted.probe ? [`${prefix}probe`] : [`${prefix}control`, `${prefix}conflict`],
  );
  const pending = new Map();
  let closed = false;
  let sequence = 0;
  const refuse = (message) => {
    closed = true;
    throw new Error(message);
  };
  return {
    async beforeTransaction({ method, request, record }) {
      const expectedPath =
        admitted.transport === "node"
          ? `/google.firestore.v1.Firestore/${method}`
          : `/v1/${database}/documents:${method === "BatchGetDocuments" ? "batchGet" : "commit"}`;
      if (
        record.path !== expectedPath ||
        closed ||
        record.host !== "firestore.googleapis.com" ||
        record.bearer !== null ||
        record.n !== sequence + 1 ||
        record.n > config.wireCap ||
        transactionMethod(record.path) !== method ||
        request.transaction ||
        request.newTransaction ||
        request.readTime ||
        (request.database !== undefined && request.database !== database)
      )
        refuse("S5b dispatch scope differs");
      if (method === "BatchGetDocuments") {
        if (
          Object.keys(request).some((key) => !["documents", "database"].includes(key)) ||
          !Array.isArray(request.documents) ||
          request.documents.length !== 1 ||
          !names.has(request.documents[0])
        )
          refuse("S5b exact read name differs");
      } else if (method === "Commit" && !admitted.probe) {
        if (
          Object.keys(request).some((key) => !["writes", "database"].includes(key)) ||
          !Array.isArray(request.writes) ||
          request.writes.length !== 1
        )
          refuse("S5b exact write count differs");
        const write = request.writes[0],
          update = write.update,
          fields = update?.fields;
        const caseId = update?.name?.slice(prefix.length);
        if (
          !names.has(update?.name) ||
          Object.keys(update ?? {})
            .sort()
            .join(",") !== "fields,name" ||
          Object.keys(write).sort().join(",") !== "currentDocument,update" ||
          Object.keys(write.currentDocument ?? {}).join(",") !== "updateTime" ||
          !write.currentDocument.updateTime ||
          (typeof write.currentDocument.updateTime === "string"
            ? !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(
                write.currentDocument.updateTime,
              )
            : typeof write.currentDocument.updateTime !== "object" ||
              Object.keys(write.currentDocument.updateTime).some(
                (key) => !["seconds", "nanos"].includes(key),
              ) ||
              !/^-?\d+$/.test(String(write.currentDocument.updateTime.seconds)) ||
              !Number.isInteger(write.currentDocument.updateTime.nanos ?? 0) ||
              (write.currentDocument.updateTime.nanos ?? 0) < 0 ||
              (write.currentDocument.updateTime.nanos ?? 0) >= 1_000_000_000) ||
          !fields ||
          Object.keys(fields).sort().join(",") !== "case,nonce,owner,value" ||
          Object.values(fields).some((field) => !field || Object.keys(field).length !== 1) ||
          fields.owner?.stringValue !== admitted.ownerId ||
          fields.nonce?.stringValue !== admitted.nonce ||
          fields.case?.stringValue !== caseId ||
          String(fields.value?.integerValue) !== "3"
        )
          refuse("S5b write ownership or version differs");
      } else refuse("S5b probe cannot commit or resume");
      sequence += 1;
      const id = `s5b-${sequence}`;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          closed = true;
          reject(new Error("S5b parent acknowledgment missing"));
        }, 13_000);
        pending.set(id, { resolve, reject, timer });
        try {
          emit({ event: "transaction-dispatch", id, method, request, record });
        } catch {
          clearTimeout(timer);
          pending.delete(id);
          closed = true;
          reject(new Error("S5b dispatch IPC failed"));
        }
      });
    },
    accept(command) {
      if (command.op !== "transactionAdmission") return false;
      const waiting = pending.get(command.id);
      if (!waiting) refuse("S5b unknown acknowledgment");
      pending.delete(command.id);
      clearTimeout(waiting.timer);
      if (
        Object.keys(command).sort().join(",") !== "authorized,id,op" ||
        command.authorized !== true
      ) {
        closed = true;
        waiting.reject(new Error("S5b parent admission refused"));
      } else waiting.resolve();
      return true;
    },
  };
}
