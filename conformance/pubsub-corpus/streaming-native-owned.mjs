import { connect as nativeConnect, createServer as nativeCreateServer } from "node:http2";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { mkdtemp, open, readFile, rm } from "node:fs/promises";
import { hostname, tmpdir, userInfo } from "node:os";
import { basename, join, relative } from "node:path";
import { createOwnedJournalWriter, createOwnedStreamingBridge } from "./streaming-bridge.mjs";

const leases = new WeakMap();
const activePorts = new Set();
let RegistryDatabase;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((r, j) => {
    resolve = r;
    reject = j;
  });
  return { promise, resolve, reject };
};
function deadline(value) {
  if (
    !Number.isFinite(value) ||
    value <= performance.now() ||
    value - performance.now() > 2147483647
  )
    throw new Error("live bounded absolute deadline required");
}
async function until(work, deadlineAt) {
  let timer;
  try {
    return await Promise.race([
      work,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("absolute deadline")),
          Math.max(0, deadlineAt - performance.now()),
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function closedOptions(options, allowed, message) {
  if (!options || ![Object.prototype, null].includes(Object.getPrototypeOf(options)))
    throw new Error(message);
  for (const key of Reflect.ownKeys(options))
    if (
      !allowed.includes(key) ||
      !Object.hasOwn(Object.getOwnPropertyDescriptor(options, key), "value")
    )
      throw new Error(message);
}

function registryRow(state) {
  const db = new RegistryDatabase(state.db, { readOnly: true });
  let row;
  try {
    row = db.prepare("SELECT * FROM reservations WHERE token = ?").get(state.token);
  } finally {
    db.close();
  }
  const cwd = realpathSync(process.cwd());
  const identity = execFileSync("ps", ["-p", String(process.pid), "-o", "uid=,comm=,args="], {
    encoding: "utf8",
  }).trim();
  const uid = userInfo().uid;
  const processIdentity = /^(\d+)\s+(\S+)\s+(.+)$/.exec(identity);
  const expectedAgent =
    process.env.AGENT_ID ?? `${userInfo().username}@${hostname()}:${process.ppid}`;
  const command = [
    "node",
    ...process.execArgv,
    relative(cwd, process.argv[1]),
    ...process.argv.slice(2),
  ].join(" ");
  if (
    !row ||
    row.pid !== process.pid ||
    row.port !== state.port ||
    row.host !== "127.0.0.1" ||
    row.service !== "codex-pubsub-native-e3" ||
    row.agent_id !== expectedAgent ||
    realpathSync(row.cwd) !== cwd ||
    row.token !== state.token ||
    row.command !== command ||
    !processIdentity ||
    Number(processIdentity[1]) !== uid ||
    basename(processIdentity[2]) !== basename(process.execPath) ||
    ![command, command.replace(/^node /, `${process.execPath} `)].includes(processIdentity[3]) ||
    (row.expires_at !== null &&
      (!Number.isSafeInteger(row.expires_at) || row.expires_at * 1000 <= Date.now()))
  )
    throw new Error("owned loopback lease does not match the current process");
  return row;
}

/** Registry capabilities are process-bound; OS ephemeral capabilities make no registry claim. */
export async function acquireOwnedLoopbackLease({ deadlineAt }) {
  deadline(deadlineAt);
  const supplied = [
    process.env.PORT,
    process.env.PORT_REGISTRY_TOKEN,
    process.env.PORT_REGISTRY_DB,
  ];
  let state;
  if (supplied.every((value) => value === undefined)) {
    state = { kind: "os-ephemeral", port: 0, pid: process.pid, consumed: false };
  } else {
    if (
      !supplied.every((value) => typeof value === "string" && value.length > 0) ||
      !/^[a-f0-9]{32}$/.test(supplied[1]) ||
      !/^\d+$/.test(supplied[0])
    )
      throw new Error("owned loopback lease required");
    state = {
      kind: "registry",
      port: Number(supplied[0]),
      token: supplied[1],
      db: supplied[2],
      pid: process.pid,
      consumed: false,
    };
    if (!Number.isSafeInteger(state.port) || state.port < 1 || state.port > 65535)
      throw new Error("owned loopback lease required");
    RegistryDatabase ??= (await import("node:sqlite")).DatabaseSync;
    registryRow(state);
  }
  const capability = Object.freeze(Object.create(null));
  leases.set(capability, state);
  return capability;
}

/** Actual loopback I/O evidence only: neither native completeness nor power-loss durability. */
export async function createOwnedNativeStreamingFixture(options) {
  closedOptions(
    options,
    ["lease", "deadlineAt", "limits", "ioBarrier", "ioFault"],
    "closed native fixture options required",
  );
  const { lease, deadlineAt, limits, ioBarrier = async () => {}, ioFault } = options;
  const state = leases.get(lease);
  if (
    !state ||
    state.pid !== process.pid ||
    state.consumed ||
    (activePorts.has(state.port) && state.port !== 0)
  )
    throw new Error("unused owned loopback lease required");
  deadline(deadlineAt);
  if (typeof ioBarrier !== "function") throw new Error("owned I/O barrier required");
  if (
    ioFault !== undefined &&
    ![
      "short-write",
      "zero-write",
      "close-file-before-sync",
      "close-directory-before-sync",
    ].includes(ioFault)
  )
    throw new Error("named owned I/O fault required");
  for (const key of [
    "maxActions",
    "maxNativeCallbacks",
    "maxHeaderBytes",
    "maxHeaderPairs",
    "maxWriterRows",
  ])
    if (!Number.isSafeInteger(limits?.[key]) || limits[key] < 1)
      throw new Error("finite native bounds required");
  const revalidate = () => {
    deadline(deadlineAt);
    if (state.kind === "registry") registryRow(state);
  };
  revalidate();
  state.consumed = true;
  activePorts.add(state.port);
  let server, client, clientStream, peerStream, file, directoryHandle, directory, bridge;
  let serverClosed = false,
    fileClosed = false,
    directoryClosed = false,
    shuttingDown = false,
    shutdownPromise;
  let seq = 0,
    eventOverflow = false,
    currentRow,
    readbackStarted = false;
  const calls = [],
    events = [],
    steps = [],
    pending = new Set();
  const systemCalls = [],
    nativePending = new Set();
  const sockets = new Set(),
    sessions = new Set(),
    streams = new Set();
  const owned = new WeakSet();
  const counts = new Map(),
    waiters = new Map();
  const peerReady = deferred(),
    peerEnd = deferred();
  let peerStreams = 0,
    requestBytes = 0,
    requestEnded = false;
  // A rejected ready barrier must remain observed when setup fails before any stream is sent.
  peerReady.promise.catch(() => {});
  peerEnd.promise.catch(() => {});
  function event(kind, fields = {}) {
    counts.set(kind, (counts.get(kind) ?? 0) + 1);
    if (events.length < limits.maxNativeCallbacks + 4) events.push({ seq: seq++, kind, ...fields });
    else {
      eventOverflow = true;
      bridge?.stopNow("uncertain");
    }
    for (const waiter of waiters.get(kind) ?? [])
      if ((counts.get(kind) ?? 0) >= waiter.count) waiter.resolve();
  }
  function invoke(owner, method, args = []) {
    if (!owned.has(owner)) throw new Error("foreign native resource refused");
    if (calls.length >= 2 * (limits.maxActions + 4)) throw new Error("native call boundary bound");
    calls.push({
      seq: seq++,
      method,
      phase: "entry",
      completion: "UNKNOWN",
      ...(method === "close" ? { code: args[0] } : {}),
    });
    try {
      const result = owner[method](...args);
      calls.push({ seq: seq++, method, phase: "return", completion: "UNKNOWN" });
      return result;
    } catch (error) {
      calls.push({ seq: seq++, method, phase: "throw", completion: "UNKNOWN" });
      throw error;
    }
  }
  function observeClosure(resource, collection, kind) {
    collection.add(resource);
    resource.on("error", (error) =>
      event(`${kind}-error`, { code: String(error.code ?? "UNKNOWN").slice(0, 64) }),
    );
    resource.once("close", () => {
      collection.delete(resource);
      event(`${kind}-close`);
    });
  }
  function observeStream(stream) {
    owned.add(stream);
    observeClosure(stream, streams, "owned-stream");
    stream.on("close", () => event("stream-close", { rstCode: stream.rstCode }));
    for (const kind of ["response", "headers", "trailers"])
      stream.on(kind, (_headers, flags, rawHeaders) => {
        if (
          !Array.isArray(rawHeaders) ||
          rawHeaders.length > limits.maxHeaderPairs * 2 ||
          rawHeaders.reduce((n, value) => n + Buffer.byteLength(value), 0) > limits.maxHeaderBytes
        ) {
          eventOverflow = true;
          bridge?.stopNow("uncertain");
          return;
        }
        event(kind === "headers" ? "additional" : kind, { flags, rawHeaders: rawHeaders.slice() });
      });
    stream.on("data", (bytes) => event("data", { bodyBytes: bytes.length, sha256: sha(bytes) }));
    stream.on("end", () => event("end"));
    stream.on("aborted", () => event("aborted", { rstCode: stream.rstCode }));
    return Object.freeze({
      on(eventName, callback) {
        stream.on(eventName, callback);
      },
      removeListener(eventName, callback) {
        stream.removeListener(eventName, callback);
      },
      write(bytes) {
        return invoke(stream, "write", [bytes]);
      },
      end() {
        return invoke(stream, "end");
      },
      close(code) {
        return invoke(stream, "close", [code]);
      },
    });
  }
  async function operation(operationName, action) {
    const row = currentRow;
    const task = (async () => {
      const descriptor = {
        operation: operationName,
        phase: "before-syscall",
        rowIndex: row?.index,
        body: row ? JSON.parse(Buffer.from(row.bodyBase64, "base64")) : undefined,
      };
      steps.push({ operation: operationName, phase: "barrier", rowIndex: row?.index });
      await ioBarrier(Object.freeze(descriptor));
      deadline(deadlineAt);
      steps.push({ operation: operationName, phase: "entry", rowIndex: row?.index });
      try {
        const result = await action();
        steps.push({ operation: operationName, phase: "settled", rowIndex: row?.index });
        await ioBarrier(Object.freeze({ ...descriptor, phase: "after-syscall" }));
        return result;
      } catch (error) {
        steps.push({ operation: operationName, phase: "rejected", rowIndex: row?.index });
        throw error;
      }
    })();
    pending.add(task);
    task.then(
      () => pending.delete(task),
      () => pending.delete(task),
    );
    return task;
  }
  function systemCall(handle, method, args, operationName) {
    if (!owned.has(handle) || (handle !== file && handle !== directoryHandle))
      throw new Error("foreign file handle refused");
    if (systemCalls.length >= 6 * limits.maxWriterRows + 8) throw new Error("native syscall bound");
    systemCalls.push({ operation: operationName, phase: "entry" });
    const work = Promise.resolve(handle[method](...args));
    nativePending.add(work);
    work.then(
      (result) => {
        nativePending.delete(work);
        systemCalls.push({
          operation: operationName,
          phase: "settled",
          ...(method === "write" ? { bytesWritten: result.bytesWritten } : {}),
        });
      },
      () => {
        nativePending.delete(work);
        systemCalls.push({ operation: operationName, phase: "rejected" });
      },
    );
    return work;
  }
  async function shutdown() {
    if (shutdownPromise) return shutdownPromise;
    shuttingDown = true;
    shutdownPromise = (async () => {
      // This supervisor grace is cleanup-only; it never extends the operation's evidence deadline.
      const cleanupAt = performance.now() + 5000;
      const completion = bridge?.done();
      if (clientStream && !clientStream.destroyed) clientStream.destroy();
      if (client && !client.destroyed) client.destroy();
      for (const stream of streams) if (!stream.destroyed) stream.destroy();
      for (const session of sessions) if (!session.destroyed) session.destroy();
      for (const socket of sockets) if (!socket.destroyed) socket.destroy();
      if (server && !serverClosed)
        await until(
          new Promise((resolve, reject) => {
            server.close((error) => {
              if (error) reject(error);
              else {
                serverClosed = true;
                resolve();
              }
            });
          }),
          cleanupAt,
        );
      await until(Promise.allSettled([completion, ...pending, ...nativePending]), cleanupAt);
      await until(
        Promise.all(
          [...streams, ...sessions, ...sockets].map(
            (resource) => new Promise((resolve) => resource.once("close", resolve)),
          ),
        ),
        cleanupAt,
      );
      if (pending.size || nativePending.size)
        throw new Error("underlying I/O settlement unconfirmed; supervisor cleanup required");
      if (file) {
        await systemCall(file, "close", [], "file-close");
        fileClosed = file.fd === -1;
      }
      if (directoryHandle) {
        await systemCall(directoryHandle, "close", [], "directory-close");
        directoryClosed = directoryHandle.fd === -1;
      }
      if (directory) await rm(directory, { recursive: true, force: true });
      activePorts.delete(state.port);
      return Object.freeze({
        pendingOperations: pending.size,
        pendingNativeOperations: nativePending.size,
        serverClosed,
        fileClosed,
        directoryClosed,
        sockets: sockets.size,
        sessions: sessions.size,
        streams: streams.size,
        clientClosed: !client || !sessions.has(client),
        crashDurability: "UNKNOWN",
      });
    })();
    return shutdownPromise;
  }
  try {
    directory = await mkdtemp(join(tmpdir(), "fireemu-native-owned-"));
    file = await open(join(directory, "wal"), "wx");
    owned.add(file);
    directoryHandle = await open(directory, "r");
    owned.add(directoryHandle);
    server = nativeCreateServer();
    owned.add(server);
    server.on("error", () => {});
    server.on("connection", (socket) => observeClosure(socket, sockets, "socket"));
    server.on("session", (session) => {
      owned.add(session);
      observeClosure(session, sessions, "peer-session");
    });
    server.on("stream", (stream) => {
      if (peerStream) {
        stream.close(8);
        return;
      }
      peerStreams++;
      peerStream = stream;
      owned.add(stream);
      observeClosure(stream, streams, "peer-stream");
      stream.on("data", (bytes) => {
        requestBytes += bytes.length;
      });
      stream.on("end", () => {
        requestEnded = true;
        peerEnd.resolve();
      });
      peerReady.resolve();
    });
    revalidate();
    await until(
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(state.port, "127.0.0.1", () => {
          server.removeListener("error", reject);
          resolve();
        });
      }),
      deadlineAt,
    );
    const authority = `http://127.0.0.1:${server.address().port}`;
    revalidate();
    client = nativeConnect(authority);
    owned.add(client);
    observeClosure(client, sessions, "session");
    client.on("goaway", (errorCode, lastStreamID) => event("goaway", { errorCode, lastStreamID }));
    await until(
      new Promise((resolve, reject) => {
        client.once("connect", resolve);
        client.once("error", reject);
      }),
      deadlineAt,
    );
    const isDataRow = () => {
      const body = JSON.parse(Buffer.from(currentRow.bodyBase64, "base64"));
      return body.type === "receipt" && body.receipt.kind === "data";
    };
    const writer = createOwnedJournalWriter({
      fileHandle: {
        write(...args) {
          return operation("write", () => {
            if (isDataRow() && ["short-write", "zero-write"].includes(ioFault))
              args[2] = ioFault === "zero-write" ? 0 : args[2] - 1;
            return systemCall(file, "write", args, "file-write");
          });
        },
        sync() {
          return operation("file-sync", async () => {
            if (isDataRow() && ioFault === "close-file-before-sync")
              await systemCall(file, "close", [], "file-close");
            return systemCall(file, "sync", [], "file-sync");
          });
        },
      },
      directoryHandle: {
        sync() {
          return operation("directory-sync", async () => {
            if (isDataRow() && ioFault === "close-directory-before-sync")
              await systemCall(directoryHandle, "close", [], "directory-close");
            return systemCall(directoryHandle, "sync", [], "directory-sync");
          });
        },
      },
      deadlineAt,
      limits,
    });
    const sessionFacade = Object.freeze({
      on(eventName, callback) {
        client.on(eventName, callback);
      },
      removeListener(eventName, callback) {
        client.removeListener(eventName, callback);
      },
      request(headers) {
        if (clientStream || shuttingDown) throw new Error("one owned native stream required");
        clientStream = invoke(client, "request", [headers]);
        return observeStream(clientStream);
      },
      destroy() {
        return invoke(client, "destroy");
      },
    });
    const peerCheck = () => {
      if (!peerStream || shuttingDown || !owned.has(peerStream))
        throw new Error("owned peer stream unavailable");
    };
    const peer = Object.freeze({
      ready: () => until(peerReady.promise, deadlineAt),
      requestEnded: () => until(peerEnd.promise, deadlineAt),
      snapshot: () => Object.freeze({ streams: peerStreams, requestBytes, requestEnded }),
      respond(headers = { ":status": 200, "content-type": "application/grpc" }, endStream = false) {
        peerCheck();
        peerStream.respond(headers, { endStream, waitForTrailers: !endStream });
      },
      send(bytes) {
        peerCheck();
        return peerStream.write(bytes);
      },
      async finish(trailers = { "grpc-status": "0" }) {
        peerCheck();
        const ready = new Promise((resolve) => peerStream.once("wantTrailers", resolve));
        peerStream.end();
        await until(ready, deadlineAt);
        peerStream.sendTrailers(trailers);
      },
      reset(code) {
        peerCheck();
        peerStream.close(code);
      },
      goaway(code) {
        peerCheck();
        peerStream.session.goaway(code);
      },
    });
    return Object.freeze({
      peer,
      createBridge(bridgeOptions) {
        closedOptions(
          bridgeOptions,
          ["guard", "liveCheck", "onFrame", "credential", "signal"],
          "closed bridge options required",
        );
        // This local native validator records raw peer headers and admits no credentials.
        if (bridgeOptions.credential !== undefined)
          throw new Error("credential-free native fixture required");
        if (bridge || shuttingDown) throw new Error("one owned bridge required");
        bridge = createOwnedStreamingBridge({
          ...bridgeOptions,
          authority,
          path: "/google.pubsub.v1.Subscriber/StreamingPull",
          session: sessionFacade,
          deadlineAt,
          limits,
          liveCheck: (intent) => {
            revalidate();
            return bridgeOptions.liveCheck(intent);
          },
          write: async (row, context) => {
            currentRow = row;
            await writer.write(row, context);
          },
        });
        return bridge;
      },
      boundarySnapshot: () =>
        structuredClone({
          calls,
          events,
          eventOverflow,
          nativeCompleteness: "UNKNOWN",
          authority: state.kind,
          pid: process.pid,
          leaseDigest: state.kind === "registry" ? sha(state.token) : null,
        }),
      ioSnapshot: () =>
        structuredClone({
          steps,
          systemCalls,
          pendingOperations: pending.size,
          pendingNativeOperations: nativePending.size,
          writer: writer.report(),
          crashDurability: "UNKNOWN",
        }),
      awaitBarrier: (work) => until(work, deadlineAt),
      waitFor(kind, count = 1) {
        if (
          !["data", "end", "stream-close", "session-close", "goaway", "aborted"].includes(kind) ||
          !Number.isSafeInteger(count) ||
          count < 1 ||
          count > limits.maxNativeCallbacks
        )
          throw new Error("bounded native barrier required");
        if ((counts.get(kind) ?? 0) >= count) return Promise.resolve();
        const waiter = deferred();
        waiter.count = count;
        if (!waiters.has(kind)) waiters.set(kind, []);
        waiters.get(kind).push(waiter);
        return until(waiter.promise, deadlineAt).finally(() => {
          waiters.set(
            kind,
            waiters.get(kind).filter((value) => value !== waiter),
          );
        });
      },
      readJournal() {
        if (readbackStarted || shuttingDown)
          throw new Error("one owned readback required before shutdown");
        readbackStarted = true;
        return operation("readback", async () => {
          systemCalls.push({ operation: "readback", phase: "entry" });
          const work = readFile(join(directory, "wal"));
          nativePending.add(work);
          try {
            const bytes = await work;
            if (bytes.length > limits.maxWriterBytes) throw new Error("owned readback byte bound");
            systemCalls.push({ operation: "readback", phase: "settled" });
            return bytes;
          } finally {
            nativePending.delete(work);
          }
        });
      },
      shutdown,
    });
  } catch (error) {
    await shutdown();
    throw error;
  }
}
