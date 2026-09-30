// Ordered storage acknowledgments only; caller screens records and owns native event provenance.
import { createHash } from "node:crypto";
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength").get;
const byteOffsetOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset").get;
const bufferOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer").get;

export function createStreamingJournal({
  maxEntries,
  maxEntryBytes,
  maxTotalBytes,
  deadlineAt,
  write,
  stopOwned,
}) {
  for (const value of [maxEntries, maxEntryBytes, maxTotalBytes])
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new Error("finite journal bounds required");
  const startedAt = performance.now();
  if (
    !Number.isFinite(deadlineAt) ||
    deadlineAt <= startedAt ||
    deadlineAt - startedAt > 2147483647
  )
    throw new Error("live bounded monotonic journal deadline required");
  for (const callback of [write, stopOwned])
    if (typeof callback !== "function") throw new Error("owned journal callbacks required");
  const pending = new Map(),
    controller = new AbortController();
  let entries = 0,
    totalBytes = 0,
    acknowledgedEntries = 0,
    drainedEntries = 0,
    reason,
    closed = false,
    haltWrites = false,
    chain = Promise.resolve(),
    ownedStarted = false,
    ownedSettled = false,
    ownedFailed = false,
    uncertainSeen = false;
  function track(id, callback) {
    let resolve, reject;
    const work = new Promise((r, j) => {
      resolve = r;
      reject = j;
    });
    const observed = work.then(
      (value) => {
        pending.delete(id);
        return value;
      },
      (error) => {
        pending.delete(id);
        throw error;
      },
    );
    pending.set(id, observed);
    try {
      resolve(callback());
    } catch (error) {
      reject(error);
    }
    return observed;
  }
  function requestOwnedStop(why) {
    if (ownedStarted) return;
    ownedStarted = true;
    track("owned-stop", () => stopOwned({ reason: why, signal: controller.signal })).then(
      () => {
        if (performance.now() >= deadlineAt) {
          uncertainSeen = true;
          stop("deadline", true);
        } else ownedSettled = true;
      },
      () => {
        ownedFailed = true;
      },
    );
  }
  function stop(why, halt = false) {
    reason ??= why;
    if (halt) {
      haltWrites = true;
      controller.abort();
    }
    requestOwnedStop(why);
  }
  const timer = setTimeout(
    () => stop("deadline", true),
    Math.max(0, deadlineAt - performance.now()),
  );
  timer.unref();
  function check() {
    if (performance.now() >= deadlineAt) stop("deadline", true);
    if (haltWrites) throw new Error("journal stopped");
  }
  async function writeBounded(row) {
    check();
    let cutoff;
    const expired = new Promise((_, reject) => {
      cutoff = setTimeout(
        () => {
          stop("deadline", true);
          reject(new Error("journal stopped"));
        },
        Math.max(0, deadlineAt - performance.now()),
      );
    });
    try {
      await Promise.race([
        track(`write:${row.index}`, () => write(row, { signal: controller.signal })),
        expired,
      ]);
      check();
    } finally {
      clearTimeout(cutoff);
    }
  }
  function append(input) {
    if (closed || reason) throw new Error("journal stopped");
    check();
    let refusal;
    const validView = ArrayBuffer.isView(input) && input instanceof Uint8Array;
    const length = validView ? byteLengthOf.call(input) : 0;
    if (!validView) refusal = "invalid-record";
    else if (entries >= maxEntries) refusal = "entry-bound";
    else if (length > maxEntryBytes) refusal = "entry-byte-bound";
    else if (length > maxTotalBytes - totalBytes) refusal = "total-byte-bound";
    if (refusal) {
      stop(refusal);
      throw new Error("journal stopped");
    }
    const index = entries++;
    totalBytes += length;
    let bytes;
    try {
      bytes = Buffer.from(new Uint8Array(bufferOf.call(input), byteOffsetOf.call(input), length));
    } catch {
      stop("invalid-record", true);
      throw new Error("journal stopped");
    }
    const row = Object.freeze({
      index,
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    let resolve, reject;
    const committed = new Promise((r, j) => {
      resolve = r;
      reject = j;
    });
    committed.catch(() => {});
    chain = chain.then(async () => {
      try {
        await writeBounded(row);
        acknowledgedEntries++;
        resolve(Object.freeze({ index: row.index, sha256: row.sha256, bodyBytes: row.bodyBytes }));
      } catch {
        stop("persistence", true);
        reject(new Error("journal stopped"));
      } finally {
        drainedEntries++;
      }
    });
    return Object.freeze({ index: row.index, committed });
  }
  async function waitBounded(work) {
    let cutoff;
    const expired = new Promise((resolve) => {
      cutoff = setTimeout(resolve, Math.max(0, deadlineAt - performance.now()));
    });
    try {
      await Promise.race([work, expired]);
    } finally {
      clearTimeout(cutoff);
    }
  }
  async function done() {
    closed = true;
    requestOwnedStop(reason ?? "local-close");
    await waitBounded(chain);
    await waitBounded(Promise.allSettled(pending.values()));
    if (performance.now() >= deadlineAt) {
      uncertainSeen = true;
      stop("deadline", true);
    }
    clearTimeout(timer);
    uncertainSeen = uncertainSeen || pending.size > 0 || drainedEntries !== entries;
    return {
      deadlineAt,
      entries,
      totalBytes,
      acknowledgedEntries,
      unknownEntries: entries - acknowledgedEntries,
      ...(reason ? { reason } : {}),
      pendingCallbacks: [...pending.keys()],
      terminationRequired: uncertainSeen || ownedFailed || !ownedSettled,
    };
  }
  return { append, done };
}
