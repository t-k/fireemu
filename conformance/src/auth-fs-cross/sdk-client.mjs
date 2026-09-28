// The parent side of an SDK driver process (see sdk-driver.mjs): commands out, events in, and a
// bounded wait for either. The process is always killed on close, so a stuck SDK promise cannot
// outlive the run.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

/** The Node driver, and the headless Chromium driver of the same protocol. */
export const DRIVERS = {
  "node-sdk": fileURLToPath(new URL("./sdk-driver.mjs", import.meta.url)),
  browser: fileURLToPath(new URL("./browser-driver.mjs", import.meta.url)),
};

export function spawnSdk(
  config,
  { timeoutMs = 60_000, spawnImpl = spawn, driver = DRIVERS["node-sdk"] } = {},
) {
  const child = spawnImpl(process.execPath, [driver], {
    env: { ...process.env, AFC_SDK_CONFIG: JSON.stringify(config) },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const events = [];
  const waiters = new Set();
  let exited;
  const deliver = (event) => {
    events.push(event);
    for (const waiter of waiters) {
      if (waiter.match(event)) {
        waiters.delete(waiter);
        clearTimeout(waiter.timer);
        waiter.resolve(event);
      }
    }
  };
  createInterface({ input: child.stdout }).on("line", (line) => {
    try {
      deliver(JSON.parse(line));
    } catch {
      deliver({ event: "unparsable-output", length: line.length });
    }
  });
  // A driver that ended (a refused request ends it) must not crash the parent on a late write.
  child.stdin.on("error", () => {});
  const stderr = [];
  child.stderr.on("data", (chunk) => stderr.push(String(chunk)));
  child.on("exit", (code, signal) => {
    exited = { code, signal };
    deliver({ event: "exit", code, signal });
    for (const waiter of waiters) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error(`sdk driver exited (${code ?? signal}) while waiting`));
    }
    waiters.clear();
  });

  /** Resolves with the first event (already seen from `from`, or future) that `match` accepts. */
  function waitFor(match, { from = 0, timeout = timeoutMs } = {}) {
    const seen = events.slice(from).find(match);
    if (seen) return Promise.resolve(seen);
    if (exited) return Promise.reject(new Error("sdk driver has exited"));
    return new Promise((resolve, reject) => {
      const waiter = { match, resolve, reject };
      waiter.timer = setTimeout(() => {
        waiters.delete(waiter);
        reject(new Error("timed out waiting for the sdk driver"));
      }, timeout);
      waiters.add(waiter);
    });
  }

  let next = 0;
  /** Sends a command and resolves with its result event (never rejects on an SDK error). */
  function send(op, fields = {}, options) {
    next += 1;
    if (exited) return Promise.reject(new Error("sdk driver has exited"));
    const id = fields.id ?? `c${next}`;
    const from = events.length;
    child.stdin.write(`${JSON.stringify({ ...fields, id, op })}\n`);
    return waitFor((event) => event.event === "result" && event.id === id, { from, ...options });
  }

  return {
    events,
    waitFor,
    send,
    stderr: () => stderr.join(""),
    ready: () => waitFor((event) => event.event === "ready"),
    async close() {
      if (!exited) {
        await send("shutdown", {}, { timeout: 5_000 }).catch(() => {});
        if (!exited) child.kill("SIGKILL");
      }
      return exited ?? (await waitFor((event) => event.event === "exit").catch(() => ({})));
    },
  };
}
