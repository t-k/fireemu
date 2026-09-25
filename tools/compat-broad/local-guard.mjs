// Local-only budget/redirect boundary shared by the two existing REST sessions.
import { writeFileSync } from "node:fs";

const expected = process.env.BROAD_ORIGIN;
const url = new URL(expected);
if (
  url.protocol !== "http:" ||
  url.hostname !== "127.0.0.1" ||
  Number(url.port) < 1024 ||
  url.origin !== expected
) {
  throw new Error("invalid owned loopback origin");
}

export function authorizeRequest(input, origin, count, elapsedMs) {
  const target = new URL(input);
  if (target.origin !== origin || target.username || target.password) {
    throw new Error("request escapes owned origin");
  }
  if (count > 1500 || elapsedMs + 5000 > 120000) {
    throw new Error("local session budget exhausted");
  }
}

const original = globalThis.fetch;
const started = performance.now();
let count = 0;
globalThis.fetch = async (input, options = {}) => {
  const target = typeof input === "string" ? input : input.url;
  authorizeRequest(target, expected, ++count, performance.now() - started);
  const response = await original(input, {
    ...options,
    redirect: "error",
    signal: AbortSignal.any([options.signal, AbortSignal.timeout(5000)].filter(Boolean)),
  });
  // Both legacy sessions assume a reset succeeded. Refuse to run seeded cases if it did not.
  if (
    options.method === "DELETE" &&
    new URL(target).pathname.startsWith("/emulator/") &&
    !response.ok
  ) {
    throw new Error("owned reset failed");
  }
  return response;
};
process.on("exit", () => {
  writeFileSync(
    process.env.BROAD_STATS,
    JSON.stringify({ requests: count, elapsedMs: performance.now() - started }),
  );
});
