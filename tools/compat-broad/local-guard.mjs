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
const original = globalThis.fetch;
const started = performance.now();
let count = 0;
globalThis.fetch = (input, options = {}) => {
  const target = new URL(typeof input === "string" ? input : input.url);
  if (target.origin !== expected || target.username || target.password) {
    throw new Error("request escapes owned origin");
  }
  if (++count > 1500 || performance.now() - started > 120000) {
    throw new Error("local session budget exhausted");
  }
  return original(input, {
    ...options,
    redirect: "error",
    signal: AbortSignal.any([options.signal, AbortSignal.timeout(5000)].filter(Boolean)),
  });
};
process.on("exit", () => {
  writeFileSync(
    process.env.BROAD_STATS,
    JSON.stringify({ requests: count, elapsedMs: performance.now() - started }),
  );
});
