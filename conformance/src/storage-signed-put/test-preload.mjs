// The network sentinel of the signed PUT tests. Every test file of this lane imports it first. Any
// http(s) request or fetch to a host other than loopback is refused and recorded in `attempts`,
// and the process exits non-zero if any attempt was recorded, even when the code under test
// swallowed the error. (On 2026-11-03 a test let the Storage SDK reach storage.googleapis.com.)

import { installEgressGuard } from "./egress.mjs";

export const attempts = [];

const LOOPBACK = ["127.0.0.1", "localhost"];

installEgressGuard(LOOPBACK, { onRefuse: (host) => attempts.push(`http: ${host}`) });

const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const href = String(input?.url ?? input);
  if (!LOOPBACK.includes(new URL(href).hostname)) {
    attempts.push(`fetch: ${href}`);
    throw new Error("fetch is not allowed in this test");
  }
  return realFetch(input, init);
};

process.on("exit", () => {
  if (attempts.length > 0) {
    console.error(`a real network request was attempted: ${attempts.join(", ")}`);
    process.exitCode = 1;
  }
});
