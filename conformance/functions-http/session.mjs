// Executes the same bounded request corpus against a deployed function or local fireemu.

import { buildInvocation, normalizeInvocation } from "./harness.mjs";

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 120_000;

async function readComplete(response) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel("bounded fixture response exceeded 2 MiB");
      throw new Error("fixture response exceeded 2 MiB");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

async function readFirstLine(response) {
  if (!response.body) throw new Error("stream ended before its first line");
  const reader = response.body.getReader();
  let prefix = "";
  while (!prefix.includes("\n")) {
    const { done, value } = await reader.read();
    if (done) throw new Error("stream ended before its first line");
    prefix += Buffer.from(value).toString("utf8");
    if (Buffer.byteLength(prefix) > 4096) throw new Error("first stream line exceeded 4 KiB");
  }
  await reader.cancel("reviewed client disconnect");
  return prefix.slice(0, prefix.indexOf("\n")).replace(/\r$/, "");
}

export async function runCases(program, endpoints, tokens, budget, {
  fetchImpl = fetch,
  replacements = {},
  onResult = () => {},
} = {}) {
  const results = {};
  for (const step of program.cases) {
    const endpoint = endpoints[step.target];
    if (!endpoint) throw new Error(`${program.id}#${step.id}: no reviewed endpoint`);
    const { url, init } = buildInvocation(step, endpoint, tokens);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      budget.take("invocation");
      const response = await fetchImpl(url, { ...init, signal: controller.signal });
      const headers = Object.fromEntries(response.headers.entries());
      let recorded;
      if (step.capture === "first-chunk-then-abort") {
        const firstLine = await readFirstLine(response);
        recorded = normalizeInvocation(response.status, headers, Buffer.alloc(0), replacements);
        recorded.body = { firstLine };
        controller.abort();
      } else {
        const bytes = await readComplete(response);
        recorded = normalizeInvocation(response.status, headers, bytes, replacements);
      }
      results[step.id] = recorded;
      await onResult(step.id, recorded);
    } catch (error) {
      error.partial = { program: program.id, cases: results, failedCase: step.id };
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
  return results;
}
