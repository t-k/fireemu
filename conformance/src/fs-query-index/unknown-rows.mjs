// The run-close check of a sandbox recording's log: which step lines did not settle their
// outcome. A step line is `<program>#<step> <status>` or `<program>#<step> grpc <code>`, as
// session.mjs logs it. A row is unknown unless production answered it definitely: an HTTP 2xx,
// or a 4xx other than 429; a gRPC code that is not a timeout, cancellation, internal error,
// exhaustion or unavailability. Status 0 (no answer) and -1 (a step whose dependency recorded
// nothing) are unknown, and so is any final 1xx or 3xx (fetch follows redirects, so one is
// not expected, but it settles nothing).
//
//   node src/fs-query-index/unknown-rows.mjs <log>   prints each unknown row with its line
//                                                     number; exit 1 when there is one
//
// Kept outside the harness digest: a stricter check never makes saved rows stale.

import { readFile } from "node:fs/promises";

const STEP_LINE = /^\S+#\S+ (?:(-?\d+)|grpc (-?\d+))$/;
/** gRPC codes that settle an outcome (OK, the client and precondition errors, UNAUTHENTICATED). */
const DEFINITE_GRPC = new Set([0, 3, 5, 6, 7, 9, 10, 11, 12, 16]);

/**
 * The same rule as a POSIX ERE, for `grep -nE` in packet after-steps. A test checks that it
 * agrees with `isUnknownRow` on every status and code it can meet.
 */
export const UNKNOWN_ROW_PATTERN =
  "#[^ ]+ (-[0-9]+|[0-9]{1,2}|[13][0-9]{2}|429|[5-9][0-9]{2}|[0-9]{4,}|grpc (-[0-9]+|[1248]|1[3-5]|1[7-9]|[2-9][0-9]|[0-9]{3,}))$";

const definiteHttp = (status) =>
  (status >= 200 && status <= 299) || (status >= 400 && status <= 499 && status !== 429);

export function isUnknownRow(line) {
  const match = STEP_LINE.exec(line);
  if (!match) return false;
  const [, http, grpc] = match;
  return http !== undefined ? !definiteHttp(Number(http)) : !DEFINITE_GRPC.has(Number(grpc));
}

/** The unknown rows of a log, with 1-based line numbers. */
export function unknownRows(log) {
  return log
    .split("\n")
    .map((text, index) => ({ line: index + 1, text: text.replace(/\r$/, "") }))
    .filter(({ text }) => isUnknownRow(text));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: unknown-rows.mjs <log>");
    process.exit(2);
  }
  const found = unknownRows(await readFile(path, "utf8"));
  for (const { line, text } of found) console.log(`${line}:${text}`);
  console.log(`unknown rows: ${found.length}`);
  if (found.length) process.exitCode = 1;
}
