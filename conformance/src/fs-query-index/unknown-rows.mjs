// The run-close check of a sandbox recording's log: which step lines did not settle their
// outcome. session.mjs logs a step as `<program>#<step> <status>` or
// `<program>#<step> grpc <code>`. A row is settled only when that outcome is a plain integer
// production answered definitely: an HTTP 2xx, or a 4xx other than 408 (a timeout), 429 and
// 499 (a cancellation, gRPC CANCELLED); a gRPC code that is not a cancellation, unknown error,
// timeout, exhaustion, internal error, unavailability or data loss. Status 0 (no answer), -1 (a
// step whose dependency recorded nothing) and any final 1xx or 3xx are unknown.
//
// The check is fail-closed: any step-shaped line (a `#<step>` token followed by whitespace)
// whose outcome is not exactly one of those plain forms is unknown too (`undefined`, `null`, a
// name, a tab, a doubled or trailing space, trailing text, `-0`), and so is a line that holds
// more than one step token or a line break inside it (CR, NEL, LS, PS), so an earlier outcome
// never hides behind a later one. A log with another number of step lines than expected fails.
//
//   node src/fs-query-index/unknown-rows.mjs <log> --expect <n>
//     prints each unknown row with its line number, then the number of step lines and of
//     unknown rows; exit 0 only when there is no unknown row and exactly <n> step lines (the
//     planned steps times the recordings: packets pass it), 1 when there is an unknown row, 3
//     when the count differs, 2 on a usage error (--expect is required)
//
// This CLI is the authority packets quote; there is no grep equivalent. Kept outside the
// harness digest: a stricter check never makes saved rows stale.

import { readFile } from "node:fs/promises";
import { isMainModule } from "./main-module.mjs";

/** A `#<step>` token followed by whitespace: the shape of every step line. */
const STEP_SHAPED = /#[^\s#]+\s/;
/** Every step token of a line. */
const STEP_TOKENS = /#[^\s#]+\s/g;
/** A plain step line: one space, then `0` or an integer without a leading zero, `-` allowed. */
const PLAIN_STEP = /#[^\s#]+ (?:(0|-?[1-9]\d*)|grpc (0|-?[1-9]\d*))$/;
/** A line break inside a line, after one trailing CR is stripped. */
const INNER_BREAK = /[\r\u0085\u2028\u2029]/;
/** gRPC codes that settle an outcome (OK, the client and precondition errors, UNAUTHENTICATED). */
const DEFINITE_GRPC = new Set([0, 3, 5, 6, 7, 9, 10, 11, 12, 16]);

const definiteHttp = (status) =>
  (status >= 200 && status <= 299) ||
  (status >= 400 && status <= 499 && ![408, 429, 499].includes(status));

const withoutCr = (line) => line.replace(/\r$/, "");

/** Whether a log line has the shape of a step line (its outcome may still be malformed). */
export const isStepLine = (line) => STEP_SHAPED.test(withoutCr(line));

export function isUnknownRow(line) {
  const text = withoutCr(line);
  if (!STEP_SHAPED.test(text)) return false;
  if (text.match(STEP_TOKENS).length > 1 || INNER_BREAK.test(text)) return true;
  const match = PLAIN_STEP.exec(text);
  if (!match) return true;
  const [, http, grpc] = match;
  return http !== undefined ? !definiteHttp(Number(http)) : !DEFINITE_GRPC.has(Number(grpc));
}

/** The number of step lines of a log and its unknown rows, with 1-based line numbers. */
export function scanLog(log) {
  const lines = log.split("\n").map((raw, index) => ({ line: index + 1, raw }));
  return {
    stepLines: lines.filter(({ raw }) => isStepLine(raw)).length,
    unknown: lines
      .filter(({ raw }) => isUnknownRow(raw))
      .map(({ line, raw }) => ({ line, text: withoutCr(raw) })),
  };
}

/** The unknown rows of a log, with 1-based line numbers. */
export const unknownRows = (log) => scanLog(log).unknown;

// `isMainModule`, not a comparison of URLs: a launch through a symlink or a path that needs
// escaping must still run the check (a skipped check would exit 0).
if (isMainModule(import.meta)) {
  const [path, flag, value, ...rest] = process.argv.slice(2);
  const expect = /^[1-9]\d*$/.test(value ?? "") ? Number(value) : undefined;
  if (!path || rest.length || flag !== "--expect" || !Number.isSafeInteger(expect)) {
    console.error("usage: unknown-rows.mjs <log> --expect <n>");
    process.exit(2);
  }
  const { stepLines, unknown } = scanLog(await readFile(path, "utf8"));
  for (const { line, text } of unknown) console.log(`${line}:${text}`);
  if (stepLines !== expect) console.log(`expected ${expect} step lines, saw ${stepLines}`);
  console.log(`step lines: ${stepLines}`);
  console.log(`unknown rows: ${unknown.length}`);
  if (stepLines !== expect) process.exitCode = 3;
  else if (unknown.length) process.exitCode = 1;
}
