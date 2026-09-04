import { AsyncLocalStorage } from "node:async_hooks";
import { format } from "node:util";

const CONSOLE_LEVELS = Object.freeze({
  log: "info",
  info: "info",
  debug: "debug",
  warn: "error",
  error: "error",
});

const TRUNCATION_MARKER = "... [truncated]";
const STRUCTURED_SEVERITIES = new Set([
  "DEBUG",
  "INFO",
  "NOTICE",
  "WARNING",
  "ERROR",
  "CRITICAL",
  "ALERT",
  "EMERGENCY",
]);
const MAX_STRUCTURED_LOG_DEPTH = 64;

// Cloud Logging documents an approximate 256 KiB limit for the whole LogEntry. Applying that
// value conservatively to the message also leaves ample room below the 16 MiB protocol limit.
export const MAX_LOG_MESSAGE_BYTES = 256 * 1024;

export function boundLogMessage(value, maxBytes = MAX_LOG_MESSAGE_BYTES) {
  const message = String(value);
  const bytes = Buffer.from(message, "utf8");
  if (bytes.length <= maxBytes) return message;
  const marker = Buffer.from(TRUNCATION_MARKER, "utf8");
  if (maxBytes <= marker.length) return marker.subarray(0, maxBytes).toString("utf8");
  let end = maxBytes - marker.length;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return `${bytes.subarray(0, end).toString("utf8")}${TRUNCATION_MARKER}`;
}

function isWithinStructuredDepth(root) {
  const pending = [{ value: root, depth: 1 }];
  while (pending.length > 0) {
    const { value, depth } = pending.pop();
    if (depth > MAX_STRUCTURED_LOG_DEPTH) return false;
    if (value && typeof value === "object") {
      for (const child of Object.values(value)) pending.push({ value: child, depth: depth + 1 });
    }
  }
  return true;
}

function structuredEntry(message, fallbackLevel) {
  try {
    const parsed = JSON.parse(message);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { level: fallbackLevel, message };
    }
    const severity = typeof parsed?.severity === "string" ? parsed.severity.toUpperCase() : "";
    if (!STRUCTURED_SEVERITIES.has(severity) || !isWithinStructuredDepth(parsed)) {
      return { level: fallbackLevel, message };
    }
    const { severity: _severity, message: structuredMessage, ...fields } = parsed;
    return {
      level: severity.toLowerCase(),
      message: typeof structuredMessage === "string" ? structuredMessage : "",
      fields,
    };
  } catch {
    // Plain console output is not structured logging.
  }
  return { level: fallbackLevel, message };
}

export function createInvocationLogger(emit) {
  const context = new AsyncLocalStorage();

  return {
    run(metadata, task) {
      return context.run(metadata, task);
    },
    install(target = console) {
      const originals = new Map();
      for (const [method, level] of Object.entries(CONSOLE_LEVELS)) {
        const original = target[method].bind(target);
        originals.set(method, original);
        target[method] = (...values) => {
          const active = context.getStore();
          if (!active?.functionName) {
            original(...values);
            return;
          }
          const message = boundLogMessage(format(...values));
          const entry =
            values.length === 1 ? structuredEntry(message, level) : { level, message };
          emit({
            ...entry,
            functionName: active.functionName,
            invocationId: active.invocationId,
            user: true,
          });
        };
      }
      return () => {
        for (const [method, original] of originals) target[method] = original;
      };
    },
  };
}
