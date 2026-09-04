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

function structuredLevel(message, fallbackLevel) {
  try {
    const parsed = JSON.parse(message);
    const severity = typeof parsed?.severity === "string" ? parsed.severity.toUpperCase() : "";
    if (severity === "DEBUG") return "debug";
    if (severity === "INFO" || severity === "NOTICE") return "info";
    if (severity === "WARNING") return "warn";
    if (["ERROR", "CRITICAL", "ALERT", "EMERGENCY"].includes(severity)) return "error";
  } catch {
    // Plain console output is not structured logging.
  }
  return fallbackLevel;
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
          const message = format(...values);
          emit({
            level: values.length === 1 ? structuredLevel(message, level) : level,
            message,
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
