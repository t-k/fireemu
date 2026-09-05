import { describe, expect, it } from "vitest";
import { parseApiError, parseSse } from "./client";

describe("API errors", () => {
  it("retains a Google RPC status for conflict handling", () => {
    expect(
      parseApiError(400, {
        error: { code: 400, status: "FAILED_PRECONDITION", message: "update time changed" },
      }),
    ).toEqual({ status: 400, code: "FAILED_PRECONDITION", message: "update time changed" });
  });
});

describe("server-sent event parsing", () => {
  it("returns complete events and keeps the remainder", () => {
    const { events, rest } = parseSse(
      'event: ready\ndata: {"a":1}\n\n: keep-alive\n\nevent: commit\ndata: {"b":2}\n\nevent: partial\ndata: {',
    );
    expect(events).toEqual([
      { event: "ready", data: '{"a":1}' },
      { event: "commit", data: '{"b":2}' },
    ]);
    expect(rest).toBe("event: partial\ndata: {");
  });

  it("joins multi-line data and defaults the event name", () => {
    const { events } = parseSse("data: one\ndata: two\n\n");
    expect(events).toEqual([{ event: "message", data: "one\ntwo" }]);
  });
});
