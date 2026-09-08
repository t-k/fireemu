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

describe("server-sent event edge cases", () => {
  it("skips an empty leading block and keeps parsing", () => {
    expect(parseSse("\n\ndata: x\n\n").events).toEqual([{ event: "message", data: "x" }]);
  });

  it("reads a data line with no value and one with no colon as empty data", () => {
    expect(parseSse("data:\n\n").events).toEqual([{ event: "message", data: "" }]);
    expect(parseSse("data\n\n").events).toEqual([{ event: "message", data: "" }]);
  });

  it("strips exactly one leading space of a value", () => {
    expect(parseSse("data:a b\n\n").events[0]?.data).toBe("a b");
    expect(parseSse("data:  two\n\n").events[0]?.data).toBe(" two");
  });

  it("ignores fields other than event and data", () => {
    expect(parseSse("id: 1\nretry: 5\ndata: x\n\n").events).toEqual([
      { event: "message", data: "x" },
    ]);
    expect(parseSse("id: 1\n\n").events).toEqual([]);
  });
});
